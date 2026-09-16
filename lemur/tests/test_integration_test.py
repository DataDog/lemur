from contextlib import contextmanager
from unittest.mock import MagicMock, Mock, call

import pytest
from flask import current_app

from lemur.test import catalog


def test_validate_task_catalog_accepts_complete_catalog():
    app = Mock()
    app.tasks = {name: Mock() for name in catalog.TASK_CATALOG}

    catalog.validate_task_catalog(app)


def test_task_catalog_matches_registered_lemur_tasks(app):
    from lemur.common.celery import celery_app

    catalog.validate_task_catalog(celery_app)


def test_validate_task_catalog_reports_missing_and_stale_tasks():
    app = Mock()
    app.tasks = {
        "lemur.common.celery.new_task": Mock(),
        "celery.backend_cleanup": Mock(),
    }

    with pytest.raises(RuntimeError) as error:
        catalog.validate_task_catalog(app)

    message = str(error.value)
    assert "missing scenarios: lemur.common.celery.new_task" in message
    assert "unregistered tasks:" in message
    assert "celery.backend_cleanup" not in message


def test_scenarios_apply_configured_arguments():
    task_name = "lemur.common.celery.sync_source"
    resolved = catalog.scenarios(
        {task_name: {"args": ["configured-source"], "kwargs": {"force": True}}}
    )

    assert resolved[task_name].args == ["configured-source"]
    assert resolved[task_name].kwargs == {"force": True}


def test_validate_isolation_requires_test_database_and_redis(app, monkeypatch):
    from lemur.test import database, runner

    current_app.config.update(
        LEMUR_TEST_ENABLED=True,
        LEMUR_TEST_DATABASE="test",
        LEMUR_TEST_DATABASE_USER="lemur_test",
        LEMUR_TEST_REDIS_DB=1,
        LEMUR_TEST_QUEUE="lemur-test",
        CELERY_DEFAULT_QUEUE="lemur-test",
        REDIS_DB=1,
    )
    row = Mock()
    row.fetchone.return_value = ("test", "lemur_test")
    monkeypatch.setattr(database.db.engine, "execute", Mock(return_value=row))

    runner.validate_isolation()


def test_validate_isolation_rejects_normal_database(app, monkeypatch):
    from lemur.test import database, runner

    current_app.config.update(
        LEMUR_TEST_ENABLED=True,
        LEMUR_TEST_DATABASE="test",
        LEMUR_TEST_DATABASE_USER="lemur_test",
        LEMUR_TEST_REDIS_DB=1,
        LEMUR_TEST_QUEUE="lemur-test",
        CELERY_DEFAULT_QUEUE="lemur-test",
        REDIS_DB=1,
    )
    row = Mock()
    row.fetchone.return_value = ("lemur", "lemur")
    monkeypatch.setattr(database.db.engine, "execute", Mock(return_value=row))

    with pytest.raises(RuntimeError, match="Refusing to run"):
        runner.validate_isolation()


def test_run_dispatches_to_test_queue_and_reports_failures(app, monkeypatch):
    from lemur.test import runner

    current_app.config.update(LEMUR_TEST_QUEUE="lemur-test")
    monkeypatch.setattr(runner, "validate_isolation", Mock())
    monkeypatch.setattr(runner, "validate_task_catalog", Mock())

    @contextmanager
    def unlocked(_run_id):
        yield

    monkeypatch.setattr(runner, "run_lock", unlocked)
    monkeypatch.setattr(
        runner,
        "_selected_scenarios",
        Mock(
            return_value={
                "lemur.common.celery.one": catalog.TaskScenario(),
                "lemur.common.celery.two": catalog.TaskScenario(args=[2]),
            }
        ),
    )

    passed = Mock(id="passed-id")
    passed.get.return_value = {"ok": True}
    failed = Mock(id="failed-id")
    failed.get.side_effect = RuntimeError("failed")
    monkeypatch.setattr(
        runner.celery_app,
        "send_task",
        Mock(side_effect=[passed, failed]),
    )
    monkeypatch.setattr(runner.metrics, "send", Mock())
    monkeypatch.setattr(runner.fixtures, "after_task", Mock())

    report = runner.run(timeout=10)

    assert report["status"] == "failed"
    assert [entry["status"] for entry in report["tasks"]] == ["passed", "failed"]
    assert runner.celery_app.send_task.call_args_list[0].kwargs["queue"] == "lemur-test"
    assert runner.celery_app.send_task.call_args_list[1].kwargs["args"] == [2]


def test_run_resets_database_inside_lock(app, monkeypatch):
    from lemur.test import runner

    events = []
    monkeypatch.setattr(runner, "validate_isolation", Mock())
    monkeypatch.setattr(runner, "validate_task_catalog", Mock())
    monkeypatch.setattr(runner, "_selected_scenarios", Mock(return_value={}))
    monkeypatch.setattr(runner.metrics, "send", Mock())
    monkeypatch.setattr(
        runner, "reset_and_seed", Mock(side_effect=lambda: events.append("reset"))
    )
    monkeypatch.setattr(
        runner.fixtures,
        "prepare",
        Mock(side_effect=lambda _run_id: events.append("prepare") or {"fixture": True}),
    )
    monkeypatch.setattr(
        runner.fixtures,
        "verify",
        Mock(side_effect=lambda _state: events.append("verify") or {}),
    )
    monkeypatch.setattr(
        runner.fixtures,
        "cleanup",
        Mock(side_effect=lambda: events.append("cleanup")),
    )

    @contextmanager
    def locked(_run_id):
        events.append("lock")
        yield
        events.append("unlock")

    monkeypatch.setattr(runner, "run_lock", locked)

    report = runner.run(reset_database=True)

    assert report["status"] == "passed"
    assert events == [
        "lock",
        "reset",
        "prepare",
        "verify",
        "cleanup",
        "unlock",
    ]


def test_after_sync_source_links_cloudfront_replacement(app, monkeypatch):
    from lemur.test import fixtures

    current_app.config["LEMUR_TEST_CLOUDFRONT_ROTATION"] = {
        "source": "lemur-test-cloudfront",
        "old_certificate": "lemur-test-cloudfront-primary",
        "new_certificate": "lemur-test-cloudfront-backup",
    }
    old_certificate = Mock(id=1, name="lemur-test-cloudfront-primary")
    new_certificate = Mock(id=2, name="lemur-test-cloudfront-backup", replaces=[])
    monkeypatch.setattr(
        fixtures.certificate_service,
        "get_by_name",
        Mock(side_effect=[old_certificate, new_certificate]),
    )
    monkeypatch.setattr(fixtures.database, "commit", Mock())
    state = {}

    fixtures.after_task(fixtures.SYNC_SOURCE_TASK, state)

    assert new_certificate.replaces == [old_certificate]
    assert state == {
        "cloudfront_old_certificate_id": 1,
        "cloudfront_new_certificate_id": 2,
    }
    fixtures.database.commit.assert_called_once_with()


def test_bootstrap_database_rejects_normal_configuration(app):
    from lemur.test import bootstrap_database

    current_app.config.update(LEMUR_TEST_BOOTSTRAP_ENABLED=False)

    with pytest.raises(RuntimeError, match="LEMUR_TEST_BOOTSTRAP_ENABLED"):
        bootstrap_database.bootstrap()


def test_bootstrap_database_rejects_wrong_identity(app, monkeypatch):
    from lemur.test import bootstrap_database

    current_app.config.update(
        LEMUR_TEST_BOOTSTRAP_ENABLED=True,
        LEMUR_TEST_BOOTSTRAP_DATABASE="lemur",
        LEMUR_TEST_BOOTSTRAP_USER="lemur",
    )
    row = Mock()
    row.fetchone.return_value = ("test", "lemur_test")
    monkeypatch.setattr(bootstrap_database.db.engine, "execute", Mock(return_value=row))

    with pytest.raises(RuntimeError, match="Refusing to bootstrap"):
        bootstrap_database.bootstrap()


def test_bootstrap_database_clears_transaction_before_autocommit(app, monkeypatch):
    from lemur.test import bootstrap_database

    current_app.config.update(
        LEMUR_TEST_BOOTSTRAP_ENABLED=True,
        LEMUR_TEST_BOOTSTRAP_DATABASE="lemur",
        LEMUR_TEST_BOOTSTRAP_USER="lemur",
        LEMUR_TEST_DATABASE="test",
        LEMUR_TEST_DATABASE_USER="lemur_test",
    )
    row = Mock()
    row.fetchone.return_value = ("lemur", "lemur")
    cursor = Mock()
    cursor.fetchone.side_effect = [None, None]
    connection = MagicMock()
    connection.cursor.return_value.__enter__.return_value = cursor
    engine = Mock()
    engine.url.password = "password"
    engine.execute.return_value = row
    engine.raw_connection.return_value = connection
    monkeypatch.setattr(bootstrap_database, "db", Mock(engine=engine))

    result = bootstrap_database.bootstrap()

    assert result == {"database": "test", "user": "lemur_test"}
    assert connection.method_calls[:2] == [
        call.rollback(),
        call.set_session(autocommit=True),
    ]
