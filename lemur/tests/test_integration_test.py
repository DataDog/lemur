from contextlib import contextmanager
from unittest.mock import Mock

import pytest
from flask import current_app

from lemur.test import catalog


def test_validate_task_catalog_accepts_complete_catalog():
    app = Mock()
    app.tasks = {name: Mock() for name in catalog.TASK_CATALOG}

    catalog.validate_task_catalog(app)


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
    from lemur.test import runner

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
    monkeypatch.setattr(runner.db.engine, "execute", Mock(return_value=row))

    runner.validate_isolation()


def test_validate_isolation_rejects_normal_database(app, monkeypatch):
    from lemur.test import runner

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
    monkeypatch.setattr(runner.db.engine, "execute", Mock(return_value=row))

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

    report = runner.run(timeout=10)

    assert report["status"] == "failed"
    assert [entry["status"] for entry in report["tasks"]] == ["passed", "failed"]
    assert runner.celery_app.send_task.call_args_list[0].kwargs["queue"] == "lemur-test"
    assert runner.celery_app.send_task.call_args_list[1].kwargs["args"] == [2]

