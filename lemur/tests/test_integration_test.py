from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, Mock, call

import botocore
import pytest
from flask import current_app, g

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


def test_reset_schema_creates_current_schema_and_stamps_head(app, monkeypatch):
    from lemur.test import database

    monkeypatch.setattr(database, "validate_database_identity", Mock())
    monkeypatch.setattr(database.db.session, "remove", Mock())
    monkeypatch.setattr(database.db.engine, "execute", Mock())
    monkeypatch.setattr(database.db, "create_all", Mock())
    monkeypatch.setattr(database, "stamp", Mock())

    database.reset_schema()

    assert Path(database.MIGRATIONS_DIRECTORY).is_absolute()
    assert Path(database.MIGRATIONS_DIRECTORY).name == "migrations"
    database.db.create_all.assert_called_once_with()
    database.stamp.assert_called_once_with(
        directory=database.MIGRATIONS_DIRECTORY, revision="head"
    )


def test_seed_creates_source_sync_user(app, monkeypatch):
    from lemur.test import database

    admin = Mock()
    monkeypatch.setattr(database.role_service, "create", Mock(return_value=admin))
    monkeypatch.setattr(database.user_service, "create", Mock())

    database._create_roles_and_users()

    usernames = [
        item.kwargs["username"] for item in database.user_service.create.call_args_list
    ]
    assert usernames == ["lemur-test", "lemur"]


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


def test_run_resets_database_inside_lock(app, monkeypatch):
    from lemur.test import runner

    events = []
    monkeypatch.setattr(runner, "validate_isolation", Mock())
    monkeypatch.setattr(runner, "validate_task_catalog", Mock())
    monkeypatch.setattr(runner, "_selected_scenarios", Mock(return_value={}))
    monkeypatch.setattr(runner.metrics, "send", Mock())
    monkeypatch.setattr(
        runner.db.session,
        "remove",
        Mock(side_effect=lambda: events.append("release")),
    )
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
        Mock(side_effect=lambda _state: events.append("cleanup")),
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
        "release",
        "verify",
        "release",
        "cleanup",
        "unlock",
    ]
    runner.fixtures.cleanup.assert_called_once_with({"fixture": True})


def test_run_skips_cleanup_when_database_reset_fails(app, monkeypatch):
    from lemur.test import runner

    monkeypatch.setattr(runner, "validate_isolation", Mock())
    monkeypatch.setattr(runner, "validate_task_catalog", Mock())
    monkeypatch.setattr(runner, "_selected_scenarios", Mock(return_value={}))
    monkeypatch.setattr(runner.metrics, "send", Mock())
    monkeypatch.setattr(
        runner, "reset_and_seed", Mock(side_effect=RuntimeError("reset failed"))
    )
    monkeypatch.setattr(runner.fixtures, "cleanup", Mock())

    @contextmanager
    def unlocked(_run_id):
        yield

    monkeypatch.setattr(runner, "run_lock", unlocked)

    report = runner.run(reset_database=True)

    assert report["status"] == "failed"
    assert report["phases"][0]["phase"] == "prepare"
    assert [phase["phase"] for phase in report["phases"]] == ["prepare"]
    runner.fixtures.cleanup.assert_not_called()


def test_run_certificates_includes_replacements_and_excludes_persistent_fixtures(
    app, monkeypatch
):
    from lemur.test import fixtures

    replacement = Mock(id=3, name="generated-replacement", replaced=[])
    run_certificate = Mock(id=2, name="lemur-test-run-123", replaced=[replacement])
    persistent_certificate = Mock(id=1, name="lemur-test-baseline", replaced=[])
    query = MagicMock()
    query.filter.return_value.all.return_value = [run_certificate]
    monkeypatch.setattr(fixtures.Certificate, "query", query)
    monkeypatch.setattr(
        fixtures.certificate_service,
        "get",
        Mock(return_value=run_certificate),
    )

    certificates = fixtures._run_certificates({"certificate_id": 2})

    assert certificates == [run_certificate, replacement]
    assert persistent_certificate not in certificates


def test_issue_test_certificate_sets_admin_identity(app, monkeypatch):
    from lemur.test import fixtures

    user = Mock(id=42, email="lemur-test@datadoghq.com")
    authority = Mock(id=7)
    schema = Mock()
    schema.load.return_value = ({}, {})
    monkeypatch.setattr(
        fixtures.user_service, "get_by_username", Mock(return_value=user)
    )
    monkeypatch.setattr(
        fixtures.authority_service, "get_by_name", Mock(return_value=authority)
    )
    monkeypatch.setattr(fixtures, "CertificateInputSchema", Mock(return_value=schema))
    monkeypatch.setattr(fixtures.certificate_service, "create", Mock())
    monkeypatch.setattr(fixtures.identity_changed, "send", Mock())

    fixtures._issue_test_certificate("run-id", [])

    assert g.current_user is user
    identity = fixtures.identity_changed.send.call_args.kwargs["identity"]
    assert identity.id == user.id
    fixtures.certificate_service.create.assert_called_once_with(creator=user)
    g.pop("current_user", None)


def test_set_endpoint_certificate_waits_for_iam_propagation(app, monkeypatch):
    from lemur.test import fixtures

    current_app.config.update(
        LEMUR_TEST_AWS_ACCOUNT="123456789012",
        LEMUR_TEST_AWS_REGION="us-east-1",
    )
    error = botocore.exceptions.ClientError(
        {"Error": {"Code": "CertificateNotFound"}}, "ModifyListener"
    )
    monkeypatch.setattr(
        fixtures.elb,
        "get_listener_arn_from_endpoint",
        Mock(return_value="listener-arn"),
    )
    monkeypatch.setattr(
        fixtures.elb,
        "attach_certificate_v2",
        Mock(side_effect=[error, {"ok": True}]),
    )
    monkeypatch.setattr(fixtures.time, "sleep", Mock())

    result = fixtures._set_endpoint_certificate(
        {"type": "alb", "name": "lemur-test-alb", "port": 443},
        "certificate-arn",
    )

    assert result == {"ok": True}
    assert fixtures.elb.attach_certificate_v2.call_count == 2
    fixtures.time.sleep.assert_called_once_with(
        fixtures.AWS_CERTIFICATE_PROPAGATION_DELAY_SECONDS
    )


def test_prepare_releases_database_session_before_aws_attachment(app, monkeypatch):
    from lemur.test import fixtures

    events = []
    certificate = Mock(id=17)
    source = Mock(label="lemur-test-aws")
    current_app.config.update(
        LEMUR_TEST_AWS_ENDPOINTS=[
            {"type": "alb", "name": "lemur-test-alb", "port": 443}
        ]
    )
    monkeypatch.setattr(fixtures, "_create_destinations", Mock(return_value=[]))
    monkeypatch.setattr(fixtures, "_create_sources", Mock(return_value=[source]))
    monkeypatch.setattr(
        fixtures, "_issue_test_certificate", Mock(return_value=certificate)
    )
    monkeypatch.setattr(
        fixtures, "_iam_certificate_arn", Mock(return_value="certificate-arn")
    )
    monkeypatch.setattr(
        fixtures.database.db.session,
        "remove",
        Mock(side_effect=lambda: events.append("release")),
    )
    monkeypatch.setattr(
        fixtures,
        "_set_endpoint_certificate",
        Mock(side_effect=lambda *_args: events.append("attach")),
    )

    state = fixtures.prepare("run-id")

    assert state == {"certificate_id": 17, "source_labels": ["lemur-test-aws"]}
    assert events == ["release", "attach"]


def test_cleanup_waits_for_listener_detachment(app, monkeypatch):
    from lemur.test import fixtures

    error = botocore.exceptions.ClientError(
        {"Error": {"Code": "DeleteConflict"}}, "DeleteServerCertificate"
    )
    plugin = Mock()
    plugin.clean.side_effect = [error, None]
    destination = Mock(plugin_name="aws-destination", options=[], label="test-aws")
    certificate = Mock(name="lemur-test-run-123", destinations=[destination])
    current_app.config.update(LEMUR_TEST_AWS_ENDPOINTS=[])
    monkeypatch.setattr(fixtures, "_run_certificates", Mock(return_value=[certificate]))
    monkeypatch.setattr(fixtures.plugins, "get", Mock(return_value=plugin))
    monkeypatch.setattr(fixtures.time, "sleep", Mock())

    fixtures.cleanup()

    assert plugin.clean.call_count == 2
    assert plugin.clean.call_args.kwargs["certificate"].name == certificate.name
    assert plugin.clean.call_args.kwargs["certificate"].body == certificate.body
    fixtures.time.sleep.assert_called_once_with(
        fixtures.AWS_CERTIFICATE_PROPAGATION_DELAY_SECONDS
    )


def test_cleanup_releases_database_session_before_external_cleanup(app, monkeypatch):
    from lemur.test import fixtures

    events = []
    plugin = Mock()
    plugin.clean.side_effect = lambda **_kwargs: events.append("clean")
    destination = Mock(plugin_name="aws-destination", options=[], label="test-aws")
    certificate = Mock(
        name="lemur-test-run-123", body="certificate", destinations=[destination]
    )
    current_app.config.update(LEMUR_TEST_AWS_ENDPOINTS=[])
    monkeypatch.setattr(fixtures, "_run_certificates", Mock(return_value=[certificate]))
    monkeypatch.setattr(fixtures.plugins, "get", Mock(return_value=plugin))
    monkeypatch.setattr(
        fixtures.database.db.session,
        "remove",
        Mock(side_effect=lambda: events.append("release")),
    )

    fixtures.cleanup()

    assert events == ["release", "clean"]


def test_deactivate_entrust_certificates_without_certificates_is_a_noop(
    app, monkeypatch
):
    from lemur.certificates import cli

    monkeypatch.setattr(cli, "get_all_valid_certs", Mock(return_value=[]))
    monkeypatch.setattr(cli.plugins, "get", Mock())

    cli.deactivate_entrust_certificates()

    cli.plugins.get.assert_not_called()


def test_verify_requires_expected_endpoint_to_use_replacement(app, monkeypatch):
    from lemur.test import fixtures

    replacement = Mock(id=2)
    certificate = Mock(id=1, replaced=[replacement])
    endpoint = Mock(primary_certificate=Mock(id=1))
    current_app.config.update(
        LEMUR_TEST_EXPECTED_ENDPOINTS=[
            {"name": "lemur-test-alb", "source": "lemur-test-aws", "rotated": True}
        ],
        LEMUR_TEST_MIN_ENDPOINTS_BY_SOURCE={},
    )
    monkeypatch.setattr(
        fixtures.certificate_service, "get", Mock(return_value=certificate)
    )
    monkeypatch.setattr(
        fixtures.endpoint_service,
        "get_by_name_and_source",
        Mock(return_value=endpoint),
    )

    with pytest.raises(RuntimeError, match="was not rotated"):
        fixtures.verify({"certificate_id": 1, "source_labels": []})


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
    engine.url.translate_connect_args.return_value = {
        "host": "postgres",
        "database": "lemur",
        "user": "lemur",
        "password": "password",
    }
    engine.execute.return_value = row
    engine.raw_connection.return_value = connection
    monkeypatch.setattr(bootstrap_database, "db", Mock(engine=engine))
    target_connection = MagicMock()
    monkeypatch.setattr(
        bootstrap_database.psycopg2,
        "connect",
        Mock(return_value=target_connection),
    )

    result = bootstrap_database.bootstrap()

    assert result == {"database": "test", "user": "lemur_test"}
    assert connection.method_calls[:2] == [
        call.rollback(),
        call.set_session(autocommit=True),
    ]
    bootstrap_database.psycopg2.connect.assert_called_once_with(
        host="postgres",
        database="test",
        user="lemur",
        password="password",
    )
    target_cursor = target_connection.cursor.return_value.__enter__.return_value
    assert target_cursor.execute.call_count == 1
