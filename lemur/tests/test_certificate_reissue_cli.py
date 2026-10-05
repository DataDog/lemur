"""
Tests for the rollback of a failed certificate reissue (CLOUDR-2368).

A failed reissue must not leave a new certificate in the database. It must also
upload the old certificate again to every destination that the new one reached.
"""
import inspect
from unittest.mock import patch

import pytest
from flask import current_app

from lemur import database
from lemur.certificates import service
from lemur.certificates.cli import request_reissue
from lemur.certificates.models import Certificate
from lemur.constants import FAILURE_METRIC_STATUS, SUCCESS_METRIC_STATUS
from lemur.tests.factories import (
    CertificateFactory,
    DestinationFactory,
    UserFactory,
)

PLUGIN_UPLOAD = "lemur.tests.plugins.destination_plugin.TestDestinationPlugin.upload"


def _make_destination(session, tag):
    destination = DestinationFactory(
        options=[{"name": "tag", "type": "str", "value": tag}]
    )
    session.commit()
    return destination


def _make_cert(session, authority, destinations=()):
    """Make a certificate. Uploads during setup are not recorded by the tests."""
    cert = CertificateFactory(user=UserFactory(), authority=authority, destinations=[])
    for destination in destinations:
        cert.destinations.append(destination)
    session.commit()
    return cert


def _tag(options):
    for option in options or []:
        if option.get("name") == "tag":
            return option.get("value")
    return None


def _messages(logger_mock):
    """Return the message text of each call to a mocked logger method."""
    result = []
    for call in logger_mock.call_args_list:
        first = call.args[0] if call.args else ""
        result.append(first.get("message", "") if isinstance(first, dict) else str(first))
    return result


def _reissue_metrics(metrics_mock):
    return [
        c.kwargs["metric_tags"]
        for c in metrics_mock.send.call_args_list
        if c.args and c.args[0] == "certificate_reissue"
    ]


@pytest.fixture
def env(session, destination_plugin, issuer_plugin, crypto_authority, logged_in_user):
    return session, crypto_authority


def test_failed_reissue_is_rolled_back_before_next_cert(env):
    session, authority = env
    dest_1 = _make_destination(session, "one")
    dest_2 = _make_destination(session, "two")
    first = _make_cert(session, authority, [dest_1])
    second = _make_cert(session, authority, [dest_2])
    first_id, first_name = first.id, first.name
    second_id = second.id
    old_names = {first.name, second.name}
    state = {"failed": False}

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):
        # The first upload of a new certificate fails. All other uploads work.
        if name not in old_names and not state["failed"]:
            state["failed"] = True
            raise RuntimeError("destination is down")

    with patch(PLUGIN_UPLOAD, upload), patch(
        "lemur.certificates.cli.metrics"
    ) as metrics_mock, patch.object(current_app.logger, "error") as log_error, patch.object(
        current_app.logger, "info"
    ) as log_info:
        request_reissue(first, False, True)
        request_reissue(second, False, True)

    # The failed replacement is not in the database.
    assert Certificate.query.filter(Certificate.replaces.any(id=first_id)).count() == 0
    assert Certificate.query.get(first_id).replaced == []
    # The next reissue worked and kept its destination.
    replacements = Certificate.query.filter(Certificate.replaces.any(id=second_id)).all()
    assert len(replacements) == 1
    assert [d.id for d in replacements[0].destinations] == [dest_2.id]

    # The failure metric and the logs are still there.
    tags = _reissue_metrics(metrics_mock)
    assert tags[0] == {"status": FAILURE_METRIC_STATUS, "certificate": first_name}
    assert tags[1]["status"] == SUCCESS_METRIC_STATUS
    assert any("Reissue failed at this step" in m for m in _messages(log_error))
    assert any("Rolling back database session" in m for m in _messages(log_info))
    assert any("Rolling back destination" in m for m in _messages(log_info))

    # The old certificate shows the failure in its description.
    description = Certificate.query.get(first_id).description
    assert "[Lemur reissue failed:" in description
    assert f"upload to destination {dest_1.label}" in description


def test_failed_upload_restores_modified_and_failed_destinations(env):
    session, authority = env
    dest_a = _make_destination(session, "A")
    dest_b = _make_destination(session, "B")
    dest_c = _make_destination(session, "C")
    cert = _make_cert(session, authority, [dest_a, dest_b, dest_c])
    old_name = cert.name
    new_uploads = []
    restores = []

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):
        if name == old_name:
            restores.append(_tag(options))
            return
        new_uploads.append(_tag(options))
        if _tag(options) == "B":
            raise RuntimeError("destination B is down")

    with patch(PLUGIN_UPLOAD, upload), patch("lemur.certificates.cli.metrics"):
        request_reissue(cert, False, True)

    # A worked and B failed. C was never reached, so it is not restored.
    assert new_uploads == ["A", "B"]
    assert sorted(restores) == ["A", "B"]


def test_commit_failure_restores_all_destinations(env):
    session, authority = env
    dest_a = _make_destination(session, "A")
    dest_b = _make_destination(session, "B")
    cert = _make_cert(session, authority, [dest_a, dest_b])
    old_name = cert.name
    new_uploads = []
    restores = []

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):
        (restores if name == old_name else new_uploads).append(_tag(options))

    real_commit = database.commit

    def failing_commit():
        callers = [(f.function, f.filename) for f in inspect.stack()]
        if any(
            fn == "create" and filename.endswith("certificates/service.py")
            for fn, filename in callers
        ):
            raise RuntimeError("commit failed")
        return real_commit()

    with patch(PLUGIN_UPLOAD, upload), patch("lemur.certificates.cli.metrics"), patch.object(
        service.database, "commit", failing_commit
    ):
        request_reissue(cert, False, True)

    # All uploads worked, then the commit failed. Every destination is restored.
    assert sorted(new_uploads) == ["A", "B"]
    assert sorted(restores) == ["A", "B"]
    assert Certificate.query.filter(Certificate.replaces.any(id=cert.id)).count() == 0
    assert "save of the new certificate to the database" in cert.description


def test_failure_before_destinations_causes_no_restore(env):
    session, authority = env
    dest_a = _make_destination(session, "A")
    cert = _make_cert(session, authority, [dest_a])
    uploads = []

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):
        uploads.append(name)

    with patch(PLUGIN_UPLOAD, upload), patch("lemur.certificates.cli.metrics"), patch(
        "lemur.certificates.cli.reissue_certificate", side_effect=RuntimeError("CA down")
    ), patch.object(current_app.logger, "info") as log_info:
        request_reissue(cert, False, True)

    assert uploads == []
    assert any("No destination was changed" in m for m in _messages(log_info))
    assert "issue of the new certificate, before any destination upload" in cert.description


def test_failed_restore_does_not_stop_others_or_notification(env):
    session, authority = env
    dest_a = _make_destination(session, "A")
    dest_b = _make_destination(session, "B")
    cert = _make_cert(session, authority, [dest_a, dest_b])
    cert.notify = True
    session.commit()
    old_name = cert.name
    restores = []

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):
        if name == old_name:
            restores.append(_tag(options))
            if _tag(options) == "A":
                raise RuntimeError("restore of A failed")
            return
        if _tag(options) == "B":
            raise RuntimeError("destination B is down")

    with patch(PLUGIN_UPLOAD, upload), patch(
        "lemur.certificates.cli.metrics"
    ) as metrics_mock, patch(
        "lemur.certificates.cli.send_reissue_failed_notification"
    ) as notify_mock:
        request_reissue(cert, True, True)

    assert sorted(restores) == ["A", "B"]
    assert notify_mock.called
    assert _reissue_metrics(metrics_mock)[0]["status"] == FAILURE_METRIC_STATUS


def test_failure_note_is_replaced_and_not_copied_to_new_cert(env):
    session, authority = env
    cert = _make_cert(session, authority)
    cert.description = "my cert"
    session.commit()

    service.mark_reissue_failure(cert, "first step", RuntimeError("one"))
    service.mark_reissue_failure(cert, "second step", RuntimeError("two"))

    # One note only. The new note replaces the old one.
    assert cert.description.count("[Lemur reissue failed:") == 1
    assert "second step" in cert.description
    assert "first step" not in cert.description
    assert cert.description.startswith("my cert ")

    # The note does not pass to the new certificate.
    new_cert = service.reissue_certificate(cert, replace=True)
    assert "Lemur reissue failed" not in new_cert.description
    assert new_cert.description.startswith(f"Reissued by Lemur for cert ID {cert.id}")


def test_failure_note_stays_within_column_limit(env):
    session, authority = env
    cert = _make_cert(session, authority)
    cert.description = "x" * 1024
    session.commit()

    assert service.mark_reissue_failure(cert, "step", RuntimeError("e" * 500))
    assert len(cert.description) <= 1024
    assert "[Lemur reissue failed:" in cert.description
