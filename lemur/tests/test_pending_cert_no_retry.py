"""Tests for fetch_acme_cert no-retry + ACME rate-limit logging (EVBL-47).

Verifies that, with retries disabled (ACME_ADDITIONAL_ATTEMPTS = 0), a pending
certificate that fails issuance is resolved immediately on the first attempt (no
re-queue), and that the failure log always carries the full ACME rate-limit
context (cn, authority, number of attempts, DNS provider, error) so rate-limit
burn is attributable for triage.
"""

import sys
from unittest.mock import MagicMock, patch

import pytest

# celery.py connects to Redis at module level; pre-import it with Redis mocked so
# the @patch decorators below don't trigger a real Redis connection on first import.
if "lemur.common.celery" not in sys.modules:
    with patch("redis.StrictRedis") as _mock_redis:
        _mock_redis.return_value.set.return_value = True
        import lemur.common.celery  # noqa: F401

import lemur.common.celery as _celery_module  # noqa: E402

from lemur.common.celery import fetch_acme_cert  # noqa: E402


@pytest.fixture(autouse=True)
def _mock_celery_current_app(monkeypatch):
    """Scope the current_app mock to each test and restore the original on teardown."""
    monkeypatch.setattr(_celery_module, "current_app", MagicMock())


def _pending_cert(id, number_attempts=0):
    pc = MagicMock()
    pc.id = id
    pc.number_attempts = number_attempts
    pc.resolved = False
    pc.cn = "*.us3.ddbuild.io"
    pc.notify = True
    pc.owner = "joe@example.com"
    pc.authority_id = 14
    pc.dns_provider_id = 6
    return pc


def _run_fetch_acme_cert(pc, last_error):
    """Run fetch_acme_cert(id) with get_ordered_certificates returning a single failure.

    Returns the started mocks keyed by name so tests can assert on call behavior.
    """
    plugin = MagicMock()
    plugin.get_ordered_certificates.return_value = [
        {"cert": False, "pending_cert": pc, "last_error": last_error}
    ]

    authority = MagicMock()
    authority.name = "LetsEncryptStaging2"
    authority.plugin_name = "acme-issuer"

    patchers = [
        patch(
            "lemur.common.celery.pending_certificate_service.get_pending_certs",
            return_value=[pc],
        ),
        patch("lemur.common.celery.get_authority", return_value=authority),
        patch("lemur.common.celery.plugins.get", return_value=plugin),
        patch("lemur.common.celery.pending_certificate_service.get", return_value=pc),
        patch("lemur.common.celery.send_pending_failure_notification"),
        patch("lemur.common.celery.pending_certificate_service.update"),
        patch("lemur.common.celery.pending_certificate_service.increment_attempt"),
        patch("lemur.common.celery.fetch_acme_cert.delay"),
    ]
    started = [p.start() for p in patchers]
    try:
        fetch_acme_cert(pc.id)
    finally:
        for p in patchers:
            p.stop()

    return {
        "get_authority": started[1],
        "update": started[5],
        "increment_attempt": started[6],
        "delay": started[7],
    }


def _rate_limit_error_log(mocks):
    """Return the failure error_log emitted via current_app.logger.error."""
    for call in _celery_module.current_app.logger.error.call_args_list:
        if call.args and isinstance(call.args[0], dict):
            log = call.args[0]
            if log.get("rate_limit_relevant") is True:
                return log
    raise AssertionError("no rate-limit-relevant error log emitted")


def test_fetch_acme_cert_failure_resolves_immediately_no_requeue():
    """With retries disabled, a failed pending cert is resolved on the first attempt."""
    pc = _pending_cert(1, number_attempts=0)
    mocks = _run_fetch_acme_cert(pc, ValueError("Failed verification"))

    # Marked resolved
    assert any(
        call.kwargs.get("resolved") is True for call in mocks["update"].call_args_list
    )
    # Not re-queued, not incremented
    mocks["delay"].assert_not_called()
    mocks["increment_attempt"].assert_not_called()


def test_fetch_acme_cert_failure_logs_rate_limit_context():
    """The failure log always carries the ACME rate-limit-relevant context."""
    pc = _pending_cert(1, number_attempts=0)
    mocks = _run_fetch_acme_cert(pc, ValueError("Failed verification"))

    log = _rate_limit_error_log(mocks)
    assert log["cn"] == pc.cn
    assert log["authority"] == "LetsEncryptStaging2"
    assert log["authority_id"] == pc.authority_id
    assert log["number_attempts"] == pc.number_attempts
    assert log["dns_provider_id"] == pc.dns_provider_id
    assert log["rate_limit_relevant"] is True
    assert "Failed verification" in log["last_error"]


def test_fetch_acme_cert_failure_logs_default_last_error_when_missing():
    """A missing last_error is logged as a meaningful default, not 'None'."""
    pc = _pending_cert(1, number_attempts=0)
    mocks = _run_fetch_acme_cert(pc, None)

    log = _rate_limit_error_log(mocks)
    assert log["last_error"] == "No error message provided by CA"
