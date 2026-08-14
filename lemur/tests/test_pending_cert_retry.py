"""Tests for fetch_acme_cert fail-fast behavior on terminal pending-cert failures (EVBL-47).

Verifies that a terminal (config / DNS-delegation / credential) failure marks the
pending certificate resolved immediately and does NOT re-queue, while a transient
failure keeps the existing bounded retry (increment + re-queue).
"""

import sys
from unittest.mock import MagicMock, patch

# celery.py connects to Redis at module level; pre-import it with Redis mocked so
# the @patch decorators below don't trigger a real Redis connection on first import.
if "lemur.common.celery" not in sys.modules:
    with patch("redis.StrictRedis") as _mock_redis:
        _mock_redis.return_value.set.return_value = True
        import lemur.common.celery  # noqa: F401

import lemur.common.celery as _celery_module  # noqa: E402

_celery_module.current_app = MagicMock()

from lemur.common.celery import fetch_acme_cert  # noqa: E402


def _pending_cert(id, number_attempts=0):
    pc = MagicMock()
    pc.id = id
    pc.number_attempts = number_attempts
    pc.resolved = False
    pc.cn = "*.us3.ddbuild.io"
    pc.notify = True
    pc.owner = "joe@example.com"
    return pc


def _run_fetch_acme_cert(pc, last_error):
    """Run fetch_acme_cert(id) with get_ordered_certificates returning a single failure.

    Returns the started mocks keyed by name so tests can assert on call behavior.
    """
    plugin = MagicMock()
    plugin.get_ordered_certificates.return_value = [
        {"cert": False, "pending_cert": pc, "last_error": last_error}
    ]

    patchers = [
        patch(
            "lemur.common.celery.pending_certificate_service.get_pending_certs",
            return_value=[pc],
        ),
        patch(
            "lemur.common.celery.get_authority",
            return_value=MagicMock(plugin_name="acme-issuer"),
        ),
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
        "get_pending_certs": started[0],
        "get_authority": started[1],
        "plugins.get": started[2],
        "pending_certificate_service.get": started[3],
        "send_pending_failure_notification": started[4],
        "pending_certificate_service.update": started[5],
        "pending_certificate_service.increment_attempt": started[6],
        "fetch_acme_cert.delay": started[7],
    }


def test_fetch_acme_cert_terminal_failure_marks_resolved_no_requeue():
    pc = _pending_cert(1)
    mocks = _run_fetch_acme_cert(
        pc, Exception("No DNS providers found for domain: us3.ddbuild.io")
    )

    # Marked resolved
    mocks["pending_certificate_service.update"].assert_any_call(1, resolved=True)
    # Notified
    mocks["send_pending_failure_notification"].assert_called_once()
    # Did NOT re-queue and did NOT increment attempts
    mocks["fetch_acme_cert.delay"].assert_not_called()
    mocks["pending_certificate_service.increment_attempt"].assert_not_called()


def test_fetch_acme_cert_transient_failure_requeues():
    pc = _pending_cert(1, number_attempts=0)
    mocks = _run_fetch_acme_cert(pc, ValueError("Failed verification"))

    # Incremented attempts and re-queued
    mocks["pending_certificate_service.increment_attempt"].assert_called_once()
    mocks["fetch_acme_cert.delay"].assert_called_once_with(1, None)
    # Did NOT mark resolved
    for call in mocks["pending_certificate_service.update"].call_args_list:
        assert call.kwargs.get("resolved") is not True
