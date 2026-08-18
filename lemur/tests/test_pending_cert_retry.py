"""Tests for fetch_acme_cert fail-fast behavior on terminal pending-cert failures (EVBL-47).

Verifies that a terminal (config / DNS-delegation / credential) failure marks the
pending certificate resolved immediately and does NOT re-queue, while a transient
failure keeps the existing bounded retry (increment + re-queue).
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
    return pc


def _run_fetch_acme_cert(pc, last_error, notify_side_effect=None):
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
        patch(
            "lemur.common.celery.send_pending_failure_notification",
            side_effect=notify_side_effect,
        ),
        patch("lemur.common.celery.pending_certificate_service.update"),
        patch("lemur.common.celery.pending_certificate_service.increment_attempt"),
        patch("lemur.common.celery.fetch_acme_cert.delay"),
    ]
    started = [p.start() for p in patchers]
    try:
        fetch_acme_cert(pc.id)
    except Exception:
        # Notification delivery (or other) failure. The helper still returns the
        # mocks so tests can assert on persisted state after a raised notification.
        pass
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


def _assert_resolved(mocks):
    """Assert the pending cert was marked resolved (regardless of status kwarg)."""
    update_mock = mocks["pending_certificate_service.update"]
    assert any(
        call.kwargs.get("resolved") is True for call in update_mock.call_args_list
    )


def test_fetch_acme_cert_terminal_failure_marks_resolved_no_requeue():
    from lemur.exceptions import NoDNSProviderError

    pc = _pending_cert(1)
    mocks = _run_fetch_acme_cert(pc, NoDNSProviderError("no provider for zone"))

    # Marked resolved
    _assert_resolved(mocks)
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


def test_fetch_acme_cert_transient_at_max_attempts_resolves_no_requeue():
    """A transient failure at the retry cap resolves instead of re-queuing.

    The retry cap is ACME_ADDITIONAL_ATTEMPTS additional attempts beyond the
    initial one (total = ACME_ADDITIONAL_ATTEMPTS + 1). Once number_attempts
    reaches the cap, the next failure gives up and marks resolved rather than
    burning another attempt against the CA's rate limit.
    """
    from lemur.constants import ACME_ADDITIONAL_ATTEMPTS

    pc = _pending_cert(1, number_attempts=ACME_ADDITIONAL_ATTEMPTS)
    mocks = _run_fetch_acme_cert(pc, ValueError("Failed verification"))

    # At the cap: marked resolved, NOT re-queued, NOT incremented further
    _assert_resolved(mocks)
    mocks["fetch_acme_cert.delay"].assert_not_called()
    mocks["pending_certificate_service.increment_attempt"].assert_not_called()


def test_fetch_acme_cert_terminal_typed_error_marks_resolved_no_requeue():
    """A typed terminal error is classified via isinstance and fails fast."""
    from lemur.exceptions import NoDNSProviderError

    pc = _pending_cert(1)
    mocks = _run_fetch_acme_cert(pc, NoDNSProviderError("no provider for zone"))

    _assert_resolved(mocks)
    mocks["send_pending_failure_notification"].assert_called_once()
    mocks["fetch_acme_cert.delay"].assert_not_called()
    mocks["pending_certificate_service.increment_attempt"].assert_not_called()


def test_fetch_acme_cert_terminal_persists_resolved_before_notify():
    """The pending cert is marked resolved even if notification delivery raises."""
    from lemur.exceptions import NoDNSProviderError

    pc = _pending_cert(1)
    mocks = _run_fetch_acme_cert(
        pc,
        NoDNSProviderError("no provider for zone"),
        notify_side_effect=RuntimeError("smtp down"),
    )

    # Still marked resolved (persisted before the notification was attempted)
    _assert_resolved(mocks)
    # Not re-queued despite the notification failure
    mocks["fetch_acme_cert.delay"].assert_not_called()
