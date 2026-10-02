"""Dedicated health task lifecycle, independent of expiration telemetry."""
from unittest.mock import MagicMock, patch

import pytest
from celery.exceptions import SoftTimeLimitExceeded


FUNCTION = "lemur.common.celery.certificate_health_check"


@pytest.fixture
def celery_module(app):
    with patch("redis.StrictRedis"):
        from lemur.common import celery
    # Other legacy task tests replace this LocalProxy globally; restore it for this test.
    with patch.object(celery, "current_app", app):
        yield celery


def test_health_task_emits_completion_and_returns_summary(celery_module):
    from lemur.certificates import health

    summary = dict(certificates_checked=3, unhealthy_certificates=1, failed_checks=2, errors=1)
    task = celery_module.certificate_health_check
    with patch.object(health, "send_certificate_health_metrics", return_value=summary), \
            patch.object(celery_module.metrics, "send") as send:
        task.push_request(id="current")
        try:
            with patch.object(celery_module, "is_task_active", return_value=False) as active:
                result = task()
        finally:
            task.pop_request()
    assert result["task_id"] == "current"
    assert result["certificates_checked"] == 3
    assert result["errors"] == 1
    active.assert_called_once_with(FUNCTION, "current", None)
    send.assert_called_once_with(FUNCTION + ".success", "counter", 1)


def test_health_task_overlap_skips_evaluation(celery_module):
    from lemur.certificates import health

    task = celery_module.certificate_health_check
    with patch.object(health, "send_certificate_health_metrics") as evaluate, \
            patch.object(celery_module.metrics, "send") as send, \
            patch.object(celery_module, "is_task_active", return_value=True):
        task.push_request(id="current")
        try:
            assert task() is None
        finally:
            task.pop_request()
    evaluate.assert_not_called()
    send.assert_not_called()


def test_health_task_soft_timeout_emits_timeout_not_success(celery_module):
    from lemur.certificates import health

    with patch.object(health, "send_certificate_health_metrics",
                      side_effect=SoftTimeLimitExceeded()), \
            patch.object(celery_module.metrics, "send") as send, \
            patch.object(celery_module, "capture_exception") as capture:
        with pytest.raises(SoftTimeLimitExceeded):
            celery_module.certificate_health_check.run()
    send.assert_called_once_with(
        "celery.timeout", "counter", 1, metric_tags={"function": FUNCTION}
    )
    capture.assert_called_once()


def test_health_task_traced_timeout_reports_failure_without_last_success(celery_module):
    from celery.signals import task_failure, task_success
    from lemur.certificates import health

    task = celery_module.certificate_health_check
    failures = []
    successes = []

    def record_failure(**kwargs):
        failures.append(kwargs)

    def record_success(**kwargs):
        successes.append(kwargs)

    task_failure.connect(record_failure, sender=task, weak=False)
    task_success.connect(record_success, sender=task, weak=False)
    try:
        with patch.object(health, "send_certificate_health_metrics",
                          side_effect=SoftTimeLimitExceeded()), \
                patch.object(task, "_backend", MagicMock()), \
                patch.object(celery_module, "red") as redis, \
                patch.object(celery_module.metrics, "send") as send, \
                patch.object(celery_module, "capture_exception"), \
                patch.object(celery_module, "is_task_active", return_value=False):
            result = task.apply(task_id="health-timeout", throw=False)
        assert result.state == "FAILURE"
        assert isinstance(result.result, SoftTimeLimitExceeded)
        assert len(failures) == 1
        assert isinstance(failures[0]["exception"], SoftTimeLimitExceeded)
        assert successes == []
        redis.set.assert_not_called()
        names = [entry.args[0] for entry in send.call_args_list]
        assert "celery.timeout" in names
        assert FUNCTION + ".success" not in names
        assert "celery.successful_task" not in names
        failure_metrics = [entry for entry in send.call_args_list
                           if entry.args[0] == "celery.failed_task"]
        assert len(failure_metrics) == 1
        assert failure_metrics[0].args[2] == 1
        duration_metrics = [entry for entry in send.call_args_list
                            if entry.args[0] == "celery.task_duration"]
        assert len(duration_metrics) == 1
        assert duration_metrics[0].kwargs["metric_tags"]["status"] in {"failure", "timeout"}
        assert "health-timeout" not in celery_module._task_started_at
    finally:
        task_failure.disconnect(record_failure, sender=task)
        task_success.disconnect(record_success, sender=task)


def test_health_task_unexpected_failure_is_not_success(celery_module):
    from lemur.certificates import health

    with patch.object(health, "send_certificate_health_metrics",
                      side_effect=RuntimeError("query failure")), \
            patch.object(celery_module.metrics, "send") as send, \
            patch.object(celery_module, "capture_exception") as capture:
        with pytest.raises(RuntimeError, match="query failure"):
            celery_module.certificate_health_check.run()
    send.assert_called_once_with(FUNCTION + ".error", "counter", 1)
    capture.assert_called_once()
