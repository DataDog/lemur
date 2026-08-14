"""Tests for centralized Celery task duration metrics."""
import sys
from unittest.mock import MagicMock, patch

if "lemur.common.celery" not in sys.modules:
    with patch("redis.StrictRedis") as _mock_redis:
        _mock_redis.return_value.set.return_value = True
        import lemur.common.celery  # noqa: F401

import lemur.common.celery as _celery_module  # noqa: E402


class FakeEinfo:
    def __init__(self, exc):
        self.exception = exc
        self.traceback = "fake traceback"


class FakeRequest:
    def __init__(self, task_id="task-1", name="lemur.common.celery.fake_task"):
        self.id = task_id
        self.hostname = "worker-1"
        self.name = name


class FakeTask:
    def __init__(self, task_id="task-1", name="lemur.common.celery.fake_task"):
        self.request = FakeRequest(task_id=task_id, name=name)
        self.hostname = "worker-1"
        self.name = name


@patch("lemur.common.celery.metrics")
def test_task_duration_emitted_on_success_and_clears_start_time(mock_metrics):
    _celery_module._task_started_at.clear()
    _celery_module._task_started_at["task-1"] = 100.0

    with patch.object(_celery_module, "current_app", MagicMock()), patch(
        "lemur.common.celery.time.monotonic", return_value=101.234
    ), patch("lemur.common.celery.time.time", return_value=2000):
        fake_task = FakeTask()
        _celery_module.report_successful_task(sender=fake_task, request=fake_task.request)

    duration_calls = [c for c in mock_metrics.send.call_args_list if c.args[0] == "celery.task_duration"]
    assert len(duration_calls) == 1
    assert duration_calls[0].kwargs["metric_tags"] == {"task_name": "lemur.common.celery.fake_task", "status": "success"}
    assert duration_calls[0].args[2] == 1233
    assert "task-1" not in _celery_module._task_started_at


@patch("lemur.common.celery.metrics")
def test_task_duration_emitted_on_failure_with_timeout_status(mock_metrics):
    _celery_module._task_started_at.clear()
    _celery_module._task_started_at["task-2"] = 50.0

    with patch.object(_celery_module, "current_app", MagicMock()), patch(
        "lemur.common.celery.time.monotonic", return_value=51.5
    ), patch("lemur.common.celery.time.time", return_value=2000):
        fake_task = FakeTask(task_id="task-2")
        _celery_module.report_failed_task(
            sender=fake_task,
            request=fake_task.request,
            einfo=FakeEinfo(_celery_module.SoftTimeLimitExceeded()),
        )

    duration_calls = [c for c in mock_metrics.send.call_args_list if c.args[0] == "celery.task_duration"]
    assert len(duration_calls) == 1
    assert duration_calls[0].kwargs["metric_tags"]["status"] == "timeout"
    assert duration_calls[0].args[2] == 1500
    assert "task-2" not in _celery_module._task_started_at


@patch("lemur.common.celery.metrics")
def test_task_duration_not_emitted_when_no_start_time(mock_metrics):
    _celery_module._task_started_at.clear()

    with patch.object(_celery_module, "current_app", MagicMock()):
        fake_task = FakeTask(task_id="task-3")
        _celery_module.report_successful_task(sender=fake_task, request=fake_task.request)

    assert not [c for c in mock_metrics.send.call_args_list if c.args[0] == "celery.task_duration"]
