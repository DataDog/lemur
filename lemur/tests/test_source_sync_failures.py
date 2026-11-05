from types import SimpleNamespace
from unittest.mock import call, patch

import pytest

from lemur.constants import FAILURE_METRIC_STATUS, SUCCESS_METRIC_STATUS
from lemur.sources import cli


@pytest.mark.parametrize(
    "failures",
    [[False], [True], [False, False], [True, False], [False, True], [True, True]],
)
def test_sync_finishes_batch_before_reporting_failure(app, failures):
    sources = [SimpleNamespace(label=f"source-{i}") for i in range(len(failures))]
    user = object()
    outcomes = [
        (
            ValueError("discovery failed")
            if failed
            else {"certificates": (0, 1), "endpoints": (0, 1, 0)}
        )
        for failed in failures
    ]
    with (
        patch.object(cli, "validate_sources", return_value=sources),
        patch.object(cli.user_service, "get_by_username", return_value=user),
        patch.object(cli.source_service, "sync", side_effect=outcomes) as sync,
        patch.object(cli, "capture_exception") as capture,
        patch.object(cli.metrics, "send") as metric,
    ):
        if any(failures):
            with pytest.raises(RuntimeError) as error:
                cli.sync([source.label for source in sources], 2)
            assert str(error.value) == "Source sync failed for: " + ", ".join(
                source.label for source, failed in zip(sources, failures) if failed
            )
        else:
            assert cli.sync([source.label for source in sources], 2) is None

        assert sync.call_args_list == [
            call(source, user, ttl_hours=2) for source in sources
        ]
        assert capture.call_count == sum(failures)
        expected_metrics = []
        for source, failed in zip(sources, failures):
            tags = {
                "source": source.label,
                "status": FAILURE_METRIC_STATUS if failed else SUCCESS_METRIC_STATUS,
            }
            if failed:
                expected_metrics.append(
                    call("source_sync_fail", "counter", 1, metric_tags=tags)
                )
            expected_metrics.append(call("source_sync", "counter", 1, metric_tags=tags))
        assert metric.call_args_list == expected_metrics


def test_source_sync_failure_reaches_celery(app):
    with patch("redis.StrictRedis"):
        from lemur.common import celery

    with (
        patch.object(celery, "is_task_active", return_value=False),
        patch.object(
            celery, "sync", side_effect=RuntimeError("Source sync failed for: test")
        ),
        patch.object(celery.metrics, "send") as metric,
    ):
        result = celery.sync_source.apply(args=("test",), throw=False)
        assert result.failed()
        assert isinstance(result.result, RuntimeError)
        assert any(
            c.args == ("celery.failed_task", "counter", 1)
            for c in metric.call_args_list
        )
        assert not any(
            c.args[0] == "lemur.common.celery.sync_source.success"
            for c in metric.call_args_list
        )
