from unittest.mock import Mock, patch

import pytest
from celery.exceptions import SoftTimeLimitExceeded

from lemur.dns_providers import cli as dns_cli


@pytest.fixture
def celery_module(app):
    # Importing the task module initializes Redis, which these unit tests do not use.
    with patch("redis.StrictRedis"):
        from lemur.common import celery
    return celery


@pytest.mark.parametrize(
    "expected,reported",
    [
        (None, []),
        (None, ()),
        (None, "()"),
        ((42,), [42]),
        ((42,), (42,)),
        ((42,), "(42,)"),
    ],
)
def test_is_task_active_matches_arguments(celery_module, expected, reported):
    with patch.object(celery_module.celery_app.control, "inspect") as inspect:
        inspect.return_value.active.return_value = {
            "worker": [{"id": "other", "name": "task", "args": reported}]
        }
        assert celery_module.is_task_active("task", "current", expected)


@pytest.mark.parametrize(
    "task",
    [
        {"id": "current", "name": "task", "args": [42]},
        {"id": "other", "name": "another_task", "args": [42]},
        {"id": "other", "name": "task", "args": [43]},
        {"id": "other", "name": "task", "args": []},
    ],
)
def test_is_task_active_ignores_non_matches(celery_module, task):
    with patch.object(celery_module.celery_app.control, "inspect") as inspect:
        inspect.return_value.active.return_value = {"worker": [task]}
        assert not celery_module.is_task_active("task", "current", (42,))


@pytest.mark.parametrize("active", [None, {}, {"worker": []}])
def test_is_task_active_without_active_tasks(celery_module, active):
    with patch.object(celery_module.celery_app.control, "inspect") as inspect:
        inspect.return_value.active.return_value = active
        assert not celery_module.is_task_active("task", "current", None)


@pytest.mark.parametrize("timeout_at", ["lookup", "set_domains"])
def test_dns_discovery_propagates_soft_timeout(timeout_at):
    provider = Mock()
    with patch.object(
        dns_cli, "get_all_dns_providers", return_value=[provider, Mock()]
    ), patch.object(dns_cli, "AcmeDnsHandler") as handler, patch.object(
        dns_cli, "set_domains"
    ) as set_domains, patch.object(
        dns_cli, "capture_exception"
    ) as capture, patch.object(
        dns_cli.metrics, "send"
    ) as send:
        lookup = handler.return_value.get_all_zones
        lookup.return_value = ["example.com"]
        if timeout_at == "lookup":
            lookup.side_effect = SoftTimeLimitExceeded()
        else:
            set_domains.side_effect = SoftTimeLimitExceeded()

        with pytest.raises(SoftTimeLimitExceeded):
            dns_cli.get_all_zones()

        lookup.assert_called_once_with(provider)
        if timeout_at == "lookup":
            set_domains.assert_not_called()
        capture.assert_not_called()
        send.assert_not_called()


def test_dns_discovery_continues_after_provider_error():
    failed_provider, healthy_provider = Mock(), Mock()
    with patch.object(
        dns_cli,
        "get_all_dns_providers",
        return_value=[failed_provider, healthy_provider],
    ), patch.object(dns_cli, "AcmeDnsHandler") as handler, patch.object(
        dns_cli, "set_domains"
    ) as set_domains, patch.object(
        dns_cli, "capture_exception"
    ) as capture, patch.object(
        dns_cli.metrics, "send"
    ):
        handler.return_value.get_all_zones.side_effect = [
            RuntimeError("provider unavailable"),
            ["example.com"],
        ]

        dns_cli.get_all_zones()

        set_domains.assert_called_once_with(healthy_provider, ["example.com"])
        capture.assert_called_once()


def test_dns_discovery_has_hard_timeout(celery_module):
    task = celery_module.get_all_zones
    assert task.soft_time_limit == 600
    assert task.time_limit == 660
