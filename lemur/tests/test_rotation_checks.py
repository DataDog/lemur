from types import SimpleNamespace
from unittest.mock import Mock, call, patch

import pytest

from lemur.certificates import cli
from lemur.plugins.lemur_statsd.lemur_statsd.plugin import StatsdMetricPlugin


@pytest.mark.parametrize("has_source", [True, False])
def test_rotation_checks_follow_delivery_outcome(app, has_source):
    source = SimpleNamespace(
        label="test-source", description='{"datacenter":"test-dc"}'
    )
    endpoint = SimpleNamespace(
        name="test", dnsname="test.invalid", source=source if has_source else None
    )
    old, new = SimpleNamespace(name="old"), SimpleNamespace(name="new")
    tags = {"endpoint": "test.invalid", "old_certificate_name": "old"}
    if has_source:
        tags.update(source="test-source", datacenter="test-dc")

    with patch.object(
        cli.deployment_service, "rotate_certificate"
    ) as rotate, patch.object(cli.metrics, "send") as send, patch.object(
        cli, "capture_exception"
    ):
        rotate.side_effect = RuntimeError("test upload failure")
        for _ in range(4):
            cli.request_rotation(endpoint, old, new, False, True)
        rotate.side_effect = None
        cli.request_rotation(endpoint, old, new, False, True)
        # A later failure starts a new sequence with the exact same grouping.
        rotate.side_effect = RuntimeError("test upload failure")
        cli.request_rotation(endpoint, old, new, False, True)

    checks = [c for c in send.call_args_list if c.args[1] == "service_check"]
    assert checks == [
        call("endpoint_rotation", "service_check", status, metric_tags=tags)
        for status in [2, 2, 2, 2, 0, 2]
    ]
    assert len([c for c in send.call_args_list if c.args[1] == "counter"]) == 6


def test_rotation_dry_run_does_not_submit_check(app):
    endpoint = SimpleNamespace(dnsname="test.invalid", source=None)
    with patch.object(
        cli.deployment_service, "rotate_certificate"
    ) as rotate, patch.object(cli.metrics, "send") as send:
        cli.request_rotation(
            endpoint,
            SimpleNamespace(name="old"),
            SimpleNamespace(name="new"),
            False,
            False,
        )
    rotate.assert_not_called()
    assert all(c.args[1] != "service_check" for c in send.call_args_list)


def test_notification_failure_does_not_mark_delivery_failed(app):
    endpoint = SimpleNamespace(name="test", dnsname="test.invalid", source=None)
    with patch.object(cli.deployment_service, "rotate_certificate"), patch.object(
        cli,
        "send_rotation_notification",
        side_effect=RuntimeError("test email failure"),
    ), patch.object(cli.metrics, "send") as send, patch.object(
        cli, "capture_exception"
    ):
        cli.request_rotation(
            endpoint,
            SimpleNamespace(name="old"),
            SimpleNamespace(name="new"),
            True,
            True,
        )
    assert (
        call(
            "endpoint_rotation",
            "service_check",
            0,
            metric_tags={"endpoint": "test.invalid", "old_certificate_name": "old"},
        )
        in send.call_args_list
    )


@pytest.mark.parametrize("status", [0, 2])
def test_statsd_submits_service_check(app, status):
    plugin = StatsdMetricPlugin()
    plugin.statsd = Mock()
    plugin.statsd.namespace = "lemur"
    plugin.submit(
        "endpoint_rotation", "service_check", status, {"endpoint": "test.invalid"}
    )
    plugin.statsd.service_check.assert_called_once_with(
        "lemur.endpoint_rotation", status, tags=["endpoint:test.invalid"]
    )
