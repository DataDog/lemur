from types import SimpleNamespace
from unittest.mock import call, patch

import pytest

from lemur.certificates import cli


@pytest.mark.parametrize("has_source", [True, False])
def test_rotation_gauge_follows_delivery_outcome(app, has_source):
    source = SimpleNamespace(label="test-source")
    endpoint = SimpleNamespace(
        name="test", dnsname="test.invalid", source=source if has_source else None
    )
    old, new = SimpleNamespace(name="old"), SimpleNamespace(name="new")
    tags = {"endpoint": "test.invalid", "old_certificate_name": "old"}
    if has_source:
        tags["source"] = "test-source"

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

    gauges = [c for c in send.call_args_list if c.args[1] == "gauge"]
    assert gauges == [
        call("endpoint_rotation_failed", "gauge", status, metric_tags=tags)
        for status in [1, 1, 1, 1, 0, 1]
    ]
    assert len([c for c in send.call_args_list if c.args[1] == "counter"]) == 6


def test_rotation_dry_run_does_not_submit_gauge(app):
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
    assert all(c.args[1] != "gauge" for c in send.call_args_list)


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
            "endpoint_rotation_failed",
            "gauge",
            0,
            metric_tags={"endpoint": "test.invalid", "old_certificate_name": "old"},
        )
        in send.call_args_list
    )
