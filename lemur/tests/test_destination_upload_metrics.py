from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from lemur.certificates import models
from lemur.constants import FAILURE_METRIC_STATUS, SUCCESS_METRIC_STATUS


@pytest.mark.parametrize("fails", [False, True])
def test_destination_upload_metrics(app, fails):
    certificate = SimpleNamespace(
        name="test-certificate",
        expired=False,
        body="body",
        private_key="key",
        chain="chain",
    )
    destination = SimpleNamespace(
        label="test-destination",
        plugin_name="test-plugin",
        options=[],
        description='{"datacenter": "us1.staging.dog"}',
    )
    plugin = Mock()
    error = ValueError("Upload failed")
    if fails:
        plugin.upload.side_effect = error
    with (
        patch.object(models.plugins, "get", return_value=plugin),
        patch.object(models, "capture_exception"),
        patch.object(models.metrics, "send") as metric,
    ):
        if fails:
            with pytest.raises(ValueError) as raised:
                models.update_destinations(certificate, destination, None)
            assert raised.value is error
        else:
            models.update_destinations(certificate, destination, None)
        tags = {
            "status": FAILURE_METRIC_STATUS if fails else SUCCESS_METRIC_STATUS,
            "certificate": certificate.name,
            "destination": destination.label,
            "datacenter": "us1.staging.dog",
        }
        metric.assert_called_once_with(
            "destination_upload", "counter", 1, metric_tags=tags
        )
