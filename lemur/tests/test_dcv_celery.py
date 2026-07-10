"""Tests for check_dcv_expiration Celery task and IssuerPlugin DCV base (RDNA-1000)."""
import datetime
from unittest.mock import MagicMock, patch


def test_issuer_plugin_dcv_default_returns_empty():
    from lemur.plugins.bases.issuer import IssuerPlugin

    plugin = IssuerPlugin()
    assert plugin.get_dcv_expiration_data() == []


@patch("lemur.common.celery.plugins")
@patch("lemur.common.celery.metrics")
@patch("lemur.common.celery.current_app", new_callable=MagicMock)
@patch("lemur.common.celery.celery_app")
def test_check_dcv_expiration_emits_metric_for_active_domain(
    mock_celery_app, mock_current_app, mock_metrics, mock_plugins
):
    mock_celery_app.current_task = None

    future = (datetime.datetime.utcnow() + datetime.timedelta(days=45)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    fake_plugin = MagicMock()
    fake_plugin.slug = "digicert-issuer"
    fake_plugin.get_dcv_expiration_data.return_value = [
        {
            "domain": "example.com",
            "dcv_expiration": future,
            "validation_type": "ov",
            "org_id": "42",
        }
    ]
    mock_plugins.all.return_value = [fake_plugin]

    from lemur.common.celery import check_dcv_expiration

    check_dcv_expiration.run()

    gauge_calls = [c for c in mock_metrics.send.call_args_list if c.args[1] == "gauge"]
    dcv_calls = [c for c in gauge_calls if "dcv.days_until_expiration" in c.args[0]]
    assert len(dcv_calls) == 1
    tags = dcv_calls[0].kwargs["metric_tags"]
    assert tags["domain"] == "example.com"
    assert tags["ca"] == "digicert-issuer"
    assert tags["validation_type"] == "ov"
    assert tags["org_id"] == "42"
    assert dcv_calls[0].args[2] >= 44


@patch("lemur.common.celery.plugins")
@patch("lemur.common.celery.metrics")
@patch("lemur.common.celery.current_app", new_callable=MagicMock)
@patch("lemur.common.celery.celery_app")
def test_check_dcv_expiration_plugin_exception_does_not_stop_others(
    mock_celery_app, mock_current_app, mock_metrics, mock_plugins
):
    mock_celery_app.current_task = None

    bad_plugin = MagicMock()
    bad_plugin.slug = "bad-issuer"
    bad_plugin.get_dcv_expiration_data.side_effect = RuntimeError("network error")

    future = (datetime.datetime.utcnow() + datetime.timedelta(days=10)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    good_plugin = MagicMock()
    good_plugin.slug = "good-issuer"
    good_plugin.get_dcv_expiration_data.return_value = [
        {
            "domain": "good.com",
            "dcv_expiration": future,
            "validation_type": "dv",
            "org_id": "99",
        }
    ]
    mock_plugins.all.return_value = [bad_plugin, good_plugin]

    from lemur.common.celery import check_dcv_expiration

    check_dcv_expiration.run()

    dcv_calls = [
        c
        for c in mock_metrics.send.call_args_list
        if len(c.args) >= 2
        and c.args[1] == "gauge"
        and "dcv.days_until_expiration" in c.args[0]
    ]
    assert len(dcv_calls) == 1
    assert dcv_calls[0].kwargs["metric_tags"]["domain"] == "good.com"

    error_calls = [
        c for c in mock_metrics.send.call_args_list
        if len(c.args) >= 1 and "dcv.expiration_check.errors" in c.args[0]
    ]
    assert error_calls
    assert error_calls[0].args[2] == 1


@patch("lemur.common.celery.plugins")
@patch("lemur.common.celery.metrics")
@patch("lemur.common.celery.current_app", new_callable=MagicMock)
@patch("lemur.common.celery.celery_app")
def test_check_dcv_expiration_empty_data_no_metric(
    mock_celery_app, mock_current_app, mock_metrics, mock_plugins
):
    mock_celery_app.current_task = None

    no_dcv_plugin = MagicMock()
    no_dcv_plugin.slug = "no-dcv-issuer"
    no_dcv_plugin.get_dcv_expiration_data.return_value = []
    mock_plugins.all.return_value = [no_dcv_plugin]

    from lemur.common.celery import check_dcv_expiration

    check_dcv_expiration.run()

    dcv_calls = [
        c for c in mock_metrics.send.call_args_list
        if len(c.args) >= 2 and c.args[1] == "gauge" and "dcv.days_until_expiration" in c.args[0]
    ]
    assert len(dcv_calls) == 0
