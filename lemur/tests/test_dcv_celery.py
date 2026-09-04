"""Tests for check_dcv_expiration Celery task and IssuerPlugin DCV base (RDNA-1000)."""
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

# celery.py connects to Redis at module level; pre-import it with Redis mocked so
# the @patch decorators below don't trigger a real Redis connection on first import.
if "lemur.common.celery" not in sys.modules:
    with patch("redis.StrictRedis") as _mock_redis:
        _mock_redis.return_value.set.return_value = True
        import lemur.common.celery  # noqa: F401

# Replace current_app in the celery module with a MagicMock. Without this, the
# @patch decorators call hasattr() on the Flask LocalProxy to check for async
# methods, which resolves the proxy and raises RuntimeError outside app context.
import lemur.common.celery as _celery_module  # noqa: E402
_celery_module.current_app = MagicMock()


def test_make_celery_registers_a_receiver_that_clears_app_logger_handlers():
    fake_app = MagicMock()
    fake_app.logger = MagicMock()
    fake_app.config.get.return_value = False

    with patch("lemur.common.celery.after_setup_logger") as mock_signal, patch(
        "lemur.common.celery.after_setup_task_logger"
    ):
        _celery_module.make_celery(fake_app)

    receiver = mock_signal.connect.call_args.args[0]
    receiver(logger=MagicMock())

    fake_app.logger.handlers.clear.assert_called_once()


def test_make_celery_receiver_closes_app_logger_handlers_before_clearing():
    fake_app = MagicMock()
    handler = MagicMock()
    fake_app.logger.handlers = [handler]
    fake_app.config.get.return_value = False

    with patch("lemur.common.celery.after_setup_logger") as mock_signal, patch(
        "lemur.common.celery.after_setup_task_logger"
    ):
        _celery_module.make_celery(fake_app)

    receiver = mock_signal.connect.call_args.args[0]
    receiver(logger=MagicMock())

    handler.close.assert_called_once()
    assert fake_app.logger.handlers == []


def test_make_celery_receiver_restores_app_logger_propagation():
    fake_app = MagicMock()
    fake_app.logger = MagicMock()
    fake_app.logger.propagate = False
    fake_app.config.get.return_value = False

    with patch("lemur.common.celery.after_setup_logger") as mock_signal, patch(
        "lemur.common.celery.after_setup_task_logger"
    ):
        _celery_module.make_celery(fake_app)

    receiver = mock_signal.connect.call_args.args[0]
    receiver(logger=MagicMock())

    assert fake_app.logger.propagate is True


def test_make_celery_receiver_applies_json_formatter_when_log_json_enabled():
    fake_app = MagicMock()
    fake_app.config.get.return_value = True

    with patch("lemur.common.celery.after_setup_logger") as mock_signal, patch(
        "lemur.common.celery.after_setup_task_logger"
    ), patch("lemur.common.celery.json_log_formatter") as mock_formatter:
        _celery_module.make_celery(fake_app)

        receiver = mock_signal.connect.call_args.args[0]
        handler = MagicMock()
        receiver(logger=MagicMock(handlers=[handler]))

    handler.setFormatter.assert_called_once_with(mock_formatter.return_value)


def test_make_celery_receiver_leaves_formatter_when_log_json_disabled():
    fake_app = MagicMock()
    fake_app.config.get.return_value = False

    with patch("lemur.common.celery.after_setup_logger") as mock_signal, patch(
        "lemur.common.celery.after_setup_task_logger"
    ), patch("lemur.common.celery.json_log_formatter") as mock_formatter:
        _celery_module.make_celery(fake_app)

        receiver = mock_signal.connect.call_args.args[0]
        handler = MagicMock()
        receiver(logger=MagicMock(handlers=[handler]))

    handler.setFormatter.assert_not_called()
    mock_formatter.assert_not_called()


def test_make_celery_wires_same_receiver_to_both_log_signals_with_weak_false():
    fake_app = MagicMock()
    fake_app.config.get.return_value = False

    with patch("lemur.common.celery.after_setup_logger") as mock_logger_signal, patch(
        "lemur.common.celery.after_setup_task_logger"
    ) as mock_task_signal:
        _celery_module.make_celery(fake_app)

    mock_logger_signal.connect.assert_called_once()
    mock_task_signal.connect.assert_called_once()
    assert (
        mock_logger_signal.connect.call_args.args[0]
        is mock_task_signal.connect.call_args.args[0]
    )
    assert mock_logger_signal.connect.call_args.kwargs["weak"] is False
    assert mock_task_signal.connect.call_args.kwargs["weak"] is False


def test_issuer_plugin_dcv_default_returns_empty():
    from lemur.plugins.bases.issuer import IssuerPlugin

    plugin = IssuerPlugin()
    assert plugin.get_dcv_expiration_data() == []


@patch("lemur.common.celery.get_all_domains")
@patch("lemur.common.celery.plugins")
@patch("lemur.common.celery.metrics")
@patch("lemur.common.celery.current_app", new_callable=MagicMock)
def test_emit_dcv_expiration_metrics_emits_metric_for_active_domain(
    mock_current_app, mock_metrics, mock_plugins, mock_get_all_domains
):
    mock_get_all_domains.return_value = [SimpleNamespace(name="example.com")]
    fake_plugin = MagicMock()
    fake_plugin.slug = "digicert-issuer"
    fake_plugin.get_dcv_expiration_data.return_value = [
        {
            "domain": "example.com",
            "dcv_expiration": "2099-01-01T00:00:00+00:00",
            "validation_type": "ov",
            "org_id": "42",
            "dcv_method": "persistent-txt",
        }
    ]
    mock_plugins.all.return_value = [fake_plugin]

    from lemur.common.celery import _emit_dcv_expiration_metrics

    _emit_dcv_expiration_metrics()

    gauge_calls = [c for c in mock_metrics.send.call_args_list if c.args[1] == "gauge"]
    dcv_calls = [c for c in gauge_calls if "dcv.days_until_expiration" in c.args[0]]
    assert len(dcv_calls) == 1
    tags = dcv_calls[0].kwargs["metric_tags"]
    assert tags["domain"] == "example.com"
    assert tags["ca"] == "digicert-issuer"
    assert tags["validation_type"] == "ov"
    assert tags["org_id"] == "42"
    assert tags["dcv_method"] == "persistent-txt"
    assert dcv_calls[0].args[2] > 0


@patch("lemur.common.celery.get_all_domains")
@patch("lemur.common.celery.plugins")
@patch("lemur.common.celery.metrics")
@patch("lemur.common.celery.current_app", new_callable=MagicMock)
def test_emit_dcv_expiration_metrics_plugin_exception_does_not_stop_others(
    mock_current_app, mock_metrics, mock_plugins, mock_get_all_domains
):
    mock_get_all_domains.return_value = [SimpleNamespace(name="good.com")]
    bad_plugin = MagicMock()
    bad_plugin.slug = "bad-issuer"
    bad_plugin.get_dcv_expiration_data.side_effect = RuntimeError("network error")

    good_plugin = MagicMock()
    good_plugin.slug = "good-issuer"
    good_plugin.get_dcv_expiration_data.return_value = [
        {
            "domain": "good.com",
            "dcv_expiration": "2099-01-01T00:00:00+00:00",
            "validation_type": "dv",
            "org_id": "99",
        }
    ]
    mock_plugins.all.return_value = [bad_plugin, good_plugin]

    from lemur.common.celery import _emit_dcv_expiration_metrics

    _emit_dcv_expiration_metrics()

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


@patch("lemur.common.celery.get_all_domains")
@patch("lemur.common.celery.plugins")
@patch("lemur.common.celery.metrics")
@patch("lemur.common.celery.current_app", new_callable=MagicMock)
def test_emit_dcv_expiration_metrics_empty_data_no_metric(
    mock_current_app, mock_metrics, mock_plugins, mock_get_all_domains
):
    mock_get_all_domains.return_value = []
    no_dcv_plugin = MagicMock()
    no_dcv_plugin.slug = "no-dcv-issuer"
    no_dcv_plugin.get_dcv_expiration_data.return_value = []
    mock_plugins.all.return_value = [no_dcv_plugin]

    from lemur.common.celery import _emit_dcv_expiration_metrics

    _emit_dcv_expiration_metrics()

    dcv_calls = [
        c for c in mock_metrics.send.call_args_list
        if len(c.args) >= 2 and c.args[1] == "gauge" and "dcv.days_until_expiration" in c.args[0]
    ]
    assert len(dcv_calls) == 0


@patch("lemur.common.celery._emit_dcv_expiration_metrics")
@patch("lemur.common.celery.certificate_service")
@patch("lemur.common.celery.cli_certificate")
@patch("lemur.common.celery.metrics")
@patch("lemur.common.celery.current_app", new_callable=MagicMock)
@patch("lemur.common.celery.celery_app")
def test_certificate_expirations_metrics_invokes_dcv_helper(
    mock_celery_app, mock_current_app, mock_metrics,
    mock_cli_certificate, mock_certificate_service, mock_dcv_helper,
):
    mock_celery_app.current_task = None

    from lemur.common.celery import certificate_expirations_metrics

    certificate_expirations_metrics.run()

    mock_dcv_helper.assert_called_once()
    mock_cli_certificate.expiration_metrics.assert_called_once()
    mock_certificate_service.send_source_destination_pairing_metrics.assert_called_once()


@patch("lemur.common.celery._emit_dcv_expiration_metrics")
def test_check_dcv_expiration_deprecated_alias_delegates(mock_dcv_helper):
    """The deprecated alias stays registered under the old FQN and delegates to
    the folded helper, so in-flight/beat-fired messages don't hit unregistered-task
    errors (EVBL-51)."""
    from lemur.common.celery import _check_dcv_expiration_deprecated

    # Registered under the exact old fully-qualified name used by the beat schedule.
    assert _check_dcv_expiration_deprecated.name == "lemur.common.celery.check_dcv_expiration"

    _check_dcv_expiration_deprecated.run()

    mock_dcv_helper.assert_called_once()


def test_dcv_domain_is_known_suffix_match():
    from lemur.common.celery import _dcv_domain_is_known

    known = {"datad0g.com", "us1.staging.dog"}
    assert _dcv_domain_is_known("datad0g.com", known)
    assert _dcv_domain_is_known("lemur-sandbox.datad0g.com", known)
    assert _dcv_domain_is_known("vault.dev.us1.staging.dog", known)
    assert not _dcv_domain_is_known("datadoghq.com", known)
    assert not _dcv_domain_is_known("unknown", known)
    assert not _dcv_domain_is_known("", known)


@patch("lemur.common.celery.get_all_domains")
@patch("lemur.common.celery.plugins")
@patch("lemur.common.celery.metrics")
@patch("lemur.common.celery.current_app", new_callable=MagicMock)
def test_emit_dcv_expiration_metrics_filters_unknown_domains(
    mock_current_app, mock_metrics, mock_plugins, mock_get_all_domains
):
    # Staging knows only its own domains; a prod domain in DigiCert should be skipped.
    mock_get_all_domains.return_value = [
        SimpleNamespace(name="lemur-sandbox.datad0g.com"),
        SimpleNamespace(name="us1.staging.dog"),
    ]
    fake_plugin = MagicMock()
    fake_plugin.slug = "digicert-issuer"
    fake_plugin.get_dcv_expiration_data.return_value = [
        {
            "domain": "lemur-sandbox.datad0g.com",
            "dcv_expiration": "2099-01-01T00:00:00+00:00",
            "validation_type": "ov",
        },
        {
            "domain": "datadoghq.com",  # prod domain — should be filtered out
            "dcv_expiration": "2099-01-01T00:00:00+00:00",
            "validation_type": "ov",
        },
    ]
    mock_plugins.all.return_value = [fake_plugin]

    from lemur.common.celery import _emit_dcv_expiration_metrics

    _emit_dcv_expiration_metrics()

    dcv_calls = [
        c for c in mock_metrics.send.call_args_list
        if len(c.args) >= 2 and c.args[1] == "gauge" and "dcv.days_until_expiration" in c.args[0]
    ]
    assert len(dcv_calls) == 1
    assert dcv_calls[0].kwargs["metric_tags"]["domain"] == "lemur-sandbox.datad0g.com"
