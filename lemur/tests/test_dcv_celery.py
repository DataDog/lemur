"""Tests for check_dcv_expiration Celery task and IssuerPlugin DCV base (RDNA-1000)."""

import sys
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


@patch("lemur.common.celery._active_domains_by_ca")
@patch("lemur.common.celery.plugins")
@patch("lemur.common.celery.metrics")
@patch("lemur.common.celery.current_app", new_callable=MagicMock)
def test_emit_dcv_expiration_metrics_emits_metric_for_active_domain(
    mock_current_app, mock_metrics, mock_plugins, mock_get_all_domains
):
    mock_get_all_domains.return_value = {"digicert-issuer": {"example.com"}}
    fake_plugin = MagicMock()
    fake_plugin.slug = "digicert-issuer"
    fake_plugin.get_dcv_expiration_data.return_value = [
        {
            "domain": "example.com",
            "dcv_expiration": "2099-01-01T00:00:00+00:00",
            "validation_type": "ov",
            "org_id": "42",
            "dcv_method": "persistent-txt",
            "dcv_status": "active",
        }
    ]
    mock_plugins.all.return_value = [fake_plugin]

    from lemur.common.celery import emit_dcv_expiration_metrics

    emit_dcv_expiration_metrics()

    gauge_calls = [c for c in mock_metrics.send.call_args_list if c.args[1] == "gauge"]
    vs_calls = [c for c in gauge_calls if "dcv.validation_status" in c.args[0]]
    assert len(vs_calls) == 1
    assert vs_calls[0].args[2] == 1  # active -> healthy
    tags = vs_calls[0].kwargs["metric_tags"]
    assert tags["domain"] == "example.com"
    assert tags["ca"] == "digicert-issuer"
    assert tags["dcv_status"] == "active"
    assert tags["dcv_method"] == "persistent-txt"
    assert tags["validation_type"] == "ov"


def test_dcv_status_ok_mapping():
    from lemur.common.celery import _dcv_status_ok

    # Shared vocabulary (both plugins normalize to active/pending/expired)
    assert _dcv_status_ok("digicert-issuer", "active") is True
    assert _dcv_status_ok("digicert-issuer", "pending") is False
    assert _dcv_status_ok("digicert-issuer", "expired") is False

    # Sectigo statuses are normalized upstream to the shared vocabulary
    assert _dcv_status_ok("sectigo-issuer", "active") is True
    assert _dcv_status_ok("sectigo-issuer", "pending") is False
    assert _dcv_status_ok("sectigo-issuer", "expired") is False

    # unknown / missing -> not healthy (fail closed)
    assert _dcv_status_ok("digicert-issuer", "unknown") is False
    assert _dcv_status_ok("sectigo-issuer", "") is False


@patch("lemur.common.celery._active_domains_by_ca")
@patch("lemur.common.celery.plugins")
@patch("lemur.common.celery.metrics")
@patch("lemur.common.celery.current_app", new_callable=MagicMock)
def test_emit_dcv_expiration_metrics_emits_validation_status_without_expiration(
    mock_current_app, mock_metrics, mock_plugins, mock_get_all_domains
):
    # Sectigo prod does not return expirationDate, so dcv_expiration is absent;
    # dcv.validation_status must still be emitted from dcv_status.
    mock_get_all_domains.return_value = {"sectigo-issuer": {"datad0g.com"}}
    fake_plugin = MagicMock()
    fake_plugin.slug = "sectigo-issuer"
    fake_plugin.get_dcv_expiration_data.return_value = [
        {
            "domain": "datad0g.com",
            "dcv_expiration": None,
            "validation_type": "dv",
            "org_id": "35917",
            "dcv_method": "persistent-txt",
            "dcv_status": "active",
        }
    ]
    mock_plugins.all.return_value = [fake_plugin]

    from lemur.common.celery import emit_dcv_expiration_metrics

    emit_dcv_expiration_metrics()

    gauge_calls = [c for c in mock_metrics.send.call_args_list if c.args[1] == "gauge"]
    vs_calls = [c for c in gauge_calls if "dcv.validation_status" in c.args[0]]
    assert len(vs_calls) == 1
    assert vs_calls[0].args[2] == 1  # active -> healthy
    assert vs_calls[0].kwargs["metric_tags"]["dcv_status"] == "active"
    assert vs_calls[0].kwargs["metric_tags"]["ca"] == "sectigo-issuer"


@patch("lemur.common.celery._active_domains_by_ca")
@patch("lemur.common.celery.plugins")
@patch("lemur.common.celery.metrics")
@patch("lemur.common.celery.current_app", new_callable=MagicMock)
def test_emit_dcv_expiration_metrics_plugin_exception_does_not_stop_others(
    mock_current_app, mock_metrics, mock_plugins, mock_get_all_domains
):
    mock_get_all_domains.return_value = {"good-issuer": {"good.com"}}
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

    from lemur.common.celery import emit_dcv_expiration_metrics

    emit_dcv_expiration_metrics()

    dcv_calls = [
        c
        for c in mock_metrics.send.call_args_list
        if len(c.args) >= 2
        and c.args[1] == "gauge"
        and "dcv.validation_status" in c.args[0]
    ]
    assert len(dcv_calls) == 1
    assert dcv_calls[0].kwargs["metric_tags"]["domain"] == "good.com"

    error_calls = [
        c
        for c in mock_metrics.send.call_args_list
        if len(c.args) >= 1 and "dcv.expiration_check.plugin.errors" in c.args[0]
    ]
    assert error_calls
    assert error_calls[0].args[2] == 1
    assert error_calls[0].kwargs["metric_tags"]["ca"] == "bad-issuer"


@patch("lemur.common.celery._active_domains_by_ca")
@patch("lemur.common.celery.plugins")
@patch("lemur.common.celery.metrics")
@patch("lemur.common.celery.current_app", new_callable=MagicMock)
def test_emit_dcv_expiration_metrics_malformed_entry_emits_error(
    mock_current_app, mock_metrics, mock_plugins, mock_get_all_domains
):
    mock_get_all_domains.return_value = {"digicert-issuer": {"example.com"}}
    fake_plugin = MagicMock()
    fake_plugin.slug = "digicert-issuer"
    fake_plugin.get_dcv_expiration_data.return_value = [
        {
            "domain": "example.com",
            "dcv_expiration": "2099-01-01T00:00:00+00:00",
            "validation_type": "ov",
            "org_id": "42",
            "dcv_method": "persistent-txt",
            "dcv_status": "active",
        },
        {"dcv_status": "active"},  # malformed: no domain
        "not-a-dict",  # malformed: not a dict
    ]
    mock_plugins.all.return_value = [fake_plugin]

    from lemur.common.celery import emit_dcv_expiration_metrics

    emit_dcv_expiration_metrics()

    # The well-formed entry still emits a gauge.
    gauge_calls = [c for c in mock_metrics.send.call_args_list if c.args[1] == "gauge"]
    vs_calls = [c for c in gauge_calls if "dcv.validation_status" in c.args[0]]
    assert len(vs_calls) == 1
    assert vs_calls[0].kwargs["metric_tags"]["domain"] == "example.com"

    # Each malformed entry surfaces as a plugin error tagged with reason=malformed_entry.
    malformed_calls = [
        c
        for c in mock_metrics.send.call_args_list
        if "dcv.expiration_check.plugin.errors" in c.args[0]
        and c.kwargs.get("metric_tags", {}).get("reason") == "malformed_entry"
    ]
    assert len(malformed_calls) == 2
    assert all(
        c.kwargs["metric_tags"]["ca"] == "digicert-issuer" for c in malformed_calls
    )


@patch("lemur.common.celery._active_domains_by_ca")
@patch("lemur.common.celery.plugins")
@patch("lemur.common.celery.metrics")
@patch("lemur.common.celery.current_app", new_callable=MagicMock)
def test_emit_dcv_expiration_metrics_empty_data_no_metric(
    mock_current_app, mock_metrics, mock_plugins, mock_get_all_domains
):
    mock_get_all_domains.return_value = {}
    no_dcv_plugin = MagicMock()
    no_dcv_plugin.slug = "no-dcv-issuer"
    no_dcv_plugin.get_dcv_expiration_data.return_value = []
    mock_plugins.all.return_value = [no_dcv_plugin]

    from lemur.common.celery import emit_dcv_expiration_metrics

    emit_dcv_expiration_metrics()

    dcv_calls = [
        c
        for c in mock_metrics.send.call_args_list
        if len(c.args) >= 2
        and c.args[1] == "gauge"
        and "dcv.validation_status" in c.args[0]
    ]
    assert len(dcv_calls) == 0


@patch("lemur.common.celery.emit_dcv_expiration_metrics")
@patch("lemur.common.celery.certificate_service")
@patch("lemur.common.celery.cli_certificate")
@patch("lemur.common.celery.metrics")
@patch("lemur.common.celery.current_app", new_callable=MagicMock)
@patch("lemur.common.celery.celery_app")
def test_certificate_expirations_metrics_invokes_dcv_helper(
    mock_celery_app,
    mock_current_app,
    mock_metrics,
    mock_cli_certificate,
    mock_certificate_service,
    mock_dcv_helper,
):
    mock_celery_app.current_task = None

    from lemur.common.celery import certificate_expirations_metrics

    certificate_expirations_metrics.run()

    mock_dcv_helper.assert_called_once()
    mock_cli_certificate.expiration_metrics.assert_called_once()
    mock_certificate_service.send_source_destination_pairing_metrics.assert_called_once()


@patch("lemur.common.celery._active_domains_by_ca")
@patch("lemur.common.celery.plugins")
@patch("lemur.common.celery.metrics")
@patch("lemur.common.celery.current_app", new_callable=MagicMock)
def test_emit_dcv_expiration_metrics_filters_unknown_domains(
    mock_current_app, mock_metrics, mock_plugins, mock_get_all_domains
):
    # Staging knows only its own domains; a prod domain in DigiCert should be skipped.
    mock_get_all_domains.return_value = {
        "digicert-issuer": {"lemur-sandbox.datad0g.com"}
    }
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

    from lemur.common.celery import emit_dcv_expiration_metrics

    emit_dcv_expiration_metrics()

    dcv_calls = [
        c
        for c in mock_metrics.send.call_args_list
        if len(c.args) >= 2
        and c.args[1] == "gauge"
        and "dcv.validation_status" in c.args[0]
    ]
    assert len(dcv_calls) == 1
    assert dcv_calls[0].kwargs["metric_tags"]["domain"] == "lemur-sandbox.datad0g.com"


@patch("lemur.common.celery._active_domains_by_ca")
@patch("lemur.common.celery.plugins")
@patch("lemur.common.celery.metrics")
@patch("lemur.common.celery.current_app", new_callable=MagicMock)
def test_emit_dcv_expiration_metrics_flags_uncovered_domain(
    mock_current_app, mock_metrics, mock_plugins, mock_active
):
    mock_active.return_value = {"digicert-issuer": {"inuse.com", "reported.com"}}
    fake_plugin = MagicMock()
    fake_plugin.slug = "digicert-issuer"
    fake_plugin.get_dcv_expiration_data.return_value = [
        {
            "domain": "reported.com",
            "dcv_method": "persistent-txt",
            "dcv_status": "active",
            "validation_type": "ov",
        },
    ]
    mock_plugins.all.return_value = [fake_plugin]

    from lemur.common.celery import emit_dcv_expiration_metrics

    emit_dcv_expiration_metrics()

    gauge_calls = [c for c in mock_metrics.send.call_args_list if c.args[1] == "gauge"]
    vs_calls = [c for c in gauge_calls if "dcv.validation_status" in c.args[0]]
    by_domain = {c.kwargs["metric_tags"]["domain"]: c for c in vs_calls}
    assert set(by_domain) == {"inuse.com", "reported.com"}
    assert by_domain["reported.com"].args[2] == 1
    assert by_domain["inuse.com"].args[2] == 0
    assert by_domain["inuse.com"].kwargs["metric_tags"]["dcv_status"] == "uncovered"


@patch("lemur.common.celery._active_domains_by_ca")
@patch("lemur.common.celery.plugins")
@patch("lemur.common.celery.metrics")
@patch("lemur.common.celery.current_app", new_callable=MagicMock)
def test_emit_dcv_expiration_metrics_skips_non_monitored_ca(
    mock_current_app, mock_metrics, mock_plugins, mock_active
):
    mock_active.return_value = {"acme-issuer": {"letsencrypt.com"}}
    no_dcv_plugin = MagicMock()
    no_dcv_plugin.slug = "acme-issuer"
    no_dcv_plugin.get_dcv_expiration_data.return_value = []
    mock_plugins.all.return_value = [no_dcv_plugin]

    from lemur.common.celery import emit_dcv_expiration_metrics

    emit_dcv_expiration_metrics()

    vs_calls = [
        c
        for c in mock_metrics.send.call_args_list
        if len(c.args) >= 2
        and c.args[1] == "gauge"
        and "dcv.validation_status" in c.args[0]
    ]
    assert vs_calls == []


@patch("lemur.common.celery._active_domains_by_ca")
@patch("lemur.common.celery.plugins")
@patch("lemur.common.celery.metrics")
@patch("lemur.common.celery.current_app", new_callable=MagicMock)
def test_emit_dcv_expiration_metrics_emits_broken_domains_count(
    mock_current_app, mock_metrics, mock_plugins, mock_active
):
    # ok.com (active), expired.com (expired), gap.com (uncovered) -> 2 broken.
    mock_active.return_value = {"digicert-issuer": {"ok.com", "expired.com", "gap.com"}}
    fake_plugin = MagicMock()
    fake_plugin.slug = "digicert-issuer"
    fake_plugin.get_dcv_expiration_data.return_value = [
        {
            "domain": "ok.com",
            "dcv_method": "persistent-txt",
            "dcv_status": "active",
            "validation_type": "ov",
        },
        {
            "domain": "expired.com",
            "dcv_method": "persistent-txt",
            "dcv_status": "expired",
            "validation_type": "ov",
        },
    ]
    mock_plugins.all.return_value = [fake_plugin]

    from lemur.common.celery import emit_dcv_expiration_metrics

    emit_dcv_expiration_metrics()

    broken_calls = [
        c
        for c in mock_metrics.send.call_args_list
        if len(c.args) >= 2
        and c.args[1] == "gauge"
        and "dcv.broken_domains" in c.args[0]
    ]
    assert len(broken_calls) == 1
    assert broken_calls[0].args[2] == 2  # expired + uncovered
    assert broken_calls[0].kwargs["metric_tags"]["ca"] == "digicert-issuer"
