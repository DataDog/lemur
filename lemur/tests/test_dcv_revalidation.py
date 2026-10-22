"""Tests for the revalidate_dcv_domains Celery task (CLOUDR-2344)."""
import sys
from unittest.mock import MagicMock, call, patch

from celery.exceptions import SoftTimeLimitExceeded

# Pre-import celery module with Redis mocked so decorators don't need a live broker.
if "lemur.common.celery" not in sys.modules:
    with patch("redis.StrictRedis") as _mock_redis:
        _mock_redis.return_value.set.return_value = True
        import lemur.common.celery  # noqa: F401

import lemur.common.celery as _celery_module  # noqa: E402

_celery_module.current_app = MagicMock()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_plugin(slug, domains, revalidate_results=None, has_revalidate=True):
    """Build a minimal fake issuer plugin."""
    plugin = MagicMock()
    plugin.slug = slug
    if has_revalidate:
        if revalidate_results is None:
            revalidate_results = {d: {"domain": d, "status": "triggered", "detail": None} for d in domains}
        plugin.revalidate_domain.side_effect = lambda d: revalidate_results.get(
            d, {"domain": d, "status": "triggered", "detail": None}
        )
    else:
        del plugin.revalidate_domain  # ensure hasattr returns False


    return plugin


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@patch("lemur.common.celery._active_domains_by_ca")
@patch("lemur.common.celery.plugins")
@patch("lemur.common.celery.metrics")
@patch("lemur.common.celery.current_app", new_callable=MagicMock)
@patch("lemur.common.celery.time")
def test_revalidate_dcv_domains_happy_path(
    mock_time, mock_current_app, mock_metrics, mock_plugins, mock_active
):
    """Both CAs' domains are triggered; counters and gauges emitted correctly."""
    mock_active.return_value = {
        "digicert-issuer": {"datadoghq.com", "datad0g.com"},
        "sectigo-issuer": {"datad0g.com"},
    }
    digicert_plugin = _make_plugin("digicert-issuer", {"datadoghq.com", "datad0g.com"})
    sectigo_plugin = _make_plugin("sectigo-issuer", {"datad0g.com"})
    mock_plugins.all.return_value = [digicert_plugin, sectigo_plugin]

    from lemur.common.celery import revalidate_dcv_domains
    revalidate_dcv_domains()

    # Both plugins' revalidate_domain called for every domain
    assert digicert_plugin.revalidate_domain.call_count == 2
    assert sectigo_plugin.revalidate_domain.call_count == 1

    triggered_calls = [
        c for c in mock_metrics.send.call_args_list
        if c.args[0] == "dcv.revalidation.triggered"
    ]
    assert len(triggered_calls) == 3  # 2 digicert + 1 sectigo

    processed_calls = [
        c for c in mock_metrics.send.call_args_list
        if c.args[0] == "dcv.revalidation.domains_processed"
    ]
    assert len(processed_calls) == 2
    # Each processed gauge = number of domains for that CA
    processed_by_ca = {c.kwargs["metric_tags"]["ca"]: c.args[2] for c in processed_calls}
    assert processed_by_ca["digicert-issuer"] == 2
    assert processed_by_ca["sectigo-issuer"] == 1

    # Rate-limit sleep called once per domain
    assert mock_time.sleep.call_count == 3


@patch("lemur.common.celery._active_domains_by_ca")
@patch("lemur.common.celery.plugins")
@patch("lemur.common.celery.metrics")
@patch("lemur.common.celery.current_app", new_callable=MagicMock)
@patch("lemur.common.celery.time")
def test_revalidate_dcv_domains_skips_plugin_without_method(
    mock_time, mock_current_app, mock_metrics, mock_plugins, mock_active
):
    """A plugin without revalidate_domain is silently skipped."""
    mock_active.return_value = {
        "digicert-issuer": {"datadoghq.com"},
        "acme-issuer": {"example.com"},
    }
    digicert_plugin = _make_plugin("digicert-issuer", {"datadoghq.com"})
    acme_plugin = _make_plugin("acme-issuer", {"example.com"}, has_revalidate=False)
    mock_plugins.all.return_value = [digicert_plugin, acme_plugin]

    from lemur.common.celery import revalidate_dcv_domains
    revalidate_dcv_domains()

    assert digicert_plugin.revalidate_domain.call_count == 1
    # acme plugin has no revalidate_domain — no calls, no errors
    triggered = [
        c for c in mock_metrics.send.call_args_list
        if c.args[0] == "dcv.revalidation.triggered"
    ]
    assert len(triggered) == 1
    assert triggered[0].kwargs["metric_tags"]["ca"] == "digicert-issuer"


@patch("lemur.common.celery._active_domains_by_ca")
@patch("lemur.common.celery.plugins")
@patch("lemur.common.celery.metrics")
@patch("lemur.common.celery.current_app", new_callable=MagicMock)
@patch("lemur.common.celery.time")
def test_revalidate_dcv_domains_per_domain_error_does_not_stop_loop(
    mock_time, mock_current_app, mock_metrics, mock_plugins, mock_active
):
    """An error on one domain is recorded but the loop continues for remaining domains."""
    mock_active.return_value = {
        "digicert-issuer": {"ok.com", "bad.com", "also-ok.com"},
    }
    results = {
        "ok.com": {"domain": "ok.com", "status": "triggered", "detail": None},
        "bad.com": {"domain": "bad.com", "status": "error", "detail": "API 500"},
        "also-ok.com": {"domain": "also-ok.com", "status": "triggered", "detail": None},
    }
    plugin = _make_plugin("digicert-issuer", {"ok.com", "bad.com", "also-ok.com"}, revalidate_results=results)
    mock_plugins.all.return_value = [plugin]

    from lemur.common.celery import revalidate_dcv_domains
    revalidate_dcv_domains()

    assert plugin.revalidate_domain.call_count == 3

    triggered = [c for c in mock_metrics.send.call_args_list if c.args[0] == "dcv.revalidation.triggered"]
    errors = [c for c in mock_metrics.send.call_args_list if c.args[0] == "dcv.revalidation.error"]
    assert len(triggered) == 2
    assert len(errors) == 1
    assert errors[0].kwargs["metric_tags"]["domain"] == "bad.com"

    processed = [c for c in mock_metrics.send.call_args_list if c.args[0] == "dcv.revalidation.domains_processed"]
    assert processed[0].args[2] == 3  # all three processed (not stopped by error)


@patch("lemur.common.celery._active_domains_by_ca")
@patch("lemur.common.celery.plugins")
@patch("lemur.common.celery.metrics")
@patch("lemur.common.celery.current_app", new_callable=MagicMock)
@patch("lemur.common.celery.time")
def test_revalidate_dcv_domains_exception_in_plugin_call_does_not_stop_loop(
    mock_time, mock_current_app, mock_metrics, mock_plugins, mock_active
):
    """An unexpected exception from revalidate_domain is caught; loop continues."""
    mock_active.return_value = {"digicert-issuer": {"a.com", "b.com"}}
    plugin = MagicMock()
    plugin.slug = "digicert-issuer"
    call_count = [0]

    def side_effect(domain):
        call_count[0] += 1
        if domain == "a.com":
            raise RuntimeError("unexpected boom")
        return {"domain": domain, "status": "triggered", "detail": None}

    plugin.revalidate_domain.side_effect = side_effect
    mock_plugins.all.return_value = [plugin]

    from lemur.common.celery import revalidate_dcv_domains
    revalidate_dcv_domains()

    assert call_count[0] == 2
    errors = [c for c in mock_metrics.send.call_args_list if c.args[0] == "dcv.revalidation.error"]
    triggered = [c for c in mock_metrics.send.call_args_list if c.args[0] == "dcv.revalidation.triggered"]
    assert len(errors) == 1
    assert len(triggered) == 1


@patch("lemur.common.celery._active_domains_by_ca")
@patch("lemur.common.celery.plugins")
@patch("lemur.common.celery.metrics")
@patch("lemur.common.celery.current_app", new_callable=MagicMock)
@patch("lemur.common.celery.time")
def test_revalidate_dcv_domains_soft_time_limit_propagates(
    mock_time, mock_current_app, mock_metrics, mock_plugins, mock_active
):
    """SoftTimeLimitExceeded propagates out of the task without being swallowed."""
    mock_active.return_value = {"digicert-issuer": {"datadoghq.com"}}
    plugin = MagicMock()
    plugin.slug = "digicert-issuer"
    plugin.revalidate_domain.side_effect = SoftTimeLimitExceeded()
    mock_plugins.all.return_value = [plugin]

    from lemur.common.celery import revalidate_dcv_domains
    try:
        revalidate_dcv_domains()
        assert False, "SoftTimeLimitExceeded should have propagated"
    except SoftTimeLimitExceeded:
        pass


@patch("lemur.common.celery._active_domains_by_ca")
@patch("lemur.common.celery.plugins")
@patch("lemur.common.celery.metrics")
@patch("lemur.common.celery.current_app", new_callable=MagicMock)
@patch("lemur.common.celery.time")
def test_revalidate_dcv_domains_not_found_emits_error(
    mock_time, mock_current_app, mock_metrics, mock_plugins, mock_active
):
    """A not_found result from revalidate_domain is counted as an error metric."""
    mock_active.return_value = {"digicert-issuer": {"unknown.com"}}
    plugin = _make_plugin(
        "digicert-issuer",
        {"unknown.com"},
        revalidate_results={"unknown.com": {"domain": "unknown.com", "status": "not_found", "detail": "no match"}},
    )
    mock_plugins.all.return_value = [plugin]

    from lemur.common.celery import revalidate_dcv_domains
    revalidate_dcv_domains()

    errors = [c for c in mock_metrics.send.call_args_list if c.args[0] == "dcv.revalidation.error"]
    assert len(errors) == 1
    assert errors[0].kwargs["metric_tags"]["domain"] == "unknown.com"
