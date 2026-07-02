"""
Celery sweep task for DigiCert DCV (Domain Control Validation) automation.

This module defines the ``validate_digicert_domains`` Celery task that runs
daily to keep all DigiCert-validated domains current.  The task is registered
with the Celery application when the full application stack is available; in
test environments the function is still importable and callable directly.
"""

from flask import current_app

# The celery_app import requires the full Flask application stack.  In test
# environments (where only stdlib and the plugin package are available) the
# import will fail, so we fall back gracefully and leave the function
# undecorated — it remains callable directly by tests.
try:
    from lemur.common.celery import celery_app as _celery_app
    _has_celery = hasattr(_celery_app, "task")
except (ImportError, AttributeError):
    _has_celery = False

from lemur.extensions import metrics
from lemur.plugins.lemur_digicert_dcv.digicert import DigiCertDCVProvider
from lemur.plugins.lemur_digicert_dcv.route53 import Route53DCVWriter


def validate_digicert_domains():
    """Sweep all DigiCert-managed domains and revalidate any that are missing
    or expiring soon.

    Controlled by two config keys:

    * ``DIGICERT_DCV_ENABLED`` (bool, default ``False``) — feature flag gate.
    * ``DIGICERT_DCV_RENEWAL_WINDOW_DAYS`` (int, default ``60``) — how many
      days ahead of expiry counts as "expiring soon".
    """
    if not current_app.config.get("DIGICERT_DCV_ENABLED", False):
        return

    provider = DigiCertDCVProvider()
    writer = Route53DCVWriter()
    window_days = current_app.config.get("DIGICERT_DCV_RENEWAL_WINDOW_DAYS", 60)

    try:
        domains = provider.list_all_domain_names()
    except Exception as e:
        metrics.send(
            "lemur.dcv.sweep_error",
            "counter",
            1,
            metric_tags={"ca": "digicert", "reason": type(e).__name__},
        )
        current_app.logger.error(
            {"error": str(e), "message": "DCV sweep failed to list domains"},
            exc_info=True,
        )
        return

    for domain_name in domains:
        status = provider.check_validation(domain_name, window_days=window_days)
        metrics.send(
            "lemur.dcv.validation_status",
            "gauge",
            1,
            metric_tags={
                "ca": "digicert",
                "domain": domain_name,
                "status": status.status,
            },
        )
        if status.status in ("MISSING", "EXPIRING_SOON"):
            _revalidate(provider, writer, domain_name)


def _revalidate(
    provider: DigiCertDCVProvider,
    writer: Route53DCVWriter,
    domain_name: str,
) -> None:
    """Initiate, write, propagate, and confirm a DCV token for *domain_name*.

    On any exception the failure metric is emitted and the error is logged, but
    the exception is swallowed so the outer sweep loop continues to the next
    domain.
    """
    metrics.send(
        "lemur.dcv.validation_triggered",
        "counter",
        1,
        metric_tags={"ca": "digicert", "domain": domain_name},
    )
    try:
        dns_record = provider.initiate_validation(domain_name)
        writer.upsert(dns_record)
        try:
            writer.wait_for_propagation(dns_record)
            provider.confirm_validation(domain_name)
            metrics.send(
                "lemur.dcv.validation_success",
                "counter",
                1,
                metric_tags={"ca": "digicert", "domain": domain_name},
            )
        except Exception:
            # Best-effort cleanup of the TXT record before re-raising so the
            # outer handler can record the failure metric.
            try:
                writer.delete(dns_record.name)
            except Exception:
                pass
            raise
    except Exception as exc:
        metrics.send(
            "lemur.dcv.validation_failed",
            "counter",
            1,
            metric_tags={
                "ca": "digicert",
                "domain": domain_name,
                "reason": type(exc).__name__,
            },
        )
        current_app.logger.exception(
            {
                "domain": domain_name,
                "error": str(exc),
                "message": "DCV sweep revalidation failed",
            }
        )


# Register the task with Celery when the application stack is present.
# In test environments _has_celery is False and the plain function is used.
if _has_celery:
    validate_digicert_domains = _celery_app.task(
        soft_time_limit=3600,
        name="lemur.plugins.lemur_digicert_dcv.tasks.validate_digicert_domains",
    )(validate_digicert_domains)
