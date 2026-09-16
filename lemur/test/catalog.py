"""Celery task catalog for the isolated Lemur sandbox test suite."""

from dataclasses import dataclass, field
from typing import Any, Dict, List


TASK_PREFIX = "lemur.common.celery."


@dataclass(frozen=True)
class TaskScenario:
    """Arguments needed to dispatch one registered Lemur task."""

    args: List[Any] = field(default_factory=list)
    kwargs: Dict[str, Any] = field(default_factory=dict)


# Keep this list explicit. A new application task must have a deliberate test
# scenario before the nightly suite is allowed to run.
TASK_CATALOG = {
    "lemur.common.celery.report_celery_last_success_metrics": TaskScenario(),
    "lemur.common.celery.fetch_acme_cert": TaskScenario(args=[0]),
    "lemur.common.celery.fetch_all_pending_acme_certs": TaskScenario(),
    "lemur.common.celery.remove_old_acme_certs": TaskScenario(),
    "lemur.common.celery.clean_all_sources": TaskScenario(),
    "lemur.common.celery.clean_source": TaskScenario(args=["lemur-test-aws"]),
    "lemur.common.celery.sync_all_sources": TaskScenario(),
    "lemur.common.celery.sync_source": TaskScenario(args=["lemur-test-aws"]),
    "lemur.common.celery.certificate_reissue": TaskScenario(),
    "lemur.common.celery.certificate_rotate": TaskScenario(),
    "lemur.common.celery.get_all_zones": TaskScenario(),
    "lemur.common.celery.check_revoked": TaskScenario(),
    "lemur.common.celery.notify_expirations": TaskScenario(),
    "lemur.common.celery.notify_authority_expirations": TaskScenario(),
    "lemur.common.celery.send_security_expiration_summary": TaskScenario(),
    "lemur.common.celery.enable_autorotate_for_certs_attached_to_endpoint": TaskScenario(),
    "lemur.common.celery.enable_autorotate_for_certs_attached_to_destination": TaskScenario(),
    "lemur.common.celery.deactivate_entrust_test_certificates": TaskScenario(),
    "lemur.common.celery.disable_rotation_of_duplicate_certificates": TaskScenario(),
    "lemur.common.celery.notify_expiring_deployed_certificates": TaskScenario(),
    "lemur.common.celery.identity_expiring_deployed_certificates": TaskScenario(),
    "lemur.common.celery.identify_expiring_deployed_certificates": TaskScenario(),
    "lemur.common.celery.certificate_expirations_metrics": TaskScenario(),
    # Deprecated alias kept for messages already present in the broker.
    "lemur.common.celery.check_dcv_expiration": TaskScenario(),
}


def registered_lemur_tasks(celery_app):
    """Return application tasks, excluding Celery's built-in tasks."""
    return {name for name in celery_app.tasks if name.startswith(TASK_PREFIX)}


def validate_task_catalog(celery_app):
    """Fail when the code and the explicit integration-test catalog diverge."""
    registered = registered_lemur_tasks(celery_app)
    cataloged = set(TASK_CATALOG)
    missing = sorted(registered - cataloged)
    stale = sorted(cataloged - registered)
    if missing or stale:
        details = []
        if missing:
            details.append("missing scenarios: {}".format(", ".join(missing)))
        if stale:
            details.append("unregistered tasks: {}".format(", ".join(stale)))
        raise RuntimeError(
            "Celery task catalog is incomplete ({})".format("; ".join(details))
        )


def scenarios(configured=None):
    """Return catalog scenarios with sandbox configuration overrides applied."""
    configured = configured or {}
    unknown = sorted(set(configured) - set(TASK_CATALOG))
    if unknown:
        raise RuntimeError(
            "Unknown task scenario overrides: {}".format(", ".join(unknown))
        )

    resolved = {}
    for task_name, default in TASK_CATALOG.items():
        override = configured.get(task_name, {})
        resolved[task_name] = TaskScenario(
            args=list(override.get("args", default.args)),
            kwargs=dict(override.get("kwargs", default.kwargs)),
        )
    return resolved
