"""Read-only certificate health evaluation and metrics (CRDL022)."""
import arrow
from celery.exceptions import SoftTimeLimitExceeded
from flask import current_app
from sqlalchemy.orm import joinedload, load_only, selectinload
from sqlalchemy.sql.expression import false

from lemur.certificates.models import Certificate
from lemur.extensions import metrics
from lemur.models import EndpointsCertificates


def rotation_enabled_without_authority(certificate, now):
    return certificate.rotation is True and certificate.authority_id is None


def missing_owner(certificate, now):
    return certificate.owner is None or not certificate.owner.strip()


def missing_creator(certificate, now):
    return certificate.user_id is None


def notifications_disabled(certificate, now):
    return certificate.notify is False


def autorotation_disabled_near_expiry(certificate, now):
    return (
        certificate.rotation is False
        and any(endpoint.active is True for endpoint in certificate.endpoints)
        and arrow.get(certificate.not_after) < now.shift(days=60)
    )


def multiple_replacements(certificate, now):
    return len(certificate.replaced) > 1


def expiring_without_replacement(certificate, now):
    return (
        certificate.rotation is True
        and not certificate.replaced
        and arrow.get(certificate.not_after)
        <= now.shift(days=certificate.rotation_policy.days)
    )


# Function names are the stable metric reason values; each predicate runs independently.
HEALTH_CHECKS = (
    rotation_enabled_without_authority,
    missing_owner,
    missing_creator,
    notifications_disabled,
    autorotation_disabled_near_expiry,
    multiple_replacements,
    expiring_without_replacement,
)


def get_certificates_for_health_check(now):
    """Stream eligible certificates with the relationships needed by the predicates."""
    return (
        Certificate.query
        .filter(Certificate.deleted.isnot(True))
        .filter(Certificate.not_after > now)
        .filter(Certificate.revoked == false())
        .options(
            load_only(
                Certificate.id, Certificate.authority_id, Certificate.owner,
                Certificate.user_id, Certificate.notify, Certificate.rotation,
                Certificate.not_after, Certificate.rotation_policy_id,
            ),
            joinedload(Certificate.rotation_policy),
            selectinload(Certificate.replaced).load_only(Certificate.id),
            selectinload(Certificate.endpoints_assoc).joinedload(EndpointsCertificates.endpoint),
        )
        .yield_per(500)
    )


def send_certificate_health_metrics():
    """Emit every known certificate/reason state and zero-inclusive completed-run summaries."""
    now = arrow.utcnow()
    summary = dict(
        certificates_checked=0, unhealthy_certificates=0, failed_checks=0, errors=0
    )
    for certificate in get_certificates_for_health_check(now):
        summary["certificates_checked"] += 1
        unhealthy = evaluation_error = False
        for check in HEALTH_CHECKS:
            reason = check.__name__
            try:
                failed = check(certificate, now)
            except SoftTimeLimitExceeded:
                raise
            except Exception:
                evaluation_error = True
                current_app.logger.exception(
                    "Error evaluating certificate health: cert_id=%s reason=%s",
                    certificate.id, reason,
                )
                continue
            if failed:
                unhealthy = True
                summary["failed_checks"] += 1
            # Submission errors abort the run rather than masquerading as evaluation errors.
            metrics.send(
                "certificates.health_check_failed", "gauge", int(failed),
                metric_tags={"cert_id": certificate.id, "reason": reason},
            )
        summary["unhealthy_certificates"] += int(unhealthy)
        summary["errors"] += int(evaluation_error)

    for name, value in summary.items():
        metrics.send(f"certificates.health_check.{name}", "gauge", value)
    return summary
