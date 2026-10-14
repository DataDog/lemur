"""CRDL022 certificate-health metric contract."""
from types import SimpleNamespace
from unittest.mock import patch

import arrow
import pytest
from celery.exceptions import SoftTimeLimitExceeded


NOW = arrow.get("2030-01-01T12:00:00Z")
REASONS = (
    "rotation_enabled_without_authority",
    "missing_owner",
    "missing_creator",
    "notifications_disabled",
    "autorotation_disabled_near_expiry",
    "multiple_replacements",
    "expiring_without_replacement",
)
SUMMARY_NAMES = (
    "certificates_checked", "unhealthy_certificates", "failed_checks", "errors"
)


def certificate(**overrides):
    values = dict(
        id=42, authority_id=1, owner="owner@example.com", user_id=1,
        notify=True, rotation=True, not_after=NOW.shift(days=90),
        rotation_policy=SimpleNamespace(days=30), endpoints=[], replaced=[],
        replaces=[], replaced_by_pending=[], notifications=[],
    )
    values.update(overrides)
    return SimpleNamespace(**values)


def emit(certificates):
    from lemur.certificates import health

    with patch.object(health, "get_certificates_for_health_check", return_value=certificates), \
            patch.object(health.arrow, "utcnow", return_value=NOW), \
            patch.object(health.metrics, "send") as send:
        summary = health.send_certificate_health_metrics()
    states = {}
    summaries = {}
    for entry in send.call_args_list:
        name, kind, value = entry.args
        assert kind == "gauge"
        if name == "certificates.health_check_failed":
            tags = entry.kwargs["metric_tags"]
            assert set(tags) == {"cert_id", "reason"}
            key = (tags["cert_id"], tags["reason"])
            assert key not in states
            states[key] = value
        else:
            assert not entry.kwargs.get("metric_tags")
            assert name not in summaries
            summaries[name] = value
    assert summaries == {
        "certificates.health_check." + name: summary[name] for name in SUMMARY_NAMES
    }
    return states, summary


def test_health_query_excludes_deleted_expired_and_revoked_with_null_safe_filters(app):
    from sqlalchemy.dialects import postgresql
    from lemur.certificates import health

    query = health.get_certificates_for_health_check(NOW)
    compiled = query.statement.compile(dialect=postgresql.dialect())
    sql = str(compiled)
    # IS NOT TRUE admits NULL deleted flags. CASE ELSE FALSE admits NULL statuses.
    assert "certificates.deleted IS NOT true" in sql
    assert "certificates.not_after > %(not_after_1)s" in sql
    assert compiled.params["not_after_1"] == NOW
    assert "CASE WHEN (certificates.status = %(status_1)s)" in sql
    assert compiled.params["status_1"] == "revoked"
    assert "ELSE %(param_2)s END = false" in sql
    assert compiled.params["param_1"] is True
    assert compiled.params["param_2"] is False
    assert query._yield_per == 500


def test_health_query_loads_metadata_without_private_key_or_certificate_bodies(app):
    from lemur.certificates import health

    query = health.get_certificates_for_health_check(NOW)
    columns = {column.key for column in query._compile_context().primary_columns}
    assert {"id", "authority_id", "owner", "user_id", "notify", "rotation", "not_after",
            "rotation_policy_id"} <= columns
    assert not {"private_key", "body", "chain", "csr"} & columns
    assert "LEFT OUTER JOIN rotation_policies" in str(query.statement)


def test_health_successor_loader_loads_only_issued_certificate_ids(app):
    from sqlalchemy import inspect
    from lemur.certificates import health
    from lemur.certificates.models import Certificate

    query = health.get_certificates_for_health_check(NOW)
    mapper = inspect(Certificate)
    path = mapper._path_registry[mapper.relationships.replaced]
    # Use the same option propagation as SQLAlchemy's select-in loader, without SQL execution.
    successors = query.session.query(Certificate)._with_current_path(path)
    successors = successors._conditional_options(*query._with_options)
    columns = {column.key for column in successors._compile_context().primary_columns}
    assert columns == {"id"}
    strategies = query._compile_context().attributes
    assert strategies[("loader", path.path)].strategy == (("lazy", "selectin"),)


def test_empty_run_emits_four_zero_summary_gauges(app):
    states, summary = emit([])
    assert states == {}
    assert summary == dict(
        certificates_checked=0, unhealthy_certificates=0, failed_checks=0, errors=0
    )


def test_healthy_certificate_emits_all_seven_zeros(app):
    states, summary = emit([certificate()])
    assert states == {(42, reason): 0 for reason in REASONS}
    assert summary == dict(
        certificates_checked=1, unhealthy_certificates=0, failed_checks=0, errors=0
    )


@pytest.mark.parametrize("reason,overrides", [
    ("rotation_enabled_without_authority", {"authority_id": None}),
    ("missing_owner", {"owner": None}),
    ("missing_owner", {"owner": ""}),
    ("missing_owner", {"owner": " \t\n"}),
    ("missing_creator", {"user_id": None}),
    ("notifications_disabled", {"notify": False}),
    ("autorotation_disabled_near_expiry", {
        "rotation": False, "endpoints": [SimpleNamespace(active=True)],
        "not_after": NOW.shift(days=59, seconds=86399),
    }),
    ("multiple_replacements", {"replaced": [certificate(id=43), certificate(id=44)]}),
    ("expiring_without_replacement", {"not_after": NOW.shift(days=30)}),
])
def test_each_reason_emits_one_failure(app, reason, overrides):
    states, summary = emit([certificate(**overrides)])
    assert states == {(42, name): int(name == reason) for name in REASONS}
    assert summary == dict(
        certificates_checked=1, unhealthy_certificates=1, failed_checks=1, errors=0
    )


@pytest.mark.parametrize("overrides", [
    {"authority_id": None, "rotation": False},
    {"notify": None},
    {"rotation": None, "endpoints": [SimpleNamespace(active=True)],
     "not_after": NOW.shift(days=1)},
    {"rotation": False, "endpoints": [SimpleNamespace(active=False)],
     "not_after": NOW.shift(days=1)},
    {"rotation": False, "endpoints": [SimpleNamespace(active=None)],
     "not_after": NOW.shift(days=1)},
    {"rotation": False, "not_after": NOW.shift(days=1)},
    {"rotation": False, "endpoints": [SimpleNamespace(active=True)],
     "not_after": NOW.shift(days=60), "rotation_policy": SimpleNamespace(days=120)},
    {"not_after": NOW.shift(days=30, seconds=1)},
    {"not_after": NOW.shift(days=1), "replaced": [certificate(id=43)]},
    {"replaces": [certificate(id=40), certificate(id=41)]},
])
def test_passing_conditions_emit_zero(app, overrides):
    states, summary = emit([certificate(**overrides)])
    assert states == {(42, reason): 0 for reason in REASONS}
    assert summary["failed_checks"] == summary["errors"] == 0


def test_utc_reissue_boundary_and_pending_issuance_still_fails(app):
    # 07:00 -05:00 is the exact same instant as 12:00 UTC.
    cert = certificate(
        not_after=arrow.get("2030-01-31T07:00:00-05:00"),
        replaced_by_pending=[SimpleNamespace(id=1)],
    )
    states, summary = emit([cert])
    assert states[(42, "expiring_without_replacement")] == 1
    assert summary["failed_checks"] == 1


def test_summary_counts_unique_unhealthy_certificates_and_all_failures(app):
    states, summary = emit([
        certificate(authority_id=None, owner="", user_id=None, notify=False,
                    not_after=NOW.shift(days=1)),
        certificate(id=43, replaced=[certificate(id=44), certificate(id=45)]),
        certificate(id=46),
    ])
    assert sum(states.values()) == 6
    assert summary == dict(
        certificates_checked=3, unhealthy_certificates=2, failed_checks=6, errors=0
    )


def test_recovered_reason_explicitly_emits_zero(app):
    cert = certificate(owner="")
    failed, _ = emit([cert])
    cert.owner = "owner@example.com"
    recovered, _ = emit([cert])
    assert failed[(42, "missing_owner")] == 1
    assert recovered[(42, "missing_owner")] == 0


def test_missing_policy_is_unknown_only_when_needed(app):
    states, summary = emit([
        certificate(rotation_policy=None, owner=""),
        certificate(id=43, rotation_policy=None, replaced=[certificate(id=44)]),
        certificate(id=45, rotation=False, rotation_policy=None),
    ])
    assert (42, "expiring_without_replacement") not in states
    assert states[(42, "missing_owner")] == 1
    assert states[(43, "expiring_without_replacement")] == 0
    assert states[(45, "expiring_without_replacement")] == 0
    assert len(states) == 20
    assert summary == dict(
        certificates_checked=3, unhealthy_certificates=1, failed_checks=1, errors=1
    )


def test_multiple_errors_count_certificate_once_and_continue(app):
    class BrokenCertificate(SimpleNamespace):
        @property
        def owner(self):
            raise RuntimeError("broken owner")

        @property
        def user_id(self):
            raise RuntimeError("broken creator")

    values = vars(certificate(notify=False)).copy()
    del values["owner"]
    del values["user_id"]
    states, summary = emit([BrokenCertificate(**values), certificate(id=43)])
    assert (42, "missing_owner") not in states
    assert (42, "missing_creator") not in states
    assert states[(42, "notifications_disabled")] == 1
    assert states[(43, "missing_owner")] == 0
    assert summary == dict(
        certificates_checked=2, unhealthy_certificates=1, failed_checks=1, errors=1
    )


def test_predicate_soft_timeout_aborts_without_summary(app):
    from lemur.certificates import health

    class TimeoutCertificate(SimpleNamespace):
        @property
        def owner(self):
            raise SoftTimeLimitExceeded()

    values = vars(certificate()).copy()
    del values["owner"]
    with patch.object(health, "get_certificates_for_health_check",
                      return_value=[TimeoutCertificate(**values)]), \
            patch.object(health.metrics, "send") as send:
        with pytest.raises(SoftTimeLimitExceeded):
            health.send_certificate_health_metrics()
    assert all(c.args[0] == "certificates.health_check_failed" for c in send.call_args_list)


def test_metric_transport_error_aborts_without_completed_summary(app):
    from lemur.certificates import health

    with patch.object(health, "get_certificates_for_health_check", return_value=[certificate()]), \
            patch.object(health.metrics, "send", side_effect=RuntimeError("transport")):
        with pytest.raises(RuntimeError, match="transport"):
            health.send_certificate_health_metrics()
