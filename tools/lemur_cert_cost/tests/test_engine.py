"""Unit tests for the cost engine (pricing, orphaning, aggregation)."""
import pytest

from lemur_cost import sample
from lemur_cost.engine import build_report, price_cert, summarize_counts
from lemur_cost.models import (
    CA_DIGICERT,
    CA_LETS_ENCRYPT,
    CA_SECTIGO,
    USAGE_IN_USE,
    USAGE_ORPHANED,
)


@pytest.fixture
def report():
    return build_report(sample.certs(), actuals=None)


def test_report_counts_and_totals(report):
    assert len(report.rows) == 11
    # Every row has a non-negative cost.
    assert all(r.list_price_yr >= 0 for r in report.rows)
    # Orphaned spend is nonzero (DigiCert + Sectigo orphans) but LE orphan is $0.
    assert report.orphaned_annual > 0


def test_ca_breakdown_contains_all_cas(report):
    by_ca = report.by("ca")
    assert CA_DIGICERT in by_ca
    assert CA_SECTIGO in by_ca
    assert CA_LETS_ENCRYPT in by_ca
    # Let's Encrypt is free.
    assert by_ca[CA_LETS_ENCRYPT] == 0.0


def test_monthly_is_annual_over_12(report):
    assert abs(report.total_monthly - report.total_annual / 12.0) < 0.01


def test_orphan_detection():
    certs = sample.certs()
    orphan = [c for c in certs if c.id == 8][0]
    active = [c for c in certs if c.id == 1][0]
    assert price_cert(orphan).usage == USAGE_ORPHANED
    assert price_cert(active).usage == USAGE_IN_USE


def test_counts_by_ca():
    counts = summarize_counts(sample.certs())
    assert counts["by_ca"][CA_DIGICERT] >= 1
    assert counts["by_ca"][CA_SECTIGO] >= 1
    assert counts["by_ca"][CA_LETS_ENCRYPT] >= 1


def test_sectigo_cheaper_than_digicert_for_same_shape():
    # Sectigo DV FQDN cheaper than DigiCert DV FQDN (per pricing table).
    sectigo = price_cert(_mk("SectigoProduction", "api.sandbox.datad0g.com"))
    digi = price_cert(_mk("DigiCertCommercial", "api.sandbox.datad0g.com"))
    assert sectigo.list_price_yr < digi.list_price_yr


def _mk(authority, cn):
    from lemur_cost.models import CertRecord

    return CertRecord(id=99, name=cn, common_name=cn, authority=authority, active=True, has_destination=True, has_endpoint=True)
