"""Tests for metric payload building + dashboard JSON generation."""
import json

import pytest

from lemur_cost import sample
from lemur_cost.dashboard import build_dashboard, REQUIRED_METRICS
from lemur_cost.emit import build_payload
from lemur_cost.engine import build_report, summarize_counts


@pytest.fixture
def report():
    return build_report(sample.certs(), actuals=None)


@pytest.fixture
def payload(report):
    counts = summarize_counts([r.cert for r in report.rows if r.cert])
    return build_payload(report, counts)


def test_payload_has_expected_metrics(payload):
    names = {s["metric"] for s in payload["series"]}
    assert "lemur.cert.cost.monthly" in names
    assert "lemur.cert.cost.monthly_by_ca" in names
    assert "lemur.cert.cost.orphaned" in names
    assert "lemur.cert.count" in names


def test_payload_ca_tag_present(payload):
    ca_tags = [s["tags"] for s in payload["series"] if s["metric"] == "lemur.cert.cost.monthly_by_ca"]
    assert ca_tags, "expected monthly_by_ca series"
    # At least one series should reference each of our three CAs.
    flat = " ".join(str(t) for s in payload["series"] for t in s["tags"])
    assert "ca:sectigo" in flat
    assert "ca:digicert" in flat
    assert "ca:letsencrypt" in flat


def test_orphaned_metric_present(payload):
    names = {s["metric"] for s in payload["series"]}
    assert "lemur.cert.cost.orphaned" in names


def test_dashboard_json_serializes():
    dash = build_dashboard()
    data = json.loads(json.dumps(dash))  # must be JSON-serializable
    assert data["title"] == "Cost of Lemur"
    # Ensure the dashboard references every metric the exporter emits.
    blob = json.dumps(data)
    for m in REQUIRED_METRICS:
        assert m in blob, f"dashboard missing metric {m}"
