"""Datadog dashboard generator.

Builds a Datadog v1 dashboard JSON ("Cost of Lemur") over the metrics the
exporter emits. The dashboard is CA-agnostic: every cost widget is sliced by
the ``ca`` (and owner/zone/env) tags, so DigiCert, Sectigo, Let's Encrypt, ACM,
and GovCloud all appear automatically as they're added to the fleet.
"""
from __future__ import annotations

import json
from typing import Dict, List

REQUIRED_METRICS = [
    "lemur.cert.cost.monthly",
    "lemur.cert.cost.monthly_by_ca",
    "lemur.cert.cost.monthly_by_owner",
    "lemur.cert.cost.monthly_by_zone",
    "lemur.cert.cost.orphaned",
    "lemur.cert.count",
    "lemur.cert.issued.count",
]


def _timeseries(title: str, query: str, yscale: str = "linear") -> dict:
    return {
        "definition": {
            "title": title,
            "type": "timeseries",
            "requests": [{"q": query, "display_type": "line"}],
            "yaxis": {"scale": yscale},
        },
        "layout": {"x": 0, "y": 0, "width": 8, "height": 4},
    }


def _toplist(title: str, query: str, order: str = "top") -> dict:
    return {
        "definition": {
            "title": title,
            "type": "toplist",
            "requests": [{"q": query, "style": {"palette": "dog_classic"}, "orderby": "value", "order": order}],
        },
        "layout": {"x": 0, "y": 0, "width": 4, "height": 4},
    }


def _query_value(title: str, query: str, unit: str = "currency") -> dict:
    return {
        "definition": {
            "title": title,
            "type": "query_value",
            "requests": [{"q": query, "aggregator": "avg"}],
            "autoscale": True,
            "precision": 2,
        },
        "layout": {"x": 0, "y": 0, "width": 4, "height": 3},
    }


def build_dashboard(title: str = "Cost of Lemur") -> Dict:
    """Assemble the dashboard JSON. Metric queries reference the emitted names;
    because they're per-CA tagged, the ``by`` widgets show every CA present."""
    widgets: List[dict] = []

    def place(w: dict) -> None:
        widgets.append(w)

    # Row 1: headline totals + orphaned (query_values)
    place(_query_value("Total Cost / month", "sum:lemur.cert.cost.monthly{}", "currency"))
    place(_query_value("Total Cost / year", "sum:lemur.cert.cost.annual{}", "currency"))
    place(
        _query_value(
            "Wasted (orphaned) / month",
            "sum:lemur.cert.cost.orphaned{}",
            "currency",
        )
    )

    # Row 2: cost over time by CA and grand total
    place(_timeseries("Monthly cost by CA ($/mo)", "sum:lemur.cert.cost.monthly_by_ca{*}.as_count()"))
    place(
        _timeseries("Monthly cost by env ($/mo)", "sum:lemur.cert.cost.monthly{*}.as_count()"),
    )

    # Row 3: top lists
    place(_toplist("Cost by CA", "top(sum:lemur.cert.cost.monthly_by_ca{*})"))
    place(_toplist("Cost by Owner", "top(sum:lemur.cert.cost.monthly_by_owner{*})"))
    place(_toplist("Cost by DC Zone", "top(sum:lemur.cert.cost.monthly_by_zone{*})"))

    # Row 4: unit economics + growth
    place(_timeseries("Active certs by CA", "sum:lemur.cert.count{*}.as_count()"))
    place(_timeseries("Certs issued", "sum:lemur.cert.issued.count{*}.as_count().fill(null)"))

    return {
        "title": title,
        "description": (
            "CA-agnostic cost of certs managed by Lemur. Sliced by the `ca` "
            "tag so DigiCert / Sectigo / Let's Encrypt / ACM each appear. "
            "Metrics emitted by the lemur-cert-cost exporter."
        ),
        "widgets": widgets,
        "layout_type": "free",
        "template_variables": [
            {"name": "ca", "prefix": "ca", "default": "*"},
            {"name": "env", "prefix": "env", "default": "*"},
        ],
        "notify_list": [],
    }


def write_dashboard(path: str, title: str = "Cost of Lemur") -> str:
    data = build_dashboard(title)
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    return path
