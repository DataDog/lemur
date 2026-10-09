"""Metric emission for the cost exporter.

Turns a CostReport into low-cardinality Datadog custom metrics (one tag
dimension per metric series so the dashboard stays clean and we don't blow up
tag cardinality). Supports three output modes:

* ``print``  — human-readable dry run (no external calls)
* ``datadog`` — POST gauges via the Datadog v2 Metrics series API
* ``statsd`` — emit via dogstatsd (agent already running)

The canonical metric family:
  lemur.cert.cost.monthly          grand total (tag: env)
  lemur.cert.cost.monthly_by_ca    tag: ca
  lemur.cert.cost.monthly_by_owner tag: owner
  lemur.cert.cost.monthly_by_zone  tag: dc_zone
  lemur.cert.cost.orphaned         tag: ca   (wasted spend)
  lemur.cert.cost.annual           grand total (tag: env)
  lemur.cert.count                 tag: ca   (unit economics)
  lemur.cert.issued.count          counter (optionally supplied by an
                                   issuance hook / rotation events)
"""
from __future__ import annotations

import time
from collections import defaultdict
from typing import Dict, Iterable, List, Optional

from .models import USAGE_ORPHANED
from .engine import CostReport


def _series(metric: str, value: float, tags: List[str], metric_type: int, ts: int) -> dict:
    return {
        "metric": metric,
        "type": metric_type,  # 1=count 2=rate 3=gauge
        "points": [[ts, round(value, 4)]],
        "tags": tags,
    }


def build_payload(report: CostReport, counts: Optional[dict] = None) -> dict:
    ts = int(time.time())
    gauge = 3
    count = 1

    series: List[dict] = []

    # Grand total by env.
    by_env = defaultdict(float)
    for r in report.rows:
        by_env[r.env] += r.monthly_cost
    for env, val in by_env.items():
        series.append(_series("lemur.cert.cost.monthly", val, [f"env:{env}"], gauge, ts))
        series.append(_series("lemur.cert.cost.annual", val * 12, [f"env:{env}"], gauge, ts))

    # By CA.
    for ca, val in report.by("ca").items():
        series.append(_series("lemur.cert.cost.monthly_by_ca", val / 12.0, [f"ca:{ca}"], gauge, ts))

    # By owner.
    for owner, val in report.by("owner").items():
        series.append(_series("lemur.cert.cost.monthly_by_owner", val / 12.0, [f"owner:{owner}"], gauge, ts))

    # By zone.
    for zone, val in report.by("zone").items():
        series.append(_series("lemur.cert.cost.monthly_by_zone", val / 12.0, [f"dc_zone:{zone}"], gauge, ts))

    # Orphaned (wasted) spend by CA.
    orphaned_by_ca: Dict[str, float] = defaultdict(float)
    for r in report.rows:
        if r.usage == USAGE_ORPHANED:
            orphaned_by_ca[r.ca] += r.monthly_cost
    for ca, val in orphaned_by_ca.items():
        series.append(_series("lemur.cert.cost.orphaned", val, [f"ca:{ca}"], gauge, ts))

    # Cert counts by CA (unit economics).
    if counts:
        for ca, n in (counts.get("by_ca") or {}).items():
            series.append(_series("lemur.cert.count", float(n), [f"ca:{ca}"], gauge, ts))

    return {"series": series}


class DatadogEmitter:
    def __init__(self, api_key: str, app_key: Optional[str] = None, site: str = "us5.datadoghq.com"):
        self.api_key = api_key
        self.app_key = app_key
        self.site = site  # e.g. us5.datadoghq.com / datadoghq.com

    def submit(self, payload: dict) -> None:
        if not self.api_key:
            raise RuntimeError("DD_API_KEY not set; cannot submit Datadog metrics")
        import requests

        headers = {"DD-API-KEY": self.api_key, "Content-Type": "application/json"}
        if self.app_key:
            headers["DD-APPLICATION-KEY"] = self.app_key
        # v2 series intake is always on the API subdomain regardless of site.
        url = f"https://api.{self.site}/api/v2/series"
        resp = requests.post(url, headers=headers, json=payload, timeout=30)
        if resp.status_code >= 400 and resp.status_code != 202:
            raise RuntimeError(f"Datadog submitMetrics -> HTTP {resp.status_code}: {resp.text[:300]}")


class StatsdEmitter:
    def __init__(self, host: str = "127.0.0.1", port: int = 8125, namespace: str = "lemur"):
        self.host = host
        self.port = port
        self.namespace = namespace

    def submit(self, payload: dict) -> None:
        """dogstatsd-friendly flat emissions over the same series."""
        try:
            import statsd
        except ImportError as exc:
            raise RuntimeError("statsd package not installed; use --mode datadog or print") from exc

        client = statsd.StatsClient(self.host, self.port)
        for s in payload.get("series", []):
            name = f"{self.namespace}.{s['metric']}"
            value = s["points"][0][1]
            tags = {t.split(":", 1)[0]: t.split(":", 1)[1] for t in s.get("tags", [])}
            kind = s["type"]
            if kind == 3:
                client.gauge(name, value, tags=tags)
            else:
                client.incr(name, count=int(value), tags=tags)
        client.wait()


def emit(report: CostReport, counts: Optional[dict] = None, mode: str = "print", emitter=None) -> dict:
    """Run the pipeline and emit. Returns the payload (always) for tests/review."""
    payload = build_payload(report, counts)
    if mode == "print":
        return payload
    if emitter is None:
        raise RuntimeError("an emitter is required for mode != print")
    emitter.submit(payload)
    return payload


def render_report(report: CostReport, counts: Optional[dict] = None) -> str:
    """Human-readable summary used by print mode."""
    lines = []
    lines.append("==" * 30)
    lines.append("LEMUR CERT COST REPORT (CA-agnostic)")
    lines.append("==" * 30)
    lines.append(f"active certs      : {len(report.rows)}")
    lines.append(f"total annual      : ${report.total_annual:,.2f}")
    lines.append(f"total monthly     : ${report.total_monthly:,.2f}")
    lines.append(f"orphaned annual   : ${report.orphaned_annual:,.2f}")
    lines.append("")
    lines.append("--- by CA (annual) ---")
    for k, v in report.by("ca").items():
        lines.append(f"  {k:<14} ${v:>12,.2f}")
    lines.append("--- by owner (annual, top 10) ---")
    for k, v in list(report.by("owner").items())[:10]:
        lines.append(f"  {k or 'n/a':<22} ${v:>10,.2f}")
    lines.append("--- by dc_zone (annual, top 10) ---")
    for k, v in list(report.by("zone").items())[:10]:
        lines.append(f"  {k or 'n/a':<20} ${v:>10,.2f}")
    if counts:
        lines.append("--- cert count by CA ---")
        for k, v in (counts.get("by_ca") or {}).items():
            lines.append(f"  {k:<14} {v}")
    return "\n".join(lines)
