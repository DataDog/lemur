"""Cost engine: joins the CA-agnostic Lemur inventory with optional per-CA
billing actuals and the pricing table to produce priced CostRows + aggregated
cost by CA / owner / zone / tier / usage.

Orphan detection mirrors CLOUDR-1957: a cert is "unused/orphaned" if it has no
destinations and no endpoints and is not the successor of an active cert in
rotation.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from .models import (
    BillingActual,
    CA_UNKNOWN,
    CertRecord,
    CostRow,
    USAGE_IN_USE,
    USAGE_ORPHANED,
)
from . import pricing as pr


@dataclass
class CostReport:
    rows: List[CostRow] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._by_ca = _aggregate(self.rows, "ca")
        self._by_owner = _aggregate(self.rows, "owner")
        self._by_zone = _aggregate(self.rows, "dc_zone")
        self._by_tier = _aggregate(self.rows, "validation_tier")
        self._by_usage = _aggregate(self.rows, "usage")

    @property
    def total_annual(self) -> float:
        return round(sum(r.effective_price_yr for r in self.rows), 2)

    @property
    def total_monthly(self) -> float:
        return round(self.total_annual / 12.0, 2)

    @property
    def orphaned_annual(self) -> float:
        return round(sum(r.effective_price_yr for r in self.rows if r.usage == USAGE_ORPHANED), 2)

    def by(self, key: str) -> Dict[str, float]:
        return dict(getattr(self, f"_by_{key}", {}))

    def summary(self) -> Dict:
        return {
            "total_annual": self.total_annual,
            "total_monthly": self.total_monthly,
            "cert_count": len(self.rows),
            "orphaned_annual": self.orphaned_annual,
            "by_ca": self.by("ca"),
            "by_owner": self.by("owner"),
            "by_zone": self.by("zone"),
            "by_tier": self.by("tier"),
            "by_usage": self.by("usage"),
        }


def _aggregate(rows: Sequence[CostRow], key: str) -> Dict[str, float]:
    totals: Dict[str, float] = defaultdict(float)
    for r in rows:
        totals[getattr(r, key) or "unknown"] += r.effective_price_yr
    return {k: round(v, 2) for k, v in sorted(totals.items(), key=lambda kv: -kv[1])}


def _is_orphaned(cert: CertRecord) -> bool:
    if cert.has_destination or cert.has_endpoint:
        return False
    if cert.in_rotation:
        return False
    # A successor of an active cert is still "in use" for replacement purposes.
    return True


def price_cert(cert: CertRecord, pricing: Optional[dict] = None) -> CostRow:
    """Resolve a single cert to a CostRow using the pricing tables."""
    p = pricing or pr.PRICING
    ca = pr.resolve_ca(cert.authority)
    shape = pr.classify_shape(cert.common_name)
    env = pr.derive_env(cert.common_name)
    zone = pr.derive_zone(cert.common_name)
    customer_facing = pr.is_customer_facing(cert.common_name)

    # Default validation tier: OV is the Datadog DigiCert/Sectigo norm; LE is DV.
    tier = "OV"
    if ca in (pr.CA_LETS_ENCRYPT, pr.CA_ACM):
        tier = "DV"

    offered, price = pr.resolve_price(ca, tier, shape)
    if not offered:
        price = 0.0

    cert.ca = ca
    cert.validation_tier = tier
    cert.shape = shape if shape else pr.SHAPE_FQDN
    cert.env = env
    cert.dc_zone = zone
    cert.customer_facing = customer_facing
    cert.usage = USAGE_ORPHANED if _is_orphaned(cert) else USAGE_IN_USE

    return CostRow(
        cert=cert,
        ca=ca,
        shape=shape,
        validation_tier=tier,
        list_price_yr=round(price, 2),
        owner=cert.owner,
        env=env,
        dc_zone=zone,
        customer_facing=customer_facing,
        usage=cert.usage,
        source="estimated",
    )


def reconcile_actual(
    row: CostRow, actuals_by_domain: Dict[str, List[BillingActual]]
) -> CostRow:
    """Overlay a matching CA billing actual (if found) onto an estimated row so
    the emitted cost prefers actuals."""
    if not row.cert:
        return row
    key = (row.cert.common_name or "").lower().strip().rstrip(".")
    hits = actuals_by_domain.get(key, [])
    if not hits:
        return row
    best = hits[0]
    if best.cost_per_year is not None:
        row.actual_price_yr = best.cost_per_year
        row.source = "actual"
    return row


def build_report(
    certs: Sequence[CertRecord],
    actuals: Optional[Sequence[BillingActual]] = None,
    pricing: Optional[dict] = None,
    reconcile: bool = True,
) -> CostReport:
    """Price every cert and optionally reconcile against CA billing actuals."""
    rows = [price_cert(c, pricing) for c in certs]

    if reconcile and actuals:
        actuals_by_domain: Dict[str, List[BillingActual]] = defaultdict(list)
        for a in actuals:
            actuals_by_domain[(a.domain or "").lower().strip().rstrip(".")].append(a)
        rows = [reconcile_actual(r, actuals_by_domain) for r in rows]

    return CostReport(rows)


def summarize_counts(certs: Sequence[CertRecord]) -> Dict[str, int]:
    """Counts of certs by CA / tier / shape / usage for the unit-economics
    metric (lemur.cert.count)."""
    by_ca: Counter = Counter()
    by_tier: Counter = Counter()
    by_shape: Counter = Counter()
    by_usage: Counter = Counter()
    for c in certs:
        c.ca = pr.resolve_ca(c.authority)
        by_ca[c.ca] += 1
        by_tier[c.validation_tier] += 1
        by_shape[c.shape] += 1
        by_usage[USAGE_ORPHANED if _is_orphaned(c) else USAGE_IN_USE] += 1
    return {"by_ca": dict(by_ca), "by_tier": dict(by_tier), "by_shape": dict(by_shape), "by_usage": dict(by_usage)}
