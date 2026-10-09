"""Data models for the Lemur certificate cost exporter.

These are plain dataclasses decoupled from any specific CA API so the cost
engine and metric emitters stay CA-agnostic.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Dict, Optional

# Validation tiers supported across commercial CAs (DV/OV/EV).
VALIDATION_TIERS = ("DV", "OV", "EV")

# Certificate shapes we price differently.
SHAPE_WILDCARD = "wildcard"
SHAPE_FQDN = "fqdn"
SHAPE_MULTI_SAN = "multi_san"

# Usage classification for cost attribution.
USAGE_IN_USE = "in_use"
USAGE_ORPHANED = "orphaned"

# Normalized CA identifiers used as the `ca` tag.
CA_DIGICERT = "digicert"
CA_SECTIGO = "sectigo"
CA_LETS_ENCRYPT = "letsencrypt"
CA_ACM = "acm"
CA_GOV = "gov"
CA_UNKNOWN = "unknown"


@dataclass
class CertRecord:
    """A certificate as surfaced by Lemur's inventory (CA-agnostic)."""

    id: int
    name: str  # Lemur certificate name (often contains CN + authority/date)
    common_name: str  # CN, e.g. `*.us1.prod.dog` or `vault.us1.prod.dog`
    authority: str  # Lemur authority name, e.g. `DigiCertCommercial`, `LetsEncryptProd`
    active: bool = True
    not_after: Optional[str] = None
    owner: str = ""
    has_destination: bool = False
    has_endpoint: bool = False
    in_rotation: bool = False
    replaced_by: Optional[str] = None
    issuer: str = ""

    # Derived (computed by pricing module, not raw from API).
    ca: str = CA_UNKNOWN
    validation_tier: str = "UNKNOWN"
    shape: str = SHAPE_FQDN
    env: str = "unknown"
    dc_zone: str = ""
    customer_facing: bool = False
    usage: str = USAGE_IN_USE

    def __post_init__(self) -> None:
        if self.shape not in (SHAPE_WILDCARD, SHAPE_FQDN, SHAPE_MULTI_SAN):
            self.shape = SHAPE_FQDN


@dataclass
class BillingActual:
    """Actual billed domain/cert from a CA billing feed (reconciliation).

    Each CA adapter normalizes its own billing response into this shape. This
    is the "ground truth" that reconciles against the estimated cost.
    """

    ca: str
    domain: str
    shape: str = SHAPE_FQDN
    validation_tier: str = "UNKNOWN"
    status: str = "active"
    cost_per_year: Optional[float] = None
    customer_facing: bool = False
    extra: Dict[str, str] = field(default_factory=dict)


@dataclass
class CostRow:
    """A single resolved cost line combining estimate + (optional) actual."""

    cert: Optional[CertRecord] = None
    ca: str = CA_UNKNOWN
    shape: str = SHAPE_FQDN
    validation_tier: str = "UNKNOWN"
    list_price_yr: float = 0.0  # from pricing table
    actual_price_yr: Optional[float] = None  # from CA billing feed (if available)
    owner: str = ""
    env: str = "unknown"
    dc_zone: str = ""
    customer_facing: bool = False
    usage: str = USAGE_IN_USE
    source: str = "estimated"  # estimated | actual

    @property
    def effective_price_yr(self) -> float:
        """Prefer the CA actual when present, else the pricing-table estimate."""
        if self.actual_price_yr is not None:
            return self.actual_price_yr
        return self.list_price_yr

    @property
    def monthly_cost(self) -> float:
        return round(self.effective_price_yr / 12.0, 2)

    def tags(self) -> Dict[str, str]:
        return {
            "ca": self.ca,
            "authority": self.cert.authority if self.cert else "",
            "validation_tier": self.validation_tier,
            "cert_shape": self.shape,
            "owner": self.owner,
            "env": self.env,
            "dc_zone": self.dc_zone,
            "customer_facing": str(self.customer_facing).lower(),
            "usage": self.usage,
            "source": self.source,
        }

    def to_dict(self) -> Dict:
        return asdict(self)
