"""CA-agnostic pricing model for Lemur certificates.

Every CA contributes its own pricing keyed by (validation_tier, shape). The
engine resolves each cert's cost purely from these tables plus a `ca` tag, so
adding a new CA (e.g. Sectigo, SSL.com) is a data change, not a code change.

Source of truth: DigiCert Domain & Certificate Billing doc, the Certificate
Provider Comparison page, and the Let's Encrypt Migration analysis. Prices are
USD/year and should be reconciled against each CA's billing feed.
"""
from __future__ import annotations

import re
from typing import Dict, Optional, Tuple

from .models import (
    CA_ACM,
    CA_DIGICERT,
    CA_GOV,
    CA_LETS_ENCRYPT,
    CA_SECTIGO,
    CA_UNKNOWN,
    SHAPE_FQDN,
    SHAPE_MULTI_SAN,
    SHAPE_WILDCARD,
)

# ---------------------------------------------------------------------------
# CA pricing tables: PRICING[ca][tier][shape] = USD/year.
# Tiers present in a CA but with ``None`` mean "not offered via Lemur" and are
# treated as not priceable (callers must skip or zero them explicitly).
# ---------------------------------------------------------------------------
PRICING: Dict[str, Dict[str, Dict[str, Optional[float]]]] = {
    CA_DIGICERT: {
        "OV": {SHAPE_WILDCARD: 688.0, SHAPE_FQDN: 338.0, SHAPE_MULTI_SAN: 338.0},
        # Contract wildcard ~688 (billing doc: list 984; contract 425-688);
        # contract FQDN ~338 (billing doc list 312). Estimates default to list;
        # actuals reconciling against contract rates should be passed in.
        "DV": {SHAPE_WILDCARD: 218.0, SHAPE_FQDN: 218.0, SHAPE_MULTI_SAN: 218.0},
        "EV": {SHAPE_WILDCARD: 438.0, SHAPE_FQDN: 438.0, SHAPE_MULTI_SAN: 438.0},
    },
    CA_SECTIGO: {
        "OV": {SHAPE_WILDCARD: 400.0, SHAPE_FQDN: 135.0, SHAPE_MULTI_SAN: 135.0},
        "DV": {SHAPE_WILDCARD: 40.0, SHAPE_FQDN: 40.0, SHAPE_MULTI_SAN: 40.0},
        "EV": {SHAPE_WILDCARD: 250.0, SHAPE_FQDN: 250.0, SHAPE_MULTI_SAN: 250.0},
    },
    CA_LETS_ENCRYPT: {
        "DV": {SHAPE_WILDCARD: 0.0, SHAPE_FQDN: 0.0, SHAPE_MULTI_SAN: 0.0},
    },
    CA_ACM: {
        # Public ACM certs are free (no key export / AWS-managed services only).
        # Private CA (PCA): ~9/cert/yr + $400/CA/mo overhead.
        "DV": {SHAPE_WILDCARD: 0.0, SHAPE_FQDN: 0.0, SHAPE_MULTI_SAN: 0.0},
        "OV": {SHAPE_WILDCARD: 0.0, SHAPE_FQDN: 0.0, SHAPE_MULTI_SAN: 0.0},
    },
    CA_GOV: {
        # GovCloud uses a separate commercial Lemur; prices mirror commercial.
        "OV": {SHAPE_WILDCARD: 688.0, SHAPE_FQDN: 338.0, SHAPE_MULTI_SAN: 338.0},
        "DV": {SHAPE_WILDCARD: 218.0, SHAPE_FQDN: 218.0, SHAPE_MULTI_SAN: 218.0},
        "EV": {SHAPE_WILDCARD: 438.0, SHAPE_FQDN: 438.0, SHAPE_MULTI_SAN: 438.0},
    },
}

# Authority-name -> CA normalization. New CAs just add a row here.
AUTHORITY_CA_MAP: Dict[str, str] = {
    "digicert": CA_DIGICERT,
    "digi": CA_DIGICERT,
    "letsencrypt": CA_LETS_ENCRYPT,
    "lets encrypt": CA_LETS_ENCRYPT,
    "isrg": CA_LETS_ENCRYPT,
    "acme": CA_LETS_ENCRYPT,
    "sectigo": CA_SECTIGO,
    "comodo": CA_SECTIGO,
    "acm": CA_ACM,
    "aws": CA_ACM,
    "gov": CA_GOV,
    "fed": CA_GOV,
}

# Internal zones that mark a cert as not customer-facing.
_INTERNAL_SUFFIXES = (".prod.dog", ".staging.dog", ".ddbuild.io", ".fed.dog", ".dog")

# Customer-facing public zones.
_CUSTOMER_ZONES = (
    "datadoghq.com",
    "datadoghq.eu",
    "datad0g.com",
    "datad0g.eu",
    "ddog-gov.com",
    "dd0g-gov.com",
    "datadog.com",
    "datadog.jp",
    "browser-intake",
    "session-replay",
    "synthetics",
    "static.datadoghq",
    "statuspage",
    "agent.datadoghq",
    "logs.datadoghq",
    "profile.datadoghq",
    "dashcon.io",
    "seekret.io",
    "vector.dev",
    "vrl.dev",
)

_STAGING_MARKERS = ("staging", "test.", "prtest")
_GOV_MARKERS = ("fed.dog", "ddog-gov.com", "dd0g-gov.com", "gov.dog")

# A wildcard/fqdn cost cover can be free for subdomains of a billed wildcard.
# Used only for DigiCert actuals reconciliation (order/domain dedup), not the
# Lemur inventory estimate (each active Lemur cert is its own license).


def resolve_ca(authority: str) -> str:
    """Map a Lemur authority name (e.g. 'DigiCertCommercial') to a CA tag."""
    if not authority:
        return CA_UNKNOWN
    lower = authority.lower()
    for key, ca in AUTHORITY_CA_MAP.items():
        if key in lower:
            return ca
    return CA_UNKNOWN


def classify_shape(common_name: str) -> str:
    """wildcard / fqdn / multi_san from a certificate CN."""
    cn = (common_name or "").strip().lower()
    if cn.startswith("*."):
        return SHAPE_WILDCARD
    if "," in cn or " " in cn:  # SAN-laden CN
        return SHAPE_MULTI_SAN
    return SHAPE_FQDN


def derive_env(common_name: str) -> str:
    """coarse env classification from a CN."""
    lower = (common_name or "").lower()
    if any(g in lower for g in _GOV_MARKERS):
        return "gov"
    if "staging" in lower:
        return "staging"
    if "prtest" in lower:
        return "prtest"
    if any(s in lower for s in _INTERNAL_SUFFIXES) or lower.endswith(".prod.dog"):
        return "prod"
    return "prod"


def derive_zone(common_name: str) -> str:
    """Best-effort datacenter zone from a CN.

    Internal certs follow the shape `*.[zone].[env].[tld]` (e.g.
    `*.us1.prod.dog` -> `us1`, `vault.edge-eu1.prod.dog` -> `edge-eu1`). We
    return the label two before the public suffix so multi-label zones (e.g.
    `edge-eu1`, `static-app.us1`) resolve to the meaningful DC granularity.
    """
    labels = (common_name or "").strip().lower().split(".")
    if labels and labels[0].startswith("*"):
        labels = labels[1:]
    if len(labels) < 3:
        return ""
    # labels[-1] should be a public-ish suffix; labels[-2] an env token.
    if labels[-1] not in ("dog", "io", "com", "net", "eu", "jp"):
        return ""
    return labels[-3]


def is_customer_facing(common_name: str) -> bool:
    lower = (common_name or "").lower()
    # Explicit internal zones are never customer-facing.
    if any(s in lower for s in _INTERNAL_SUFFIXES):
        return False
    return any(z.replace(".datadoghq", ".datadoghq") in lower or z in lower for z in _CUSTOMER_ZONES)


def resolve_price(ca: str, tier: str, shape: str) -> Tuple[bool, Optional[float]]:
    """Return (offered, price_yr). offered=False means the CA doesn't offer
    this tier/shape combination, so it is not priceable."""
    tier_map = PRICING.get(ca, {})
    shape_map = tier_map.get(tier)
    if shape_map is None:
        return False, None
    # If a CA lacks an explicit multi_san price, fall back to FQDN.
    price = shape_map.get(shape)
    if price is None and shape == SHAPE_MULTI_SAN:
        price = shape_map.get(SHAPE_FQDN)
    if price is None:
        return False, None
    return True, price


def default_pricing() -> Dict[str, Dict[str, Dict[str, Optional[float]]]]:
    """Deep copy of the default pricing table (safe to mutate per-run)."""
    import copy

    return copy.deepcopy(PRICING)
