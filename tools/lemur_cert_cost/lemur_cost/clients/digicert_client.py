"""DigiCert billing actuals client (read-only).

Fetches DigiCert's domain inventory and recent orders via the public v2 API
(``X-DC-DEVKEY`` auth) and normalizes it into BillingActual records. This is
the same endpoint surface the lemur_digicert plugin and the digicert-probe
task use.
"""
from __future__ import annotations

from typing import List

from ..models import BillingActual, CA_DIGICERT, SHAPE_WILDCARD, SHAPE_FQDN
from .http import get_json


class DigiCertClient:
    def __init__(self, api_key: str, base_url: str = "https://www.digicert.com", timeout: float = 30.0):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _headers(self) -> dict:
        return {"X-DC-DEVKEY": self.api_key, "Accept": "application/json"}

    def get_domains(self, limit: int = 1000) -> List[BillingActual]:
        """DigiCert /services/v2/domain -> domains list."""
        actuals: List[BillingActual] = []
        data = get_json(
            f"{self.base_url}/services/v2/domain",
            headers=self._headers(),
            params={"limit": limit, "offset": 0},
            timeout=self.timeout,
        )
        for d in data.get("domains", []) or []:
            name = d.get("name") or ""
            actuals.append(
                BillingActual(
                    ca=CA_DIGICERT,
                    domain=name,
                    shape=SHAPE_WILDCARD if name and name.startswith("*.") else SHAPE_FQDN,
                    validation_tier=(d.get("validation") or {}).get("type", "UNKNOWN")
                    if isinstance(d.get("validation"), dict)
                    else "UNKNOWN",
                    status=str(d.get("status") or "active"),
                    cost_per_year=None,  # resolved against pricing table / contract
                    customer_facing=any(
                        z in name for z in ("datadoghq", "datad0g", "synthetics", "agent.")
                    ),
                )
            )
        return actuals

    def get_orders(self, limit: int = 1000) -> List[BillingActual]:
        """Recent orders — used to detect issuance/renewal spend events."""
        actuals: List[BillingActual] = []
        data = get_json(
            f"{self.base_url}/services/v2/order/certificate",
            headers=self._headers(),
            params={"limit": limit, "offset": 0},
            timeout=self.timeout,
        )
        for o in data.get("orders", []) or []:
            cert = o.get("certificate") or {}
            name = cert.get("common_name") or cert.get("commonName") or ""
            if not name:
                continue
            actuals.append(
                BillingActual(
                    ca=CA_DIGICERT,
                    domain=name,
                    shape=SHAPE_WILDCARD if name.startswith("*.") else SHAPE_FQDN,
                    validation_tier="OV",
                    status=str(o.get("status") or "active"),
                    cost_per_year=None,
                    extra={"order_id": str(o.get("id") or ""), "date": o.get("date_created") or ""},
                )
            )
        return actuals
