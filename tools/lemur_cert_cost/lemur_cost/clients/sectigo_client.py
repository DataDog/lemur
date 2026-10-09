"""Sectigo Cert Manager billing actuals client (read-only).

Talks to the same Sectigo Cert Manager REST API surface the lemur_sectigo
plugin uses (``/dcv/v1/validation`` for domain DCV status, org domain
enumeration) without depending on the third-party ``cert-manager`` package.

Sectigo has no itemized per-cert price in DCV responses, so actuals here carry
domain/status and the *price* is resolved from the CA pricing table. The value
of this feed is (a) confirming which Sectigo domains are live/validated and
(b) reconciliation so orphaned/wasted Sectigo spend is visible.
"""
from __future__ import annotations

from typing import List, Optional

import requests

from ..models import BillingActual, CA_SECTIGO, SHAPE_WILDCARD, SHAPE_FQDN
from .http import ClientError


class SectigoClient:
    def __init__(
        self,
        base_url: str = "https://cert-manager.com/api",
        username: Optional[str] = None,
        password: Optional[str] = None,
        login_uri: Optional[str] = None,
        timeout: float = 30.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.login_uri = login_uri or f"{self.base_url}/login"
        self.timeout = timeout
        self._session = requests.Session()

    # -- auth ---------------------------------------------------------------
    def login(self) -> None:
        """Open a session. Sectigo Cert Manager sets a session cookie on login
        that subsequent API calls must carry."""
        if not (self.username and self.password):
            raise ClientError("Sectigo credentials not configured (SECTIGO_USERNAME/PASSWORD)")
        try:
            resp = self._session.post(
                self.login_uri,
                json={"username": self.username, "password": self.password},
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise ClientError(f"Sectigo login failed: {exc}") from exc
        if resp.status_code >= 400:
            raise ClientError(f"Sectigo login -> HTTP {resp.status_code}: {resp.text[:300]}")

    def _get(self, path: str, **params) -> any:
        url = f"{self.base_url}{path}"
        try:
            resp = self._session.get(url, params=params or None, timeout=self.timeout)
        except requests.RequestException as exc:
            raise ClientError(f"GET {url} failed: {exc}") from exc
        if resp.status_code >= 400:
            raise ClientError(f"GET {url} -> HTTP {resp.status_code}: {resp.text[:300]}")
        try:
            return resp.json()
        except ValueError as exc:
            raise ClientError(f"GET {url} returned non-JSON: {resp.text[:200]}") from exc

    # -- data ---------------------------------------------------------------
    def get_dcv_validation(self) -> List[BillingActual]:
        """GET /dcv/v1/validation -> live Sectigo domains + DCV status."""
        rows = self._get("/dcv/v1/validation")
        if not isinstance(rows, list):
            raise ClientError("Sectigo /dcv/v1/validation did not return a list")
        actuals: List[BillingActual] = []
        for entry in rows:
            domain = (entry.get("domain") or "").strip().lower().rstrip(".")
            if not domain:
                continue
            actuals.append(
                BillingActual(
                    ca=CA_SECTIGO,
                    domain=domain,
                    shape=SHAPE_WILDCARD if domain.startswith("*.") else SHAPE_FQDN,
                    validation_tier="DV" if str(entry.get("validationType", "dv")).lower() == "dv" else "OV",
                    status=(
                        entry.get("dcvStatus") or entry.get("status") or "active"
                    ).lower(),
                    cost_per_year=None,
                    extra={"dcv_method": str(entry.get("dcvMethod") or "")},
                )
            )
        return actuals

    def close(self) -> None:
        self._session.close()
