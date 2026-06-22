from datetime import datetime, timedelta, timezone
from typing import Optional

import requests
from flask import current_app

from lemur.plugins.lemur_digicert_dcv.provider import (
    DCVAPIError,
    DCVDomainNotRegistered,
    DCVProvider,
    DNSRecord,
    ValidationStatus,
)


class DigiCertDCVProvider(DCVProvider):
    def __init__(self):
        self._base_url = current_app.config.get("DIGICERT_URL")
        self._session = requests.Session()
        self._session.headers.update(
            {
                "X-DC-DEVKEY": current_app.config["DIGICERT_API_KEY"],
                "Content-Type": "application/json",
            }
        )

    # -- HTTP helpers --------------------------------------------------------

    def _get(self, path: str, **params) -> dict:
        url = f"{self._base_url}{path}"
        resp = self._session.get(url, params=params or None)
        if resp.status_code >= 400:
            raise DCVAPIError(
                domain="",
                ca="digicert",
                reason=f"GET {path} returned {resp.status_code}: {resp.text}",
            )
        return resp.json()

    def _post(self, path: str, body: dict) -> dict:
        url = f"{self._base_url}{path}"
        resp = self._session.post(url, json=body)
        if resp.status_code >= 400:
            raise DCVAPIError(
                domain="",
                ca="digicert",
                reason=f"POST {path} returned {resp.status_code}: {resp.text}",
            )
        return resp.json()

    # -- Domain lookup -------------------------------------------------------

    def _find_domain_record(self, domain: str) -> Optional[dict]:
        """Return CertCentral domain record dict or None if not registered."""
        data = self._get("/services/v2/domain", name=domain, include_dcv="true")
        for record in data.get("domains", []):
            if record.get("name") == domain:
                return record
        return None

    # -- DCVProvider implementation ------------------------------------------

    def check_validation(self, domain: str, window_days: Optional[int] = None) -> ValidationStatus:
        if window_days is None:
            window_days = current_app.config.get("DIGICERT_DCV_RENEWAL_WINDOW_DAYS", 60)

        try:
            record = self._find_domain_record(domain)
        except DCVAPIError as exc:
            if not exc.domain:
                raise DCVAPIError(domain=domain, ca=exc.ca, reason=exc.reason) from exc
            raise

        if not record:
            return ValidationStatus(status="MISSING")

        expiry_str = record.get("dcv_expiration_date")
        if not expiry_str:
            return ValidationStatus(status="MISSING")

        try:
            expiry = datetime.strptime(expiry_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            raise DCVAPIError(
                domain=domain,
                ca="digicert",
                reason=f"Unexpected dcv_expiration_date format: {expiry_str!r}",
            )

        now = datetime.now(tz=timezone.utc)

        if expiry < now:
            return ValidationStatus(status="MISSING", expiry=expiry)
        if expiry < now + timedelta(days=window_days):
            return ValidationStatus(status="EXPIRING_SOON", expiry=expiry)
        return ValidationStatus(status="VALID", expiry=expiry)

    def initiate_validation(self, domain: str) -> DNSRecord:
        record = self._find_domain_record(domain)
        if not record:
            raise DCVDomainNotRegistered(domain)
        domain_id = record["id"]
        data = self._post(f"/services/v2/domain/{domain_id}/dcv/token", {})
        token = data.get("token") or (data.get("dcv_token") or {}).get("token")
        if not token:
            raise DCVAPIError(
                domain=domain,
                ca="digicert",
                reason=f"No token in /dcv/token response: {data}",
            )
        return DNSRecord(name=f"_dv.{domain}", value=f"{token}.dcv.digicert.com")

    def confirm_validation(self, domain: str) -> bool:
        raise NotImplementedError("Implemented in Task 4")

    def register_domain(self, domain: str) -> None:
        raise NotImplementedError("Implemented in Task 5")

    def list_all_domain_names(self) -> list:
        """Page through all domains in CertCentral. Used by the Celery sweep."""
        names = []
        offset = 0
        limit = 100
        while True:
            data = self._get("/services/v2/domain", offset=offset, limit=limit)
            batch = data.get("domains", [])
            names.extend(d["name"] for d in batch)
            if len(batch) < limit:
                break
            offset += limit
        return names
