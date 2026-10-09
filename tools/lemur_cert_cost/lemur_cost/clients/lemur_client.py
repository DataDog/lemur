"""Lemur inventory client (read-only).

Paginates Lemur's certificates endpoint to build CA-agnostic CertRecords, and
optionally fetches authorities to derive validation tier. Mirrors the pattern
used by the lemur-acme-top-domains task.
"""
from __future__ import annotations

from typing import List, Optional

from ..models import CertRecord
from .http import ClientError, get_json


class LemurClient:
    def __init__(self, base_url: str, token: str, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}

    def _get(self, path: str, **params) -> dict:
        return get_json(
            f"{self.base_url}{path}",
            headers=self._headers(),
            params=params or None,
            timeout=self.timeout,
        )

    def get_authorities(self) -> dict:
        """Return authority id -> raw authority mapping (for tier derivation)."""
        out = {}
        page = 1
        while True:
            data = self._get("/api/1/authorities", count=200, page=page)
            items = data.get("items", []) or []
            for it in items:
                out[str(it.get("id"))] = it
            if not self._has_next(data):
                break
            page += 1
        return out

    def list_certificates(
        self, active_only: bool = True, page_size: int = 200, max_pages: int = 1000
    ) -> List[CertRecord]:
        """Paginate all certificates (optionally active only) into CertRecords."""
        records: List[CertRecord] = []
        page = 1
        while page <= max_pages:
            params: dict = {"count": page_size, "page": page}
            if active_only:
                params["filter"] = "active;true"
            try:
                data = self._get("/api/1/certificates", **params)
            except ClientError:
                # Fall back to full fetch + client-side active filter if the
                # server rejects the filter syntax.
                data = self._get("/api/1/certificates", count=page_size, page=page)
                if not data.get("items"):
                    break
                # Re-read this page's objects; caller handles active filter.
                for row in data.get("items", []):
                    records.append(_to_cert_record(row))
                if not self._has_next(data):
                    break
                page += 1
                continue

            for row in data.get("items", []) or []:
                rec = _to_cert_record(row)
                if active_only and not rec.active:
                    continue
                records.append(rec)
            if not self._has_next(data):
                break
            page += 1
        return records

    @staticmethod
    def _has_next(data: dict) -> bool:
        pagination = data.get("pagination", {}) or {}
        total = pagination.get("total")
        page = pagination.get("page") or 1
        count = len(data.get("items", []) or [])
        if total is None:
            return count >= 200
        return page * count < total


def _to_cert_record(row: dict) -> CertRecord:
    name = row.get("name") or ""
    common_name = row.get("commonName") or row.get("cn") or name
    authority = ""
    auth = row.get("authority") or {}
    if isinstance(auth, dict):
        authority = auth.get("name") or auth.get("pluginName") or ""
    elif isinstance(auth, str):
        authority = auth

    endpoint_list = row.get("endpoints") or []
    dest_list = row.get("destinations") or []
    return CertRecord(
        id=int(row.get("id") or 0),
        name=name,
        common_name=common_name,
        authority=authority,
        active=bool(row.get("active", True)),
        not_after=row.get("notAfter"),
        owner=row.get("owner") or row.get("user") or "",
        has_destination=bool(dest_list) or bool(row.get("destinationIds")),
        has_endpoint=bool(endpoint_list) or bool(row.get("endpointIds")),
        in_rotation=bool(row.get("rotation", False)),
        replaced_by=row.get("replacedBy"),
        issuer=(row.get("issuer") or ""),
    )
