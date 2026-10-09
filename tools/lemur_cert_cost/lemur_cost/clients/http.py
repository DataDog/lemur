"""Tiny HTTP helpers shared by the CA clients.

Thin wrapper over ``requests`` that raises a consistent error type and keeps
auth header handling per service. Read-only (GET) by design — the exporter
never mutates any CA.
"""
from __future__ import annotations

from typing import Dict, Optional

import requests


class ClientError(RuntimeError):
    """Raised when a CA/API call fails (network, auth, or non-2xx)."""


def get_json(
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, str]] = None,
    timeout: float = 30.0,
) -> Dict:
    """GET and return the parsed JSON object. Raises ClientError on failure."""
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=timeout)
    except requests.RequestException as exc:  # network / timeout
        raise ClientError(f"GET {url} failed: {exc}") from exc

    if resp.status_code >= 400:
        snippet = (resp.text or "")[:300]
        raise ClientError(f"GET {url} -> HTTP {resp.status_code}: {snippet}")
    try:
        return resp.json()
    except ValueError as exc:
        raise ClientError(f"GET {url} returned non-JSON: {resp.text[:200]}") from exc


def resolve_int(value) -> int:
    """Safely coerce a numeric id (Sectigo ids can come back as strings)."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
