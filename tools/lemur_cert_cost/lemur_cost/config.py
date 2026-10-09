"""Environment-driven configuration for the exporter.

Everything is opt-in via env vars so the tool runs read-only by default and
only talks to Datadog / CAs when keys are present.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class Config:
    # Lemur inventory (required for estimates).
    lemur_url: Optional[str] = None
    lemur_token: Optional[str] = None
    lemur_active_only: bool = True

    # DigiCert actuals.
    digicert_api_key: Optional[str] = None
    digicert_base_url: str = "https://www.digicert.com"

    # Sectigo actuals.
    sectigo_enabled: bool = False
    sectigo_base_url: str = "https://cert-manager.com/api"
    sectigo_username: Optional[str] = None
    sectigo_password: Optional[str] = None

    # Emission.
    mode: str = "print"  # print | datadog | statsd
    dd_api_key: Optional[str] = None
    dd_app_key: Optional[str] = None
    dd_site: str = "us5.datadoghq.com"
    statsd_host: str = "127.0.0.1"
    statsd_port: int = 8125

    # Pricing override (JSON path) — optional.
    pricing_file: Optional[str] = None

    @classmethod
    def from_env(cls, env: Optional[Dict[str, str]] = None) -> "Config":
        e = env if env is not None else os.environ
        return cls(
            lemur_url=e.get("LEMUR_URL") or e.get("LEMUR_BASE_URL"),
            lemur_token=e.get("LEMUR_TOKEN") or e.get("LEMUR_API_KEY"),
            lemur_active_only=(e.get("LEMUR_ACTIVE_ONLY", "true").lower() != "false"),
            digicert_api_key=e.get("DIGICERT_API_KEY"),
            digicert_base_url=e.get("DIGICERT_BASE_URL", "https://www.digicert.com"),
            sectigo_enabled=e.get("SECTIGO_ENABLED", "false").lower() in ("1", "true", "yes"),
            sectigo_base_url=e.get("SECTIGO_BASE_URL", "https://cert-manager.com/api"),
            sectigo_username=e.get("SECTIGO_USERNAME"),
            sectigo_password=e.get("SECTIGO_PASSWORD"),
            mode=e.get("LEMUR_COST_MODE", "print"),
            dd_api_key=e.get("DD_API_KEY"),
            dd_app_key=e.get("DD_APP_KEY"),
            dd_site=e.get("DD_SITE", "us5.datadoghq.com"),
            statsd_host=e.get("STATSD_HOST", "127.0.0.1"),
            statsd_port=int(e.get("STATSD_PORT", "8125")),
            pricing_file=e.get("LEMUR_COST_PRICING_FILE"),
        )

    def load_pricing(self) -> Optional[dict]:
        if not self.pricing_file:
            return None
        import json

        with open(self.pricing_file, "r") as fh:
            return json.load(fh)
