"""Bundled sample inventory so the exporter runs without any credentials.

Covers DigiCert, Sectigo, and Let's Encrypt certs across prod/staging, wildcard
and FQDN, customer-facing and internal, plus orphaned certs — enough to show
the CA-agnostic breakdown in `--sample` mode.
"""
from __future__ import annotations

from .models import CertRecord


def certs():
    rows = [
        CertRecord(
            id=1, name="us1-prod-wc", common_name="*.us1.prod.dog",
            authority="DigiCertCommercial", active=True, owner="team-networkedge",
            not_after="2027-04-02", has_destination=True, has_endpoint=True,
        ),
        CertRecord(
            id=2, name="static-eu1", common_name="*.static-app.eu1.prod.dog",
            authority="DigiCertCommercial", active=True, owner="team-networkedge",
            not_after="2027-03-10", has_destination=True, has_endpoint=True,
        ),
        CertRecord(
            id=3, name="vault-us1-staging", common_name="vault.us1.staging.dog",
            authority="DigiCertCommercial", active=True, owner="team-vault",
            not_after="2027-02-15", has_destination=True, has_endpoint=False,
        ),
        CertRecord(
            id=4, name="wildcard-datadoghq", common_name="*.datadoghq.com",
            authority="DigiCertCommercial", active=True, owner="team-edge",
            not_after="2027-05-01", has_destination=True, has_endpoint=True,
        ),
        # Sectigo — already live via cert-manager / lemur plugin.
        CertRecord(
            id=5, name="sectigo-ov-wc", common_name="*.api.us1.fed.dog",
            authority="SectigoProduction", active=True, owner="team-runtime",
            not_after="2027-06-20", has_destination=True, has_endpoint=True,
        ),
        CertRecord(
            id=6, name="sectigo-dv-fqdn", common_name="api.sandbox.datad0g.com",
            authority="SectigoProduction", active=True, owner="team-runtime",
            not_after="2027-01-05", has_destination=False, has_endpoint=True,
        ),
        # Let's Encrypt (free).
        CertRecord(
            id=7, name="le-us3", common_name="*.us3.prod.dog",
            authority="LetsEncryptProduction", active=True, owner="team-networkedge",
            not_after="2026-12-01", has_destination=True, has_endpoint=True,
        ),
        # Orphaned — no destinations, no endpoints (CLOUDR-1957-style waste).
        CertRecord(
            id=8, name="orphan-edge-us2", common_name="*.edge-us2.prod.dog",
            authority="DigiCertCommercial", active=True, owner="team-edge",
            not_after="2027-04-30", has_destination=False, has_endpoint=False,
            in_rotation=False,
        ),
        CertRecord(
            id=9, name="orphan-sectigo", common_name="obsolete.corp.datad0g.com",
            authority="SectigoProduction", active=True, owner="team-old",
            not_after="2026-11-11", has_destination=False, has_endpoint=False,
        ),
        # GovCloud-style.
        CertRecord(
            id=10, name="gov-us1", common_name="*.us1.fed.dog",
            authority="DigiCertGov", active=True, owner="team-gov",
            not_after="2027-03-22", has_destination=True, has_endpoint=True,
        ),
        # Let's Encrypt orphan (zero cost — shows $0 in orphaned).
        CertRecord(
            id=11, name="le-orphan", common_name="*.prtest09.staging.dog",
            authority="LetsEncryptProduction", active=True, owner="team-networkedge",
            not_after="2026-12-15", has_destination=False, has_endpoint=False,
        ),
    ]
    return rows
