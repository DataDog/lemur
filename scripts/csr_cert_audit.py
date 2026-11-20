#!/usr/bin/env python3
"""
csr_cert_audit.py — Find DigiCert-issued certs not managed by Lemur.

Queries:
  1. DigiCert CertCentral API  — all issued orders
  2. Lemur API (via ddcert/Lemur REST) — all certificate external_ids

Subtracts Lemur-known external_ids from DigiCert's issued set.
Result = CSR-originated certs that Lemur doesn't manage (expiry blind spots).

Usage:
    python3 scripts/csr_cert_audit.py [--expiring-within 90]

Requires env vars:
    DIGICERT_API_KEY   DigiCert CertCentral API key
    LEMUR_API_KEY      Lemur API token

In a workspace these are available via workspace_secret.
Locally: set them in your shell before running.
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone, timedelta

import requests


DIGICERT_URL = "https://www.digicert.com"
LEMUR_URL = "https://lemur-commercial.us1.ddbuild.io"


# ---------------------------------------------------------------------------
# Secret resolution
# ---------------------------------------------------------------------------

def _secret(name):
    """Resolve a secret from env or workspace_secret (when running in a workspace)."""
    val = os.environ.get(name)
    if val:
        return val
    # workspace_secret is available when running inside a Datadog workspace (SSH)
    result = subprocess.run(
        ["workspace_secret", name], capture_output=True, text=True
    )
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip()
    sys.exit(
        f"ERROR: {name} not found.\n"
        f"  - Run inside a workspace (ssh workspace-<name>), or\n"
        f"  - Set {name} in your environment: export {name}=<value>\n"
        f"  - DigiCert key: op item get 'Lemur DigiCert' --vault Datadog --fields credential\n"
        f"  - Lemur key: ddcert whoami then ddcert users create-api-key"
    )


# ---------------------------------------------------------------------------
# DigiCert: fetch all issued certificate order IDs + metadata
# ---------------------------------------------------------------------------

def digicert_issued_certs(api_key):
    """Return dict of {str(cert_id): {cn, dns_names, valid_till, order_id}} for all issued orders."""
    session = requests.Session()
    session.headers.update({
        "X-DC-DEVKEY": api_key,
        "Content-Type": "application/json",
    })

    certs = {}
    offset = 0
    limit = 1000

    print("Fetching DigiCert issued orders...", file=sys.stderr)
    while True:
        resp = session.get(
            f"{DIGICERT_URL}/services/v2/order/certificate"
            f"?filters[status]=issued&limit={limit}&offset={offset}"
        )
        resp.raise_for_status()
        data = resp.json()
        orders = data.get("orders", [])
        if not orders:
            break

        for order in orders:
            cert = order.get("certificate", {})
            cert_id = str(cert.get("id", ""))
            if not cert_id:
                continue
            certs[cert_id] = {
                "cert_id":    cert_id,
                "order_id":   str(order.get("id", "")),
                "cn":         cert.get("common_name", ""),
                "dns_names":  cert.get("dns_names", []),
                "valid_till": cert.get("valid_till", ""),
                "issued":     order.get("date_created", ""),
            }

        if len(orders) < limit:
            break
        offset += limit
        print(f"  fetched {offset} orders so far...", file=sys.stderr)

    print(f"DigiCert: {len(certs)} issued certs total", file=sys.stderr)
    return certs


# ---------------------------------------------------------------------------
# Lemur: fetch all external_ids
# ---------------------------------------------------------------------------

def lemur_external_ids(api_key):
    """Return set of external_ids Lemur knows about."""
    session = requests.Session()
    session.headers.update({
        "Authorization": f"token {api_key}",
        "Content-Type": "application/json",
    })

    ids = set()
    page = 1
    page_size = 1000

    print("Fetching Lemur certificate external_ids...", file=sys.stderr)
    while True:
        resp = session.get(
            f"{LEMUR_URL}/api/1/certificates",
            params={"page": page, "count": page_size, "fields": "id,external_id,name"},
        )
        resp.raise_for_status()
        data = resp.json()
        items = data.get("items", [])
        if not items:
            break

        for cert in items:
            ext_id = cert.get("external_id")
            if ext_id:
                ids.add(str(ext_id))

        total = data.get("total", 0)
        if page * page_size >= total:
            break
        page += 1
        print(f"  fetched {min(page * page_size, total)}/{total} certs...", file=sys.stderr)

    print(f"Lemur: {len(ids)} certs with external_ids", file=sys.stderr)
    return ids


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--expiring-within",
        type=int,
        default=0,
        metavar="DAYS",
        help="Only show certs expiring within N days (0 = show all)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON instead of table",
    )
    args = parser.parse_args()

    digicert_key = _secret("DIGICERT_API_KEY")
    lemur_key = _secret("LEMUR_API_KEY")

    dc_certs = digicert_issued_certs(digicert_key)
    lemur_ids = lemur_external_ids(lemur_key)

    # Subtraction: DigiCert issued - Lemur known = CSR-originated
    csr_certs = {
        cid: meta
        for cid, meta in dc_certs.items()
        if cid not in lemur_ids
    }

    print(f"\nSubtraction: {len(dc_certs)} DigiCert - {len(lemur_ids)} Lemur known = {len(csr_certs)} CSR-originated\n", file=sys.stderr)

    # Optionally filter by expiry
    now = datetime.now(timezone.utc)
    results = []
    for meta in sorted(csr_certs.values(), key=lambda x: x.get("valid_till", "")):
        if args.expiring_within and meta.get("valid_till"):
            try:
                exp = datetime.fromisoformat(meta["valid_till"].replace("Z", "+00:00"))
                if (exp - now).days > args.expiring_within:
                    continue
            except ValueError:
                pass
        results.append(meta)

    if args.json:
        print(json.dumps(results, indent=2))
        return

    if not results:
        print("No CSR-originated certs found" + (f" expiring within {args.expiring_within} days" if args.expiring_within else "") + ".")
        return

    # Table output
    header = f"{'CN':<45} {'EXPIRES':<12} {'DAYS LEFT':>9}  {'CERT ID':>10}  {'ORDER ID':>10}"
    print(header)
    print("-" * len(header))
    for m in results:
        exp_str = ""
        days_str = ""
        if m.get("valid_till"):
            try:
                exp = datetime.fromisoformat(m["valid_till"].replace("Z", "+00:00"))
                exp_str = exp.strftime("%Y-%m-%d")
                days_left = (exp - now).days
                days_str = str(days_left)
                if days_left <= 14:
                    days_str = f"🔴 {days_str}"
                elif days_left <= 30:
                    days_str = f"⚠️  {days_str}"
            except ValueError:
                pass
        print(f"{m['cn']:<45} {exp_str:<12} {days_str:>9}  {m['cert_id']:>10}  {m['order_id']:>10}")


if __name__ == "__main__":
    main()
