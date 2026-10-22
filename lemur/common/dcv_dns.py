"""DNS-native verification of persistent DCV (_validation-persist) TXT records.

DNS-PERSIST-01 (draft-ietf-acme-dns-persist) / CA/Browser Forum method
3.2.2.4.22 validates domain control with a static TXT record at
_validation-persist.<base-domain> that names the account a CA will use to issue
certificates. This module verifies that record directly from DNS rather than
trusting the CA's reported status, so we can detect a missing, wrong, or
corrupted record at the source.

Record placement follows the CA/Browser Forum definition: a persistent record
is published at the **Base Domain Name** (the registrable domain / eTLD+1, e.g.
`_validation-persist.datad0g.com`) and, per DigiCert's DNS DCV methods, that
validation covers subdomains and wildcards of the base domain. So verification
resolves each domain's Base Domain Name (via the IANA Public Suffix List) and
queries that single label -- no label-walking is required, and a bare public
suffix is never queried.
"""

import time

import dns.exception
from lemur.common.utils import normalize_ca_name
import dns.flags
import dns.resolver
from publicsuffixlist import PublicSuffixList

_PSL = PublicSuffixList()


def _base_domain(domain):
    """Return the CA/Browser Forum Base Domain Name (registrable domain / eTLD+1)
    for a domain, or None if it is itself a bare public suffix or not an FQDN.

    e.g. "api.datad0g.com" -> "datad0g.com", "a.b.example.co.uk" -> "example.co.uk",
         "example.co.uk" -> "example.co.uk", "co.uk" -> None.
    """
    return _PSL.privatesuffix(domain.rstrip("."))


def _parse_persist_txt(txt):
    """Parse a single _validation-persist TXT value.

    Format (draft-ietf-acme-dns-persist): "issuer-domain-name; key=value; key=value"
    e.g. "digicert.com;accounturi=https://digicert.com/account/abc; policy=wildcard"
         "sectigo.com;accounturi=acct:1234@sectigo.com"
         "digicert.com;accounturi=https://...; persistUntil=253402300799"

    Returns {issuer_domain.lower(): {"account_uri": str, "persist_until": int|None,
    "policy": str|None}} where persist_until is a UNIX timestamp (base-10 seconds
    per the draft), or None if the record carries no persistUntil, and policy is
    the record's `policy` parameter (e.g. "wildcard") or None. Returns None if
    unparseable (no issuer, no accounturi, or a malformed persistUntil timestamp
    -- per the draft, a record whose persistUntil is not a valid timestamp is
    malformed).
    """
    parts = [p.strip() for p in txt.split(";")]
    if not parts or not parts[0]:
        return None
    issuer = parts[0].lower()
    params = {}
    for p in parts[1:]:
        if "=" in p:
            key, _, value = p.partition("=")
            params[key.strip().lower()] = value.strip()
    account_uri = params.get("accounturi")
    if not account_uri:
        return None
    persist_until = None
    pu = params.get("persistuntil")
    if pu is not None:
        # persistUntil is a base-10 UNIX timestamp. A non-integer value makes the
        # whole record malformed (draft: CAs must reject a malformed timestamp).
        if not pu.isdigit():
            return None
        persist_until = int(pu)
    return {
        issuer: {
            "account_uri": account_uri,
            "persist_until": persist_until,
            "policy": params.get("policy"),
        }
    }


def _resolve_persist_txt(domain):
    """Resolve _validation-persist.<domain> TXT records.

    Returns (status, values):
      status in {"ok", "missing", "dns_error"}
      values: list of TXT string values (status == "ok")
    Transient resolver failures (timeout, no nameservers) map to "dns_error" so
    callers can distinguish "definitely absent" from "couldn't tell".
    """
    resolver = dns.resolver.Resolver()
    # Request DNSSEC records (DO bit); honor the resolver's authenticated-data
    # answer where the zone is signed (draft security considerations 7.5).
    resolver.use_edns(0, dns.flags.DO)
    # Bound each query so a slow resolver can't stall the whole celery task.
    resolver.timeout = 2.0
    resolver.lifetime = 5.0
    qname = f"_validation-persist.{domain}"
    try:
        answer = resolver.resolve(qname, "TXT")
    except dns.resolver.NXDOMAIN:
        return "missing", []
    except dns.resolver.NoAnswer:
        return "missing", []
    except dns.exception.DNSException:
        return "dns_error", []
    values = []
    for rdata in answer:
        try:
            values.append(b"".join(rdata.strings).decode("utf-8", "replace"))
        except Exception:
            # A malformed TXT rdata shouldn't crash the whole verification run.
            return "dns_error", []
    return "ok", values


def verify_persist_records(domains, expected_uris):
    """Verify _validation-persist records for each domain against expected URIs.

    expected_uris: dict {issuer_domain: expected_account_uri}, e.g.
      {"digicert.com": "https://...", "sectigo.com": "acct:...@sectigo.com"}

    Returns a list of dicts, one per (domain, issuer) pair:
      {"domain", "ca", "status", "account_uri", "persist_until"}
      status in {"ok", "missing", "wrong", "expired", "unparseable", "dns_error"}
      -- expired: the record matches the expected account URI but carries a
         persistUntil that has already passed (must not be accepted per the draft).

    Each domain resolves to its CA/Browser Forum Base Domain Name and the
    _validation-persist record is queried there (results are deduplicated across
    domains sharing a base domain, so subdomain SANs don't issue redundant DNS
    lookups).
    """
    results = []
    now = int(time.time())
    base_cache = {}
    for domain in domains:
        base = _base_domain(domain)
        if not base:
            # A SAN whose registrable/base domain can't be determined (bare public
            # suffix, single label): there is no valid validation point.
            for issuer in expected_uris:
                results.append(
                    {
                        "domain": domain,
                        "ca": normalize_ca_name(issuer),
                        "status": "missing",
                        "account_uri": None,
                        "persist_until": None,
                    }
                )
            continue
        if base not in base_cache:
            base_cache[base] = _resolve_persist_txt(base)
        status, values = base_cache[base]
        if status == "dns_error":
            # One row per issuer so each CA's series gets a failing sample during
            # a DNS outage instead of going stale on a single ca:unknown row.
            for issuer in expected_uris:
                results.append(
                    {
                        "domain": domain,
                        "ca": normalize_ca_name(issuer),
                        "status": "dns_error",
                        "account_uri": None,
                        "persist_until": None,
                    }
                )
            continue
        found = {}
        unparseable = False
        if status == "ok":
            for value in values:
                try:
                    parsed = _parse_persist_txt(value)
                except Exception:
                    # A single malformed record shouldn't crash the whole run.
                    parsed = None
                if parsed is None:
                    unparseable = True
                    continue
                found.update(parsed)
        for issuer, expected in expected_uris.items():
            if unparseable:
                results.append(
                    {
                        "domain": domain,
                        "ca": normalize_ca_name(issuer),
                        "status": "unparseable",
                        "account_uri": None,
                        "persist_until": None,
                    }
                )
                continue
            entry = found.get(issuer)
            actual = entry["account_uri"] if entry else None
            persist_until = entry["persist_until"] if entry else None
            if actual is None:
                result_status = "missing"
            elif actual != expected:
                result_status = "wrong"
            elif persist_until is not None and persist_until <= now:
                # The record is correct but its persistUntil has passed; per the
                # draft an expired persistUntil must not be accepted. Report a
                # distinct status so the monitor can distinguish "expired" from
                # a healthy, active record.
                result_status = "expired"
            else:
                result_status = "ok"
            results.append(
                {
                    "domain": domain,
                    "ca": normalize_ca_name(issuer),
                    "status": result_status,
                    "account_uri": actual,
                    "persist_until": persist_until,
                }
            )
    return results
