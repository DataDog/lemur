"""DNS-native verification of persistent DCV (_validation-persist) TXT records.

DNS-PERSIST-01 (draft-ietf-acme-dns-persist) validates domain control with a
static TXT record at _validation-persist.<domain> that names the ACME account a
CA will use to issue certificates. This module verifies that record directly from
DNS rather than trusting the CA's reported status, so we can detect a missing,
wrong, or corrupted record at the source.

A persistent record is published once per DNS zone (via the terraform modules),
so verification resolves the exact label first and falls back up to the zone
apex to cover subdomain SANs; it never queries a bare public suffix.
"""

import dns.exception
import dns.flags
import dns.resolver


def _parse_persist_txt(txt):
    """Parse a single _validation-persist TXT value into {issuer: account_uri}.

    Format (draft-ietf-acme-dns-persist): "issuer-domain-name; key=value; key=value"
    e.g. "digicert.com;accounturi=https://digicert.com/account/abc"
         "sectigo.com;accounturi=acct:1234@sectigo.com"
    Returns {issuer_domain.lower(): account_uri} or None if unparseable (no issuer
    or no accounturi).
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
    return {issuer: account_uri}


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


def _domain_candidates(domain):
    """Yield `<domain>` then its parent labels, closest-first, down to a
    2-label registrable-looking apex.

    A persistent record is published once per DNS zone (e.g. at
    `_validation-persist.datad0g.com`), while a certificate's SAN set can include
    subdomains (`api.datad0g.com`). To avoid flagging a subdomain SAN as
    "missing" when its zone's record exists, resolve the closest candidate that
    has a record, then fall back up the labels. Never query a bare public suffix
    (one label), which is outside our DNS zones and could belong to an unrelated
    party. e.g. "api.datad0g.com" -> ["api.datad0g.com", "datad0g.com"].
    """
    labels = domain.rstrip(".").split(".")
    while len(labels) >= 2:
        yield ".".join(labels)
        labels = labels[1:]


def _resolve_persist_walk(domain):
    """Resolve `_validation-persist.<candidate>` from the closest label down to
    the apex; return the first that exists.

    Returns (status, values):
      - ("ok", values) for the closest candidate that exists
      - ("missing", []) if no candidate exists anywhere on the path
      - ("dns_error", []) if no candidate exists but at least one was unresolved
        (we could not confirm its absence, so callers should not treat it as
        definitively missing).
    """
    saw_error = False
    for candidate in _domain_candidates(domain):
        status, values = _resolve_persist_txt(candidate)
        if status == "ok":
            return status, values
        if status == "dns_error":
            saw_error = True
    return ("dns_error" if saw_error else "missing"), []


def verify_persist_records(domains, expected_uris):
    """Verify _validation-persist records for each domain against expected URIs.

    expected_uris: dict {issuer_domain: expected_account_uri}, e.g.
      {"digicert.com": "https://...", "sectigo.com": "acct:...@sectigo.com"}

    Returns a list of dicts, one per (domain, issuer) pair:
      {"domain", "ca", "status", "account_uri"}
      status in {"ok", "missing", "wrong", "unparseable", "dns_error"}
    """
    results = []
    for domain in domains:
        # Resolve at the exact label first, then fall back to ancestor (zone)
        # labels, so a subdomain SAN covered by the zone's persistent record is
        # not falsely flagged missing.
        status, values = _resolve_persist_walk(domain)
        if status == "dns_error":
            results.append(
                {
                    "domain": domain,
                    "ca": "unknown",
                    "status": "dns_error",
                    "account_uri": None,
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
        if unparseable:
            results.append(
                {
                    "domain": domain,
                    "ca": "unknown",
                    "status": "unparseable",
                    "account_uri": None,
                }
            )
        for issuer, expected in expected_uris.items():
            actual = found.get(issuer)
            if actual is None:
                result_status = "missing"
            elif actual != expected:
                result_status = "wrong"
            else:
                result_status = "ok"
            results.append(
                {
                    "domain": domain,
                    "ca": issuer,
                    "status": result_status,
                    "account_uri": actual,
                }
            )
    return results
