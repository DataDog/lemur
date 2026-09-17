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
    """Yield `<domain>` then its parent labels, closest-first, down to the
    registrable domain (public suffix + one label).

    A persistent record is published once per DNS zone (e.g. at
    `_validation-persist.datad0g.com`), while a certificate's SAN set can include
    subdomains (`api.datad0g.com`). To avoid flagging a subdomain SAN as
    "missing" when its zone's record exists, resolve the closest candidate that
    has a record, then fall back up the labels. Never query a bare public suffix:
    a single-label TLD (".com") is excluded by the label guard, and a
    multi-label registry suffix ("co.uk") by the
    _MULTI_LABEL_PUBLIC_SUFFIXES set, so a walk always stops at the registrable
    domain, which is inside our own DNS zones.
    e.g. "api.datad0g.com" -> ["api.datad0g.com", "datad0g.com"],
         "api.example.co.uk" -> ["api.example.co.uk", "example.co.uk"].
    """
    labels = domain.rstrip(".").split(".")
    while labels:
        candidate = ".".join(labels)
        # A single label is a bare TLD; a known multi-label registry suffix is a
        # bare public suffix. Both are outside our zones - stop the walk before
        # querying them (the registrable domain was already yielded).
        if len(labels) == 1 or candidate in _MULTI_LABEL_PUBLIC_SUFFIXES:
            break
        yield candidate
        labels = labels[1:]


# Multi-label public suffixes that must never be queried directly. The original
# 2-label guard already stops a walk at a bare single-label TLD (e.g. ".com");
# this set closes the gap for registry-suffix TLDs such as "co.uk", where
# "example.co.uk" is the registrable domain but "co.uk" alone is a bare public
# suffix outside our DNS zones. Kept intentionally small and auditable (not the
# full Public Suffix List); it covers the realistic cases a Domain Control
# Validation name might hit.
_MULTI_LABEL_PUBLIC_SUFFIXES = frozenset(
    {
        # UK
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "nhs.uk",
        "plc.uk", "sch.uk",
        # AU
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
        # JP
        "co.jp", "or.jp", "ne.jp", "ac.jp", "ad.jp",
        # NZ
        "co.nz", "net.nz", "org.nz", "govt.nz", "school.nz", "geek.nz",
        # IN
        "co.in", "net.in", "org.in", "gen.in", "firm.in",
        # BR / CN / KR / MX / SG / HK / MY / ZA / TR / TW / TH / AR / CL / CO
        "com.br", "net.br", "org.br",
        "com.cn", "net.cn", "org.cn",
        "co.kr", "or.kr", "net.kr", "go.kr", "ac.kr", "re.kr",
        "com.mx", "com.sg", "com.hk", "com.my",
        "co.za", "org.za", "net.za", "web.za",
        "com.tr", "net.tr", "org.tr",
        "com.tw", "org.tw", "idv.tw", "gov.tw",
        "co.th", "in.th", "ac.th", "go.th",
        "com.ar", "com.cl", "com.co",
    }
)


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
