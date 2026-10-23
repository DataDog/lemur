"""Tests for DNS-native _validation-persist DCV verification (draft-ietf-acme-dns-persist)."""

from unittest.mock import patch

from lemur.common.dcv_dns import (
    _base_domain,
    _parse_persist_txt,
    _resolve_persist_txt,
    verify_persist_records,
)


# --- _base_domain (CA/Browser Forum Base Domain Name / eTLD+1 via IANA PSL) ---

def test_base_domain_computes_cabf_base_domain_name():
    assert _base_domain("api.datad0g.com") == "datad0g.com"
    assert _base_domain("a.b.datad0g.com") == "datad0g.com"
    assert _base_domain("datad0g.com.") == "datad0g.com"


def test_base_domain_handles_multi_label_public_suffixes():
    # a.b.example.co.uk -> example.co.uk (not co.uk). Never a bare public suffix.
    assert _base_domain("a.b.example.co.uk") == "example.co.uk"
    assert _base_domain("example.co.uk") == "example.co.uk"


def test_base_domain_returns_none_for_bare_public_suffix():
    assert _base_domain("co.uk") is None
    assert _base_domain("com") is None


# --- _parse_persist_txt ---

def test_parse_persist_txt_digicert():
    assert _parse_persist_txt(
        "digicert.com;accounturi=https://digicert.com/account/abc"
    ) == {
        "digicert.com": {
            "account_uri": "https://digicert.com/account/abc",
            "persist_until": None,
            "policy": None,
        }
    }


def test_parse_persist_txt_sectigo():
    assert _parse_persist_txt("sectigo.com;accounturi=acct:1234@sectigo.com") == {
        "sectigo.com": {
            "account_uri": "acct:1234@sectigo.com",
            "persist_until": None,
            "policy": None,
        }
    }


def test_parse_persist_txt_with_persist_until():
    parsed = _parse_persist_txt(
        "digicert.com;accounturi=https://digicert.com/account/abc; persistUntil=253402300799"
    )
    assert parsed == {
        "digicert.com": {
            "account_uri": "https://digicert.com/account/abc",
            "persist_until": 253402300799,
            "policy": None,
        }
    }


def test_parse_persist_txt_with_policy():
    parsed = _parse_persist_txt(
        "digicert.com;accounturi=https://digicert.com/account/abc; policy=wildcard"
    )
    assert parsed == {
        "digicert.com": {
            "account_uri": "https://digicert.com/account/abc",
            "persist_until": None,
            "policy": "wildcard",
        }
    }


def test_parse_persist_txt_malformed_persist_until_is_unparseable():
    # Per the draft a malformed persistUntil timestamp makes the record malformed.
    assert (
        _parse_persist_txt(
            "digicert.com;accounturi=https://digicert.com/account/abc; persistUntil=not-a-ts"
        )
        is None
    )


def test_parse_persist_txt_unparseable():
    assert _parse_persist_txt("") is None
    assert _parse_persist_txt("digicert.com;nouri=1") is None
    assert _parse_persist_txt(";accounturi=x") is None


# --- _resolve_persist_txt ---

def test_resolve_persist_txt_missing_on_nxdomain():
    with patch("lemur.common.dcv_dns.dns.resolver.Resolver") as mock_resolver_cls:
        mock_resolver = mock_resolver_cls.return_value
        mock_resolver.resolve.side_effect = __import__("dns").resolver.NXDOMAIN()
        status, values = _resolve_persist_txt("example.com")
    assert status == "missing"
    assert values == []


def test_resolve_persist_txt_dns_error_on_timeout():
    with patch("lemur.common.dcv_dns.dns.resolver.Resolver") as mock_resolver_cls:
        mock_resolver = mock_resolver_cls.return_value
        mock_resolver.resolve.side_effect = __import__("dns").resolver.LifetimeTimeout()
        status, values = _resolve_persist_txt("example.com")
    assert status == "dns_error"
    assert values == []


def test_resolve_persist_txt_joins_multiple_txt_strings():
    class FakeRdata:
        strings = (b"digicert.com;accounturi=https://digicert.com/account/abc",)

    class FakeAnswer:
        def __iter__(self):
            return iter([FakeRdata()])

    with patch("lemur.common.dcv_dns.dns.resolver.Resolver") as mock_resolver_cls:
        mock_resolver = mock_resolver_cls.return_value
        mock_resolver.resolve.return_value = FakeAnswer()
        status, values = _resolve_persist_txt("example.com")
    assert status == "ok"
    assert values == ["digicert.com;accounturi=https://digicert.com/account/abc"]


# --- verify_persist_records ---

def test_verify_persist_records_ok():
    expected = {
        "digicert.com": "https://digicert.com/account/abc",
        "sectigo.com": "acct:1@sectigo.com",
    }
    with patch(
        "lemur.common.dcv_dns._resolve_persist_txt",
        return_value=(
            "ok",
            [
                "digicert.com;accounturi=https://digicert.com/account/abc",
                "sectigo.com;accounturi=acct:1@sectigo.com",
            ],
        ),
    ):
        results = verify_persist_records(["example.com"], expected)
    assert {r["status"] for r in results} == {"ok"}
    assert {r["ca"] for r in results} == {"digicert.com", "sectigo.com"}


def test_verify_persist_records_wrong():
    expected = {"digicert.com": "https://digicert.com/account/abc"}
    with patch(
        "lemur.common.dcv_dns._resolve_persist_txt",
        return_value=(
            "ok",
            ["digicert.com;accounturi=https://digicert.com/account/DIFFERENT"],
        ),
    ):
        results = verify_persist_records(["example.com"], expected)
    assert results[0]["status"] == "wrong"
    assert results[0]["account_uri"] == "https://digicert.com/account/DIFFERENT"


def test_verify_persist_records_missing():
    expected = {"digicert.com": "https://digicert.com/account/abc"}
    with patch(
        "lemur.common.dcv_dns._resolve_persist_txt", return_value=("missing", [])
    ):
        results = verify_persist_records(["example.com"], expected)
    assert results[0]["status"] == "missing"


def test_verify_persist_records_dns_error():
    expected = {"digicert.com": "https://digicert.com/account/abc"}
    with patch(
        "lemur.common.dcv_dns._resolve_persist_txt", return_value=("dns_error", [])
    ):
        results = verify_persist_records(["example.com"], expected)
    assert results[0]["status"] == "dns_error"


def test_verify_persist_records_unparseable_surfaced():
    expected = {"digicert.com": "https://digicert.com/account/abc"}
    with patch(
        "lemur.common.dcv_dns._resolve_persist_txt",
        return_value=("ok", ["not-a-valid-record"]),
    ):
        results = verify_persist_records(["example.com"], expected)
    statuses = {r["status"] for r in results}
    assert "unparseable" in statuses
    assert len(results) == 1  # one row per (domain, issuer); unparseable wins


def test_verify_persist_records_expired_persist_until():
    # The record matches the expected URI but its persistUntil has passed: per the
    # draft an expired persistUntil must not be accepted -> a distinct "expired"
    # status, and persist_until is surfaced.
    expected = {"digicert.com": "https://digicert.com/account/abc"}
    with patch(
        "lemur.common.dcv_dns._resolve_persist_txt",
        return_value=(
            "ok",
            ["digicert.com;accounturi=https://digicert.com/account/abc; persistUntil=1"],
        ),
    ):
        results = verify_persist_records(["example.com"], expected)
    assert results[0]["status"] == "expired"
    assert results[0]["persist_until"] == 1


def test_verify_persist_records_future_persist_until_ok():
    # A persistUntil in the future does not make the record unhealthy.
    expected = {"digicert.com": "https://digicert.com/account/abc"}
    with patch(
        "lemur.common.dcv_dns._resolve_persist_txt",
        return_value=(
            "ok",
            [
                "digicert.com;accounturi=https://digicert.com/account/abc; persistUntil=4102444800"
            ],
        ),
    ):
        results = verify_persist_records(["example.com"], expected)
    assert results[0]["status"] == "ok"
    assert results[0]["persist_until"] == 4102444800


def test_verify_persist_records_multiple_txt_records_in_one_response():
    expected = {
        "digicert.com": "https://digicert.com/account/abc",
        "sectigo.com": "acct:1@sectigo.com",
    }
    # Both CAs in a single DNS response (two TXT records).
    with patch(
        "lemur.common.dcv_dns._resolve_persist_txt",
        return_value=(
            "ok",
            [
                "digicert.com;accounturi=https://digicert.com/account/abc",
                "sectigo.com;accounturi=acct:1@sectigo.com",
            ],
        ),
    ):
        results = verify_persist_records(["example.com"], expected)
    assert {r["status"] for r in results} == {"ok"}
    assert len(results) == 2


def test_verify_persist_records_dns_error_per_issuer():
    # On a DNS error every issuer in expected_uris must get a failing row (not one
    # ca:unknown) so each CA's series does not go stale.
    expected = {
        "digicert.com": "https://digicert.com/account/abc",
        "sectigo.com": "acct:1@sectigo.com",
    }
    with patch(
        "lemur.common.dcv_dns._resolve_persist_txt", return_value=("dns_error", [])
    ):
        results = verify_persist_records(["example.com"], expected)
    assert len(results) == 2
    assert {r["ca"] for r in results} == {"digicert.com", "sectigo.com"}
    assert all(r["status"] == "dns_error" for r in results)


def test_verify_persist_records_subdomain_uses_base_domain():
    # A subdomain SAN is verified against the _validation-persist record at its
    # CA/Browser Forum Base Domain Name, not the exact label (DigiCert DNS DCV
    # validates the submitted base domain and covers subdomains).
    expected = {"digicert.com": "https://digicert.com/account/abc"}
    calls = []

    def fake_resolve(candidate):
        calls.append(candidate)
        if candidate == "datad0g.com":
            return ("ok", ["digicert.com;accounturi=https://digicert.com/account/abc"])
        return ("missing", [])

    with patch("lemur.common.dcv_dns._resolve_persist_txt", side_effect=fake_resolve):
        results = verify_persist_records(["api.datad0g.com"], expected)
    # Only the base domain is queried (no label walk).
    assert calls == ["datad0g.com"]
    assert results[0]["status"] == "ok"


def test_verify_persist_records_dedupes_base_domain_across_subdomains():
    # Multiple subdomains sharing a base domain trigger only one DNS query, but
    # each domain gets its own (domain, issuer) result row.
    expected = {"digicert.com": "https://digicert.com/account/abc"}
    calls = []

    def fake_resolve(candidate):
        calls.append(candidate)
        return ("ok", ["digicert.com;accounturi=https://digicert.com/account/abc"])

    with patch("lemur.common.dcv_dns._resolve_persist_txt", side_effect=fake_resolve):
        results = verify_persist_records(
            ["api.datad0g.com", "www.datad0g.com", "datad0g.com"], expected
        )
    assert calls == ["datad0g.com"]  # single DNS query for the shared base
    assert len(results) == 3
    assert all(r["status"] == "ok" for r in results)


def test_verify_persist_records_bare_public_suffix_san_is_missing():
    # A SAN whose base cannot be determined has no valid validation point.
    expected = {"digicert.com": "https://digicert.com/account/abc"}
    with patch("lemur.common.dcv_dns._resolve_persist_txt", return_value=("ok", [])):
        results = verify_persist_records(["co.uk"], expected)
    assert results[0]["status"] == "missing"
