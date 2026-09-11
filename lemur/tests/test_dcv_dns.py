"""Tests for DNS-native _validation-persist DCV verification (draft-ietf-acme-dns-persist)."""

from unittest.mock import patch

from lemur.common.dcv_dns import (
    _parse_persist_txt,
    _resolve_persist_txt,
    verify_persist_records,
)


def test_parse_persist_txt_digicert():
    assert _parse_persist_txt(
        "digicert.com;accounturi=https://digicert.com/account/abc"
    ) == {"digicert.com": "https://digicert.com/account/abc"}


def test_parse_persist_txt_sectigo():
    assert _parse_persist_txt("sectigo.com;accounturi=acct:1234@sectigo.com") == {
        "sectigo.com": "acct:1234@sectigo.com"
    }


def test_parse_persist_txt_unparseable():
    assert _parse_persist_txt("") is None
    assert _parse_persist_txt("digicert.com;nouri=1") is None
    assert _parse_persist_txt(";accounturi=x") is None


def test_resolve_persist_txt_missing_on_nxdomain():
    with patch("lemur.common.dcv_dns.dns.resolver.Resolver") as mock_resolver_cls:
        mock_resolver = mock_resolver_cls.return_value
        mock_resolver.resolve.side_effect = __import__("dns").resolver.NXDOMAIN()
        status, values = _resolve_persist_txt("example.com")
    assert status == "missing"
    assert values == []


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
            [
                "digicert.com;accounturi=https://digicert.com/account/DIFFERENT",
            ],
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
        return_value=(
            "ok",
            [
                "not-a-valid-record",
            ],
        ),
    ):
        results = verify_persist_records(["example.com"], expected)
    statuses = {r["status"] for r in results}
    assert "unparseable" in statuses
    assert "missing" in statuses  # digicert.com never found


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
