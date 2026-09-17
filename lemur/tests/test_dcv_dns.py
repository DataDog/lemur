"""Tests for DNS-native _validation-persist DCV verification (draft-ietf-acme-dns-persist)."""

from unittest.mock import patch

from lemur.common.dcv_dns import (
    _domain_candidates,
    _parse_persist_txt,
    _resolve_persist_walk,
    _resolve_persist_txt,
    verify_persist_records,
)


def test_parse_persist_txt_digicert():
    assert _parse_persist_txt(
        "digicert.com;accounturi=https://digicert.com/account/abc"
    ) == {
        "digicert.com": {"account_uri": "https://digicert.com/account/abc", "persist_until": None}
    }


def test_parse_persist_txt_sectigo():
    assert _parse_persist_txt("sectigo.com;accounturi=acct:1234@sectigo.com") == {
        "sectigo.com": {"account_uri": "acct:1234@sectigo.com", "persist_until": None}
    }


def test_parse_persist_txt_with_persist_until():
    parsed = _parse_persist_txt(
        "digicert.com;accounturi=https://digicert.com/account/abc; persistUntil=253402300799"
    )
    assert parsed == {
        "digicert.com": {
            "account_uri": "https://digicert.com/account/abc",
            "persist_until": 253402300799,
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


def test_verify_persist_records_expired_persist_until():
    # The record matches the expected URI but its persistUntil has passed: per the
    # draft an expired persistUntil must not be accepted -> a distinct "expired"
    # status, and persist_until is surfaced.
    expected = {"digicert.com": "https://digicert.com/account/abc"}
    with patch(
        "lemur.common.dcv_dns._resolve_persist_txt",
        return_value=(
            "ok",
            [
                "digicert.com;accounturi=https://digicert.com/account/abc; persistUntil=1",
            ],
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
                "digicert.com;accounturi=https://digicert.com/account/abc; persistUntil=4102444800",
            ],
        ),
    ):
        results = verify_persist_records(["example.com"], expected)
    assert results[0]["status"] == "ok"
    assert results[0]["persist_until"] == 4102444800


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


def test_domain_candidates_bounded_to_registrable_apex():
    # Walks from the exact label down to a 2-label apex; never a bare public suffix.
    assert list(_domain_candidates("api.datad0g.com")) == [
        "api.datad0g.com",
        "datad0g.com",
    ]
    assert list(_domain_candidates("a.b.datad0g.com")) == [
        "a.b.datad0g.com",
        "b.datad0g.com",
        "datad0g.com",
    ]
    assert list(_domain_candidates("datad0g.com.")) == ["datad0g.com"]


def test_domain_candidates_never_query_bare_multilabel_public_suffix():
    # Finding (review): len(labels) >= 2 does not reliably identify a registrable
    # domain. api.example.co.uk would otherwise walk all the way to the bare
    # public suffix co.uk. It must stop at the registrable domain example.co.uk.
    assert list(_domain_candidates("api.example.co.uk")) == [
        "api.example.co.uk",
        "example.co.uk",
    ]
    assert list(_domain_candidates("example.co.uk")) == ["example.co.uk"]
    # A bare public suffix yields no candidates at all.
    assert list(_domain_candidates("co.uk")) == []
    # A multi-label public-suffix candidate like com.au also never walked.
    assert list(_domain_candidates("x.com.au")) == ["x.com.au"]


def test_verify_persist_records_subdomain_covers_from_ancestor_record():
    # Finding 3: a subdomain SAN is covered by the persistent record published at
    # the zone apex, so it must resolve "ok" (not "missing").
    expected = {"digicert.com": "https://digicert.com/account/abc"}
    calls = []

    def fake_resolve(candidate):
        calls.append(candidate)
        if candidate == "api.datad0g.com":
            return ("missing", [])
        if candidate == "datad0g.com":
            return (
                "ok",
                [
                    "digicert.com;accounturi=https://digicert.com/account/abc",
                    "sectigo.com;accounturi=acct:1@sectigo.com",
                ],
            )
        return ("dns_error", [])  # never reached for public suffix

    with patch("lemur.common.dcv_dns._resolve_persist_txt", side_effect=fake_resolve):
        results = verify_persist_records(["api.datad0g.com"], expected)
    assert calls == ["api.datad0g.com", "datad0g.com"]
    assert results[0]["status"] == "ok"
    assert results[0]["ca"] == "digicert.com"


def test_verify_persist_records_subdomain_truly_missing():
    # A subdomain with no record at any level is a real gap -> "missing".
    expected = {"digicert.com": "https://digicert.com/account/abc"}
    with patch(
        "lemur.common.dcv_dns._resolve_persist_txt", return_value=("missing", [])
    ):
        results = verify_persist_records(["api.datad0g.com"], expected)
    assert len(results) == 1
    assert results[0]["status"] == "missing"


def test_resolve_persist_walk_falls_back_to_ancestor():
    def fake_resolve(candidate):
        if candidate == "b.datad0g.com":
            return ("ok", ["digicert.com;accounturi=x"])
        return ("missing", [])

    with patch("lemur.common.dcv_dns._resolve_persist_txt", side_effect=fake_resolve):
        status, values = _resolve_persist_walk("a.b.datad0g.com")
    assert status == "ok"
    assert values == ["digicert.com;accounturi=x"]


def test_resolve_persist_walk_dns_error_when_any_candidate_unresolved():
    def fake_resolve(candidate):
        if candidate == "datad0g.com":
            return ("dns_error", [])
        return ("missing", [])

    with patch("lemur.common.dcv_dns._resolve_persist_txt", side_effect=fake_resolve):
        status, values = _resolve_persist_walk("api.datad0g.com")
    assert status == "dns_error"
    assert values == []
