from unittest.mock import Mock, patch

import dns.exception
import dns.resolver
import pytest

from lemur.dns_providers import util


@patch("lemur.dns_providers.util.dns.resolver.Resolver")
def test_get_dns_records_raises_lookup_errors_when_requested(mock_resolver):
    mock_resolver.return_value.resolve.side_effect = dns.exception.Timeout
    with pytest.raises(dns.exception.Timeout):
        util.get_dns_records("example.com", "TXT", raise_errors=True)


@patch("lemur.dns_providers.util.dns.resolver.Resolver")
def test_get_dns_records_missing_records_are_empty(mock_resolver):
    for error in (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        mock_resolver.return_value.resolve.side_effect = error
        assert util.get_dns_records("example.com", "TXT", raise_errors=True) == []


@patch("lemur.dns_providers.util.dns.resolver.Resolver")
def test_get_dns_records_uses_configured_resolver(mock_resolver):
    resolver = mock_resolver.return_value
    resolver.nameservers = ["169.254.20.10"]
    resolver.resolve.return_value = [Mock(strings=[b"challenge-token"])]

    assert util.get_dns_records("_acme-challenge.example.com", "TXT") == [
        "challenge-token"
    ]
    assert resolver.nameservers == ["169.254.20.10"]
    resolver.resolve.assert_called_once_with(
        "_acme-challenge.example.com", "TXT", lifetime=5
    )


@patch("lemur.dns_providers.util.dns.resolver.Resolver")
def test_get_dns_records_preserves_explicit_nameserver(mock_resolver):
    resolver = mock_resolver.return_value
    resolver.resolve.return_value = []

    assert util.get_dns_records("example.com", "TXT", "192.0.2.53") == []
    assert resolver.nameservers == ["192.0.2.53"]
    resolver.resolve.assert_called_once_with("example.com", "TXT", lifetime=5)


@patch("lemur.dns_providers.util.metrics")
@patch("lemur.dns_providers.util.capture_exception")
@patch("lemur.dns_providers.util.dns.resolver.Resolver")
def test_get_dns_records_handles_timeout(mock_resolver, mock_capture, mock_metrics):
    mock_resolver.return_value.resolve.side_effect = dns.exception.Timeout

    assert util.get_dns_records("example.com", "TXT") == []
    mock_capture.assert_called_once_with()
    mock_metrics.send.assert_called_once_with("get_dns_records.fail", "counter", 1)


@patch("lemur.dns_providers.util.dns.resolver.get_default_resolver")
@patch("lemur.dns_providers.util.dns.query.udp")
def test_authoritative_discovery_has_bounded_udp_timeout(mock_udp, mock_resolver):
    mock_resolver.return_value.nameservers = ["169.254.20.10"]
    mock_udp.side_effect = dns.exception.Timeout

    with pytest.raises(dns.exception.Timeout):
        util.get_authoritative_nameserver("example.com")

    assert mock_udp.call_args.kwargs == {"timeout": 5}
