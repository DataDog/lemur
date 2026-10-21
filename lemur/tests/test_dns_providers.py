import json
import unittest
from unittest.mock import patch

import dns.exception
from lemur.dns_providers import util as dnsutil
from lemur.dns_providers.schemas import dns_provider_output_schema


class TestDNSProvider(unittest.TestCase):
    @patch("lemur.dns_providers.util.dns.query.udp", side_effect=dns.exception.Timeout)
    @patch("lemur.dns_providers.util.dns.resolver.get_default_resolver")
    def test_authoritative_nameserver_timeout(self, mock_resolver, mock_udp):
        mock_resolver.return_value.nameservers = ["192.0.2.53"]

        with self.assertRaisesRegex(
            dnsutil.DNSResolveError, "Timed out querying nameserver 192.0.2.53"
        ) as error:
            dnsutil.get_authoritative_nameserver("example.com")

        self.assertIsInstance(error.exception.__cause__, dns.exception.Timeout)
        mock_udp.assert_called_once()
        timeout = mock_udp.call_args.kwargs["timeout"]
        self.assertGreater(timeout, 0)
        self.assertLessEqual(timeout, 30)

    def test_is_valid_domain(self):
        self.assertTrue(dnsutil.is_valid_domain("example.com"))
        self.assertTrue(dnsutil.is_valid_domain("foo.bar.org"))
        self.assertTrue(dnsutil.is_valid_domain("exam--ple.io"))
        self.assertTrue(dnsutil.is_valid_domain("a.example.com"))
        self.assertTrue(dnsutil.is_valid_domain("example.io"))
        self.assertTrue(
            dnsutil.is_valid_domain(
                "example-of-under-63-character-domain-label-length-limit-1234567.com"
            )
        )
        self.assertFalse(
            dnsutil.is_valid_domain(
                "example-of-over-63-character-domain-label-length-limit-123456789.com"
            )
        )
        self.assertTrue(dnsutil.is_valid_domain("_acme-chall.example.com"))
        self.assertFalse(dnsutil.is_valid_domain("e/xample.com"))
        self.assertFalse(dnsutil.is_valid_domain("exam\\ple.com"))
        self.assertFalse(dnsutil.is_valid_domain("<example.com"))
        self.assertFalse(dnsutil.is_valid_domain("*.example.com"))
        self.assertFalse(dnsutil.is_valid_domain("-example.io"))
        self.assertFalse(dnsutil.is_valid_domain("example-.io"))
        self.assertFalse(dnsutil.is_valid_domain("example..io"))
        self.assertFalse(dnsutil.is_valid_domain("exa mple.io"))
        self.assertFalse(dnsutil.is_valid_domain("-"))


def test_output_schema(dns_provider):
    # no credentials using the output schema dump
    assert dns_provider.credentials
    assert json.loads(dns_provider.credentials)["account_id"]
    dump = dns_provider_output_schema.dump(dns_provider).data
    assert "name" in dump
    assert "credentials" not in dump


def test_json(dns_provider):
    # we can still get credentials using json.load
    assert "account_id" in json.loads(dns_provider.credentials)


def test_update(dns_provider, session):
    from lemur.dns_providers import service as dns_provider_service

    new_data = {
        "name": "updated-provider",
        "description": "updated description",
        "provider_type": {
            "name": "route53",
            "requirements": [
                {"name": "account_id", "value": "123456789"},
            ],
        },
    }
    updated = dns_provider_service.update(dns_provider.id, new_data)

    assert updated is not None
    assert updated.name == "updated-provider"
    assert updated.description == "updated description"
    assert updated.provider_type == "route53"

    import json
    creds = json.loads(updated.credentials)
    assert creds["account_id"] == "123456789"
