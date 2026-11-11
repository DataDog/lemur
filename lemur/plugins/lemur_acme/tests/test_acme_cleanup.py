import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from billiard.exceptions import SoftTimeLimitExceeded
from flask import Flask

from lemur.plugins.lemur_acme import plugin


class TestAcmeCleanup(unittest.TestCase):
    def setUp(self):
        self.context = Flask(__name__).app_context()
        self.context.push()
        self.addCleanup(self.context.pop)
        for name in ("metrics", "capture_exception", "csr_to_string"):
            patcher = patch.object(plugin, name)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(plugin, "AcmeDnsHandler")
        self.handler = patcher.start().return_value
        self.addCleanup(patcher.stop)
        self.handler.dns_providers_for_domain = {}
        self.client = Mock()
        self.handler.setup_acme_client.return_value = (self.client, {})
        self.client.new_order.return_value.uri = "https://ca.example/order/1"
        self.authorizations = [Mock()]
        self.handler.get_authorizations.return_value = self.authorizations
        self.original_error = RuntimeError("DNS lookup timed out")
        self.handler.finalize_authorizations.side_effect = self.original_error
        self.pending = SimpleNamespace(
            authority=Mock(), external_id=1, dns_provider_id=1, csr="csr"
        )
        for service, value in (
            (plugin.authorization_service, SimpleNamespace(domains=["example.com"])),
            (plugin.dns_provider_service, Mock()),
        ):
            patcher = patch.object(service, "get", return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.issuer = plugin.ACMEIssuerPlugin()

    def test_cleanup_uses_handler_with_original_dns_provider_mapping(self):
        result = self.issuer.get_ordered_certificates([self.pending])

        self.assertIn("example.com", self.handler.dns_providers_for_domain)
        self.handler.cleanup_dns_challenges.assert_called_once_with(
            self.client, self.authorizations
        )
        self.assertFalse(result[0]["cert"])
        self.assertIn(str(self.original_error), result[0]["last_error"])

    def test_cleanup_failure_does_not_mask_issuance_error(self):
        self.handler.cleanup_dns_challenges.side_effect = RuntimeError("Cleanup failed")

        with self.assertLogs(level="WARNING") as logs:
            result = self.issuer.get_ordered_certificates([self.pending])

        self.assertIn("Unable to clean up DNS challenges", " ".join(logs.output))
        self.assertIn(str(self.original_error), result[0]["last_error"])
        self.assertNotIn("Cleanup failed", result[0]["last_error"])

    def test_success_does_not_invoke_error_cleanup(self):
        self.handler.finalize_authorizations.side_effect = None
        self.handler.request_certificate.return_value = ("certificate", "chain")

        result = self.issuer.get_ordered_certificates([self.pending])

        self.assertEqual(result[0]["cert"]["body"], "certificate")
        self.handler.cleanup_dns_challenges.assert_not_called()

    def test_cleanup_failure_preserves_soft_timeout(self):
        self.handler.finalize_authorizations.side_effect = SoftTimeLimitExceeded()
        self.handler.cleanup_dns_challenges.side_effect = RuntimeError("Cleanup failed")

        with self.assertLogs(level="WARNING"):
            result = self.issuer.get_ordered_certificates([self.pending])

        self.assertFalse(result[0]["cert"])
        self.assertIn("SoftTimeLimitExceeded", result[0]["last_error"])
        self.assertNotIn("Cleanup failed", result[0]["last_error"])

    def test_failure_uses_its_own_order_in_a_batch(self):
        second = SimpleNamespace(
            authority=Mock(), external_id=2, dns_provider_id=1, csr="csr"
        )
        self.client.new_order.side_effect = [
            SimpleNamespace(uri="https://ca.example/order/1"),
            SimpleNamespace(uri="https://ca.example/order/2"),
        ]

        with self.assertLogs(level="ERROR"):
            result = self.issuer.get_ordered_certificates([self.pending, second])

        for index, pending in enumerate((self.pending, second), start=1):
            self.assertIs(result[index - 1]["pending_cert"], pending)
            self.assertIn(
                f"https://ca.example/order/{index}", result[index - 1]["last_error"]
            )
