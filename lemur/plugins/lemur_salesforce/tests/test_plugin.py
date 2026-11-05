"""
Tests for lemur_salesforce plugin.

Uses unittest.mock to patch sf_api calls — no live Salesforce org required.
For sandbox integration tests, set SALESFORCE_ORG_URL to a scratch org.
"""

from unittest.mock import MagicMock, patch

import pytest

from lemur.plugins.lemur_salesforce.plugin import (
    SalesforceIssuerPlugin,
    SalesforceSourcePlugin,
    SalesforceDestinationPlugin,
)


FAKE_CSR = """-----BEGIN CERTIFICATE REQUEST-----
MIICvDCCAaQCAQAwdzELMAkGA1UEBhMCVVMxDTALBgNVBAgMBFRlc3QxDTALBgNV
BAcMBFRlc3QxDTALBgNVBAoMBFRlc3QxHTAbBgNVBAMMFHBhcnRuZXJzLmRhdGFk
b2docS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7fake==
-----END CERTIFICATE REQUEST-----"""

FAKE_CERT = """-----BEGIN CERTIFICATE-----
MIICvDCCAaQCAQAwdzELMAkGA1UEBhMCVVMxDTALBgNVBAgMBFRlc3QxDTALBgNV
-----END CERTIFICATE-----"""

FAKE_CHAIN = """-----BEGIN CERTIFICATE-----
MIICvDCCAaQCAQAwdzELMAkGA1UEBhMCVVMxDTALBgNVBAgMBFRlc3QxDTALBgNV
-----END CERTIFICATE-----"""


# ---------------------------------------------------------------------------
# IssuerPlugin tests
# ---------------------------------------------------------------------------

class TestSalesforceIssuerPlugin:

    @patch("lemur.plugins.lemur_salesforce.plugin.sf_api.create_ca_signed_cert")
    @patch("lemur.plugins.lemur_salesforce.plugin.sf_api.get_csr")
    @patch("lemur.plugins.lemur_salesforce.plugin.plugins")
    def test_create_certificate_delegates_to_digicert(
        self, mock_plugins, mock_get_csr, mock_create_cert, app
    ):
        """IssuerPlugin should discard Lemur's CSR, get Salesforce's, delegate to DigiCert."""
        mock_get_csr.return_value = FAKE_CSR
        mock_create_cert.return_value = "cert-object-id"

        mock_digicert = MagicMock()
        mock_digicert.create_certificate.return_value = (FAKE_CERT, FAKE_CHAIN, "dc-12345")
        mock_plugins.get.return_value = mock_digicert

        plugin = SalesforceIssuerPlugin()
        issuer_options = {
            "orgUrl": "https://datadoghq.my.salesforce.com",
            "certDeveloperName": "partners_datadoghq_com_20270115",
        }

        body, chain, ext_id = plugin.create_certificate("IGNORED_CSR", issuer_options)

        # Should have created a cert in Salesforce
        mock_create_cert.assert_called_once_with(
            "https://datadoghq.my.salesforce.com",
            "partners_datadoghq_com_20270115",
        )
        # Should have retrieved the Salesforce-generated CSR (not Lemur's)
        mock_get_csr.assert_called_once()
        # Should have delegated to DigiCert with the Salesforce CSR
        mock_digicert.create_certificate.assert_called_once_with(FAKE_CSR, issuer_options)
        # Should return DigiCert's result unchanged
        assert body == FAKE_CERT
        assert chain == FAKE_CHAIN
        assert ext_id == "dc-12345"

    @patch("lemur.plugins.lemur_salesforce.plugin.plugins")
    def test_get_ordered_certificate_delegates_to_digicert(self, mock_plugins, app):
        mock_digicert = MagicMock()
        mock_digicert.get_ordered_certificate.return_value = {
            "body": FAKE_CERT, "chain": FAKE_CHAIN, "external_id": "dc-99"
        }
        mock_plugins.get.return_value = mock_digicert

        plugin = SalesforceIssuerPlugin()
        pending = MagicMock()
        result = plugin.get_ordered_certificate(pending)

        mock_digicert.get_ordered_certificate.assert_called_once_with(pending)
        assert result["external_id"] == "dc-99"

    def test_revoke_is_noop(self, app, caplog):
        """Revoke should log and return without raising."""
        plugin = SalesforceIssuerPlugin()
        cert = MagicMock()
        cert.name = "test-cert"
        # Should not raise
        plugin.revoke_certificate(cert, {"comments": "test"})


# ---------------------------------------------------------------------------
# SourcePlugin tests
# ---------------------------------------------------------------------------

class TestSalesforceSourcePlugin:

    @patch("lemur.plugins.lemur_salesforce.plugin.sf_api.list_certificates")
    def test_get_certificates_returns_correct_shape(self, mock_list, app):
        mock_list.return_value = [
            {"body": FAKE_CERT, "chain": None, "name": "partners_datadoghq_com"},
            {"body": FAKE_CERT, "chain": None, "name": "govsupport_ddog_gov_com"},
        ]

        plugin = SalesforceSourcePlugin()
        options = [{"name": "orgUrl", "value": "https://datadoghq.my.salesforce.com"}]
        result = plugin.get_certificates(options)

        assert len(result) == 2
        assert result[0]["name"] == "partners_datadoghq_com"
        assert "body" in result[0]
        assert "chain" in result[0]

    def test_get_endpoints_returns_empty(self):
        plugin = SalesforceSourcePlugin()
        assert plugin.get_endpoints({}) == []


# ---------------------------------------------------------------------------
# DestinationPlugin tests
# ---------------------------------------------------------------------------

class TestSalesforceDestinationPlugin:

    def test_requires_key_is_false(self):
        """Critical: Lemur must not block on missing private key."""
        assert SalesforceDestinationPlugin.requires_key is False

    def test_sync_as_source_points_to_source_slug(self):
        assert SalesforceDestinationPlugin.sync_as_source is True
        assert SalesforceDestinationPlugin.sync_as_source_name == "salesforce-source"

    @patch("lemur.plugins.lemur_salesforce.plugin.sf_api.deploy_signed_cert")
    @patch("lemur.plugins.lemur_salesforce.plugin.sf_api.update_site_cert_binding")
    def test_upload_calls_deploy_and_binding_update(
        self, mock_bind, mock_deploy, app
    ):
        mock_deploy.return_value = "deploy-abc123"

        plugin = SalesforceDestinationPlugin()
        options = [
            {"name": "orgUrl", "value": "https://datadoghq.my.salesforce.com"},
            {"name": "certDeveloperName", "value": "partners_datadoghq_com_20270115"},
            {"name": "siteDeveloperName", "value": "partners"},
            {"name": "domainName", "value": "partners.datadoghq.com"},
        ]

        plugin.upload(
            name="test",
            body=FAKE_CERT,
            private_key=None,      # Salesforce holds the key
            cert_chain=FAKE_CHAIN,
            options=options,
        )

        mock_deploy.assert_called_once()
        deploy_args = mock_deploy.call_args[0]
        assert deploy_args[1] == "partners_datadoghq_com_20270115"
        assert FAKE_CERT.rstrip() in deploy_args[2]  # body in bundle
        assert FAKE_CHAIN.strip() in deploy_args[2]  # chain in bundle

        mock_bind.assert_called_once_with(
            "https://datadoghq.my.salesforce.com",
            "partners",
            "partners_datadoghq_com_20270115",
        )

    @patch("lemur.plugins.lemur_salesforce.plugin.sf_api.deploy_signed_cert")
    @patch("lemur.plugins.lemur_salesforce.plugin.sf_api.update_site_cert_binding")
    def test_upload_handles_none_chain(self, mock_bind, mock_deploy, app):
        """upload() should not crash when cert_chain is None."""
        mock_deploy.return_value = "deploy-xyz"

        plugin = SalesforceDestinationPlugin()
        options = [
            {"name": "orgUrl", "value": "https://datadoghq.my.salesforce.com"},
            {"name": "certDeveloperName", "value": "test_cert"},
            {"name": "siteDeveloperName", "value": "testsite"},
            {"name": "domainName", "value": "test.datadoghq.com"},
        ]

        plugin.upload("test", FAKE_CERT, None, None, options)
        mock_deploy.assert_called_once()
