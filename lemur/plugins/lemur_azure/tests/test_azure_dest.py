import os
import unittest
from datetime import datetime
from unittest.mock import patch, ANY

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, pkcs12
from flask import Flask
from lemur.common.utils import parse_private_key

from lemur.tests.vectors import (
    INTERMEDIATE_CERT,
    INTERMEDIATE_CERT_STR,
    ROOTCA_CERT,
    ROOTCA_CERT_STR,
    ROOTCA_KEY,
    SAN_CERT,
    SAN_CERT_KEY,
    SAN_CERT_STR,
)


def issue_certificate(subject, issuer, public_key, signing_key):
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2025, 1, 1))
        .not_valid_after(datetime(2030, 1, 1))
        .sign(signing_key, hashes.SHA256())
    )


class TestAzureDestination(unittest.TestCase):
    def setUp(self):
        # Creates a new Flask application for a test duration. In python 3.8, manual push of application context is
        # needed to run tests in dev environment without getting error 'Working outside of application context'.
        _app = Flask("lemur_test_azure_dest")
        self.ctx = _app.app_context()
        assert self.ctx
        self.ctx.push()
        ca_key = parse_private_key(ROOTCA_KEY)
        leaf_key = parse_private_key(SAN_CERT_KEY)
        ca_name = x509.Name(
            [
                x509.NameAttribute(x509.OID_COMMON_NAME, "Test CA"),
                x509.NameAttribute(x509.OID_ORGANIZATION_NAME, "Let's Encrypt"),
            ]
        )
        self.ca = issue_certificate(ca_name, ca_name, ca_key.public_key(), ca_key)
        self.leaf = issue_certificate(
            x509.Name([x509.NameAttribute(x509.OID_COMMON_NAME, "localhost")]),
            ca_name,
            leaf_key.public_key(),
            ca_key,
        )
        self.wrong_key_ca = issue_certificate(
            ca_name,
            ca_name,
            leaf_key.public_key(),
            leaf_key,
        )
        self.options = [
            {"name": "azureKeyVaultUrl", "value": "https://couldbeanyvalue.com"},
            {"name": "azureTenant", "value": "mockedTenant"},
            {"name": "azureAppID", "value": "mockedAPPid"},
            {"name": "azurePassword", "value": "norealPW"},
            {"name": "authenticationMethod", "value": "azureApp"},
        ]

    def tearDown(self):
        self.ctx.pop()

    @patch("azure.keyvault.certificates.CertificateClient.import_certificate")
    def test_upload_selects_verified_issuer(self, import_certificate_mock):
        from lemur.plugins.lemur_azure.plugin import AzureDestinationPlugin

        for chain in (
            [self.ca, ROOTCA_CERT],
            [ROOTCA_CERT, self.ca],
            [self.wrong_key_ca, ROOTCA_CERT, self.ca],
            [self.ca, self.ca],
        ):
            with self.subTest(chain=chain):
                import_certificate_mock.reset_mock()
                AzureDestinationPlugin().upload(
                    "Test_Certificate",
                    self.leaf.public_bytes(Encoding.PEM).decode(),
                    SAN_CERT_KEY,
                    "\n".join(c.public_bytes(Encoding.PEM).decode() for c in chain),
                    self.options,
                )
                import_certificate_mock.assert_called_once()
                args = import_certificate_mock.call_args.kwargs
                self.assertEqual(
                    args["certificate_name"], "localhost-LetsEncrypt-RSA2048"
                )
                _, leaf, uploaded_chain = pkcs12.load_key_and_certificates(
                    args["certificate_bytes"], None
                )
                self.assertEqual(leaf, self.leaf)
                self.assertCountEqual(uploaded_chain, chain)

    @patch("lemur.plugins.lemur_azure.plugin.CertificateClient")
    def test_upload_rejects_missing_issuer(self, client_mock):
        from lemur.plugins.lemur_azure.plugin import AzureDestinationPlugin

        for chain, error in (
            (None, "Certificate chain is empty"),
            ("", "Certificate chain is empty"),
            (ROOTCA_CERT_STR, "does not contain"),
            (self.wrong_key_ca.public_bytes(Encoding.PEM).decode(), "does not contain"),
        ):
            with self.subTest(chain=chain):
                with self.assertRaisesRegex(ValueError, error):
                    AzureDestinationPlugin().upload(
                        "Test_Certificate",
                        self.leaf.public_bytes(Encoding.PEM).decode(),
                        SAN_CERT_KEY,
                        chain,
                        self.options,
                    )
                client_mock.assert_not_called()

    @patch("azure.keyvault.certificates.CertificateClient.import_certificate")
    def test_upload_preserves_full_chain(self, import_certificate_mock):
        from lemur.plugins.lemur_azure.plugin import AzureDestinationPlugin

        options = [
            {"name": "azureKeyVaultUrl", "value": "https://couldbeanyvalue.com"},
            {"name": "azureTenant", "value": "mockedTenant"},
            {"name": "azureAppID", "value": "mockedAPPid"},
            {"name": "azurePassword", "value": "norealPW"},
            {"name": "authenticationMethod", "value": "azureApp"},
        ]
        AzureDestinationPlugin().upload(
            "Test_Certificate",
            SAN_CERT_STR,
            SAN_CERT_KEY,
            INTERMEDIATE_CERT_STR + "\n" + ROOTCA_CERT_STR,
            options,
        )

        import_certificate_mock.assert_called_once()
        private_key, cert, chain = pkcs12.load_key_and_certificates(
            import_certificate_mock.call_args.kwargs["certificate_bytes"], None
        )
        self.assertEqual(cert, SAN_CERT)
        self.assertEqual(
            private_key.public_key().public_numbers(),
            cert.public_key().public_numbers(),
        )
        self.assertEqual(chain, [INTERMEDIATE_CERT, ROOTCA_CERT])

    @patch.dict(os.environ, {"VAULT_ADDR": "https://fakevaultinstance:8200"})
    @patch("azure.keyvault.certificates.CertificateClient.import_certificate")
    def test_upload(self, import_certificate_mock):
        from lemur.plugins.lemur_azure.plugin import AzureDestinationPlugin

        subject = AzureDestinationPlugin()

        name = "Test_Certificate"
        body = self.leaf.public_bytes(Encoding.PEM).decode()
        private_key = SAN_CERT_KEY
        cert_chain = self.ca.public_bytes(Encoding.PEM).decode()

        def _assert_certificate_imported():
            import_certificate_mock.assert_called_with(
                certificate_name="localhost-LetsEncrypt-RSA2048",
                certificate_bytes=ANY,
                enabled=True,
                policy=ANY,
                tags={"lemur.managed": "true"},
            )

        with self.subTest(case="upload cert using azureApp auth method"):
            options = [
                {"name": "azureKeyVaultUrl", "value": "https://couldbeanyvalue.com"},
                {"name": "azureTenant", "value": "mockedTenant"},
                {"name": "azureAppID", "value": "mockedAPPid"},
                {"name": "azurePassword", "value": "norealPW"},
                {"name": "authenticationMethod", "value": "azureApp"},
            ]
            subject.upload(name, body, private_key, cert_chain, options)
            _assert_certificate_imported()

        with self.subTest(case="upload cert using hashicorpVault auth method"):
            options = [
                {"name": "azureKeyVaultUrl", "value": "https://couldbeanyvalue.com"},
                {"name": "azureTenant", "value": "mockedTenant"},
                {"name": "authenticationMethod", "value": "hashicorpVault"},
                {"name": "hashicorpVaultRoleName", "value": "mockedRole"},
                {"name": "hashicorpVaultMountPoint", "value": "azure"},
            ]
            subject.upload(name, body, private_key, cert_chain, options)
            _assert_certificate_imported()
