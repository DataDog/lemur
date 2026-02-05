from unittest import TestCase, mock
from lemur.tests.vectors import (
    INTERMEDIATE_CERT_STR,
    WILDCARD_CERT_STR,
    WILDCARD_CERT_KEY,
)
from .cert_constants import (
    DIGICERT_RSA2048_CERT_STR,
    DIGICERT_RSA4096_CERT_STR,
    DIGICERT_RSA_CHAIN_STR,
    DIGICERT_ECC_CHAIN_STR,
    DIGICERT_ECC256_CERT_STR,
    DIGICERT_ECC384_CERT_STR,
    SECTIGO_RSA_CHAIN_STR,
    SECTIGO_RSA2048_CERT_STR,
    SECTIGO_ECC_CHAIN_STR,
    SECTIGO_ECC256_CERT_STR,
)
from lemur.plugins.lemur_coa.plugin import (
    AdapterDestinationPlugin,
    AdapterSourcePlugin,
)
from lemur.plugins.lemur_coa.pb import (
    service_pb2_grpc as adapter_pb2_grpc,
    service_pb2 as adapter_pb2,
)
from dd_internal_authentication.client import (
    JWTInternalServiceAuthClientTokenManager,
)
from flask import Flask
from concurrent import futures
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import serialization
import grpc


class NoopCertOrchestrationAdapter:
    """
    Noop implementation of a Cert Orchestration Adapter that stores certificates in-memory instead of Vault.
    Used for testing purposes only.
    """

    def __init__(self):
        self.certs = {}

    def Upload(self, request, context):
        self.certs[request.vault_path] = dict(
            crt=request.certificate,
            intermediate=request.intermediate,
            key=request.private_key,
        )
        return adapter_pb2.CertificateUploadResponse()

    def List(self, request, context):
        certificates = []
        path_prefix = request.vault_path
        for path, cert_data in self.certs.items():
            if path.startswith(path_prefix):
                certificates.append(adapter_pb2.VaultCertificate(certificate=cert_data["crt"], vault_path=path))
        return adapter_pb2.ListCertificatesResponse(certificates=certificates)

    def assert_contains_cert_at_path(self, path, certificate, intermediate, private_key):
        assert path in self.certs
        actual = self.certs.get(path)
        expected = dict(
            crt=certificate,
            intermediate=intermediate,
            key=private_key,
        )
        assert expected == actual


@mock.patch.object(
    JWTInternalServiceAuthClientTokenManager,
    "get_token",
    return_value="abc1234",
)
class TestAdapterDestinationPlugin(TestCase):
    def setUp(self):
        # Creates a new Flask application for a test duration.
        _app = Flask(__name__)
        self.ctx = _app.app_context()
        assert self.ctx
        self.ctx.push()

        # Create a Cert Orchestration Adapter service for a test duration.
        self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=1))
        self.port = self.server.add_secure_port("[::]:0", grpc.local_server_credentials())
        self.server_impl = NoopCertOrchestrationAdapter()
        adapter_pb2_grpc.add_CertificateServicer_to_server(self.server_impl, self.server)
        self.server.start()

    def tearDown(self):
        self.ctx.pop()
        self.server.stop(0)

    def test_simple_upload(self, *args):
        options = [
            {
                "name": "audience",
                "value": "cert-orchestration",
            },
            {
                "name": "hostname",
                "value": "localhost",
            },
            {
                "name": "port",
                "value": self.port,
            },
            {
                "name": "paths",
                "value": "/kv/k8s/ingress-haproxy/shared/public-certificates,/kv/k8s/ingress-envoy/shared/public-certificates",
            },
            {
                "name": "use_xdcgw",
                "value": False,
            },
        ]

        plugin = AdapterDestinationPlugin()

        plugin.upload(
            name="star.wild.example.org",
            body=WILDCARD_CERT_STR,
            private_key=WILDCARD_CERT_KEY,
            cert_chain=INTERMEDIATE_CERT_STR,
            options=options,
        )
        self.server_impl.assert_contains_cert_at_path(
            path="/kv/k8s/ingress-haproxy/shared/public-certificates/*.wild.example.org_LemurTrustEnterprisesLtd_RSA2048",
            certificate=WILDCARD_CERT_STR,
            intermediate=INTERMEDIATE_CERT_STR,
            private_key=WILDCARD_CERT_KEY,
        )
        self.server_impl.assert_contains_cert_at_path(
            path="/kv/k8s/ingress-envoy/shared/public-certificates/*.wild.example.org_LemurTrustEnterprisesLtd_RSA2048",
            certificate=WILDCARD_CERT_STR,
            intermediate=INTERMEDIATE_CERT_STR,
            private_key=WILDCARD_CERT_KEY,
        )

    def test_upload_digicert(self, *args):
        options = [
            {
                "name": "audience",
                "value": "cert-orchestration",
            },
            {
                "name": "hostname",
                "value": "localhost",
            },
            {
                "name": "port",
                "value": self.port,
            },
            {
                "name": "paths",
                "value": "/kv/k8s/ingress-haproxy/shared/public-certificates",
            },
            {
                "name": "use_xdcgw",
                "value": False,
            },
        ]

        plugin = AdapterDestinationPlugin()

        plugin.upload(
            name="star.lemur-sandbox.datad0g.com",
            body=DIGICERT_RSA2048_CERT_STR,
            private_key=WILDCARD_CERT_KEY,
            cert_chain=DIGICERT_RSA_CHAIN_STR,
            options=options,
        )
        self.server_impl.assert_contains_cert_at_path(
            path="/kv/k8s/ingress-haproxy/shared/public-certificates/*.lemur-sandbox.datad0g.com_DigiCert_RSA2048",
            certificate=DIGICERT_RSA2048_CERT_STR,
            intermediate=DIGICERT_RSA_CHAIN_STR,
            private_key=WILDCARD_CERT_KEY,
        )

        plugin.upload(
            name="star.lemur-sandbox.datad0g.com",
            body=DIGICERT_RSA4096_CERT_STR,
            private_key=WILDCARD_CERT_KEY,
            cert_chain=DIGICERT_RSA_CHAIN_STR,
            options=options,
        )
        self.server_impl.assert_contains_cert_at_path(
            path="/kv/k8s/ingress-haproxy/shared/public-certificates/*.lemur-sandbox.datad0g.com_DigiCert_RSA4096",
            certificate=DIGICERT_RSA4096_CERT_STR,
            intermediate=DIGICERT_RSA_CHAIN_STR,
            private_key=WILDCARD_CERT_KEY,
        )

        plugin.upload(
            name="lemur-sandbox.datad0g.com",
            body=DIGICERT_ECC256_CERT_STR,
            private_key=WILDCARD_CERT_KEY,
            cert_chain=DIGICERT_ECC_CHAIN_STR,
            options=options,
        )
        self.server_impl.assert_contains_cert_at_path(
            path="/kv/k8s/ingress-haproxy/shared/public-certificates/lemur-sandbox.datad0g.com_DigiCert_ECCPRIME256V1",
            certificate=DIGICERT_ECC256_CERT_STR,
            intermediate=DIGICERT_ECC_CHAIN_STR,
            private_key=WILDCARD_CERT_KEY,
        )

        plugin.upload(
            name="star.lemur-sandbox.datad0g.com",
            body=DIGICERT_ECC384_CERT_STR,
            private_key=WILDCARD_CERT_KEY,
            cert_chain=DIGICERT_ECC_CHAIN_STR,
            options=options,
        )
        self.server_impl.assert_contains_cert_at_path(
            path="/kv/k8s/ingress-haproxy/shared/public-certificates/*.lemur-sandbox.datad0g.com_DigiCert_ECCSECP384R1",
            certificate=DIGICERT_ECC384_CERT_STR,
            intermediate=DIGICERT_ECC_CHAIN_STR,
            private_key=WILDCARD_CERT_KEY,
        )

    def test_upload_sectigo(self, *args):
        options = [
            {
                "name": "audience",
                "value": "cert-orchestration",
            },
            {
                "name": "hostname",
                "value": "localhost",
            },
            {
                "name": "port",
                "value": self.port,
            },
            {
                "name": "paths",
                "value": "/kv/k8s/ingress-haproxy/shared/public-certificates",
            },
            {
                "name": "use_xdcgw",
                "value": False,
            },
        ]

        plugin = AdapterDestinationPlugin()

        plugin.upload(
            name="star.test.lemur-sandbox.datad0g.com",
            body=SECTIGO_RSA2048_CERT_STR,
            private_key=WILDCARD_CERT_KEY,
            cert_chain=SECTIGO_RSA_CHAIN_STR,
            options=options,
        )
        self.server_impl.assert_contains_cert_at_path(
            path="/kv/k8s/ingress-haproxy/shared/public-certificates/*.test.lemur-sandbox.datad0g.com_Sectigo_RSA2048",
            certificate=SECTIGO_RSA2048_CERT_STR,
            intermediate=SECTIGO_RSA_CHAIN_STR,
            private_key=WILDCARD_CERT_KEY,
        )

        plugin.upload(
            name="star.lemur-sandbox.datad0g.com",
            body=SECTIGO_ECC256_CERT_STR,
            private_key=WILDCARD_CERT_KEY,
            cert_chain=SECTIGO_ECC_CHAIN_STR,
            options=options,
        )
        self.server_impl.assert_contains_cert_at_path(
            path="/kv/k8s/ingress-haproxy/shared/public-certificates/*.lemur-sandbox.datad0g.com_Sectigo_ECCPRIME256V1",
            certificate=SECTIGO_ECC256_CERT_STR,
            intermediate=SECTIGO_ECC_CHAIN_STR,
            private_key=WILDCARD_CERT_KEY,
        )

    def test_get_certificates(self, *args):
        options = [
            {
                "name": "audience",
                "value": "cert-orchestration",
            },
            {
                "name": "hostname",
                "value": "localhost",
            },
            {
                "name": "port",
                "value": self.port,
            },
            {
                "name": "paths",
                "value": "/kv/k8s/ingress-haproxy/shared/public-certificates",
            },
            {
                "name": "use_xdcgw",
                "value": False,
            },
        ]

        destination_plugin = AdapterDestinationPlugin()
        source_plugin = AdapterSourcePlugin()

        destination_plugin.upload(
            name="star.lemur-sandbox.datad0g.com",
            body=DIGICERT_RSA4096_CERT_STR,
            private_key=WILDCARD_CERT_KEY,
            cert_chain=INTERMEDIATE_CERT_STR,
            options=options,
        )
        destination_plugin.upload(
            name="lemur-sandbox.datad0g.com",
            body=DIGICERT_ECC256_CERT_STR,
            private_key=WILDCARD_CERT_KEY,
            cert_chain=DIGICERT_ECC_CHAIN_STR,
            options=options,
        )

        certificates = source_plugin.get_certificates(options)
        assert len(certificates) == 2

        # Create a map to verify certificates in any order
        cert_map = {cert["name"]: cert["body"] for cert in certificates}

        assert "*.lemur-sandbox.datad0g.com" in cert_map
        assert are_certs_equal(cert_map["*.lemur-sandbox.datad0g.com"], DIGICERT_RSA4096_CERT_STR)

        assert "lemur-sandbox.datad0g.com" in cert_map
        assert are_certs_equal(cert_map["lemur-sandbox.datad0g.com"], DIGICERT_ECC256_CERT_STR)

    def assert_endpoint_values(self, endpoint, dnsname, path, registry_type, port, endpoint_type):
        assert endpoint["name"] == path
        assert endpoint["dnsname"] == dnsname
        assert endpoint["type"] == endpoint_type
        assert endpoint["port"] == port
        assert endpoint["primary_certificate"]["name"] == dnsname
        assert endpoint["primary_certificate"]["path"] == path
        assert endpoint["primary_certificate"]["registry_type"] == registry_type

    def test_get_endpoints(self, *args):
        options = [
            {
                "name": "audience",
                "value": "cert-orchestration",
            },
            {
                "name": "hostname",
                "value": "localhost",
            },
            {
                "name": "port",
                "value": self.port,
            },
            {
                "name": "paths",
                "value": "/kv/k8s/ingress-haproxy/shared/public-certificates",
            },
            {
                "name": "use_xdcgw",
                "value": False,
            },
        ]

        destination_plugin = AdapterDestinationPlugin()
        source_plugin = AdapterSourcePlugin()

        destination_plugin.upload(
            name="star.wild.example.org",
            body=WILDCARD_CERT_STR,
            private_key=WILDCARD_CERT_KEY,
            cert_chain=INTERMEDIATE_CERT_STR,
            options=options,
        )

        endpoints = source_plugin.get_endpoints(options)

        # Verify we got the expected endpoint
        assert len(endpoints) == 1
        endpoint = endpoints[0]

        first_endpoint_path = (
            "/kv/k8s/ingress-haproxy/shared/public-certificates/*.wild.example.org_LemurTrustEnterprisesLtd_RSA2048"
        )
        self.assert_endpoint_values(
            endpoint=endpoint,
            dnsname="*.wild.example.org",
            path=first_endpoint_path,
            registry_type="vault",
            port=443,
            endpoint_type="vault-managed",
        )

        # Upload another certificate and verify both endpoints are returned
        destination_plugin.upload(
            name="lemur-sandbox.datad0g.com",
            body=DIGICERT_ECC256_CERT_STR,
            private_key=WILDCARD_CERT_KEY,
            cert_chain=DIGICERT_ECC_CHAIN_STR,
            options=options,
        )

        endpoints = source_plugin.get_endpoints(options)
        assert len(endpoints) == 2

        # Create a new map with the updated endpoints
        endpoint_map = {endpoint["name"]: endpoint for endpoint in endpoints}

        # Verify both endpoints exist
        assert first_endpoint_path in endpoint_map

        second_endpoint_path = (
            "/kv/k8s/ingress-haproxy/shared/public-certificates/lemur-sandbox.datad0g.com_DigiCert_ECCPRIME256V1"
        )
        assert second_endpoint_path in endpoint_map

        # Verify the new endpoint's data
        new_endpoint = endpoint_map[second_endpoint_path]
        self.assert_endpoint_values(
            endpoint=new_endpoint,
            dnsname="lemur-sandbox.datad0g.com",
            path=second_endpoint_path,
            registry_type="vault",
            port=443,
            endpoint_type="vault-managed",
        )


def are_certs_equal(cert1_pem_string, cert2_pem_string):
    """
    Compare two certificates by their content, formatting is not important.
    Returns True if the certificates are cryptographically identical.
    """
    # Convert PEM strings to certificate objects
    cert1 = load_pem_x509_certificate(cert1_pem_string.encode("utf-8"))
    cert2 = load_pem_x509_certificate(cert2_pem_string.encode("utf-8"))

    # Compare by DER representation
    cert1_der = cert1.public_bytes(encoding=serialization.Encoding.DER)
    cert2_der = cert2.public_bytes(encoding=serialization.Encoding.DER)
    return cert1_der == cert2_der
