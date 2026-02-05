from cryptography.x509 import OID_ORGANIZATION_NAME, load_pem_x509_certificates, NameOID
from cryptography.hazmat.primitives import serialization
from lemur.plugins.lemur_coa.pb import (
    service_pb2_grpc as adapter_pb2_grpc,
    service_pb2 as adapter_pb2,
)
from dd_internal_authentication.client import (
    JWTInternalServiceAuthClientTokenManager,
)
from flask import current_app
from lemur.common.utils import (
    check_validation,
    parse_certificate,
    get_key_type_from_certificate,
)
from lemur.common.defaults import common_name
from lemur.plugins.bases import DestinationPlugin, SourcePlugin
import grpc
import os


def create_coa_connection(plugin, options):
    """Create a connection to the Certificate Orchestration Adapter service."""

    # if we are are NOT using the xdcgw, then send the request to the hostname and port defined in the options.
    # otherwise, send the request to the source xdcgw endpoint.
    if plugin.get_option("use_xdcgw", options) is False:
        hostname = plugin.get_option("hostname", options)
        port = plugin.get_option("port", options)
        endpoint = f"{hostname}:{port}"
        # setup an insecure channel if we are using localhost, otherwise use ssl
        channel_type = grpc.local_channel_credentials() if hostname == "localhost" else grpc.ssl_channel_credentials()
    else:
        endpoint = "source-crossdc-gateway.service-discovery.all-clusters.local-dc.fabric.dog:8081"
        channel_type = grpc.ssl_channel_credentials()

    host = plugin.get_option("hostname", options)

    token_manager_args = {}
    if plugin.get_option("use_ticino", options):
        token_manager_args["issuer"] = "sycamore"

    token_manager = JWTInternalServiceAuthClientTokenManager(**token_manager_args)
    token = token_manager.get_token(plugin.get_option("audience", options))
    grpc_options = [
        ("grpc.default_authority", host),
        ("grpc.ssl_target_name_override", endpoint),
    ]

    channel = grpc.secure_channel(endpoint, channel_type, options=grpc_options)
    stub = adapter_pb2_grpc.CertificateStub(channel)

    paths = plugin.get_option("paths", options)
    if not paths:
        paths_list = []
    else:
        paths_list = paths.split(",")

    auth_token = ("authorization", f"Bearer {token}")

    return stub, channel, paths_list, host, auth_token


class AdapterDestinationPlugin(DestinationPlugin):
    title = "Cert Orchestration Adapter"
    slug = "cert-orchestration-adapter-dest"
    description = "Uploads certificates to cross-DC Vault instances using the Cert Orchestration Adapter service."

    author = "Bob Shannon"
    author_url = "https://github.com/DataDog/lemur"

    options = [
        {
            "name": "audience",
            "type": "str",
            "required": True,
            "helpMessage": "Audience claim for the JWT used to authenticate with the Cert Orchestration Adapter service.",
        },
        {
            "name": "hostname",
            "type": "str",
            "required": True,
            "validation": check_validation("^.*.fabric.dog|localhost$"),  # Match a fabric DNS name or localhost.
            "helpMessage": "Hostname of the endpoint to use when connecting to the Cert Orchestration Adapter service. "
            "Must be a valid Fabric DNS name or localhost.",
        },
        {
            "name": "port",
            "type": "int",
            "required": True,
            "validation": check_validation(r"^\d+$"),  # Match one or more repeating digits.
            "helpMessage": "Port of the endpoint to use when connecting to the Cert Orchestration Adapter.",
        },
        {
            "name": "paths",
            "type": "str",
            "required": True,
            "validation": check_validation(r"^(/[\w-]+)+(,[/\w-]+)*$"),  # Match a comma delimited list of file paths.
            "helpMessage": "Comma delimited list of paths to upload each certificate to.",
        },
        {
            "name": "use_xdcgw",
            "type": "bool",
            "required": True,
            "helpMessage": "If this request needs to be proxied through the Cross DC Gateway",
            "default": True,
        },
        {
            "name": "use_ticino",
            "type": "bool",
            "required": True,
            "helpMessage": "If this request should use Ticino tokens for cross-DC ISA",
            "default": False,
        },
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):
        """
        Uploads a certificate to the configured Cert Orchestration Adapter service.
        """
        try:
            stub, channel, paths_list, host, auth_token = create_coa_connection(self, options)

            if not paths_list:
                current_app.logger.error("No paths provided for certificate upload")
                return

            with channel:
                for path in paths_list:
                    current_app.logger.info(
                        {
                            "message": "Uploading certificate to cross-DC vault instance via Cert Orchestration Adapter service.",
                            "name": name,
                            "endpoint": host,
                            "path": path,
                        }
                    )

                    parsed_crt = parse_certificate(body)
                    parsed_chain = parse_certificate(cert_chain)
                    ca_vendor = parse_ca_vendor(parsed_chain)
                    key_type = get_key_type_from_certificate(body)
                    crt_name = f"{common_name(parsed_crt)}_{ca_vendor}_{key_type}"

                    stub.Upload(
                        request=adapter_pb2.CertificateUploadRequest(
                            certificate=body,
                            intermediate=cert_chain,
                            private_key=private_key,
                            vault_path=os.path.join(path, crt_name),
                        ),
                        metadata=[auth_token],
                    )
        except Exception as e:
            current_app.logger.error(f"Error uploading certificate: {e}", exc_info=True)
            raise


class AdapterSourcePlugin(SourcePlugin):
    title = "Cert Orchestration Adapter"
    slug = "coa-source"
    description = "Retrieves certificates from cross-DC Vault instances using the Cert Orchestration Adapter service."

    author = "Maxime Perusse"
    author_url = "https://github.com/DataDog/lemur"

    has_active_endpoint = (
        True  # certificates stored in vault via COA should always be included in certificate metrics and monitoring
    )

    options = [
        {
            "name": "audience",
            "type": "str",
            "required": True,
            "helpMessage": "Audience claim for the JWT used to authenticate with the Cert Orchestration Adapter service.",
        },
        {
            "name": "hostname",
            "type": "str",
            "required": True,
            "validation": check_validation("^.*.fabric.dog|localhost$"),  # Match a fabric DNS name or localhost.
            "helpMessage": "Hostname of the endpoint to use when connecting to the Cert Orchestration Adapter service. "
            "Must be a valid Fabric DNS name or localhost.",
        },
        {
            "name": "port",
            "type": "int",
            "required": True,
            "helpMessage": "Port of the endpoint to use when connecting to the Cert Orchestration Adapter.",
        },
        {
            "name": "paths",
            "type": "str",
            "required": True,
            "validation": check_validation(r"^(/[\w-]+)+(,[/\w-]+)*$"),  # Match a comma delimited list of file paths.
            "helpMessage": "Comma delimited list of paths used to scan for certificates.",
        },
        {
            "name": "use_xdcgw",
            "type": "bool",
            "required": True,
            "helpMessage": "If this request needs to be proxied through the Cross DC Gateway",
            "default": True,
        },
        {
            "name": "use_ticino",
            "type": "bool",
            "required": True,
            "helpMessage": "If this request should use Ticino tokens for cross-DC ISA",
            "default": False,
        },
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_certificates(self, options):
        """
        Pull certificates from the configured Cert Orchestration Adapter service.
        Returns a list of dictionaries containing the certificate PEM body, chain, and a name.
        """
        certificate_data = []

        try:
            certificates = self.fetch_certificates_from_paths(options)

            for cert_obj in certificates:
                try:
                    cert_info = self.extract_certificate_info(cert_obj.certificate, include_cert_chain=True)
                    certificate_data.append(cert_info)
                except Exception as e:
                    current_app.logger.warning(f"Error parsing certificate: {e}", exc_info=True)
                    # Add the certificate with a generic name if parsing fails
                    certificate_data.append(
                        {
                            "body": cert_obj.certificate,
                            "name": f"unknown-cert-{len(certificate_data)}",
                            "chain": None,
                        }
                    )
        except Exception as e:
            current_app.logger.error(f"Error retrieving certificates: {e}", exc_info=True)

        return certificate_data

    def get_certificate_by_name(self, certificate_name, options):
        """
        Retrieves a specific certificate by its Common Name (CN) from the available certificates.
        """
        current_app.logger.info(f"Looking for certificate with Common Name: {certificate_name}")

        # Get all certificates and filter by common name
        certificates = self.get_certificates(options)

        for cert in certificates:
            if cert.get("name") == certificate_name:
                current_app.logger.info(f"Found certificate with Common Name: {certificate_name}")
                return cert

        current_app.logger.warning(f"Certificate with Common Name '{certificate_name}' not found")
        return None

    def get_endpoints(self, options, **kwargs):
        """Returns endpoints for certificates stored in Vault using the Cert Orchestration Adapter."""
        endpoints = []

        try:
            certificates = self.fetch_certificates_from_paths(options)

            for cert_obj in certificates:
                try:
                    cert_info = self.extract_certificate_info(cert_obj.certificate, include_cert_chain=False)

                    # Create endpoint entry using certificate data from Vault
                    endpoint = {
                        "name": cert_obj.vault_path,
                        "dnsname": cert_info["name"],
                        "type": "vault-managed",
                        "port": 443,
                        "policy": {
                            "name": f"policy-{cert_info['name']}-vault",
                            "ciphers": [],  # we do not enforce any Cipher policies during certificate pull operations
                        },
                        "primary_certificate": {
                            "name": cert_info["name"],
                            "path": cert_obj.vault_path,
                            "registry_type": "vault",
                        },
                    }
                    endpoints.append(endpoint)
                except Exception as e:
                    current_app.logger.warning(
                        f"Error processing certificate for endpoint: {e}",
                        exc_info=True,
                    )
        except Exception as e:
            current_app.logger.error(f"Error discovering vault certificate endpoints: {e}")

        return endpoints

    def fetch_certificates_from_paths(self, options):
        """
        Fetches certificates from all configured paths.
        Returns flat list of certificate objects.
        """
        certificates = []

        stub, channel, paths_list, host, auth_token = create_coa_connection(self, options)

        if not paths_list:
            current_app.logger.error("No paths provided for certificate operations")
            return []

        with channel:
            for path in paths_list:
                current_app.logger.info(
                    {
                        "message": "Fetching certificates from cross-DC vault instance",
                        "endpoint": host,
                        "path": path,
                    }
                )

                try:
                    response = stub.List(
                        request=adapter_pb2.ListCertificatesRequest(vault_path=path),
                        metadata=[auth_token],
                    )
                    certificates.extend(response.certificates)
                except Exception as e:
                    current_app.logger.error(f"Error listing certificates at {path}: {e}")

        return certificates

    def extract_certificate_info(self, cert_pem, include_cert_chain):
        """
        Extracts information from a PEM-formatted certificate string including common name,
        certificate body, and optionally the certificate chain.
        Returns a dictionary with the extracted certificate information.
        """
        certs = list(load_pem_x509_certificates(cert_pem.encode("utf-8")))

        if not certs:
            raise ValueError("No certificates found in PEM data")

        # First certificate is the leaf certificate
        leaf_cert = certs[0]
        common_name = leaf_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

        # Convert the leaf certificate back to PEM format to extract the body
        body = leaf_cert.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8")

        result = {
            "name": common_name,
            "body": body,
        }

        if include_cert_chain and len(certs) > 1:
            # Convert the chain certificates back to PEM format
            chain_pem = b""
            for cert in certs[1:]:
                # NOTE: Potential enhancement: We could add validation here to check if certificates
                # are CA certificates by examining cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca
                # This would allow us to filter out non-CA certificates that shouldn't be in the chain.
                #
                # NOTE: Another enhancement would be to validate certificate order by checking
                # cert.subject and cert.issuer relationships to ensure certificates are in the
                # correct hierarchical order. If they're not, we could reorder them properly.
                #
                # Since these issues can cause certificate validation failures in certain clients, we should
                # flag problematic certificate chains. Currently, we accept chains as-is without validation,
                # which might lead to silent failures in downstream systems.
                chain_pem += cert.public_bytes(encoding=serialization.Encoding.PEM)

            result["chain"] = chain_pem.decode("utf-8") if chain_pem else None

        return result


def parse_ca_vendor(chain):
    org_name = chain.subject.get_attributes_for_oid(OID_ORGANIZATION_NAME)[0].value.strip()
    if "DigiCert" in org_name:
        return "DigiCert"
    elif "Sectigo" in org_name:
        return "Sectigo"
    return org_name.replace(" ", "").strip()
