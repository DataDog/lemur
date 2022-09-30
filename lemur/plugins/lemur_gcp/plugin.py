from flask import current_app
from google.cloud.compute_v1.services import ssl_certificates

from lemur.common.utils import parse_certificate, split_pem
from lemur.common.defaults import common_name, issuer, not_before
from lemur.plugins.bases import DestinationPlugin, SourcePlugin
from lemur.plugins import lemur_gcp as gcp
from lemur.plugins.lemur_gcp import auth
from lemur.plugins.lemur_gcp.endpoints import fetch_target_proxies, update_target_proxy_cert


class GCPDestinationPlugin(DestinationPlugin):
    title = "GCP"
    slug = "gcp-destination"
    version = gcp.VERSION
    description = "Allow the uploading of certificates to GCP"
    author = "Mitch Cail"
    author_url = "https://github.com/Datadog/lemur"

    options = [
        {
            "name": "projectID",
            "type": "str",
            "required": True,
            "helpMessage": "GCP Project ID",
        },
        {
            "name": "authenticationMethod",
            "type": "select",
            "required": True,
            "available": ["vault", "serviceAccountToken"],
            "helpMessage": "Authentication method to use",
        },
        {
            "name": "vaultMountPoint",
            "type": "str",
            "required": False,
            "helpMessage": "Path to vault secret",
        },
        {
            "name": "serviceAccountTokenPath",
            "type": "str",
            "required": False,
            "helpMessage": "Path to vault secret",
        }
    ]

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):
        try:
            ssl_certificate_body = {
                "name": self._certificate_name(body),
                "certificate": self._full_ca(body, cert_chain),
                "description": "",
                "private_key": private_key,
            }
            credentials = auth.get_gcp_credentials(self, options)
            return self._insert_gcp_certificate(
                self.get_option("projectID", options),
                ssl_certificate_body,
                credentials,
            )

        except Exception as e:
            if "already exists" in str(e):
                return
            current_app.logger.error(
                f"Issue with uploading {name} to GCP. Action failed with the following log: {e}",
                exc_info=True,
            )
            raise Exception(f"Issue uploading certificate to GCP: {e}")

    def _insert_gcp_certificate(self, project_id, ssl_certificate_body, credentials):
        return ssl_certificates.SslCertificatesClient(credentials=credentials).insert(
            project=project_id, ssl_certificate_resource=ssl_certificate_body
        )

    def _certificate_name(self, body):
        """
        We need to change the name of the certificate that we are uploading to comply with GCP naming standards.
        The cert name will follow the convention "ssl-{Cert CN}-{Date Issued}-{Issuer}"
        """
        cert = parse_certificate(body)
        cn = common_name(cert)
        authority = issuer(cert)
        issued_on = not_before(cert).date()

        cert_name = f"ssl-{cn}-{authority}-{issued_on}"

        return self._modify_cert_name_for_gcp(cert_name)

    def _modify_cert_name_for_gcp(self, cert_name):
        # Modify the cert name to comply with GCP naming convention
        gcp_name = cert_name.replace('.', '-')
        gcp_name = gcp_name.replace('*', "star")
        gcp_name = gcp_name.lower()
        gcp_name = gcp_name[:63]
        gcp_name = gcp_name.rstrip('.*-')

        return gcp_name

    def _full_ca(self, body, cert_chain):
        # in GCP you need to assemble the cert body and the cert chain in the same parameter
        return f"{body}\n{cert_chain}"


class GCPSourcePlugin(SourcePlugin):
    title = "GCP"
    slug = "gcp-source"
    description = "Discovers all SSL certificates and HTTPs target proxies (global) / L7 and SSL target proxies / L4"
    version = gcp.VERSION

    author = "Henry Wang"
    author_url = "https://github.com/Datadog/lemur"

    options = [
        {
            "name": "projectID",
            "type": "str",
            "required": True,
            "helpMessage": "GCP Project ID",
        },
        {
            "name": "authenticationMethod",
            "type": "select",
            "required": True,
            "available": ["vault", "serviceAccountToken"],
            "helpMessage": "Authentication method to use",
        },
        {
            "name": "vaultMountPoint",
            "type": "str",
            "required": False,
            "helpMessage": "Path to vault secret",
        },
        {
            "name": "serviceAccountTokenPath",
            "type": "str",
            "required": False,
            "helpMessage": "Path to vault secret",
        }
    ]

    def get_certificates(self, options, **kwargs):
        try:
            credentials = auth.get_gcp_credentials(self, options)
            project_id = self.get_option("projectID", options)
            client = ssl_certificates.SslCertificatesClient(credentials=credentials)
            certs = []
            for cert_meta in client.list(project=project_id):
                try:
                    if cert_meta.type_ != "SELF_MANAGED":
                        continue
                    cert = self.parse_certificate_meta(cert_meta)
                    if cert:
                        certs.append(cert)
                except Exception as e:
                    current_app.logger.error(
                        f"Issue with fetching certificate {cert_meta.name} from GCP. Action failed with the following "
                        f"log: {e}",
                        exc_info=True,
                    )
            return certs
        except Exception as e:
            current_app.logger.error(
                f"Issue with fetching certificates from GCP. Action failed with the following log: {e}",
                exc_info=True,
            )
            raise Exception(f"Issue fetching certificates from GCP: {e}")

    def get_certificate_by_name(self, certificate_name, options):
        try:
            credentials = auth.get_gcp_credentials(self, options)
            project_id = self.get_option("projectID", options)
            client = ssl_certificates.SslCertificatesClient(credentials=credentials)
            cert_meta = client.get(project=project_id, ssl_certificate=certificate_name)
            if cert_meta:
                cert = self.parse_certificate_meta(cert_meta)
                if cert:
                    return cert
            return None
        except Exception as e:
            current_app.logger.error(
                f"Issue with fetching certificate by name from GCP. Action failed with the following log: {e}",
                exc_info=True,
            )
            raise Exception(f"Issue fetching certificate from GCP: {e}")

    @staticmethod
    def parse_certificate_meta(certificate_meta):
        """
        Returns a body and a chain.
        :param certificate_meta:
        """
        chain = []
        # Skip CSR if it's part of the certificate returned by the GCP API.
        for cert in split_pem(certificate_meta.certificate):
            if "-----BEGIN CERTIFICATE-----" in cert:
                chain.append(cert)
        if not chain:
            return None
        return dict(
            body=chain[0],
            chain="\n".join(chain[1:]),
            name=certificate_meta.name,
        )

    def get_endpoints(self, options, **kwargs):
        try:
            credentials = auth.get_gcp_credentials(self, options)
            project_id = self.get_option("projectID", options)
            endpoints = fetch_target_proxies(project_id, credentials)
            return endpoints
        except Exception as e:
            current_app.logger.error(
                f"Issue with fetching endpoints from GCP. Action failed with the following log: {e}",
                exc_info=True,
            )
            raise Exception(f"Issue fetching endpoints from GCP: {e}")

    def update_endpoint(self, endpoint, certificate):
        options = endpoint.source.options
        credentials = auth.get_gcp_credentials(self, options)
        project_id = self.get_option("projectID", options)
        update_target_proxy_cert(project_id, credentials, endpoint, certificate)

    def clean(self, certificate, options, **kwargs):
        raise NotImplementedError
