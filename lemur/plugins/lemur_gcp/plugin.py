from flask import current_app
from google.cloud.compute_v1.services import ssl_certificates
from google.oauth2 import service_account
import google.auth
import hvac
import os

from lemur.common.utils import parse_certificate
from lemur.common.defaults import common_name, issuer, not_before
from lemur.plugins.bases import DestinationPlugin
from lemur.plugins import lemur_gcp as gcp


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
        """
        Args:
        certificate_file: path to the file with the certificate you want to create in your project.
        private_key_file: path to the private key you used to sign the certificate with.
        certificate_name: name for the certificate once it's created in your project.

        """

        try:
            ssl_certificate_body = {
                "name": self._gcp_name(body),
                "certificate": body,
                "description": "",
                "private_key": private_key,
            }
            credentials = self._get_gcp_credentials(options)
            return self._insert_gcp_certificate(
                self.get_option("projectID", options),
                ssl_certificate_body,
                credentials,
            )

        except Exception as e:
            current_app.logger.error(
                f"Issue with uploading {name} to GCP. Action failed with the following log: {e}",
                exc_info=True,
            )
            raise Exception(f"Issue uploading certificate to GCP: {e}")

    def _insert_gcp_certificate(self, project_id, ssl_certificate_body, credentials):
        return ssl_certificates.SslCertificatesClient(credentials=credentials).insert(
            project=project_id, ssl_certificate_resource=ssl_certificate_body
        )

    def _get_gcp_credentials(self, options):
        if self.get_option('authenticationMethod', options) == "vault":
            # make a request to vault for GCP token
            return self._get_gcp_credentials_from_vault(options)
        elif self.get_option('authenticationMethod', options) == "serviceAccountToken":
            if self.get_option('serviceAccountTokenPath', options) is not None:
                return service_account.Credentials.from_service_account_file(
                    self.get_option('serviceAccountTokenPath', options)
                )

        raise Exception("No supported way to authenticate with GCP")

    def _get_gcp_credentials_from_vault(self, options):
        service_token = hvac.Client(os.environ['VAULT_ADDR']) \
            .secrets.gcp \
            .generate_oauth2_access_token(
            roleset="",
            mount_point=f"{self.get_option('vaultMountPoint', options)}"
        )["data"]["token"].rstrip(".")
        credentials, _ = google.auth.default()  # Fetch default GCP credentials current environment
        credentials.token = service_token  # replace the token from Native IAM with the Dataproc token fetched from Vault

        return credentials

    def _gcp_name(self, body):
        cert = parse_certificate(body)
        cn = common_name(cert)
        authority = issuer(cert)
        issued_on = not_before(cert).date()
        # we need to replace any '.' or '*' chars to comply with GCP naming
        gcp_name = f"ssl-{cn}-{authority}-{issued_on}".replace('.', '-').replace('*', "star")

        return gcp_name