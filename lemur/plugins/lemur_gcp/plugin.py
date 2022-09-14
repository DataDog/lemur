from flask import current_app
from google.cloud.compute_v1.services import ssl_certificates
from google.oauth2 import service_account
import google.auth
import hvac
import os

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
            "name": "Account Id",
            "type": "str",
            "required": True,
            "helpMessage": "GCP Project ID",
        },
        {
            "name": "Service Account Name",
            "type": "str",
            "required": True,
            "helpMessage": "GCP Service Account Name",
        },
        {
            "name": "Use Vault",
            "type": "bool",
            "required": True,
            "helpMessage": "using vault for authentication?",
            "default": False,
        },
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
                "name": name,
                "certificate": body,
                "description": "",
                "private_key": private_key,
            }
            credentials = self._get_gcp_credentials(options)
            return self._insert_gcp_certificate(
                self.get_option("accountName", options),
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

        if self.get_option('Use Vault', options) is True:
            # make a request to vault for GCP token
            return self._get_gcp_credentials_from_vault(options)
        elif current_app.config.get("GOOGLE_APPLICATION_CREDENTIALS") is not None:
            return service_account.Credentials.from_service_account_file(
                current_app.config.get("GOOGLE_APPLICATION_CREDENTIALS")
            )
        else:
            raise Exception("No supported way to authenticate with GCP")

    def _get_gcp_credentials_from_vault(self, options):
        service_token = hvac.Client(os.environ['VAULT_ADDR']) \
            .secrets.gcp \
            .generate_oauth2_access_token(
            roleset="",
            mount_point=f"cloud-iam/gcp/{self.get_option('Account Id', options)}/impersonated-account/{self.get_option('serviceAccountName', options)}"
        )["data"]["token"].rstrip(".")
        credentials, _ = google.auth.default()  # Fetch the default credentials from Emissary Native IAM
        credentials.token = service_token  # replace the token from Native IAM with the Dataproc token fetched from Vault

        return credentials
