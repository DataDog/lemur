from google.cloud.compute_v1.services import ssl_certificates
from google.oauth2 import service_account
from sentry_sdk import capture_exception
from flask import current_app

from lemur.plugins.bases import DestinationPlugin


class GCPDestinationPlugin(DestinationPlugin):
    title = "GCP"
    slug = "gcp-destination"
    description = "Allow the uploading of certificates to GCP"
    author = "Mitch Cail"
    author_url = "https://github.com/Datadog/lemur"

    options = [
        {
            "name": "accountName",
            "type": "str",
            "required": True,
            "helpMessage": "GCP Project Name",
        }
    ]

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):
        """
        Args:
        certificate_file: path to the file with the certificate you want to create in your project.
        private_key_file: path to the private key you used to sign the certificate with.
        certificate_name: name for the certificate once it's created in your project.

        *NOTE: We are relying on the GOOGLE_APPLICATION_CREDENTIALS env variable to be set to authenticate
        """

        try:
            ssl_certificate_body = {
                "name": name,
                "certificate": body,
                "private_key": private_key,
            }

            return self._insert_gcp_certificate(self.get_option("accountName", options), ssl_certificate_body)

        # TODO: better error handling
        except Exception as e:
            current_app.logger.warn(
                f"Issue with uploading a {name} to GCP. Action failed with the following log: {e}", exc_info=True
            )
            capture_exception()

    def _insert_gcp_certificate(self, project_id, ssl_certificate_body):

        credentials = service_account.Credentials.from_service_account_file('/tmp/authentication.json')
        return ssl_certificates.SslCertificatesClient(credentials=credentials).insert(
            project=project_id, ssl_certificate_resource=ssl_certificate_body
        )
