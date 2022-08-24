from google.cloud.compute_v1.services import ssl_certificates
from sentry_sdk import capture_exception
import os

from lemur.plugins.bases import DestinationPlugin


class GCPDestinationPlugin(DestinationPlugin):
    title = "GCP"
    slug = "gcp-destination"
    description = "Allow the uploading of certificates to GCP"
    version = lemur_gcp.VERSION
    author = "Mitch Cail"
    author_url = "https://github.com/Datadog/lemur"

    options = []

    def upload(self, certificate_name, description, private_key, certificate, project_id, **kwargs):
        """
        Args:
        project_id: project ID or project number of the Cloud project you want to use.
        certificate_file: path to the file with the certificate you want to create in your project.
        private_key_file: path to the private key you used to sign the certificate with.
        certificate_name: name for the certificate once it's created in your project.
        description: description of the certificate.

        *NOTE: We are relying on the GOOGLE_APPLICATION_CREDENTIALS env variable to be set to authenticate
        """
        try:
            ssl_certificate_body = {
                "name": certificate_name,
                "description": description,
                "certificate": certificate,
                "private_key": private_key,
            }

            return self._insert_gcp_certificate(project_id, ssl_certificate_body)

        # TODO: better error handling
        except ClientError:
            capture_exception()

    def deploy(self, elb_name, account, region, certificate):
        pass

    def clean(self, certificate, options, **kwargs):
        # This is where the certs will be removed
        pass

    def _insert_gcp_certificate(self, project_id, ssl_certificate_body):
        return ssl_certificates.SslCertificatesClient().insert(
            project=project_id, ssl_certificate_resource=ssl_certificate_body
        )