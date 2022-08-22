from googleapiclient import discovery
from sentry_sdk import capture_exception
import os

from lemur.plugins.bases import DestinationPlugin


class GCPDestinationPlugin(DestinationPlugin):
    requires_key = False
    title = "GCP"
    slug = "gcp-destination"
    description = "Allow the uploading of certificates to GCP"

    author = "Mitch Cail"
    author_url = "https://github.com/Datadog/lemur"

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
            service = discovery.build("compute", "v1")

            ssl_certificate_body = {
                "name": certificate_name,
                "description": description,
                "certificate": certificate,
                "privateKey": private_key,
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
        service = discovery.build("compute", "v1")

        response = service.sslCertificates().insert(
            project=project_id, body=ssl_certificate_body
        )

        return response.execute()