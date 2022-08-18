from lemur.plugins.bases import DestinationPlugin


class GCPDestinationPlugin(DestinationPlugin):
    requires_key = False
    title = "GCP"
    slug = "gcp-destination"
    description = "Allow the uploading of certificates to GCP"

    author = "Mitch Cail"
    author_url = "https://github.com/Datadog/lemur"

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):
        try:

            # This is where the logic for uploading a cert will go.

            # - How to upload a cert into GCP?
            # - Looks like we need to configure for global and regional?
            #     - asumming only working with global certs
            # - fetch creds from vault
            ######  from SSL project  ######
            #
            # gcloud compute ssl-certificates create $name \
            #   --private-key=$keyfile \
            #   --certificate=$fullca \
            #   --region=$region
            #


            pass
        except ClientError:
            capture_exception()

    def deploy(self, elb_name, account, region, certificate):
        pass

    def clean(self, certificate, options, **kwargs):
        # This is where the certs will be removed
        pass