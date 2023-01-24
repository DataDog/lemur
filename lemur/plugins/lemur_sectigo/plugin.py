from validators.url import regex as url_regex

from cert_manager import Client
from flask import current_app
from lemur.common.utils import validate_conf
from lemur.plugins.bases import IssuerPlugin


class SectigoIssuerPlugin(IssuerPlugin):
    title = "Sectigo"
    slug = "sectigo-issuer"
    description = "Enables the creation of certificates by the Sectico Certificate Manager (SCM) REST API."

    author = "Bob Shannon"
    author_url = "https://github.com/Datadog/lemur"

    def __init__(self, *args, **kwargs):
        required_vars = [
            "SECTIGO_BASE_URL",
            "SECTIGO_LOGIN_URI",
            "SECTIGO_USERNAME",
            "SECTIGO_PASSWORD",
        ]

        validate_conf(current_app, required_vars)

        self.client = Client(
            base_url=current_app.config.get("SECTIGO_BASE_URL"),
            login_uri=current_app.config.get("SECTIGO_LOGIN_URI"),
            username=current_app.config.get("SECTIGO_USERNAME"),
            password=current_app.config.get("SECTIGO_PASSWORD"),
        )

        super(SectigoIssuerPlugin, self).__init__(*args, **kwargs)

    def create_certificate(self, csr, issuer_options):
        raise NotImplementedError

    def create_authority(self, options):
        raise NotImplementedError

    def revoke_certificate(self, certificate, reason):
        raise NotImplementedError

    def get_ordered_certificate(self, certificate):
        raise NotImplementedError

    def cancel_ordered_certificate(self, pending_cert, **kwargs):
        raise NotImplementedError
