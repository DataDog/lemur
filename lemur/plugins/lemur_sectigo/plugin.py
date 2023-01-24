import arrow
import pem

from cert_manager import Client, Organization, Pending, SSL
from flask import current_app
from lemur.common.utils import validate_conf
from lemur.plugins.bases import IssuerPlugin
from retrying import retry

_MAX_CERTIFICATE_VALIDITY_DAYS = (
    397  # No public certificate can be valid for more than 397 days.
)


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
            "SECTIGO_ORG_NAME",
            "SECTIGO_CERT_TYPE",
            "SECTIGO_ROOT",
        ]

        validate_conf(current_app, required_vars)

        self.client = Client(
            base_url=current_app.config.get("SECTIGO_BASE_URL"),
            login_uri=current_app.config.get("SECTIGO_LOGIN_URI"),
            username=current_app.config.get("SECTIGO_USERNAME"),
            password=current_app.config.get("SECTIGO_PASSWORD"),
        )
        self.org = Organization(client=self.client)
        self.ssl = SSL(client=self.client)

        super(SectigoIssuerPlugin, self).__init__(*args, **kwargs)

    def create_certificate(self, csr, issuer_options):
        cert_org = self.org.find(org_name=current_app.config.get("SECTIGO_ORG_NAME"))
        cert_type = current_app.config.get("SECTIGO_CERT_TYPE")
        cert_validity_days = _MAX_CERTIFICATE_VALIDITY_DAYS

        min_start = arrow.utcnow()
        max_end = arrow.utcnow().shift(days=_MAX_CERTIFICATE_VALIDITY_DAYS)
        validity_end = issuer_options.get("validity_end", max_end)
        if min_start <= validity_end <= max_end:
            cert_validity_days = (validity_end - min_start).days

        result = self.ssl.enroll(
            cert_type_name=cert_type,
            csr=csr,
            term=cert_validity_days,
            org_id=cert_org[0]["id"],
        )
        current_app.logger.info(
            {
                "message": "Issued Sectigo certificate.",
                "term": cert_validity_days,
                "cert_type": cert_type,
                "cert_org": cert_org,
                "result": result,
            }
        )

        @retry(wait_fixed=2000, stop_max_delay=300000)
        def collect_certificate():
            """
            Collect the certificate from Sectigo.
            """
            try:
                current_app.logger.info(
                    {"message": "Collecting certificate from Sectigo..."}
                )
                cert_pem = self.ssl.collect(cert_id=result["sslId"], cert_format="pem")
                end_entity, intermediate, root = pem.parse(cert_pem)
                return (
                    "\n".join(str(end_entity).splitlines()),
                    "\n".join(str(intermediate).splitlines()),
                    result["sslId"],
                )
            except Pending:
                current_app.logger.info(
                    {"message": "Certificate is still pending, will retry collecting it again..."}
                )
                raise
            except Exception:
                current_app.logger.error(
                    {"message": "Collection attempt failed."},
                    exc_info=True,
                )

        return collect_certificate()

    def create_authority(self, options):
        name = "sectigo_" + "_".join(options["name"].split(" ")) + "_admin"
        role = {"username": "", "password": "", "name": name}
        return current_app.config.get("SECTIGO_ROOT"), "", [role]

    def revoke_certificate(self, certificate, reason):
        raise NotImplementedError

    def get_ordered_certificate(self, certificate):
        raise NotImplementedError

    def cancel_ordered_certificate(self, pending_cert, **kwargs):
        raise NotImplementedError
