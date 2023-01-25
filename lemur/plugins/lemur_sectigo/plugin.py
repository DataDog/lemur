import arrow
import pem

from cert_manager import Client, Organization, Pending, SSL
from flask import current_app
from lemur.common.utils import validate_conf
from lemur.plugins.bases import IssuerPlugin
from retrying import retry

_MAX_CERTIFICATE_VALIDITY_DAYS = 365  # No public certificate can be valid for more than 397 days, and Sectigo only supports up-to 365 day terms.


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

        super(SectigoIssuerPlugin, self).__init__(*args, **kwargs)

    def create_certificate(self, csr, issuer_options):
        org = Organization(client=self.client)
        ssl = SSL(client=self.client)

        cert_org = org.find(org_name=current_app.config.get("SECTIGO_ORG_NAME"))
        cert_type = current_app.config.get("SECTIGO_CERT_TYPE")
        cert_validity_days = _MAX_CERTIFICATE_VALIDITY_DAYS

        min_start = arrow.utcnow()
        max_end = arrow.utcnow().shift(days=_MAX_CERTIFICATE_VALIDITY_DAYS)
        validity_end = issuer_options.get("validity_end", max_end)
        if min_start <= validity_end <= max_end:
            current_app.logger.warning(
                {
                    "message": f"Requested certificate with a term greater than the maximum allowed "
                    f"of {_MAX_CERTIFICATE_VALIDITY_DAYS} days. Certificate will be therefore be "
                    f"issued with the maximum allowed {_MAX_CERTIFICATE_VALIDITY_DAYS} day term."
                }
            )
            cert_validity_days = (validity_end - min_start).days

        supported_terms = ssl.types[cert_type]["terms"]
        if cert_validity_days not in supported_terms:
            requested_validity = cert_validity_days
            cert_validity_days = min(
                supported_terms, key=lambda x: abs(x - requested_validity)
            )
            current_app.logger.warning(
                {
                    "message": f"Requested certificate with {requested_validity} day term but only the "
                    f"following terms are only supported: {supported_terms}. Certificate will instead "
                    f"be issued with a {cert_validity_days} day term."
                }
            )

        result = ssl.enroll(
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

        @retry(
            wait_fixed=2000,
            stop_max_delay=300000,
            retry_on_exception=retry_if_certificate_pending,
        )
        def collect_certificate():
            """
            Collect the certificate from Sectigo.
            """
            try:
                current_app.logger.info(
                    {"message": "Collecting certificate from Sectigo..."}
                )
                cert_pem = ssl.collect(cert_id=result["sslId"], cert_format="pem")
                parts = pem.parse(cert_pem.encode("utf-8"))
                ca_bundle = [str(c) for c in parts[:-1]]
                ca_bundle.reverse()
                ca_bundle = "".join(ca_bundle)
                issued_cert = str(parts[-1])

                return (
                    issued_cert,
                    ca_bundle,
                    result["sslId"],
                )
            except Pending:
                current_app.logger.info(
                    {
                        "message": "Certificate is still pending, will retry collecting it again..."
                    }
                )
                raise

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


def retry_if_certificate_pending(exception):
    return isinstance(exception, Pending)
