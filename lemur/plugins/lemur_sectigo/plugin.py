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
        validity_end = issuer_options.get("validity_end")
        supported_terms = ssl.types[cert_type]["terms"]
        cert_validity_days = _determine_certificate_term(validity_end, supported_terms)

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

        return _collect_certificate(result["sslId"], ssl)

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


def _retry_if_certificate_pending(exception):
    return isinstance(exception, Pending)


@retry(
    wait_fixed=2000,
    stop_max_delay=300000,
    retry_on_exception=_retry_if_certificate_pending,
)
def _collect_certificate(cert_id, ssl_client):
    """
    Collect the certificate from Sectigo.
    """
    try:
        current_app.logger.info({"message": "Collecting certificate from Sectigo..."})
        cert_pem = ssl_client.collect(cert_id=cert_id, cert_format="pem")
        parts = pem.parse(cert_pem.encode("utf-8"))
        ca_bundle = [str(c) for c in parts[:-1]]
        ca_bundle.reverse()
        ca_bundle = "".join(ca_bundle)
        issued_cert = str(parts[-1])

        return (
            issued_cert,
            ca_bundle,
            cert_id,
        )
    except Pending:
        current_app.logger.info(
            {
                "message": "Certificate is still pending, will retry collecting it again..."
            }
        )
        raise


def _determine_certificate_term(validity_end, supported_terms):
    min_start = arrow.utcnow()
    max_end = arrow.utcnow().shift(days=_MAX_CERTIFICATE_VALIDITY_DAYS)
    cert_term_days = _MAX_CERTIFICATE_VALIDITY_DAYS
    if min_start <= validity_end <= max_end:
        current_app.logger.warning(
            {
                "message": f"Requested certificate with a term greater than the maximum allowed "
                f"of {_MAX_CERTIFICATE_VALIDITY_DAYS} days. Certificate will be therefore be "
                f"issued with the maximum allowed {_MAX_CERTIFICATE_VALIDITY_DAYS} day term."
            }
        )
        cert_term_days = (validity_end - min_start).days

    if cert_term_days not in supported_terms:
        unsupported_cert_term_days = cert_term_days
        supported_cert_term_days = min(
            supported_terms, key=lambda x: abs(x - unsupported_cert_term_days)
        )
        current_app.logger.warning(
            {
                "message": f"Requested certificate with {unsupported_cert_term_days} day term but only the "
                f"following terms are only supported: {supported_terms}. Certificate will instead "
                f"be issued with a {supported_cert_term_days} day term."
            }
        )
        return supported_cert_term_days

    return cert_term_days
