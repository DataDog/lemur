"""Helpers for interacting with AWS Certificate Manager."""

from cryptography.hazmat.primitives import hashes
from flask import current_app

from lemur.common.utils import parse_certificate
from lemur.extensions import metrics
from lemur.plugins.lemur_aws.sts import sts_client


# ListCertificates returns only RSA_2048 certificates by default. Explicitly request
# every key type supported by ACM so source discovery and destination idempotency see
# the same complete inventory.
ACM_KEY_TYPES = [
    "RSA_1024",
    "RSA_2048",
    "RSA_3072",
    "RSA_4096",
    "EC_prime256v1",
    "EC_secp384r1",
    "EC_secp521r1",
]


def certificate_fingerprint(body):
    """Return the SHA-256 fingerprint for a PEM-encoded certificate."""
    return parse_certificate(body).fingerprint(hashes.SHA256())


def _get_imported_certificates(client, skip_missing=False):
    """Return the complete imported-certificate inventory for an ACM client.

    Source discovery can ignore an ARN deleted between List and Get. Destination
    deduplication keeps the default fail-closed behavior. All other errors propagate.
    """
    certificates = []
    next_token = None

    while True:
        params = {"Includes": {"keyTypes": ACM_KEY_TYPES}}
        if next_token:
            params["NextToken"] = next_token

        response = client.list_certificates(**params)
        for summary in response.get("CertificateSummaryList", []):
            if summary.get("Type") != "IMPORTED":
                continue

            arn = summary["CertificateArn"]
            try:
                certificate = client.get_certificate(CertificateArn=arn)
            except client.exceptions.ResourceNotFoundException:
                if not skip_missing:
                    raise
                continue
            certificates.append(
                {
                    "arn": arn,
                    "body": certificate["Certificate"],
                    "chain": certificate.get("CertificateChain"),
                }
            )

        next_token = response.get("NextToken")
        if not next_token:
            return certificates


@sts_client("acm")
def get_imported_certificates(**kwargs):
    """Assume the configured account role and return imported ACM certificates."""
    client = kwargs.pop("client")
    certificates = _get_imported_certificates(client, skip_missing=True)
    metrics.send(
        "get_all_acm_certificates",
        "gauge",
        len(certificates),
    )
    return certificates


@sts_client("acm")
def upload_cert(body, private_key, cert_chain=None, **kwargs):
    """Import a certificate unless its fingerprint already exists in the region.

    ACM list results are eventually consistent, so rapid concurrent or post-timeout
    retries can import duplicates before the first import becomes visible.
    """
    assert isinstance(private_key, str)
    client = kwargs.pop("client")
    fingerprint = certificate_fingerprint(body)

    for certificate in _get_imported_certificates(client):
        if certificate_fingerprint(certificate["body"]) == fingerprint:
            current_app.logger.info(
                {
                    "message": "ACM certificate already exists",
                    "certificate_arn": certificate["arn"],
                }
            )
            return {
                "CertificateArn": certificate["arn"],
                "AlreadyExists": True,
            }

    params = {
        "Certificate": body.encode("utf-8"),
        "PrivateKey": private_key.encode("utf-8"),
    }
    if cert_chain:
        params["CertificateChain"] = cert_chain.encode("utf-8")

    response = client.import_certificate(**params)
    metrics.send("upload_acm_cert", "counter", 1)
    current_app.logger.info(
        {
            "message": "Imported certificate into ACM",
            "certificate_arn": response.get("CertificateArn"),
        }
    )
    return response
