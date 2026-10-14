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
def upload_cert(body, private_key, cert_chain=None, replaces=(), **kwargs):
    """Import new certificates, or reimport an explicit replacement at the same ARN.

    Reimport deploys the renewal to all consumers of the ARN as AWS propagates it.
    It does not wait for Lemur's endpoint rotation task.

    ACM list results are eventually consistent, so rapid concurrent or post-timeout
    retries can import duplicates before the first import becomes visible.
    """
    assert isinstance(private_key, str)
    client = kwargs.pop("client")
    fingerprint = certificate_fingerprint(body)
    if len(replaces) > 1:
        raise ValueError(
            "ACM reimport supports at most one predecessor certificate. "
            "Multiple predecessors may map to different ACM ARNs, and this upload "
            "can update only one ARN, so it cannot safely choose which to overwrite."
        )

    predecessor = certificate_fingerprint(replaces[0]) if replaces else None
    matches = [
        certificate
        for certificate in _get_imported_certificates(client)
        if certificate_fingerprint(certificate["body"]) in {fingerprint, predecessor}
    ]
    # Include both old and new fingerprints: a separately imported renewal must not
    # hide the old ARN that is still attached to consumers.
    if len(matches) > 1:
        raise ValueError(
            "Multiple ACM ARNs match the current or predecessor certificate. "
            "Cannot safely choose which ARN to reuse; resolve the duplicate imports first."
        )
    if replaces and not matches:
        raise ValueError(
            "No ACM ARN matches the current or predecessor certificate in this account "
            "and region. Cannot renew in place without an existing ARN; check the "
            "destination and replacement link."
        )

    if matches:
        certificate = matches[0]
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

    if replaces:
        params["CertificateArn"] = matches[0]["arn"]

    response = client.import_certificate(**params)
    metrics.send("upload_acm_cert", "counter", 1)
    current_app.logger.info(
        {
            "message": "Imported certificate into ACM",
            "certificate_arn": response.get("CertificateArn"),
        }
    )
    return response
