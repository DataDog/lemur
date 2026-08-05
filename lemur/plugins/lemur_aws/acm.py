"""
.. module: lemur.plugins.lemur_aws.acm
    :platform: Unix
    :synopsis: Contains helper functions for interactive with AWS ACM Apis.
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Pinmarva <pinmarva@gmail.com>
"""
import botocore

from retrying import retry
from sentry_sdk import capture_exception

from lemur.extensions import metrics
from lemur.plugins.lemur_aws.sts import sts_client


def retry_throttled(exception):
    """
    Determines if this exception is due to throttling
    :param exception:
    :return:
    """
    if isinstance(exception, botocore.exceptions.ClientError):
        if exception.response["Error"]["Code"] == "NoSuchEntity":
            return False

        # No need to retry deletion requests if there is a DeleteConflict error.
        # This error indicates that the certificate is still attached to an entity
        # and cannot be deleted.
        if exception.response["Error"]["Code"] == "DeleteConflict":
            return False

    metrics.send("acm_retry", "counter", 1, metric_tags={"exception": str(exception)})
    return True


def get_id_from_arn(arn):
    """
    Extract the certificate name from an arn.

    examples:
    'arn:aws:acm:us-west-2:123456789012:certificate/1aa111a1-1a11-1111-11aa-a11aa111aa11' '1aa111a1-1a11-1111-11aa-a11aa111aa11'

    :param arn: ACM TLS certificate arn
    :return: id of the certificate as uploaded to AWS
    """
    return arn.split("/")[-1]


@sts_client("acm")
@retry(retry_on_exception=retry_throttled, wait_fixed=2000, stop_max_attempt_number=25)
def upload_cert(name, body, private_key, cert_chain=None, certificate_arn=None, **kwargs):
    """
    Upload a certificate to ACM AWS

    If ``certificate_arn`` is supplied the certificate is reimported into that
    existing ARN, which replaces the material in place while preserving the ARN and
    its AWS service associations.

    :param body:
    :param private_key:
    :param cert_chain:
    :param certificate_arn: if set, reimport into this existing ARN
    :return:
    """
    assert isinstance(private_key, str)
    client = kwargs.pop("client")

    metrics.send("upload_acm_cert", "counter", 1, metric_tags={"name": name})

    # Make the push idempotent, the way the IAM destination is. IAM keys on the cert
    # name (ServerCertificateName) so re-uploading the same cert is a no-op; ACM has no
    # name, only ARNs, so we tag each import with the Lemur name and look it up here. If
    # we already imported a cert for this name, reimport into that same ARN in place
    # instead of creating a duplicate.
    if not certificate_arn:
        certificate_arn = _find_managed_cert_arn(client, name)

    params = dict(Certificate=str(body), PrivateKey=str(private_key))
    if cert_chain:
        params["CertificateChain"] = str(cert_chain)
    if certificate_arn:
        # Reimport in place: preserves the ARN and its AWS service associations. ACM
        # rejects Tags on reimport (the cert already carries them from its first import).
        params["CertificateArn"] = certificate_arn
    else:
        # First import for this name: tag it so Lemur recognizes it as managed
        # (is_lemur_managed) and can find it for the idempotent reimport above.
        params["Tags"] = [
            {"Key": MANAGED_TAG, "Value": "true"},
            {"Key": NAME_TAG, "Value": name},
        ]

    try:
        return client.import_certificate(**params)
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] != "EntityAlreadyExists":
            raise e


@sts_client("acm")
@retry(retry_on_exception=retry_throttled, wait_fixed=2000, stop_max_attempt_number=25)
def delete_cert(cert_arn, **kwargs):
    """
    Delete a certificate from ACM AWS

    :param cert_arn:
    :return:
    """
    client = kwargs.pop("client")
    metrics.send("delete_acm_cert", "counter", 1, metric_tags={"cert_arn": cert_arn})
    try:
        client.delete_certificate(CertificateArn=cert_arn)
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise e


@sts_client("acm")
def get_certificate(name, **kwargs):
    """
    Retrieves an acm SSL certificate.

    :return:
    """
    return _get_certificate(name, **kwargs)


@retry(retry_on_exception=retry_throttled, wait_fixed=2000, stop_max_attempt_number=25)
def _get_certificate(arn, **kwargs):
    metrics.send("get_acm_certificate", "counter", 1, metric_tags={"arn": arn})
    client = kwargs.pop("client")
    try:
        return client.get_certificate(CertificateArn=arn)
    except client.exceptions.ResourceNotFoundException:
        capture_exception()
        return None


@sts_client("acm")
def get_certificates(**kwargs):
    """
    Fetches one page of acm certificate objects for a given account.
    :param kwargs:
    :return:
    """
    return _get_certificates(**kwargs)


@retry(retry_on_exception=retry_throttled, wait_fixed=2000, stop_max_attempt_number=25)
def _get_certificates(**kwargs):
    metrics.send("get_acm_certificates", "counter", 1)
    # ACM's ListCertificates only returns RSA_1024 and RSA_2048 certs unless Includes.keyTypes
    # is set, so without this it silently skips ECC and larger RSA certs during discovery.
    return kwargs.pop("client").list_certificates(
        **kwargs,
        CertificateStatuses=[
            'ISSUED'
        ],
        Includes={
            'keyTypes': [
                'RSA_1024', 'RSA_2048', 'RSA_3072', 'RSA_4096',
                'EC_prime256v1', 'EC_secp384r1', 'EC_secp521r1',
            ]
        },
    )


@sts_client("acm")
def get_all_certificates(**kwargs):
    """
    Use STS to fetch all of the ACM SSL certificates from a given account
    :param restrict_path: If provided, only return certificates with a matching Path value.
    """
    certificates = []
    account_number = kwargs.get("account_number")
    metrics.send(
        "get_all_acm_certificates",
        "counter",
        1,
        metric_tags={"account_number": account_number},
    )

    while True:
        response = _get_certificates(**kwargs)
        metadata = response["CertificateSummaryList"]

        for m in metadata:
            certificate = _get_certificate(
                m["CertificateArn"],
                client=kwargs["client"]
            )

            if certificate is None:
                continue

            certificate.update(
                name=m["DomainName"],
                external_id=m["CertificateArn"]
            )
            certificates.append(certificate)

        if not response.get("Marker"):
            return certificates
        else:
            kwargs.update(dict(Marker=response["Marker"]))


MANAGED_TAG = "lemur.managed"
NAME_TAG = "lemur.name"


def _has_managed_tag(tags):
    """True if an ACM Tags list contains lemur.managed = true."""
    return any(t["Key"] == MANAGED_TAG and t.get("Value") == "true" for t in tags)


def _find_managed_cert_arn(client, name):
    """Return the ARN of the lemur.managed ACM cert tagged for this Lemur name, or None.

    This is how the ACM destination emulates the IAM destination's name-based
    idempotency: ACM has no name key, so we tag each import with lemur.name and look it
    up here to reimport in place instead of creating a duplicate on every push. Note
    ACM's ListCertificates is eventually consistent, so a brand-new import may not be
    found by an immediate re-push.
    """
    paginator = client.get_paginator("list_certificates")
    for page in paginator.paginate(CertificateStatuses=["ISSUED"]):
        for summary in page.get("CertificateSummaryList", []):
            arn = summary["CertificateArn"]
            tags = client.list_tags_for_certificate(CertificateArn=arn).get("Tags", [])
            if _has_managed_tag(tags) and any(
                t["Key"] == NAME_TAG and t.get("Value") == name for t in tags
            ):
                return arn
    return None


@sts_client("acm")
@retry(retry_on_exception=retry_throttled, wait_fixed=2000, stop_max_attempt_number=25)
def is_lemur_managed(certificate_arn, **kwargs):
    """True if the ACM certificate carries the lemur.managed tag."""
    client = kwargs.pop("client")
    tags = client.list_tags_for_certificate(CertificateArn=certificate_arn).get("Tags", [])
    return _has_managed_tag(tags)
