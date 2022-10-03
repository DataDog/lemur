from flask import current_app
from google.cloud.compute_v1.services import ssl_certificates

from lemur.common.defaults import common_name, issuer, not_before
from lemur.common.utils import parse_certificate, split_pem


def get_name(body):
    """
    We need to change the name of the certificate that we are uploading to comply with GCP naming standards.
    The cert name will follow the convention "ssl-{Cert CN}-{Date Issued}-{Issuer}"
    """
    cert = parse_certificate(body)
    cn = common_name(cert)
    authority = issuer(cert)
    issued_on = not_before(cert).date()

    cert_name = f"ssl-{cn}-{authority}-{issued_on}"

    return modify_cert_name_for_gcp(cert_name)


def modify_cert_name_for_gcp(cert_name):
    # Modify the cert name to comply with GCP naming convention
    gcp_name = cert_name.replace('.', '-')
    gcp_name = gcp_name.replace('*', "star")
    gcp_name = gcp_name.lower()
    gcp_name = gcp_name[:63]
    gcp_name = gcp_name.rstrip('.*-')
    return gcp_name


def full_ca(body, cert_chain):
    # in GCP you need to assemble the cert body and the cert chain in the same parameter
    return f"{body}\n{cert_chain}"


def insert_certificate(project_id, ssl_certificate_body, credentials):
    return ssl_certificates.SslCertificatesClient(credentials=credentials).insert(
        project=project_id, ssl_certificate_resource=ssl_certificate_body
    )


def fetch_all(project_id, credentials):
    client = ssl_certificates.SslCertificatesClient(credentials=credentials)
    certs = []
    for cert_meta in client.list(project=project_id):
        try:
            if cert_meta.type_ != "SELF_MANAGED":
                continue
            cert = parse_certificate_meta(cert_meta)
            if cert:
                certs.append(cert)
        except Exception as e:
            current_app.logger.error(
                f"Issue with fetching certificate {cert_meta.name} from GCP. Action failed with the following "
                f"log: {e}",
                exc_info=True,
            )
            raise e
    return certs


def fetch_by_name(project_id, credentials, certificate_name):
    client = ssl_certificates.SslCertificatesClient(credentials=credentials)
    cert_meta = client.get(project=project_id, ssl_certificate=certificate_name)
    if cert_meta:
        cert = parse_certificate_meta(cert_meta)
        if cert:
            return cert
    return None


def parse_certificate_meta(certificate_meta):
    """
    Returns a body and a chain.
    :param certificate_meta:
    """
    chain = []
    # Skip CSR if it's part of the certificate returned by the GCP API.
    for cert in split_pem(certificate_meta.certificate):
        if "-----BEGIN CERTIFICATE-----" in cert:
            chain.append(cert)
    if not chain:
        return None
    return dict(
        body=chain[0],
        chain="\n".join(chain[1:]),
        name=certificate_meta.name,
    )
