from cryptography import x509
from flask import current_app
from google.cloud.compute_v1.services import ssl_certificates

from lemur.common.defaults import common_name, text_to_slug
from lemur.common.utils import parse_certificate, split_pem


def get_name(body):
    """
    We need to change the name of the certificate that we are uploading to comply with GCP naming standards.
    The cert name will follow the convention "{cn}-{authority}-{serial}". This is guaranteed to be unique
    across CAs and complies with naming restrictions from the GCP API. If the combined authority and serial
    number of certificate is longer than 63 characters, an exception is raised. This assumes the CA conforms
    to https://www.rfc-editor.org/rfc/rfc3280#section-4.1.2.2 and the serial number is a positive integer.
    """
    cert = parse_certificate(body)
    authority = modify_for_gcp(get_issuer(cert))
    serial = modify_for_gcp(hex(cert.serial_number))
    suffix = f"-{authority}-{serial}"
    if len(suffix) > 63:
        raise Exception(f"Could not create certificate due to naming restrictions: {cert.serial_number}")
    cn = modify_for_gcp(common_name(cert))
    available_chars = 63 - len(suffix)
    cn = cn[:available_chars]
    cert_name = f"{cn}{suffix}"
    return cert_name


def get_issuer(cert):
    authority = cert.issuer.get_attributes_for_oid(x509.OID_ORGANIZATION_NAME)
    if not authority:
        current_app.logger.error(
            "Unable to get issuer! Cert serial {:x}".format(cert.serial_number)
        )
        return "<unknown>"
    return text_to_slug(authority[0].value, "")


def modify_for_gcp(name):
    # Modify the name to comply with GCP naming convention
    gcp_name = name.replace('.', '-')
    gcp_name = gcp_name.replace("*", "star")
    gcp_name = gcp_name.lower()
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


def get_self_link(project, name):
    return f"https://www.googleapis.com/compute/v1/projects/{project}/global/sslCertificates/{name}"


def calc_diff(certs, new_cert, old_cert):
    """
    Produces a list of certificate self-links where new_cert is added and old_cert is removed, if it exists.
    :param certs:
    :param new_cert:
    :param old_cert:
    :return:
    """
    # Shallow copy the list of self-links (strings)
    result = list(certs)
    new_cert_idx = -1
    for idx, self_link in enumerate(certs):
        if self_link == old_cert:
            new_cert_idx = idx
            break
    if new_cert_idx != -1:
        result[new_cert_idx] = new_cert
    else:
        result.append(new_cert)
    return result
