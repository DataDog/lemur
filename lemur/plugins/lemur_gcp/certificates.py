from lemur.common.defaults import common_name, issuer, not_before
from lemur.common.utils import parse_certificate


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
