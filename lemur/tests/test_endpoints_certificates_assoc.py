import pytest
from lemur.endpoints.models import Endpoint
from lemur.models import EndpointsCertificates
from lemur.tests.factories import CertificateFactory, EndpointFactory


def test_primary_certificate_assoc(session):
    """Ensure that a primary certificate can be associated with an endpoint."""
    # Create and associate primary certificate with an endpoint
    crt = CertificateFactory()

    expected_endpoint = EndpointFactory()
    expected_endpoint.primary_certificate = crt

    actual_endpoint = session.query(Endpoint).filter(Endpoint.name == expected_endpoint.name).scalar()
    assert expected_endpoint == actual_endpoint
    assert actual_endpoint.primary_certificate == crt


def test_secondary_certificates_assoc(session):
    """Ensure that secondary certificates can be associated with an endpoint."""
    # Create and associate primary certificate with an endpoint
    crt = CertificateFactory()

    expected_endpoint = EndpointFactory()
    expected_endpoint.primary_certificate = crt

    # Create and associate secondary certificates with endpoint
    additional_certs = [CertificateFactory() for _ in range(0, 5)]

    for crt in additional_certs:
        # TODO(EDGE-1363) Expose API for managing secondary certificates associated with an endpoint
        expected_endpoint.certificates_assoc.append(
            EndpointsCertificates(certificate=crt, endpoint=expected_endpoint, primary_certificate=False)
        )

    actual_endpoint = session.query(Endpoint).filter(Endpoint.name == expected_endpoint.name).scalar()
    assert expected_endpoint == actual_endpoint


def test_primary_certificate_uniqueness(session):
    """Ensure that only one primary certificate can be associated with an endpoint."""
    # Create and associate two primary certificates with an endpoint
    crt = CertificateFactory()
    endpoint = EndpointFactory()
    endpoint.primary_certificate = crt

    # TODO(EDGE-1363) Expose API for managing secondary certificates associated with an endpoint
    endpoint.certificates_assoc.append(
        EndpointsCertificates(certificate=CertificateFactory(), endpoint=endpoint, primary_certificate=True)
    )

    with pytest.raises(Exception):
        session.commit()


def test_certificate_uniqueness(session):
    """Ensure that a given certificate can only be associated with an endpoint once."""
    # Create and associate primary certificate with an endpoint
    crt = CertificateFactory()
    endpoint = EndpointFactory()
    endpoint.primary_certificate = crt

    # Associate the same secondary certificate with the endpoint twice
    for _ in range(0, 2):
        # TODO(EDGE-1363) Expose API for managing secondary certificates associated with an endpoint
        endpoint.certificates_assoc.append(
            EndpointsCertificates(certificate=crt, endpoint=endpoint, primary_certificate=False)
        )

    with pytest.raises(Exception):
        session.commit()
