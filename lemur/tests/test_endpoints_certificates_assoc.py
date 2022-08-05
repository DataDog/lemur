import pytest
import uuid
from lemur import database
from lemur.certificates import service as certificate_service
from lemur.endpoints import service as endpoint_service
from lemur.endpoints.models import Endpoint
from lemur.extensions import db
from lemur.models import EndpointsCertificates
from lemur.tests.factories import AuthorityFactory, CertificateFactory, UserFactory, SourceFactory
from lemur.tests.vectors import (
    CSR_STR,
)


def _fake_name():
    return uuid.uuid4().hex


def _fake_cert():
    return certificate_service.create(
        authority=AuthorityFactory(),
        name=_fake_name(),
        csr=CSR_STR,
        creator=UserFactory(),
        owner="foo@example.com",
    )


def test_primary_certificate_assoc():
    """Ensure that a primary certificate can be associated with an endpoint."""
    # Create and associate primary certificate with an endpoint
    crt = _fake_cert()

    expected_endpoint = endpoint_service.create(name=_fake_name(), certificate=crt, source=SourceFactory())

    actual_endpoint = endpoint_service.get_by_name(expected_endpoint.name)
    assert expected_endpoint == actual_endpoint
    assert actual_endpoint.primary_certificate == crt


def test_secondary_certificates_assoc():
    """Ensure that secondary certificates can be associated with an endpoint."""
    # Create and associate primary certificate with an endpoint
    crt = _fake_cert()

    expected_endpoint = endpoint_service.create(name=_fake_name(), certificate=crt, source=SourceFactory())

    # Create and associate secondary certificates with endpoint
    additional_certs = [CertificateFactory() for _ in range(0, 5)]

    # TODO(EDGE-1363) Expose API for managing secondary certificates associated with an endpoint
    for crt in additional_certs:
        expected_endpoint.certificates_assoc.append(
            EndpointsCertificates(certificate=crt, endpoint=expected_endpoint, primary_certificate=False)
        )
    database.update(expected_endpoint)

    actual_endpoint = endpoint_service.get_by_name(expected_endpoint.name)
    assert expected_endpoint == actual_endpoint


def test_primary_certificate_uniqueness():
    """Ensure that only one primary certificate can be associated with an endpoint."""
    # Create and associate two primary certificates with an endpoint
    endpoint = Endpoint(name=_fake_name())
    endpoint.certificate = _fake_cert()

    endpoint.certificates_assoc.append(
        EndpointsCertificates(certificate=_fake_cert(), endpoint=endpoint, primary_certificate=True)
    )

    db.session.add(endpoint)
    db.session.commit()


def test_certificate_uniqueness():
    """Ensure that a given certificate can only be associated with an endpoint once."""
    # Create and associate primary certificate with an endpoint
    endpoint = Endpoint(name=_fake_name())
    endpoint.certificate = _fake_cert()

    # Associate the same secondary certificate with the endpoint twice
    crt = _fake_cert()

    for _ in range(0, 2):
        endpoint.certificates_assoc.append(
            EndpointsCertificates(certificate=crt, endpoint=endpoint, primary_certificate=False)
        )

    with pytest.raises(Exception):
        db.session.add(endpoint)
        db.session.commit()
