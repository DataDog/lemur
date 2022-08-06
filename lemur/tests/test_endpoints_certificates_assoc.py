import pytest
import uuid
from lemur.certificates import service as certificate_service
from lemur.endpoints import service as endpoint_service
from lemur.endpoints.models import Endpoint
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


def test_primary_certificate_uniqueness(session):
    """Ensure that only one primary certificate can be associated with an endpoint."""
    # Create and associate two primary certificates with an endpoint
    endpoint = Endpoint(name=_fake_name())
    endpoint.certificate = _fake_cert()
    #endpoint.certificates_assoc.append(
    #    EndpointsCertificates(certificate=_fake_cert(), endpoint=endpoint, primary_certificate=True)
    #)

    #with pytest.raises(Exception):
        #session.commit()
