import pytest

from lemur.sources.views import *  # noqa

from .vectors import (
    VALID_ADMIN_API_TOKEN,
    VALID_ADMIN_HEADER_TOKEN,
    VALID_USER_HEADER_TOKEN,
    WILDCARD_CERT_STR,
    WILDCARD_CERT_KEY,
)


def validate_source_schema(client):
    from lemur.sources.schemas import SourceInputSchema

    input_data = {
        "label": "exampleSource",
        "options": {},
        "plugin": {"slug": "aws-source"},
    }

    data, errors = SourceInputSchema().load(input_data)
    assert not errors


def test_create_certificate(user, source):
    from lemur.sources.service import certificate_create

    with pytest.raises(Exception):
        certificate_create({}, source)

    data = {
        "body": WILDCARD_CERT_STR,
        "private_key": WILDCARD_CERT_KEY,
        "owner": "bob@example.com",
        "creator": user["user"],
    }

    cert = certificate_create(data, source)
    assert cert.notifications


def test_sync_endpoints(session):
    from unittest import mock
    from lemur.endpoints import service as endpoint_service
    from lemur.sources import service as source_service
    from lemur.tests.factories import EndpointFactory, SourceFactory, CertificateFactory
    from lemur.plugins.lemur_aws.plugin import AWSSourcePlugin

    source = SourceFactory()
    source.plugin_name = "aws-source"

    crt1 = CertificateFactory()
    crt2 = CertificateFactory()
    crt3 = CertificateFactory()
    existing_endpoint = EndpointFactory(
        name="test-lb-4", dnsname="test4.example.com", port=443
    )
    existing_endpoint.primary_certificate = crt1
    existing_endpoint.source = source
    session.commit()

    with mock.patch.object(
        AWSSourcePlugin,
        "get_endpoints",
        return_value=[
            dict(
                name="test-lb-1",
                dnsname="test1.example.com",
                type="elbv2",
                port=443,
                policy=dict(
                    name="none",
                    ciphers=[],
                ),
                primary_certificate=dict(
                    name=crt1.name,
                    path="/fakecrt1",
                    registry_type="iam",
                ),
                sni_certificates=[
                    dict(
                        name=crt2.name,
                        path="/fakecrt2",
                        registry_type="iam",
                    )
                ],
            ),
            dict(
                name="test-lb-2",
                dnsname="test2.example.com",
                type="elbv2",
                port=443,
                policy=dict(
                    name="none",
                    ciphers=[],
                ),
                certificate_name=crt2.name,
                certificate_path="/fakecrt2",
                registry_type="iam",
            ),
            dict(
                name="test-lb-3",
                dnsname="test3.example.com",
                type="elbv2",
                port=443,
                policy=dict(
                    name="none",
                    ciphers=[],
                ),
                sni_certificates=[
                    dict(
                        name=crt1.name,
                        path="/fakecrt1",
                        registry_type="iam",
                    ),
                    dict(
                        name=crt2.name,
                        path="/fakecrt2",
                        registry_type="iam",
                    ),
                ],
                registry_type="iam",
            ),
            dict(
                name="test-lb-4",
                dnsname="test4.example.com",
                type="elbv2",
                port=443,
                policy=dict(
                    name="none",
                    ciphers=[],
                ),
                primary_certificate=dict(
                    name=crt2.name,
                    path="/fakecrt2",
                    registry_type="iam",
                ),
                sni_certificates=[
                    dict(
                        name=crt3.name,
                        path="/fakecrt3",
                        registry_type="iam",
                    )
                ],
                registry_type="iam",
            ),
        ],
    ):
        new, updated, updated_by_hash = source_service.sync_endpoints(source)

    assert new == 3
    assert updated == 1
    assert updated_by_hash == 0

    ep1 = endpoint_service.get_by_name("test-lb-1")
    assert ep1.name == "test-lb-1"
    assert ep1.primary_certificate.name == crt1.name
    assert len(ep1.sni_certificates) == 1
    assert ep1.sni_certificates[0].name == crt2.name

    ep2 = endpoint_service.get_by_name("test-lb-2")
    assert ep2.name == "test-lb-2"
    assert ep2.primary_certificate.name == crt2.name
    assert len(ep2.sni_certificates) == 0

    ep3 = endpoint_service.get_by_name("test-lb-3")
    assert ep3.name == "test-lb-3"
    assert ep3.primary_certificate is None
    assert len(ep3.sni_certificates) == 2
    assert ep3.sni_certificates[0].name == crt1.name
    assert ep3.sni_certificates[1].name == crt2.name

    ep4 = endpoint_service.get_by_name("test-lb-4")
    assert ep4.primary_certificate.name == crt2.name
    assert len(ep4.sni_certificates) == 1
    assert ep4.sni_certificates[0].name == crt3.name


def test_sync_endpoints_differentiates_by_hostname(session):
    """CLOUDR-1927: a single (dnsname, port) served from multiple sources (DCs)
    with distinct hostnames must produce one Endpoint row per hostname, not
    collapse to a single row."""
    from unittest import mock
    from lemur.endpoints.models import Endpoint
    from lemur.sources import service as source_service
    from lemur.tests.factories import SourceFactory, CertificateFactory
    from lemur.plugins.lemur_aws.plugin import AWSSourcePlugin

    crt = CertificateFactory()

    source_us1 = SourceFactory()
    source_us1.plugin_name = "aws-source"
    source_us1.options = [{"name": "hostname", "value": "adapter.us1.fabric.dog"}]
    source_us5 = SourceFactory()
    source_us5.plugin_name = "aws-source"
    source_us5.options = [{"name": "hostname", "value": "adapter.us5.fabric.dog"}]

    def endpoint_payload():
        return [
            dict(
                name="ignored",  # overridden by the source hostname
                dnsname="*.logs.mrf.datadoghq.com",
                type="vault-managed",
                port=443,
                policy=dict(name="none", ciphers=[]),
                primary_certificate=dict(
                    name=crt.name,
                    path="/kv/data/certs",
                    registry_type="vault",
                ),
                sni_certificates=[],
                registry_type="vault",
            )
        ]

    with mock.patch.object(
        AWSSourcePlugin, "get_endpoints", side_effect=lambda options: endpoint_payload()
    ):
        source_service.sync_endpoints(source_us1)
        source_service.sync_endpoints(source_us5)

    rows = Endpoint.query.filter(
        Endpoint.dnsname == "*.logs.mrf.datadoghq.com"
    ).all()
    assert len(rows) == 2
    assert {r.name for r in rows} == {
        "adapter.us1.fabric.dog",
        "adapter.us5.fabric.dog",
    }


def test_sync_endpoints_updates_existing_name_not_duplicates(session):
    """CLOUDR-1927: an existing endpoint for the same source is matched on its
    source_id and its name is updated to the source hostname, rather than a
    duplicate row being appended."""
    from unittest import mock
    from lemur.endpoints.models import Endpoint
    from lemur.sources import service as source_service
    from lemur.tests.factories import (
        SourceFactory,
        CertificateFactory,
        EndpointFactory,
    )
    from lemur.plugins.lemur_aws.plugin import AWSSourcePlugin

    crt = CertificateFactory()
    source = SourceFactory()
    source.plugin_name = "aws-source"
    source.options = [{"name": "hostname", "value": "adapter.us1.fabric.dog"}]

    # Pre-existing endpoint for this source carrying the old (vault-path) name.
    existing = EndpointFactory(
        name="/kv/data/certs/old",
        dnsname="*.unique2.datadoghq.com",
        port=443,
    )
    existing.source = source
    session.commit()

    def endpoint_payload():
        return [
            dict(
                name="ignored",
                dnsname="*.unique2.datadoghq.com",
                type="vault-managed",
                port=443,
                policy=dict(name="none", ciphers=[]),
                primary_certificate=dict(
                    name=crt.name,
                    path="/kv/data/certs",
                    registry_type="vault",
                ),
                sni_certificates=[],
                registry_type="vault",
            )
        ]

    with mock.patch.object(
        AWSSourcePlugin, "get_endpoints", side_effect=lambda options: endpoint_payload()
    ):
        source_service.sync_endpoints(source)

    rows = Endpoint.query.filter(
        Endpoint.dnsname == "*.unique2.datadoghq.com"
    ).all()
    assert len(rows) == 1  # updated in place, not duplicated
    assert rows[0].name == "adapter.us1.fabric.dog"


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 404),
        (VALID_ADMIN_HEADER_TOKEN, 404),
        (VALID_ADMIN_API_TOKEN, 404),
        ("", 401),
    ],
)
def test_source_get(client, source_plugin, token, status):
    assert (
        client.get(api.url_for(Sources, source_id=43543), headers=token).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_source_post_(client, token, status):
    assert (
        client.post(
            api.url_for(Sources, source_id=1), data={}, headers=token
        ).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 403),
        (VALID_ADMIN_HEADER_TOKEN, 400),
        (VALID_ADMIN_API_TOKEN, 400),
        ("", 401),
    ],
)
def test_source_put(client, token, status):
    assert (
        client.put(
            api.url_for(Sources, source_id=1), data={}, headers=token
        ).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 403),
        (VALID_ADMIN_HEADER_TOKEN, 200),
        (VALID_ADMIN_API_TOKEN, 200),
        ("", 401),
    ],
)
def test_source_delete(client, token, status):
    assert (
        client.delete(api.url_for(Sources, source_id=1), headers=token).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_source_patch(client, token, status):
    assert (
        client.patch(
            api.url_for(Sources, source_id=1), data={}, headers=token
        ).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 200),
        (VALID_ADMIN_HEADER_TOKEN, 200),
        (VALID_ADMIN_API_TOKEN, 200),
        ("", 401),
    ],
)
def test_sources_list_get(client, source_plugin, token, status):
    assert client.get(api.url_for(SourcesList), headers=token).status_code == status


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 403),
        (VALID_ADMIN_HEADER_TOKEN, 400),
        (VALID_ADMIN_API_TOKEN, 400),
        ("", 401),
    ],
)
def test_sources_list_post(client, token, status):
    assert (
        client.post(api.url_for(SourcesList), data={}, headers=token).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_sources_list_put(client, token, status):
    assert (
        client.put(api.url_for(SourcesList), data={}, headers=token).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_sources_list_delete(client, token, status):
    assert client.delete(api.url_for(SourcesList), headers=token).status_code == status


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_sources_list_patch(client, token, status):
    assert (
        client.patch(api.url_for(SourcesList), data={}, headers=token).status_code
        == status
    )
