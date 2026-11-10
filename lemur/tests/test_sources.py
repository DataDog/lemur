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

    source_service.plugins.register(AWSSourcePlugin)
    source = SourceFactory()
    source.plugin_name = "aws-source"

    crt1 = CertificateFactory()
    crt2 = CertificateFactory()
    crt3 = CertificateFactory()
    existing_endpoint = EndpointFactory(
        name="test-lb-4", dnsname="test4.example.com", port=443, active=False
    )
    existing_endpoint.primary_certificate = crt1
    existing_endpoint.source = source
    undiscovered_endpoint = EndpointFactory(active=False, source=source)
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
    assert ep4.id == existing_endpoint.id
    assert ep4.active is True
    assert ep4.primary_certificate.name == crt2.name
    assert len(ep4.sni_certificates) == 1
    assert ep4.sni_certificates[0].name == crt3.name
    session.refresh(undiscovered_endpoint)
    assert undiscovered_endpoint.active is False


def _reported_endpoint(crt, name, dnsname, port=443):
    """
    An endpoint as a source plugin reports it. sync_endpoints changes the dictionary,
    so each sync needs a new one.
    """
    return dict(
        name=name,
        dnsname=dnsname,
        type="elbv2",
        port=port,
        policy=dict(name="none", ciphers=[]),
        primary_certificate=dict(name=crt.name, path="/fakecrt", registry_type="iam"),
    )


def test_sync_endpoints_keeps_one_row_for_each_source(session):
    """Two sources report the same dnsname and port (CLOUDR-1927). Each one keeps its own row."""
    from unittest import mock
    from lemur.endpoints.models import Endpoint
    from lemur.sources import service as source_service
    from lemur.tests.factories import SourceFactory, CertificateFactory
    from lemur.plugins.lemur_aws.plugin import AWSSourcePlugin

    source_service.plugins.register(AWSSourcePlugin)
    source_a = SourceFactory(plugin_name="aws-source")
    source_b = SourceFactory(plugin_name="aws-source")
    crt = CertificateFactory()
    session.commit()

    def get_endpoints(*args, **kwargs):
        return [_reported_endpoint(crt, "/vault/path/dedupe-1", "dedupe1.example.com")]

    with mock.patch.object(AWSSourcePlugin, "get_endpoints", side_effect=get_endpoints):
        assert source_service.sync_endpoints(source_a)[:2] == (1, 0)
        assert source_service.sync_endpoints(source_b)[:2] == (1, 0)
        # A new sync of the first source updates its row. It makes no new row.
        assert source_service.sync_endpoints(source_a)[:2] == (0, 1)

    rows = Endpoint.query.filter(Endpoint.dnsname == "dedupe1.example.com").all()
    assert len(rows) == 2
    assert {row.source_id for row in rows} == {source_a.id, source_b.id}
    assert all(row.primary_certificate.name == crt.name for row in rows)


def test_sync_endpoints_keeps_one_row_for_each_name(session):
    """One source reports the same dnsname and port with two names, for example two Vault paths."""
    from unittest import mock
    from lemur.endpoints.models import Endpoint
    from lemur.sources import service as source_service
    from lemur.tests.factories import SourceFactory, CertificateFactory
    from lemur.plugins.lemur_aws.plugin import AWSSourcePlugin

    source_service.plugins.register(AWSSourcePlugin)
    source = SourceFactory(plugin_name="aws-source")
    crt = CertificateFactory()
    session.commit()

    def get_endpoints(*args, **kwargs):
        return [
            _reported_endpoint(crt, "/vault/path-a/dedupe-2", "dedupe2.example.com"),
            _reported_endpoint(crt, "/vault/path-b/dedupe-2", "dedupe2.example.com"),
        ]

    with mock.patch.object(AWSSourcePlugin, "get_endpoints", side_effect=get_endpoints):
        assert source_service.sync_endpoints(source)[:2] == (2, 0)
        assert source_service.sync_endpoints(source)[:2] == (0, 2)

    rows = Endpoint.query.filter(Endpoint.dnsname == "dedupe2.example.com").all()
    assert {row.name for row in rows} == {
        "/vault/path-a/dedupe-2",
        "/vault/path-b/dedupe-2",
    }


def test_sync_endpoints_retry_uses_the_same_key(session):
    """After a lost database connection, the second search must use the same key."""
    from unittest import mock
    from sqlalchemy.exc import OperationalError
    from lemur.endpoints import service as endpoint_service
    from lemur.sources import service as source_service
    from lemur.tests.factories import SourceFactory, CertificateFactory
    from lemur.plugins.lemur_aws.plugin import AWSSourcePlugin

    source_service.plugins.register(AWSSourcePlugin)
    source = SourceFactory(plugin_name="aws-source")
    crt = CertificateFactory()
    session.commit()

    connection_lost = OperationalError("SELECT 1", {}, Exception("connection lost"))
    connection_lost.connection_invalidated = True

    def get_endpoints(*args, **kwargs):
        return [_reported_endpoint(crt, "/vault/path/dedupe-3", "dedupe3.example.com")]

    with mock.patch.object(
        AWSSourcePlugin, "get_endpoints", side_effect=get_endpoints
    ), mock.patch.object(
        endpoint_service, "get_by_dedupe_key", side_effect=[connection_lost, None]
    ) as lookup, mock.patch(
        "lemur.sources.service.database.rollback"
    ):
        new, updated, _ = source_service.sync_endpoints(source)

    assert (new, updated) == (1, 0)
    assert lookup.call_count == 2
    for call in lookup.call_args_list:
        assert call.args == ("dedupe3.example.com", 443, source, "/vault/path/dedupe-3")


def test_get_by_dedupe_key(session):
    from lemur.endpoints import service as endpoint_service
    from lemur.tests.factories import EndpointFactory, SourceFactory

    source_a = SourceFactory()
    source_b = SourceFactory()
    endpoint = EndpointFactory(
        name="dk-name", dnsname="dk.example.com", port=443, source=source_a
    )
    session.commit()

    find = endpoint_service.get_by_dedupe_key
    assert find("dk.example.com", 443, source_a, "dk-name") == endpoint
    # Each part of the key is part of the match.
    assert find("other.example.com", 443, source_a, "dk-name") is None
    assert find("dk.example.com", 8443, source_a, "dk-name") is None
    assert find("dk.example.com", 443, source_b, "dk-name") is None
    assert find("dk.example.com", 443, source_a, "other-name") is None


def test_get_by_dnsname_and_port_is_deprecated(session):
    from lemur.endpoints import service as endpoint_service

    with pytest.warns(DeprecationWarning, match="CLOUDR-1927"):
        assert endpoint_service.get_by_dnsname_and_port("none.example.com", 443) is None


def test_is_attached_to_endpoint_with_the_same_name_in_two_sources(session):
    """Endpoints of many sources can have one name. The endpoint that the caller gives is the one checked."""
    from unittest import mock
    from lemur.certificates import service as certificate_service
    from lemur.sources import service as source_service
    from lemur.tests.factories import EndpointFactory, SourceFactory
    from lemur.plugins.lemur_aws.plugin import AWSSourcePlugin

    source_service.plugins.register(AWSSourcePlugin)
    source_a = SourceFactory(plugin_name="aws-source")
    source_b = SourceFactory(plugin_name="aws-source")
    endpoint_a = EndpointFactory(
        name="same-name", dnsname="same.example.com", port=443, source=source_a
    )
    endpoint_b = EndpointFactory(
        name="same-name", dnsname="same.example.com", port=443, source=source_b
    )
    session.commit()

    with mock.patch.object(
        AWSSourcePlugin, "get_endpoint_certificate_names", return_value=["cert-a"]
    ) as names:
        assert certificate_service.is_attached_to_endpoint(
            "cert-a", "same-name", endpoint=endpoint_b
        )
        assert not certificate_service.is_attached_to_endpoint(
            "other-cert", "same-name", endpoint=endpoint_a
        )

    assert [call.args[0] for call in names.call_args_list] == [endpoint_b, endpoint_a]


def test_endpoint_nested_schema_has_the_source_label(session):
    from lemur.schemas import EndpointNestedOutputSchema
    from lemur.tests.factories import EndpointFactory, SourceFactory

    endpoint = EndpointFactory(source=SourceFactory(label="schema-source-1"))
    session.commit()

    data, errors = EndpointNestedOutputSchema().dump(endpoint)

    assert not errors
    # The output schema changes the keys to camelCase. The certificate page reads this key.
    assert data["sourceLabel"] == "schema-source-1"


def test_endpoint_nested_schema_for_an_endpoint_without_a_source(session):
    """An endpoint with no source must not break the answer of the certificate API."""
    from lemur.schemas import EndpointNestedOutputSchema
    from lemur.tests.factories import EndpointFactory

    endpoint = EndpointFactory(source=None)
    session.commit()

    data, errors = EndpointNestedOutputSchema().dump(endpoint)

    assert not errors
    assert data["name"] == endpoint.name
    assert not data.get("sourceLabel")


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
