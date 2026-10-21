from unittest.mock import patch

import pytest
from sqlalchemy import inspect

from lemur.auth.service import create_token
from lemur.endpoints.views import EndpointDeactivate, Endpoints, api
from lemur.roles import service as role_service
from lemur.tests.factories import (
    ApiKeyFactory,
    CertificateFactory,
    EndpointFactory,
    RoleFactory,
    UserFactory,
)


def authorization(session, role_name, api_key=False):
    role = role_service.get_by_name(role_name) or RoleFactory(name=role_name)
    user = UserFactory(roles=[role])
    key = ApiKeyFactory(user=user) if api_key else None
    session.commit()
    return {"Authorization": "Bearer " + create_token(user, aid=key.id if key else None)}


def columns(model):
    return {attribute.key: getattr(model, attribute.key) for attribute in inspect(model).mapper.column_attrs}


@pytest.mark.parametrize("role_name", ["operator", "admin"])
@pytest.mark.parametrize("orphaned", [False, True])
@pytest.mark.parametrize("api_key", [False, True])
def test_deactivate_preserves_endpoint_and_certificates(
    client, session, role_name, orphaned, api_key
):
    headers = authorization(session, role_name, api_key)
    endpoint = EndpointFactory()
    if orphaned:
        endpoint.source = None
    primary, sni = CertificateFactory(), CertificateFactory()
    endpoint.primary_certificate = primary
    endpoint.set_certificate_path(primary, "/primary/")
    endpoint.add_sni_certificate(sni, "/sni/")
    control = EndpointFactory()
    session.commit()
    before = columns(endpoint)
    certificates_before = [columns(primary), columns(sni)]
    associations_before = [columns(assoc) for assoc in endpoint.certificates_assoc]

    with patch("lemur.endpoints.service.log_service.audit_log") as audit:
        response = client.post(
            api.url_for(EndpointDeactivate, endpoint_id=endpoint.id),
            headers=headers,
            json={"name": "must not change", "sourceId": 999999, "active": True},
        )

    assert response.status_code == 200
    assert response.get_json() == {"id": endpoint.id, "active": False}
    session.refresh(endpoint)
    session.refresh(control)
    after = columns(endpoint)
    assert [key for key in before if before[key] != after[key]] == ["active"]
    assert control.active is True
    assert [columns(primary), columns(sni)] == certificates_before
    assert [columns(assoc) for assoc in endpoint.certificates_assoc] == associations_before
    audit.assert_called_once_with(
        "deactivate_endpoint", endpoint.name, f"Deactivated endpoint {endpoint.id}"
    )
    read = client.get(api.url_for(Endpoints, endpoint_id=endpoint.id), headers=headers)
    assert read.status_code == 200
    assert read.get_json()["active"] is False
    assert read.get_json()["sourceLabel"] == (None if orphaned else endpoint.source.label)


def test_deactivate_is_idempotent(client, session):
    headers = authorization(session, "operator")
    endpoint = EndpointFactory()
    session.commit()
    url = api.url_for(EndpointDeactivate, endpoint_id=endpoint.id)
    with patch("lemur.endpoints.service.log_service.audit_log") as audit:
        assert client.post(url, headers=headers).status_code == 200
        assert client.post(url, headers=headers).get_json() == {"id": endpoint.id, "active": False}
    audit.assert_called_once()


@pytest.mark.parametrize("api_key", [False, True])
def test_deactivate_requires_write_permission(client, session, api_key):
    headers = authorization(session, "endpoint-viewer", api_key)
    endpoint = EndpointFactory()
    session.commit()
    response = client.post(
        api.url_for(EndpointDeactivate, endpoint_id=endpoint.id), headers=headers
    )
    assert response.status_code == 403
    session.refresh(endpoint)
    assert endpoint.active is True


def test_deactivate_requires_authentication(client, session):
    endpoint = EndpointFactory()
    session.commit()
    response = client.post(api.url_for(EndpointDeactivate, endpoint_id=endpoint.id))
    assert response.status_code == 401
    session.refresh(endpoint)
    assert endpoint.active is True


def test_deactivate_missing_endpoint(client, session):
    headers = authorization(session, "admin")
    response = client.post(
        api.url_for(EndpointDeactivate, endpoint_id=2147483647), headers=headers
    )
    assert response.status_code == 404
    assert response.get_json() == {"message": "Endpoint not found"}


def test_deactivate_audits_actor(client, session):
    role = role_service.get_by_name("operator") or RoleFactory(name="operator")
    user = UserFactory(roles=[role])
    endpoint = EndpointFactory()
    session.commit()
    headers = {"Authorization": "Bearer " + create_token(user)}
    with patch("lemur.logs.service.current_app.logger.info") as info:
        response = client.post(
            api.url_for(EndpointDeactivate, endpoint_id=endpoint.id), headers=headers
        )
    assert response.status_code == 200
    entries = [
        call.args[0] for call in info.call_args_list
        if isinstance(call.args[0], dict) and call.args[0].get("action") == "deactivate_endpoint"
    ]
    assert len(entries) == 1
    assert entries[0]["user"] == user.email
    assert entries[0]["entity"] == endpoint.name
    assert entries[0]["details"] == f"Deactivated endpoint {endpoint.id}"
