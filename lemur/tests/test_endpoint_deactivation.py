from unittest.mock import patch

import pytest
from sqlalchemy import inspect

from lemur.auth.service import create_token
from lemur.endpoints.views import EndpointActive, Endpoints, api
from lemur.models import roles_users
from lemur.roles import service as role_service
from lemur.roles.models import Role
from lemur.tests.factories import (
    ApiKeyFactory,
    CertificateFactory,
    EndpointFactory,
    RoleFactory,
    UserFactory,
)


@pytest.fixture(scope="module", autouse=True)
def clean_up_test_roles(db):
    created_names = [
        name for name in ("operator", "endpoint-viewer")
        if role_service.get_by_name(name) is None
    ]
    yield
    db.session.rollback()
    for name in created_names:
        role = role_service.get_by_name(name)
        if role:
            db.session.execute(roles_users.delete().where(roles_users.c.role_id == role.id))
            db.session.query(Role).filter(Role.id == role.id).delete()
    db.session.commit()


def authorization(session, role_name, api_key=False):
    role = role_service.get_by_name(role_name) or RoleFactory(name=role_name)
    user = UserFactory(roles=[role])
    key = ApiKeyFactory(user=user) if api_key else None
    session.commit()
    return {"Authorization": "Bearer " + create_token(user, aid=key.id if key else None)}


def columns(model):
    return {attribute.key: getattr(model, attribute.key) for attribute in inspect(model).mapper.column_attrs}


@pytest.fixture(params=[False, True])
def activation(request):
    return request.param


@pytest.mark.parametrize("role_name", ["operator", "admin"])
@pytest.mark.parametrize("orphaned", [False, True])
@pytest.mark.parametrize("api_key", [False, True])
def test_deactivate_preserves_endpoint_and_certificates(
    client, session, role_name, orphaned, api_key, activation
):
    active = activation
    action = "reactivate" if active else "deactivate"
    headers = authorization(session, role_name, api_key)
    endpoint = EndpointFactory(active=not active)
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
            api.url_for(EndpointActive, endpoint_id=endpoint.id),
            headers=headers,
            json={"name": "must not change", "sourceId": 999999, "active": active},
        )

    assert response.status_code == 200
    assert response.get_json() == {"id": endpoint.id, "active": active}
    session.refresh(endpoint)
    session.refresh(control)
    after = columns(endpoint)
    assert [key for key in before if before[key] != after[key]] == ["active"]
    assert control.active is True
    assert [columns(primary), columns(sni)] == certificates_before
    assert [columns(assoc) for assoc in endpoint.certificates_assoc] == associations_before
    audit.assert_called_once_with(
        f"{action}_endpoint", endpoint.name, f"{action.capitalize()}d endpoint {endpoint.id}"
    )
    read = client.get(api.url_for(Endpoints, endpoint_id=endpoint.id), headers=headers)
    assert read.status_code == 200
    assert read.get_json()["active"] is active
    assert read.get_json()["sourceLabel"] == (None if orphaned else endpoint.source.label)


def test_deactivate_is_idempotent(client, session, activation):
    active = activation
    headers = authorization(session, "operator")
    endpoint = EndpointFactory(active=not active)
    session.commit()
    url = api.url_for(EndpointActive, endpoint_id=endpoint.id)
    with patch("lemur.endpoints.service.log_service.audit_log") as audit:
        assert client.post(url, headers=headers, json={"active": active}).status_code == 200
        with patch("lemur.endpoints.service.current_app.logger.debug") as debug:
            assert client.post(url, headers=headers, json={"active": active}).get_json() == {
                "id": endpoint.id, "active": active,
            }
        debug.assert_called_once_with(
            "Endpoint %s already has active=%s; no-op", endpoint.id, active
        )
    audit.assert_called_once()


@pytest.mark.parametrize("api_key", [False, True])
def test_deactivate_requires_write_permission(client, session, api_key, activation):
    active = activation
    headers = authorization(session, "endpoint-viewer", api_key)
    endpoint = EndpointFactory(active=not active)
    session.commit()
    response = client.post(
        api.url_for(EndpointActive, endpoint_id=endpoint.id), headers=headers, json={"active": active}
    )
    assert response.status_code == 403
    session.refresh(endpoint)
    assert endpoint.active is not active


def test_deactivate_requires_authentication(client, session, activation):
    active = activation
    endpoint = EndpointFactory(active=not active)
    session.commit()
    response = client.post(api.url_for(EndpointActive, endpoint_id=endpoint.id), json={"active": active})
    assert response.status_code == 401
    session.refresh(endpoint)
    assert endpoint.active is not active


def test_deactivate_missing_endpoint(client, session, activation):
    active = activation
    headers = authorization(session, "admin")
    response = client.post(
        api.url_for(EndpointActive, endpoint_id=2147483647), headers=headers, json={"active": active}
    )
    assert response.status_code == 404
    assert response.get_json() == {"message": "Endpoint not found"}


def test_deactivate_audits_actor(client, session, activation):
    active = activation
    action = "reactivate" if active else "deactivate"
    role = role_service.get_by_name("operator") or RoleFactory(name="operator")
    user = UserFactory(roles=[role])
    endpoint = EndpointFactory(active=not active)
    session.commit()
    headers = {"Authorization": "Bearer " + create_token(user)}
    with patch("lemur.logs.service.current_app.logger.info") as info:
        response = client.post(
            api.url_for(EndpointActive, endpoint_id=endpoint.id), headers=headers, json={"active": active}
        )
    assert response.status_code == 200
    entries = [
        call.args[0] for call in info.call_args_list
        if isinstance(call.args[0], dict) and call.args[0].get("action") == f"{action}_endpoint"
    ]
    assert len(entries) == 1
    assert entries[0]["user"] == user.email
    assert entries[0]["entity"] == endpoint.name
    assert entries[0]["details"] == f"{action.capitalize()}d endpoint {endpoint.id}"


@pytest.mark.parametrize("payload", [None, [], "false", {}, {"active": None},
                                    {"active": "false"}, {"active": "true"},
                                    {"active": 0}, {"active": 1}])
def test_active_rejects_non_boolean_payload(client, session, payload):
    headers = authorization(session, "operator")
    endpoint = EndpointFactory()
    session.commit()
    response = client.post(
        api.url_for(EndpointActive, endpoint_id=endpoint.id), headers=headers, json=payload
    )
    assert response.status_code == 400
    assert response.get_json() == {"message": "active must be a JSON boolean"}
    session.refresh(endpoint)
    assert endpoint.active is True
