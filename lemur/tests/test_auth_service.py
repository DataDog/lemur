import pytest

from lemur.auth.service import AuthenticatedResource, create_token
from lemur.roles import service as role_service
from lemur.tests.factories import RoleFactory, UserFactory


def invoke_authenticated_resource(app, method, headers=None):
    handler = lambda: ({"message": "ok"}, 200)
    for decorator in AuthenticatedResource.method_decorators:
        handler = decorator(handler)

    with app.test_request_context(method=method, headers=headers):
        return handler()


def authorization_header(user):
    return {"Authorization": "Basic " + create_token(user)}


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
def test_authenticated_resource_allows_read_only_safe_methods(
    app, session, method
):
    user = UserFactory(roles=[RoleFactory(name="read-only")])
    session.commit()

    response, status = invoke_authenticated_resource(
        app, method, authorization_header(user)
    )

    assert status == 200
    assert response == {"message": "ok"}


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_authenticated_resource_rejects_read_only_write_methods(
    app, session, method
):
    user = UserFactory(roles=[RoleFactory(name="read-only")])
    session.commit()

    response, status = invoke_authenticated_resource(
        app, method, authorization_header(user)
    )

    assert status == 403
    assert response == {"message": "Operator role is required for write operations"}


@pytest.mark.parametrize("role_name", ["operator", "admin"])
@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_authenticated_resource_allows_privileged_write_methods(
    app, session, method, role_name
):
    role = role_service.get_by_name(role_name) or RoleFactory(name=role_name)
    user = UserFactory(roles=[role])
    session.commit()

    response, status = invoke_authenticated_resource(
        app, method, authorization_header(user)
    )

    assert status == 200
    assert response == {"message": "ok"}


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_authenticated_resource_authenticates_before_checking_write_access(
    app, session, method
):
    response = invoke_authenticated_resource(app, method)

    assert response.status_code == 401
    assert response.get_json() == {"message": "Missing authorization header"}
