from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

from freezegun import freeze_time
import pytest

from flask import current_app

from lemur.auth.views import *  # noqa
from lemur.tests.conf import (
    OAUTH_STATE_TOKEN_STALE_TOLERANCE_SECONDS,
    OAUTH_STATE_TOKEN_SECRET,
)


def test_build_hmac(client):
    from lemur.auth.views import build_hmac

    assert isinstance(build_hmac(), hmac.HMAC)

    # make a bad key
    current_app.config["OAUTH_STATE_TOKEN_SECRET"] = "not-bytes-like"
    assert not build_hmac()

    # put back a good key, for remaining tests
    current_app.config["OAUTH_STATE_TOKEN_SECRET"] = OAUTH_STATE_TOKEN_SECRET


def test_generate_state_token(client):
    from lemur.auth.views import generate_state_token

    assert generate_state_token()


def test_verify_state_token(client):
    from lemur.auth.views import generate_state_token
    from lemur.auth.views import verify_state_token

    token = generate_state_token()
    assert verify_state_token(token)

    with freeze_time(
        datetime.now(timezone.utc)
        - timedelta(seconds=OAUTH_STATE_TOKEN_STALE_TOLERANCE_SECONDS),
        tick=True,
    ):
        stale_token = generate_state_token()
    assert not verify_state_token(stale_token)

    assert not verify_state_token("123456:f4k8")
    assert not verify_state_token("123456::f4k8")
    assert not verify_state_token("123456f4k8")
    assert not verify_state_token("")

    # force a new key to get generated and stored at runtime
    current_app.config["OAUTH_STATE_TOKEN_SECRET"] = None
    token_via_runtime_key = generate_state_token()
    assert verify_state_token(token_via_runtime_key)


@pytest.mark.parametrize(
    "assign_default_role,expected_roles",
    [
        (False, ["reader@datadoghq.com"]),
        (True, ["reader@datadoghq.com", "operator"]),
    ],
)
def test_create_user_roles_can_control_default_role(
    app, assign_default_role, expected_roles
):
    profile = {"email": "reader@datadoghq.com"}

    def get_role(name):
        return SimpleNamespace(name=name, third_party=True)

    with patch.dict(app.config, {"LEMUR_DEFAULT_ROLE": "operator"}), patch(
        "lemur.auth.views.role_service.get_by_name", side_effect=get_role
    ):
        roles = create_user_roles(
            profile, assign_default_role=assign_default_role
        )

    assert [role.name for role in roles] == expected_roles


def test_create_user_roles_assigns_default_role_by_default(app):
    profile = {"email": "reader@datadoghq.com"}

    def get_role(name):
        return SimpleNamespace(name=name, third_party=True)

    with patch.dict(app.config, {"LEMUR_DEFAULT_ROLE": "operator"}), patch(
        "lemur.auth.views.role_service.get_by_name", side_effect=get_role
    ):
        roles = create_user_roles(profile)

    assert [role.name for role in roles] == ["reader@datadoghq.com", "operator"]


@pytest.mark.parametrize(
    "existing_roles,groups,assign_default_role",
    [
        (None, [], False),
        ([], ["unrelated-team"], False),
        (["operator"], [], True),
        (["admin"], [], False),
        (None, ["resource-management"], True),
        (None, ["team-fabricgateways"], True),
    ],
)
def test_vault_assigns_default_role_from_existing_roles_or_groups(
    app, existing_roles, groups, assign_default_role
):
    profile = {"email": "user@datadoghq.com", "groups": groups}
    user = None
    if existing_roles is not None:
        user = SimpleNamespace(
            id=1,
            active=True,
            roles=[SimpleNamespace(name=role) for role in existing_roles],
        )
    updated_user = SimpleNamespace(id=1, active=True)
    authenticator = SimpleNamespace(authenticate=lambda token: profile)
    config = {
        "VAULT_CLIENT_ID": "lemur",
        "VAULT_ISSUER_URL": "https://vault.example.com",
        "LEMUR_DEFAULT_ROLE": "operator",
    }

    with patch.dict(app.config, config), app.test_request_context(
        json={"id_token": "token"}
    ), patch(
        "lemur.auth.views.JWTAuthenticator.instance", return_value=authenticator
    ), patch("lemur.auth.views.user_service.get_by_email", return_value=user), patch(
        "lemur.auth.views.create_user_roles", return_value=[]
    ) as create_roles, patch(
        "lemur.auth.views.update_user", return_value=updated_user
    ), patch(
        "lemur.auth.views.create_token", return_value="session-token"
    ), patch(
        "lemur.auth.views.identity_changed.send"
    ):
        response = Vault().post()

    assert response == {"token": "session-token"}
    create_roles.assert_called_once_with(
        profile, assign_default_role=assign_default_role
    )
