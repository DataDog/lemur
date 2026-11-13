import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import g
from sqlalchemy import text

from lemur.auth.vault_jwt_auth import JWTAuthenticator
from lemur.readonly import views

ISSUER = "https://identity.example/readonly"


@pytest.fixture
def readonly_token(app, user, session, monkeypatch):
    session.commit()
    app.config.update(
        READ_ONLY_API_ENABLED=True,
        READ_ONLY_API_AUDIENCE="certificate-reader",
        READ_ONLY_API_ISSUERS=[ISSUER],
        READ_ONLY_API_ENVIRONMENT="test",
    )
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update(kid="test-key", use="sig", alg="RS256")
    monkeypatch.setattr(
        JWTAuthenticator,
        "_make_issuer_request",
        lambda self, issuer: ({"keys": [jwk]}, 3600),
    )
    monkeypatch.setattr(JWTAuthenticator, "_instances", {})

    def token(**overrides):
        claims = dict(
            iss=ISSUER,
            aud="certificate-reader",
            sub="human-id",
            email=user["user"].email,
            environment="test",
            iat=int(time.time()),
            exp=int(time.time()) + 300,
        )
        claims.update(overrides)
        return {
            "Authorization": "Bearer "
            + jwt.encode(claims, key, algorithm="RS256", headers={"kid": "test-key"})
        }

    yield token
    app.config["READ_ONLY_API_ENABLED"] = False


def test_disabled_by_default(app, client):
    app.config["READ_ONLY_API_ENABLED"] = False
    assert client.get("/api/1/readonly/session").status_code == 404


@pytest.mark.parametrize(
    "claims",
    [
        {"iss": "https://untrusted.example"},
        {"aud": "other"},
        {"environment": "other"},
        {"email": ""},
        {"sub": ""},
        {"exp": None},
        {"exp": 0},
    ],
)
def test_rejects_invalid_identity(client, readonly_token, claims):
    assert (
        client.get("/api/1/readonly/session", headers=readonly_token(**claims)).status_code == 401
    )


def test_requires_existing_active_account(client, readonly_token, user, session):
    assert client.get("/api/1/readonly/session").status_code == 401
    assert (
        client.get(
            "/api/1/readonly/session", headers=readonly_token(email="unknown@example.com")
        ).status_code
        == 403
    )
    user["user"].active = False
    session.commit()
    assert client.get("/api/1/readonly/session", headers=readonly_token()).status_code == 403


def test_metadata_search_pagination_and_detail(client, readonly_token, certificate):
    headers = readonly_token()
    response = client.get("/api/1/readonly/session", headers=headers)
    assert response.status_code == 200
    assert response.json["readOnly"] is True
    assert response.headers["Cache-Control"] == "no-store"
    response = client.get(
        "/api/1/readonly/certificates", query_string={"query": certificate.cn}, headers=headers
    )
    assert response.status_code == 200
    assert certificate.id in [item["id"] for item in response.json["items"]]
    response = client.get("/api/1/readonly/certificates/{}".format(certificate.id), headers=headers)
    assert response.status_code == 200
    assert response.json["id"] == certificate.id
    assert not {"body", "chain", "csr", "privateKey", "user", "sources"} & response.json.keys()
    for destination in response.json["destinations"]:
        assert set(destination) == {"id", "label"}
    first_page = client.get("/api/1/readonly/certificates?count=1", headers=headers).json
    assert len(first_page["items"]) == 1
    next_page = client.get("/api/1/readonly/certificates?page=2&count=1", headers=headers).json
    assert next_page["total"] == first_page["total"]
    if next_page["items"]:
        assert next_page["items"][0]["id"] < first_page["items"][0]["id"]
    empty_page = first_page["total"] // 100 + 2
    assert (
        client.get(
            "/api/1/readonly/certificates",
            query_string={"page": empty_page, "count": 100},
            headers=headers,
        ).json["items"]
        == []
    )
    for suffix in ("?count=101", "?page=0", "?target=other", "?page=1&page=2"):
        assert (
            client.get("/api/1/readonly/certificates" + suffix, headers=headers).status_code == 400
        )


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
def test_rejects_mutation_methods(client, readonly_token, method):
    for path in ("session", "certificates", "certificates/1", "certificates/1/export"):
        response = client.open("/api/1/readonly/" + path, method=method, headers=readonly_token())
        assert response.status_code == 405


def test_credential_cannot_access_management_api(client, readonly_token):
    assert client.get("/api/1/certificates", headers=readonly_token()).status_code == 403
    assert (
        client.get(
            "/api/1/readonly/certificates/1/privateKey", headers=readonly_token()
        ).status_code
        == 404
    )


def test_database_rejects_even_accidental_writes(
    client, readonly_token, certificate, monkeypatch, user, session
):
    def accidental_write(_certificate):
        g.readonly_session.execute(text("UPDATE users SET active = false"))
        return {}

    monkeypatch.setattr(views, "metadata", accidental_write)
    response = client.get(
        "/api/1/readonly/certificates/{}".format(certificate.id), headers=readonly_token()
    )
    assert response.status_code == 500
    session.refresh(user["user"])
    assert user["user"].active
