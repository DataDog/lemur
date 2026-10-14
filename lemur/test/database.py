"""Database lifecycle for the isolated Lemur sandbox test environment."""

import secrets
from datetime import datetime, timedelta
from pathlib import Path

from flask import current_app
from flask_migrate import stamp
from sqlalchemy.sql import text

from lemur import database
from lemur.authorities import service as authority_service
from lemur.extensions import db
from lemur.notifications import service as notification_service
from lemur.plugins.base import plugins
from lemur.policies import service as policy_service
from lemur.roles import service as role_service
from lemur.users import service as user_service

MIGRATIONS_DIRECTORY = str(Path(__file__).resolve().parents[1] / "migrations")


def validate_database_identity():
    """Refuse destructive work outside the dedicated database and role."""
    identity = db.engine.execute(
        text("SELECT current_database(), current_user")
    ).fetchone()
    expected_database = current_app.config.get("LEMUR_TEST_DATABASE", "test")
    expected_user = current_app.config.get("LEMUR_TEST_DATABASE_USER", "lemur_test")
    if tuple(identity) != (expected_database, expected_user):
        raise RuntimeError(
            "Refusing to run against database={!r}, user={!r}; expected database={!r}, user={!r}".format(
                identity[0], identity[1], expected_database, expected_user
            )
        )
    return tuple(identity)


def reset_schema():
    """Recreate only the public schema in the dedicated test database."""
    validate_database_identity()
    db.session.remove()
    db.engine.execute(text("DROP SCHEMA public CASCADE"))
    db.engine.execute(text("CREATE SCHEMA public AUTHORIZATION CURRENT_USER"))
    db.engine.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
    db.create_all()
    stamp(directory=MIGRATIONS_DIRECTORY, revision="head")


def _create_roles_and_users():
    admin = role_service.create(
        "admin", description="Lemur sandbox test administrator role."
    )
    role_service.create("operator", description="Lemur sandbox test operator role.")
    role_service.create("read-only", description="Lemur sandbox test read only role.")
    test_user = user_service.create(
        username="lemur-test",
        password=secrets.token_urlsafe(32),
        email="lemur-test@datadoghq.com",
        active=True,
        profile_picture=None,
        roles=[admin],
    )
    user_service.create(
        username="lemur",
        password=secrets.token_urlsafe(32),
        email="lemur@nobody.com",
        active=True,
        profile_picture=None,
        roles=[admin],
    )
    return test_user


def _create_test_authority(user):
    issuer = plugins.get("cryptography-issuer")
    if not issuer:
        raise RuntimeError("cryptography-issuer plugin is required for Lemur tests")

    now = datetime.utcnow()
    return authority_service.create(
        name="TestCA",
        owner=user.email,
        description="Isolated Lemur sandbox test certificate authority",
        common_name="Lemur Sandbox Test Root CA",
        country="US",
        state="New York",
        location="New York",
        organization="Datadog",
        organizational_unit="Resource Management",
        type="root",
        signing_algorithm="sha256WithRSA",
        key_type="RSA2048",
        sensitivity="medium",
        serial_number=1,
        first_serial=1,
        validity_start=now - timedelta(days=1),
        validity_end=now + timedelta(days=3650),
        plugin={"slug": issuer.slug, "plugin_object": issuer},
        extensions={"sub_alt_names": {"names": []}, "custom": []},
        creator=user,
        roles=[],
    )


def seed():
    """Create the minimum application records needed by real task runs."""
    validate_database_identity()
    user = _create_roles_and_users()
    policy_service.update_default_rotation_policy()
    notification_service.create_default_expiration_notifications(
        "DEFAULT_SECURITY",
        current_app.config.get("LEMUR_SECURITY_TEAM_EMAIL"),
    )
    authority = _create_test_authority(user)
    database.commit()
    return {"user_id": user.id, "authority_id": authority.id}


def reset_and_seed():
    """Reset the isolated schema and seed deterministic application state."""
    reset_schema()
    return seed()
