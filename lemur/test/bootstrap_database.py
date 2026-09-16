"""Create the isolated Lemur sandbox test database and login role."""

import os

from flask import current_app
from psycopg2 import sql
from sqlalchemy.sql import text

from lemur import create_app
from lemur.extensions import db


def bootstrap():
    """Create or update only the configured test role and database."""
    if not current_app.config.get("LEMUR_TEST_BOOTSTRAP_ENABLED", False):
        raise RuntimeError("LEMUR_TEST_BOOTSTRAP_ENABLED must be true")

    config = current_app.config
    expected_database = config.get("LEMUR_TEST_BOOTSTRAP_DATABASE", "lemur")
    expected_user = config.get("LEMUR_TEST_BOOTSTRAP_USER", "lemur")
    identity = db.engine.execute(
        text("SELECT current_database(), current_user")
    ).fetchone()
    if tuple(identity) != (expected_database, expected_user):
        raise RuntimeError(
            "Refusing to bootstrap from database={!r}, user={!r}; expected database={!r}, user={!r}".format(
                identity[0], identity[1], expected_database, expected_user
            )
        )

    database_name = config.get("LEMUR_TEST_DATABASE", "test")
    database_user = config.get("LEMUR_TEST_DATABASE_USER", "lemur_test")
    database_password = db.engine.url.password
    if not database_password:
        raise RuntimeError("The configured database password is empty")

    connection = db.engine.raw_connection()
    try:
        connection.rollback()
        connection.set_session(autocommit=True)
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT 1 FROM pg_roles WHERE rolname = %s", (database_user,)
            )
            if cursor.fetchone():
                cursor.execute(
                    sql.SQL("ALTER ROLE {} LOGIN PASSWORD %s").format(
                        sql.Identifier(database_user)
                    ),
                    (database_password,),
                )
            else:
                cursor.execute(
                    sql.SQL("CREATE ROLE {} LOGIN PASSWORD %s").format(
                        sql.Identifier(database_user)
                    ),
                    (database_password,),
                )

            cursor.execute(
                "SELECT 1 FROM pg_database WHERE datname = %s", (database_name,)
            )
            if not cursor.fetchone():
                cursor.execute(
                    sql.SQL("CREATE DATABASE {} OWNER {}").format(
                        sql.Identifier(database_name), sql.Identifier(database_user)
                    )
                )
            cursor.execute(
                sql.SQL("ALTER DATABASE {} OWNER TO {}").format(
                    sql.Identifier(database_name), sql.Identifier(database_user)
                )
            )
    finally:
        connection.close()

    return {"database": database_name, "user": database_user}


def main():
    """Run the bootstrap using the normal Lemur configuration."""
    app = create_app(os.environ.get("LEMUR_CONF"))
    with app.app_context():
        print("Bootstrapped Lemur test database: {}".format(bootstrap()))


if __name__ == "__main__":
    main()
