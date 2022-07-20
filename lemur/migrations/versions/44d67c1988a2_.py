"""Support many-to-many relation between certificates and endpoints

Revision ID: 44d67c1988a2
Revises: a9987414cf36
Create Date: 2022-07-20 18:05:10.859504

"""

# revision identifiers, used by Alembic.
revision = '44d67c1988a2'
down_revision = 'a9987414cf36'

from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import text


def upgrade():
    print("Creating endpoints_certificates table")
    op.create_table(
        "endpoints_certificates",
        sa.Column("certificate_id", sa.Integer(), nullable=False),
        sa.Column("endpoint_id", sa.Integer(), nullable=False),
        sa.Column("path", sa.String(length=256), nullable=True),
        sa.Column("primary", sa.Boolean(), nullable=False),
    )
    op.create_primary_key(
        None,
        "endpoints_certificates",
        ["certificate_id", "endpoint_id"]
    )

    print("Creating certificates_id foreign key on endpoints_certificates table")
    op.create_foreign_key(
        None,
        "endpoints_certificates",
        "certificates",
        ["certificate_id"],
        ["id"],
        ondelete="CASCADE",
    )

    print("Creating endpoints_id foreign key on endpoints_certificates table")
    op.create_foreign_key(
        None,
        "endpoints_certificates",
        "endpoints",
        ["endpoint_id"],
        ["id"],
        ondelete="CASCADE",
    )

    print("Populating endpoints_certificates table")
    conn = op.get_bind()
    for endpoint_id, certificate_id, certificate_path in conn.execute(
            text("select id, certificate_id, certificate_path from endpoints")
    ):
        stmt = text(
            "insert into endpoints_certificates (endpoint_id, certificate_id, path, \"primary\") values (:endpoint_id, :certificate_id, :path, :primary)"
        )
        stmt = stmt.bindparams(
            endpoint_id=endpoint_id, certificate_id=certificate_id, path=certificate_path, primary=True
        )
        op.execute(stmt)


def downgrade():
    print("Removing foreign key constraints on endpoints_certificates table")
    op.drop_constraint(None, "endpoints_certificates", type_="foreignkey")

    print("Removing endpoints_certificates table")
    op.drop_table("endpoints_certificates")
