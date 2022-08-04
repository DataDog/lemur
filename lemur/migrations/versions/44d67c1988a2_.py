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
        sa.Column("primary_certificate", sa.Boolean(), nullable=False),
    )
    op.create_primary_key(
        None,
        "endpoints_certificates",
        ["certificate_id", "endpoint_id"]
    )

    print("Creating certificate_id_fkey foreign key on endpoints_certificates table")
    op.create_foreign_key(
        "certificate_id_fkey",
        "endpoints_certificates",
        "certificates",
        ["certificate_id"],
        ["id"],
        ondelete="CASCADE",
    )

    print("Creating endpoint_id_fkey foreign key on endpoints_certificates table")
    op.create_foreign_key(
        "endpoint_id_fkey",
        "endpoints_certificates",
        "endpoints",
        ["endpoint_id"],
        ["id"],
        ondelete="CASCADE",
    )

    print("Creating partial index unique_primary_certificate_ix on endpoints_certificates table")
    op.create_index(
        "unique_primary_certificate_ix",
        "endpoints_certificates",
        ["endpoint_id", "primary_certificate"],
        postgresql_where=text("primary_certificate"),
    )  # Enforces that only a single primary certificate can be associated with an endpoint.

    print("Populating endpoints_certificates table")
    conn = op.get_bind()
    for endpoint_id, certificate_id, certificate_path in conn.execute(
            text("select id, certificate_id, certificate_path from endpoints")
    ):
        stmt = text(
            "insert into endpoints_certificates (endpoint_id, certificate_id, path, primary_certificate) values (:endpoint_id, :certificate_id, :path, :primary_certificate)"
        )
        stmt = stmt.bindparams(
            endpoint_id=endpoint_id, certificate_id=certificate_id, path=certificate_path, primary_certificate=True
        )
        op.execute(stmt)

    print("Removing endpoints_certificate_id_fkey foreign key from endpoints table")
    op.drop_constraint("endpoints_certificate_id_fkey", "endpoints", type_="foreignkey")

    print("Removing certificate_id and certificate_path columns from endpoints table")
    op.drop_column("endpoints", "certificate_id")
    op.drop_column("endpoints", "certificate_path")


def downgrade():
    print("Restoring certificate_id and certificate_path columns to endpoints table")
    op.add_column("endpoints", sa.Column("certificate_id", sa.Integer(), nullable=True))
    op.add_column("endpoints", sa.Column("certificate_path", sa.String(length=256), nullable=True))

    print("Restoring endpoints_certificate_id_fkey foreign key to endpoints table")
    op.create_foreign_key(
        "endpoints_certificate_id_fkey",
        "endpoints",
        "certificates",
        ["certificate_id"],
        ["id"],
    )

    conn = op.get_bind()
    for certificate_id, endpoint_id, path in conn.execute(
        text("select certificate_id, endpoint_id, path from endpoints_certificates")
    ):
        stmt = text(
            "update endpoints set certificate_id = :certificate_id, certificate_path = :certificate_path where id = :endpoint_id"
        )
        stmt = stmt.bindparams(
            certificate_id=certificate_id, endpoint_id = endpoint_id, certificate_path=certificate_path
        )
        op.execute(stmt)

    print("Removing endpoints_certificates table")
    op.drop_table("endpoints_certificates")
