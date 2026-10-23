"""Add unique constraint on destinations.label

Prod and staging were verified clean (no duplicate destination labels)
before this migration was created.

Revision ID: b7c8d9e0f1a2
Revises: a1b2c3d4e5f6
Create Date: 2026-10-22

"""

# revision identifiers, used by Alembic.
revision = "b7c8d9e0f1a2"
down_revision = "44d67c1988a2"

from alembic import op


def upgrade():
    op.create_unique_constraint(
        "uq_destinations_label", "destinations", ["label"]
    )


def downgrade():
    op.drop_constraint(
        "uq_destinations_label", "destinations", type_="unique"
    )
