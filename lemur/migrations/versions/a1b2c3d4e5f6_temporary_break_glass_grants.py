"""Add temporary_break_glass_grants table for time-limited break-glass role.

Revision ID: a1b2c3d4e5f6
Revises: 44d67c1988a2
Create Date: 2025-02-27

NOTE: This table was created in all environments before this migration was
committed to git. The upgrade is idempotent — it skips creation if the
table already exists so it is safe to run against existing environments.

"""

# revision identifiers, used by Alembic.
revision = "a1b2c3d4e5f6"
down_revision = "44d67c1988a2"
branch_labels = None
depends_on = None

import sqlalchemy as sa
from alembic import op


def upgrade():
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    if "temporary_break_glass_grants" in inspector.get_table_names():
        return  # already exists in all envs; nothing to do

    op.create_table(
        "temporary_break_glass_grants",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("granted_by_id", sa.Integer(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["granted_by_id"],
            ["users.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_temporary_break_glass_grants_user_id",
        "temporary_break_glass_grants",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        "ix_temporary_break_glass_grants_expires_at",
        "temporary_break_glass_grants",
        ["expires_at"],
        unique=False,
    )


def downgrade():
    op.drop_index(
        "ix_temporary_break_glass_grants_expires_at",
        table_name="temporary_break_glass_grants",
    )
    op.drop_index(
        "ix_temporary_break_glass_grants_user_id",
        table_name="temporary_break_glass_grants",
    )
    op.drop_table("temporary_break_glass_grants")
