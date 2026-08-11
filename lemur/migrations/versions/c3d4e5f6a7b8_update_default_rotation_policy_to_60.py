"""Update the default rotation policy to 60 days.

The historical migration (a02a678ddc25) seeded the named 'default' RotationPolicy
at 30 days. Certs with a NULL rotation_policy_id are evaluated against
LEMUR_DEFAULT_ROTATION_INTERVAL (default 60) via _default_rotation_days() in
certificates/models.py, so the seeded default policy and the runtime NULL-policy
fallback can diverge (e.g. sandbox 'default' policy was 35d). This migration
brings the 'default' policy in line with the 60-day fallback.

Revision ID: c3d4e5f6a7b8
Revises: a1b2c3d4e5f6
Create Date: 2026-08-11
"""

# revision identifiers, used by Alembic.
revision = "c3d4e5f6a7b8"
down_revision = "a1b2c3d4e5f6"
branch_labels = None
depends_on = None

from alembic import op
from sqlalchemy.sql import text


def upgrade():
    conn = op.get_bind()
    conn.execute(
        text("UPDATE rotation_policies SET days = :days WHERE name = 'default'"),
        {"days": 60},
    )
    # Defensive: create the row if it somehow doesn't exist (the historical
    # migration a02a678ddc25 created it, but guard against a missing seed).
    row = conn.execute(
        text("SELECT id FROM rotation_policies WHERE name = 'default'")
    ).fetchone()
    if row is None:
        conn.execute(
            text("INSERT INTO rotation_policies (days, name) VALUES (:days, 'default')"),
            {"days": 60},
        )


def downgrade():
    conn = op.get_bind()
    conn.execute(
        text("UPDATE rotation_policies SET days = :days WHERE name = 'default'"),
        {"days": 30},
    )
