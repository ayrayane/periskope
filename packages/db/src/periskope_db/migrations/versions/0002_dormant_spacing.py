"""Instances can space out dormant projects (weekly after 7 idle days, monthly after 6 months)."""
from alembic import op

revision = "0002"
down_revision = "0001"


def upgrade() -> None:
    op.execute("ALTER TABLE gitlab_instances ADD COLUMN space_dormant boolean NOT NULL DEFAULT false")
