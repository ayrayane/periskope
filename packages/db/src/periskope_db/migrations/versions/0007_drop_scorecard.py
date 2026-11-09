"""The six Scorecard checks leave the catalog: drop the scope decisions seeded for them at install."""
from alembic import op

revision = "0007"
down_revision = "0006"


def upgrade() -> None:
    op.execute("DELETE FROM scope_decisions WHERE target = 'check' AND target_id LIKE 'scorecard.%'")


def downgrade() -> None:
    pass
