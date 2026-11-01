"""Index on runs.finished_at: the metrics scrape and the alert pass read the last hour or day of finished runs."""
from alembic import op

revision = "0005"
down_revision = "0004"


def upgrade() -> None:
    op.execute("CREATE INDEX runs_finished ON runs (finished_at)")
    op.execute("CREATE INDEX runs_created ON runs (created_at)")


def downgrade() -> None:
    op.execute("DROP INDEX runs_created")
    op.execute("DROP INDEX runs_finished")
