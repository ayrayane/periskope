"""Indexes for the portfolio's keyset pages (name and last success)."""
from alembic import op

revision = "0004"
down_revision = "0003"


def upgrade() -> None:
    op.execute("CREATE INDEX projects_path_id ON projects (path, id)")
    op.execute("CREATE INDEX project_state_last_success ON project_state (last_success_at DESC NULLS LAST)")
