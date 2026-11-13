"""GitLab topics of a project, lower-cased: the topics prod, test and dev tell its environment."""
from alembic import op

revision = "0009"
down_revision = "0008"


def upgrade() -> None:
    op.execute("ALTER TABLE projects ADD COLUMN topics text[] NOT NULL DEFAULT '{}'")


def downgrade() -> None:
    op.execute("ALTER TABLE projects DROP COLUMN topics")
