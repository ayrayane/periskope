"""Hot settings an admin changes from the interface (task hours, retention, quotas); infrastructure stays in the values."""
from alembic import op

revision = "0003"
down_revision = "0002"


def upgrade() -> None:
    op.execute("""
CREATE TABLE settings (
    key text PRIMARY KEY,
    value jsonb NOT NULL,
    updated_by text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
""")
