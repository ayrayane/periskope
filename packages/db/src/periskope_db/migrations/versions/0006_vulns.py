"""Open vulnerabilities of each project, as GitLab reports them: counts by severity for the dashboard, and the findings (CVE or title) for the vulnerability page."""
from alembic import op

revision = "0006"
down_revision = "0005"


def upgrade() -> None:
    op.execute("ALTER TABLE project_state ADD COLUMN vulns jsonb, ADD COLUMN vuln_findings jsonb")


def downgrade() -> None:
    op.execute("ALTER TABLE project_state DROP COLUMN vulns, DROP COLUMN vuln_findings")
