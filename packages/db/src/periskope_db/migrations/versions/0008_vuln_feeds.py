"""Exploitation feeds read from an internal mirror: CISA's KEV catalogue and FIRST's EPSS scores, replaced whole each night."""
from alembic import op

revision = "0008"
down_revision = "0007"


def upgrade() -> None:
    op.execute("""
CREATE TABLE vuln_kev (cve text PRIMARY KEY, date_added date, due_date date, ransomware boolean NOT NULL DEFAULT false);
CREATE TABLE vuln_epss (cve text PRIMARY KEY, score real NOT NULL, percentile real NOT NULL);
CREATE TABLE vuln_feeds (name text PRIMARY KEY, url text NOT NULL, fetched_at timestamptz, rows integer, published text, error text);
""")


def downgrade() -> None:
    op.execute("DROP TABLE vuln_feeds; DROP TABLE vuln_epss; DROP TABLE vuln_kev")
