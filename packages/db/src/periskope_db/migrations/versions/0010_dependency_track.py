"""Dependency-Track, read only: its trees (one per environment, one per JAR delivery) with their bricks and findings;
the SSVC response; the ledger of every finding opened and closed; alerts already sent.
project_status is project_state with GitLab's dependency findings replaced by Dependency-Track's: what every screen reads."""
from alembic import op

revision = "0010"
down_revision = "0009"


def upgrade() -> None:
    op.execute("""
CREATE TABLE dt_projects (
    uuid text PRIMARY KEY,
    name text NOT NULL,
    version text,
    -- The tree it belongs to (its own uuid for a tree), and its parent in it.
    root text NOT NULL,
    parent text,
    kind text NOT NULL CHECK (kind IN ('tree', 'brick')),
    -- A tree « CMS · prod|test|dev » is an environment; any other tree is a delivered version (e.g. « CMS · 5.2.0 (livraison JAR) »).
    env text,
    active boolean NOT NULL DEFAULT true,
    bom_at timestamptz,
    -- Deployed by tag instead of digest: the GitOps job tags the brick « deploiement-par-tag ».
    by_tag boolean NOT NULL DEFAULT false,
    components integer,
    no_purl integer,
    project_id bigint REFERENCES projects(id) ON DELETE SET NULL,
    synced_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX dt_projects_project ON dt_projects (project_id);
CREATE INDEX dt_projects_root ON dt_projects (root);

CREATE TABLE dt_findings (
    project text NOT NULL REFERENCES dt_projects(uuid) ON DELETE CASCADE,
    component text NOT NULL,
    vuln text NOT NULL,
    key text NOT NULL,
    cve boolean NOT NULL,
    severity text NOT NULL,
    title text,
    component_name text,
    component_version text,
    purl text,
    vector text,
    kev boolean NOT NULL DEFAULT false,
    epss real,
    -- DT's analysis: NOT_AFFECTED and FALSE_POSITIVE are « non concerné » (VEX); an accepted risk is an exception with an end date.
    state text,
    suppressed boolean NOT NULL DEFAULT false,
    response text,
    justification text,
    detail text,
    analysed_at timestamptz,
    expires_on date,
    attributed_at timestamptz,
    PRIMARY KEY (project, component, vuln)
);
CREATE INDEX dt_findings_key ON dt_findings (key);

-- The vulnerability data sources DT mirrors (NVD, GitHub, OSV): when each last completed.
CREATE TABLE dt_sources (name text PRIMARY KEY, status text, completed_at timestamptz, error text, read_at timestamptz NOT NULL DEFAULT now());

-- Open findings of each Periskope project, as DT's trees give them; rebuilt at each DT synchronisation.
CREATE TABLE dt_state (project_id bigint PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE, findings jsonb NOT NULL, bricks jsonb NOT NULL);

-- Every finding (project, key) ever open, with when it opened and closed and its deadline: the indicators' memory.
CREATE TABLE vuln_ledger (
    project_id bigint NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    key text NOT NULL,
    opened_at timestamptz NOT NULL,
    closed_at timestamptz,
    priority text,
    response text,
    deadline_at timestamptz,
    PRIMARY KEY (project_id, key, opened_at)
);
CREATE UNIQUE INDEX vuln_ledger_open ON vuln_ledger (project_id, key) WHERE closed_at IS NULL;

-- Every source of CVE data and when it last completed: KEV and EPSS read by Periskope, NVD, GitHub and OSV mirrored by DT.
CREATE VIEW vuln_sources AS
SELECT upper(name) AS name, fetched_at AS completed_at, error, 'periskope' AS via FROM vuln_feeds
UNION ALL SELECT upper(name), completed_at, error, 'dependency-track' FROM dt_sources;

CREATE TABLE alerts_sent (kind text NOT NULL, key text NOT NULL, sent_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (kind, key));

-- SSVC (CISA, deployer tree reduced to our facts): exploitation from KEV and EPSS, exposure and mission impact from the
-- environment (prod exposed), automatable or total impact from the CVSS vector (network, no privilege, no user) or a critical severity.
CREATE FUNCTION ssvc(kev boolean, epss real, threshold real, severity text, vector text, exposed boolean) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
SELECT CASE
    WHEN coalesce(kev, false) THEN CASE WHEN exposed THEN 'immediate' ELSE 'out_of_cycle' END
    WHEN severity IN ('info', 'unknown') THEN 'deferred'
    WHEN epss >= threshold THEN CASE WHEN exposed AND strong THEN 'immediate' WHEN exposed THEN 'out_of_cycle' ELSE 'scheduled' END
    ELSE CASE WHEN exposed AND strong THEN 'out_of_cycle' WHEN exposed THEN 'scheduled' ELSE 'deferred' END
END FROM (SELECT severity = 'critical' OR coalesce(vector ~ 'AV:N' AND vector ~ 'AC:L' AND vector ~ 'PR:N' AND vector ~ 'UI:N', false) AS strong) s
$$;

-- Exposed: deployed in a prod tree (DT findings carry their environments); otherwise the project's topic, an unclassified one counting as prod.
CREATE FUNCTION exposed(f jsonb, topics text[]) RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
SELECT CASE WHEN f ? 'envs' THEN f->'envs' ? 'prod' ELSE 'prod' = ANY(topics) OR NOT topics && ARRAY['test', 'dev'] END
$$;

CREATE FUNCTION vuln_counts(findings jsonb) RETURNS jsonb
LANGUAGE sql IMMUTABLE AS $$
SELECT jsonb_build_object('critical', count(*) FILTER (WHERE x->>'severity' = 'critical'), 'high', count(*) FILTER (WHERE x->>'severity' = 'high'),
    'medium', count(*) FILTER (WHERE x->>'severity' = 'medium'), 'low', count(*) FILTER (WHERE x->>'severity' = 'low'),
    'info', count(*) FILTER (WHERE x->>'severity' = 'info'), 'unknown', count(*) FILTER (WHERE x->>'severity' = 'unknown'))
FROM jsonb_array_elements(findings) x
$$;

-- With DT, GitLab keeps code, secrets and application findings (SAST, secrets, DAST); dependencies and images come from DT alone.
-- shortcut: the counts are then those of the findings kept (GitLab's first 100 per project), no longer GitLab's own totals.
CREATE VIEW project_status AS
SELECT s.project_id, s.score, s.coverage, s.last_run_id, s.last_success_at, s.last_error, s.next_due_at, s.fingerprint, s.by_dimension, s.statuses,
    CASE WHEN m.findings IS NULL THEN s.vulns ELSE vuln_counts(m.findings) END AS vulns,
    coalesce(m.findings, s.vuln_findings) AS vuln_findings, d.bricks AS dt
FROM project_state s
LEFT JOIN dt_state d ON d.project_id = s.project_id
LEFT JOIN LATERAL (
    SELECT d.findings || coalesce((SELECT jsonb_agg(x) FROM jsonb_array_elements(s.vuln_findings) x
        WHERE x->>'type' NOT IN ('dependency_scanning', 'container_scanning', 'cluster_image_scanning')), '[]'::jsonb) AS findings
    WHERE d.findings IS NOT NULL) m ON true;
""")


def downgrade() -> None:
    op.execute("""
DROP VIEW project_status; DROP VIEW vuln_sources;
DROP FUNCTION vuln_counts(jsonb); DROP FUNCTION exposed(jsonb, text[]); DROP FUNCTION ssvc(boolean, real, real, text, text, boolean);
DROP TABLE alerts_sent; DROP TABLE vuln_ledger; DROP TABLE dt_state; DROP TABLE dt_sources; DROP TABLE dt_findings; DROP TABLE dt_projects;
""")
