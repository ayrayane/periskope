"""The eleven tables of the spec (users and permissions counted as one)."""
from alembic import op

revision = "0001"
down_revision = None

SCHEMA = """
CREATE TABLE gitlab_instances (
    slug text PRIMARY KEY,
    name text NOT NULL,
    url text NOT NULL,
    rate_per_min int NOT NULL DEFAULT 600,
    sonar_url text,
    enterprise boolean NOT NULL DEFAULT true,
    enabled boolean NOT NULL DEFAULT true,
    last_sync_at timestamptz,
    tracked_namespaces jsonb NOT NULL DEFAULT '[]',
    excluded_namespaces jsonb NOT NULL DEFAULT '[]'
);

CREATE TABLE projects (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    instance text NOT NULL REFERENCES gitlab_instances(slug),
    gitlab_id bigint NOT NULL,
    path text NOT NULL,
    namespace_path text NOT NULL,
    namespace_kind text NOT NULL,
    default_branch text,
    archived boolean NOT NULL DEFAULT false,
    enabled boolean NOT NULL DEFAULT true,
    excluded_reason text,
    -- An admin put an excluded project back: sync no longer excludes it.
    reinstated boolean NOT NULL DEFAULT false,
    target_level int NOT NULL DEFAULT 3 CHECK (target_level BETWEEN 1 AND 5),
    sonar_key text,
    sonar_key_manual boolean NOT NULL DEFAULT false,
    last_activity_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (instance, gitlab_id),
    UNIQUE (instance, path)
);
CREATE INDEX projects_namespace ON projects (instance, namespace_path text_pattern_ops);

CREATE TABLE runs (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id bigint NOT NULL REFERENCES projects(id),
    branch text NOT NULL,
    commit_sha text,
    trigger text NOT NULL CHECK (trigger IN ('webhook', 'nightly', 'user', 'pipeline')),
    requested_by text,
    status text NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    finished_at timestamptz,
    error text,
    score real,
    coverage real,
    reused_from bigint REFERENCES runs(id),
    referential_version text NOT NULL,
    gitlab_calls int,
    results jsonb,
    by_dimension jsonb
);
CREATE INDEX runs_project_branch ON runs (project_id, branch, created_at DESC);
-- One active run per project and branch, guaranteed by the database.
CREATE UNIQUE INDEX runs_one_active ON runs (project_id, branch) WHERE status IN ('queued', 'running');

CREATE TABLE project_state (
    project_id bigint PRIMARY KEY REFERENCES projects(id),
    score real,
    coverage real,
    last_run_id bigint REFERENCES runs(id),
    last_success_at timestamptz,
    last_error text,
    next_due_at timestamptz NOT NULL DEFAULT now(),
    fingerprint text,
    by_dimension jsonb,
    statuses jsonb
);
CREATE INDEX project_state_score ON project_state (score);
CREATE INDEX project_state_due ON project_state (next_due_at);

-- Raw evidence, kept 14 days: dropping a day is dropping a partition.
CREATE TABLE run_evidence (
    run_id bigint NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    evidence jsonb NOT NULL
) PARTITION BY RANGE (created_at);
CREATE INDEX run_evidence_run ON run_evidence (run_id);

CREATE TABLE fingerprints (
    project_id bigint NOT NULL REFERENCES projects(id),
    commit_sha text NOT NULL,
    settings_hash text NOT NULL,
    sonar_analysis_id text,
    run_id bigint NOT NULL REFERENCES runs(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    results jsonb NOT NULL,
    UNIQUE (project_id, commit_sha, settings_hash)
);

CREATE TABLE history_monthly (
    project_id bigint NOT NULL REFERENCES projects(id),
    month date NOT NULL,
    score real,
    coverage real,
    by_dimension jsonb,
    PRIMARY KEY (project_id, month)
);

CREATE TABLE activities (
    uuid text NOT NULL,
    referential_version text NOT NULL,
    name text NOT NULL,
    dimension text NOT NULL,
    subdimension text NOT NULL,
    level int NOT NULL,
    usefulness int NOT NULL,
    depends_on jsonb NOT NULL DEFAULT '[]',
    PRIMARY KEY (uuid, referential_version)
);

CREATE TABLE scope_decisions (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    target text NOT NULL CHECK (target IN ('check', 'activity')),
    target_id text NOT NULL,
    instance text REFERENCES gitlab_instances(slug),
    project_id bigint REFERENCES projects(id),
    decision text NOT NULL CHECK (decision IN ('retained', 'excluded')),
    reason text NOT NULL,
    author text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (project_id IS NULL OR instance IS NOT NULL)
);
CREATE UNIQUE INDEX scope_decisions_target ON scope_decisions (target, target_id, instance, project_id) NULLS NOT DISTINCT;

CREATE TABLE users (
    sub text PRIMARY KEY,
    username text NOT NULL,
    email text,
    roles jsonb NOT NULL DEFAULT '[]',
    groups jsonb NOT NULL DEFAULT '[]',
    last_login timestamptz NOT NULL DEFAULT now()
);

-- Rights granted by hand, on top of GitLab membership (a CISO in no group, for example).
CREATE TABLE permissions (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    subject text NOT NULL,
    instance text REFERENCES gitlab_instances(slug),
    scope_kind text NOT NULL CHECK (scope_kind IN ('all', 'namespace', 'project')),
    scope_value text,
    role text NOT NULL CHECK (role IN ('viewer', 'maintainer', 'admin'))
);
CREATE INDEX permissions_subject ON permissions (subject);

CREATE TABLE audit_log (
    at timestamptz NOT NULL DEFAULT now(),
    actor text NOT NULL,
    action text NOT NULL,
    target text NOT NULL,
    before jsonb,
    after jsonb
) PARTITION BY RANGE (at);

-- Creates the partitions from the given day on; the scheduler calls it every night.
CREATE FUNCTION periskope_partitions(from_day date, days int) RETURNS void LANGUAGE plpgsql AS $$
DECLARE d date; m date;
BEGIN
  FOR i IN 0..days LOOP
    d := from_day + i;
    EXECUTE format('CREATE TABLE IF NOT EXISTS run_evidence_%s PARTITION OF run_evidence FOR VALUES FROM (%L) TO (%L)',
                   to_char(d, 'YYYYMMDD'), d, d + 1);
  END LOOP;
  FOR i IN 0..1 LOOP
    m := date_trunc('month', from_day + i * interval '1 month')::date;
    EXECUTE format('CREATE TABLE IF NOT EXISTS audit_log_%s PARTITION OF audit_log FOR VALUES FROM (%L) TO (%L)',
                   to_char(m, 'YYYYMM'), m, (m + interval '1 month')::date);
  END LOOP;
END $$;
SELECT periskope_partitions(current_date, 7);
"""


def upgrade() -> None:
    op.execute(SCHEMA)
