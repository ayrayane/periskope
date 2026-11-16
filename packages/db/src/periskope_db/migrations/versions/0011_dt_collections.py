"""Dependency-Track mirrors GitLab (one DT project per GitLab path, its version the GitLab tag). A delivered version is a collection
project (named after the product, its version the delivery's) that the GitOps repository fills with the chosen brick versions.
The trees the screens read are these collections."""
from alembic import op

revision = "0011"
down_revision = "0010"


def upgrade() -> None:
    op.execute("""
-- Read again in the new shape at the next sync; findings follow by cascade.
DELETE FROM dt_projects;
DELETE FROM dt_state;
ALTER TABLE dt_projects DROP COLUMN root, DROP COLUMN kind, DROP COLUMN env;
CREATE INDEX dt_projects_parent ON dt_projects (parent);

-- The collection projects of DT, read at each sync.
CREATE TABLE dt_collections (uuid text PRIMARY KEY, name text NOT NULL, version text, active boolean NOT NULL, read_at timestamptz NOT NULL DEFAULT now());

-- A tree is a delivered version, without environment (counted as production); its bricks are the DT projects under it.
CREATE VIEW dt_trees AS
SELECT c.uuid, c.name || coalesce(' ' || c.version, '') AS name, NULL::text AS env, c.active, c.read_at AS synced_at FROM dt_collections c;
CREATE VIEW dt_bricks AS
SELECT d.parent AS root, d.uuid, d.name, d.version, d.active, d.bom_at, d.by_tag, d.components, d.no_purl, d.project_id
FROM dt_projects d JOIN dt_collections c ON c.uuid = d.parent;

-- A version in no delivered version has no environment: the project's topics say whether it is exposed.
CREATE OR REPLACE FUNCTION exposed(f jsonb, topics text[]) RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
SELECT CASE WHEN jsonb_array_length(coalesce(f->'envs', '[]')) > 0 THEN f->'envs' ? 'prod' ELSE 'prod' = ANY(topics) OR NOT topics && ARRAY['test', 'dev'] END
$$;
""")


def downgrade() -> None:
    op.execute("""
CREATE OR REPLACE FUNCTION exposed(f jsonb, topics text[]) RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
SELECT CASE WHEN f ? 'envs' THEN f->'envs' ? 'prod' ELSE 'prod' = ANY(topics) OR NOT topics && ARRAY['test', 'dev'] END
$$;
DROP VIEW dt_bricks; DROP VIEW dt_trees; DROP TABLE dt_collections;
DROP INDEX dt_projects_parent;
DELETE FROM dt_projects;
DELETE FROM dt_state;
ALTER TABLE dt_projects ADD COLUMN root text NOT NULL, ADD COLUMN kind text NOT NULL CHECK (kind IN ('tree', 'brick')), ADD COLUMN env text;
CREATE INDEX dt_projects_root ON dt_projects (root);
""")
