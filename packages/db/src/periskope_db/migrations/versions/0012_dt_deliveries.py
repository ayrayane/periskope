"""A delivered version is no longer a collection project with the bricks as children (a DT project has one parent, and a brick
version may be in several delivered versions): it is a DT project tagged « version-livree », whose SBOM holds the chosen brick
versions as components. Which delivered versions hold which brick goes to dt_members."""
from alembic import op

revision = "0012"
down_revision = "0011"


def upgrade() -> None:
    op.execute("""
DROP VIEW dt_bricks;
-- Read again in the new shape at the next sync; findings follow by cascade.
DELETE FROM dt_projects;
DELETE FROM dt_state;
DELETE FROM dt_collections;
DROP INDEX dt_projects_parent;
ALTER TABLE dt_projects DROP COLUMN parent;

CREATE TABLE dt_members (
    tree text NOT NULL REFERENCES dt_collections(uuid) ON DELETE CASCADE,
    project text NOT NULL REFERENCES dt_projects(uuid) ON DELETE CASCADE,
    PRIMARY KEY (tree, project)
);
CREATE INDEX dt_members_project ON dt_members (project);

-- One row per brick and delivered version holding it.
CREATE VIEW dt_bricks AS
SELECT m.tree AS root, d.uuid, d.name, d.version, d.active, d.bom_at, d.by_tag, d.components, d.no_purl, d.project_id
FROM dt_members m JOIN dt_projects d ON d.uuid = m.project;
""")


def downgrade() -> None:
    op.execute("""
DROP VIEW dt_bricks;
DROP TABLE dt_members;
DELETE FROM dt_projects;
DELETE FROM dt_state;
DELETE FROM dt_collections;
ALTER TABLE dt_projects ADD COLUMN parent text;
CREATE INDEX dt_projects_parent ON dt_projects (parent);
CREATE VIEW dt_bricks AS
SELECT d.parent AS root, d.uuid, d.name, d.version, d.active, d.bom_at, d.by_tag, d.components, d.no_purl, d.project_id
FROM dt_projects d JOIN dt_collections c ON c.uuid = d.parent;
""")
