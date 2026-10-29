"""Inventory and memberships, read from GitLab with the instance's service token."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import asyncpg
from periskope_clients.gitlab import GitLab
from periskope_core.settings import Instance


def exclusion(p: dict[str, Any], excluded_namespaces: list[str]) -> str | None:
    """Why a project is not tracked, or None. The namespace kind is GitLab's own: a group cannot fake it."""
    ns = p["namespace"]["full_path"]
    if p["namespace"]["kind"] == "user":
        return "projet personnel"
    if p.get("archived"):
        return "projet archivé"
    if not p.get("default_branch") or p.get("empty_repo"):
        return "projet vide"
    if any(ns == e or ns.startswith(e + "/") for e in excluded_namespaces):
        return "namespace exclu"
    return None


async def sync_projects(db: asyncpg.Pool, gl: GitLab, instance: Instance) -> dict[str, int]:
    """Adds new projects, disables archived or deleted ones (keeping their history), refreshes names and branches."""
    seen: list[int] = []
    rows = []
    for root in instance.tracked_namespaces:
        # Keyset pagination of 100, no per-project call: about ten calls for 1,000 projects.
        res = await gl.pages(f"/groups/{root.replace('/', '%2F')}/projects", include_subgroups="true", order_by="id",
                             sort="asc", pagination="keyset", max_pages=200)
        if res is None:
            raise RuntimeError(f"groupe {root} illisible avec le jeton de service")
        for p in res[0]:
            seen.append(p["id"])
            rows.append((instance.slug, p["id"], p["path_with_namespace"], p["namespace"]["full_path"], p["namespace"]["kind"],
                         p.get("default_branch"), bool(p.get("archived")), exclusion(p, instance.excluded_namespaces),
                         p["path_with_namespace"].replace("/", "_"), _ts(p.get("last_activity_at"))))
    async with db.acquire() as conn, conn.transaction():
        await conn.executemany(
            """INSERT INTO projects (instance, gitlab_id, path, namespace_path, namespace_kind, default_branch, archived,
                                     excluded_reason, enabled, sonar_key, last_activity_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8::text, $8::text IS NULL, $9, $10)
               ON CONFLICT (instance, gitlab_id) DO UPDATE SET
                 path = excluded.path, namespace_path = excluded.namespace_path, namespace_kind = excluded.namespace_kind,
                 default_branch = excluded.default_branch, archived = excluded.archived, last_activity_at = excluded.last_activity_at,
                 -- what was set by hand survives the sync
                 excluded_reason = CASE WHEN projects.reinstated THEN NULL ELSE excluded.excluded_reason END,
                 enabled = projects.reinstated OR excluded.excluded_reason IS NULL,
                 sonar_key = CASE WHEN projects.sonar_key_manual THEN projects.sonar_key ELSE excluded.sonar_key END""",
            rows,
        )
        gone = await conn.execute(
            "UPDATE projects SET enabled = false, excluded_reason = 'supprimé ou sorti des groupes suivis'"
            " WHERE instance = $1 AND NOT (gitlab_id = ANY($2::bigint[])) AND enabled", instance.slug, seen)
        await conn.execute(
            "INSERT INTO project_state (project_id) SELECT id FROM projects WHERE instance = $1 AND enabled ON CONFLICT DO NOTHING", instance.slug)
        await conn.execute("UPDATE gitlab_instances SET last_sync_at = now() WHERE slug = $1", instance.slug)
    return {"seen": len(seen), "disabled": int(gone.split()[-1])}


def _ts(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


GUEST = 10


def seen(node: dict[str, Any]) -> bool:
    """Minimal access (5) does not show the group's projects in GitLab, so not in Periskope either."""
    return ((node.get("accessLevel") or {}).get("integerValue") or 0) >= GUEST


MEMBERSHIPS = """
query($username: String!, $groups: String, $projects: String) {
  user(username: $username) {
    groupMemberships(first: 100, after: $groups) { pageInfo { hasNextPage endCursor } nodes { accessLevel { integerValue } group { fullPath } } }
    projectMemberships(first: 100, after: $projects) { pageInfo { hasNextPage endCursor } nodes { accessLevel { integerValue } project { fullPath id } } }
  }
}
"""


async def gitlab_user(gl: GitLab, username: str, email: str | None) -> dict[str, Any] | None:
    """The GitLab account of a Keycloak user, or None. A same login with another e-mail is another person: never matched.
    Blocked, deactivated and bot accounts see nothing."""
    def same_person(u: dict[str, Any]) -> bool:
        known = u.get("email") or u.get("public_email")
        return not (email and known) or known.lower() == email.lower()

    found = [u for u in await gl.get("/users", username=username) or [] if u["username"].lower() == username.lower() and same_person(u)]
    if not found and email:
        # Login names may differ between Keycloak and GitLab: fall back on the exact e-mail.
        found = [u for u in await gl.get("/users", search=email) or [] if (u.get("email") or "").lower() == email.lower()]
    if len(found) != 1:
        return None
    user = found[0]
    return user if user.get("state") == "active" and not user.get("bot") else None


async def memberships(gl: GitLab, username: str, email: str | None) -> dict[str, list] | None:
    """Groups and projects the user belongs to on this instance; None when they have no usable account there."""
    user = await gitlab_user(gl, username, email)
    if user is None:
        return None
    username = user["username"]
    # A finished connection restarts from its first page while the other continues: sets absorb the repeats.
    groups: set[str] = set()
    projects: dict[str, int] = {}
    cursors: dict[str, str | None] = {"groups": None, "projects": None}
    for _ in range(20):
        data = await gl.graphql(MEMBERSHIPS, username=username, **cursors)
        user = (data or {}).get("user")
        if user is None:
            return None
        g, p = user["groupMemberships"], user["projectMemberships"]
        groups.update(n["group"]["fullPath"] for n in g["nodes"] if n.get("group") and seen(n))
        projects.update((n["project"]["fullPath"], int(n["project"]["id"].rsplit("/", 1)[-1])) for n in p["nodes"] if n.get("project") and seen(n))
        cursors = {"groups": g["pageInfo"]["endCursor"] if g["pageInfo"]["hasNextPage"] else None,
                   "projects": p["pageInfo"]["endCursor"] if p["pageInfo"]["hasNextPage"] else None}
        if not any(cursors.values()):
            break
    return {"groups": sorted(groups), "projects": sorted(projects.items()), "at": datetime.now(UTC).isoformat()}
