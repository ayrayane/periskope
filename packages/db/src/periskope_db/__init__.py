"""PostgreSQL access shared by the three services. Every read of projects or runs goes through Viewer.where()."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

import asyncpg


async def _init(conn: asyncpg.Connection) -> None:
    await conn.set_type_codec("jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog")


async def connect(url: str | None = None, **kw) -> asyncpg.Pool:
    return await asyncpg.create_pool(url or os.environ["PERISKOPE_DATABASE_URL"], init=_init, **kw)


@dataclass(frozen=True)
class Viewer:
    """Who is reading, and the projects they may see: GitLab membership plus rights granted by hand."""
    sub: str
    username: str
    admin: bool = False
    # Reads every project of every instance without administering anything (e.g. a workspace manager role).
    reads_all: bool = False
    # (instance, namespace path) pairs: every project under the path is visible.
    namespaces: frozenset[tuple[str, str]] = field(default_factory=frozenset)
    # (instance, gitlab project id) pairs.
    projects: frozenset[tuple[str, int]] = field(default_factory=frozenset)
    # (instance, path) of namespaces or projects where this viewer may launch runs and override scope:
    # where GitLab makes them Maintainer or Owner, plus rights granted by hand.
    maintains: frozenset[tuple[str, str]] = field(default_factory=frozenset)

    def where(self, alias: str = "p", start: int = 1) -> tuple[str, list]:
        """SQL condition on a projects row restricting it to this viewer, and its parameters ($start…)."""
        if self.admin or self.reads_all:
            return "true", []
        ns = sorted(self.namespaces)
        pr = sorted(self.projects)
        sql = (
            f"(EXISTS (SELECT 1 FROM unnest(${start}::text[], ${start + 1}::text[]) AS v(i, n)"
            f" WHERE {alias}.instance = v.i AND ({alias}.namespace_path = v.n OR left({alias}.namespace_path, length(v.n) + 1) = v.n || '/'))"
            f" OR ({alias}.instance, {alias}.gitlab_id) IN (SELECT * FROM unnest(${start + 2}::text[], ${start + 3}::bigint[])))"
        )
        return sql, [[i for i, _ in ns], [n for _, n in ns], [i for i, _ in pr], [g for _, g in pr]]

    def can_maintain(self, instance: str, path: str) -> bool:
        if self.admin:
            return True
        return any(i == instance and (path == p or path.startswith(p + "/")) for i, p in self.maintains)
