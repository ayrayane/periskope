"""Scope decisions in the database, and the displayed score recomputed when they change (past runs stay as they were)."""
from __future__ import annotations

from typing import Any

import asyncpg
from periskope_core.models import CheckStatus
from periskope_core.scope import ScopeDecision, excluded
from periskope_core.scoring import score

COLUMNS = "target, target_id, decision, reason, instance, project_id"


async def decisions_for(db: asyncpg.Pool | asyncpg.Connection, instance: str | None, project_id: int | None) -> list[ScopeDecision]:
    rows = await db.fetch(
        f"SELECT {COLUMNS} FROM scope_decisions WHERE instance IS NULL OR (instance = $1 AND (project_id IS NULL OR project_id = $2))",
        instance, project_id)
    return [ScopeDecision(**dict(r)) for r in rows]


async def rescore(db: asyncpg.Pool, *, instance: str | None = None, project_id: int | None = None) -> int:
    """Recompute project_state from each project's last reference run under the scope in force today."""
    rows = await db.fetch(
        "SELECT p.id, p.instance, p.target_level, r.results FROM projects p JOIN project_state s ON s.project_id = p.id"
        " JOIN runs r ON r.id = s.last_run_id WHERE ($1::text IS NULL OR p.instance = $1) AND ($2::bigint IS NULL OR p.id = $2)",
        instance, project_id)
    # The decisions table is small: read it once, resolve per project in memory.
    decisions = [ScopeDecision(**dict(d)) for d in await db.fetch(f"SELECT {COLUMNS} FROM scope_decisions")]
    for r in rows:
        checks, activities = excluded(decisions, r["instance"], r["id"])
        s = score({i: CheckStatus(v["status"]) for i, v in r["results"].items()}, target_level=r["target_level"],
                  excluded_checks=checks, excluded_activities=activities)
        await db.execute(
            "UPDATE project_state SET score = $2, coverage = $3, by_dimension = $4, statuses = $5 WHERE project_id = $1",
            r["id"], s.score, s.coverage, s.by_dimension, {a.activity: {"status": a.status, "to_confirm": a.to_confirm} for a in s.activities})
    return len(rows)


async def put(conn: asyncpg.Connection, d: ScopeDecision, author: str) -> dict[str, Any] | None:
    """Upsert one decision; returns the previous one for the audit log."""
    before = await conn.fetchrow(
        f"SELECT {COLUMNS}, author, updated_at FROM scope_decisions WHERE target = $1 AND target_id = $2"
        " AND instance IS NOT DISTINCT FROM $3 AND project_id IS NOT DISTINCT FROM $4", d.target, d.target_id, d.instance, d.project_id)
    await conn.execute(
        "INSERT INTO scope_decisions (target, target_id, decision, reason, instance, project_id, author) VALUES ($1, $2, $3, $4, $5, $6, $7)"
        " ON CONFLICT (target, target_id, instance, project_id) DO UPDATE SET decision = $3, reason = $4, author = $7, updated_at = now()",
        d.target, d.target_id, d.decision, d.reason, d.instance, d.project_id, author)
    return dict(before) if before else None


async def remove(conn: asyncpg.Connection, target: str, target_id: str, instance: str | None, project_id: int | None) -> dict[str, Any] | None:
    row = await conn.fetchrow(
        f"DELETE FROM scope_decisions WHERE target = $1 AND target_id = $2 AND instance IS NOT DISTINCT FROM $3"
        f" AND project_id IS NOT DISTINCT FROM $4 RETURNING {COLUMNS}, author", target, target_id, instance, project_id)
    return dict(row) if row else None
