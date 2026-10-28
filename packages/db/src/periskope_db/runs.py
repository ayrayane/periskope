"""Run lifecycle: one active run per project and branch, written once, project state updated in the same transaction."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import asyncpg
from periskope_core.referential import REFERENTIAL_VERSION

EVIDENCE_DAYS = 14


class AlreadyActive(Exception):
    def __init__(self, run_id: int):
        super().__init__(f"run {run_id} already active")
        self.run_id = run_id


async def create(db: asyncpg.Pool | asyncpg.Connection, project_id: int, branch: str, trigger: str, requested_by: str | None) -> int:
    try:
        return await db.fetchval(
            "INSERT INTO runs (project_id, branch, trigger, requested_by, status, referential_version)"
            " VALUES ($1, $2, $3, $4, 'queued', $5) RETURNING id",
            project_id, branch, trigger, requested_by, REFERENTIAL_VERSION,
        )
    except asyncpg.UniqueViolationError:
        active = await db.fetchval("SELECT id FROM runs WHERE project_id = $1 AND branch = $2 AND status IN ('queued', 'running')", project_id, branch)
        raise AlreadyActive(active) from None


async def claim(db: asyncpg.Pool, run_id: int) -> asyncpg.Record | None:
    """Mark a queued run running; None when it was cancelled or already taken."""
    return await db.fetchrow(
        "UPDATE runs r SET status = 'running', started_at = now() FROM projects p"
        " WHERE r.id = $1 AND r.status = 'queued' AND p.id = r.project_id"
        " RETURNING r.id, r.branch, r.project_id, p.instance, p.gitlab_id, p.path, p.default_branch, p.target_level",
        run_id,
    )


async def reusable(db: asyncpg.Pool, project_id: int, commit_sha: str) -> dict[str, Any] | None:
    """Results of the latest run at this commit, for checks that depend only on the commit."""
    row = await db.fetchrow(
        "SELECT run_id, results FROM fingerprints WHERE project_id = $1 AND commit_sha = $2 ORDER BY created_at DESC LIMIT 1",
        project_id, commit_sha,
    )
    return dict(row) if row else None


async def succeed(
    db: asyncpg.Pool, run_id: int, *, commit_sha: str, settings_hash: str, results: dict[str, Any], evidence: dict[str, Any],
    score: float | None, coverage: float, by_dimension: dict[str, Any], statuses: dict[str, Any], reused_from: int | None,
    gitlab_calls: int, fingerprint_reused: bool,
) -> None:
    async with db.acquire() as conn, conn.transaction():
        run = await conn.fetchrow(
            "UPDATE runs SET status = 'succeeded', finished_at = now(), commit_sha = $2, results = $3, score = $4, coverage = $5,"
            " by_dimension = $6, reused_from = $7, gitlab_calls = $8 WHERE id = $1 AND status = 'running' RETURNING project_id, branch",
            run_id, commit_sha, results, score, coverage, by_dimension, reused_from, gitlab_calls,
        )
        if run is None:
            return  # cancelled meanwhile: a run is never rewritten
        # A reused analysis keeps no raw evidence, only the pointer to the original.
        if not fingerprint_reused:
            await conn.execute("INSERT INTO run_evidence (run_id, evidence) VALUES ($1, $2)", run_id, evidence)
            await conn.execute(
                "INSERT INTO fingerprints (project_id, commit_sha, settings_hash, run_id, results) VALUES ($1, $2, $3, $4, $5)"
                " ON CONFLICT (project_id, commit_sha, settings_hash) DO UPDATE SET run_id = excluded.run_id, results = excluded.results, created_at = now()",
                run["project_id"], commit_sha, settings_hash, run_id, results,
            )
        # Only the default branch is the project's reference.
        await conn.execute(
            "INSERT INTO project_state (project_id, score, coverage, last_run_id, last_success_at, last_error, next_due_at, fingerprint, by_dimension, statuses)"
            " SELECT p.id, $2, $3, $4, now(), NULL, $5, $6, $7, $8 FROM projects p WHERE p.id = $1 AND p.default_branch = $9"
            " ON CONFLICT (project_id) DO UPDATE SET score = $2, coverage = $3, last_run_id = $4, last_success_at = now(), last_error = NULL,"
            " next_due_at = $5, fingerprint = $6, by_dimension = $7, statuses = $8",
            run["project_id"], score, coverage, run_id, datetime.now(UTC) + timedelta(days=1), f"{commit_sha}:{settings_hash}",
            by_dimension, statuses, run["branch"],
        )


async def fail(db: asyncpg.Pool, run_id: int, error: str) -> None:
    """The run fails; the project's last valid score stays displayed, with the error beside it."""
    async with db.acquire() as conn, conn.transaction():
        run = await conn.fetchrow(
            "UPDATE runs SET status = 'failed', finished_at = now(), error = $2 WHERE id = $1 AND status IN ('queued', 'running')"
            " RETURNING project_id, branch", run_id, error,
        )
        if run:
            await conn.execute(
                "INSERT INTO project_state (project_id, last_error) SELECT id, $2 FROM projects WHERE id = $1 AND default_branch = $3"
                " ON CONFLICT (project_id) DO UPDATE SET last_error = $2",
                run["project_id"], error, run["branch"],
            )
