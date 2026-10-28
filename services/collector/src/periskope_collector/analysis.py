"""One analysis: load the project once, reuse what its commit already proved, run the rest, score, store."""
from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any

import asyncpg
import structlog
from periskope_checks import REGISTRY, run_all
from periskope_checks.context import Context
from periskope_checks.registry import Depends
from periskope_clients.gitlab import GitLab, SourceDown, run_calls
from periskope_core.models import CheckStatus
from periskope_core.scope import ScopeDecision, excluded
from periskope_core.scoring import score
from periskope_db import runs

log = structlog.get_logger()
RUN_TIMEOUT_S = 300
# Live data ages without a commit; it is left out of the settings fingerprint.
LIVE_KEYS = {"mergeRequests", "pipelines", "vulnerabilities", "lastActivityAt", "repository"}


def settings_hash(project: dict[str, Any], approvals: Any, tokens: Any) -> str:
    stable = {k: v for k, v in project.items() if k not in LIVE_KEYS}
    raw = json.dumps([stable, approvals, [(t.get("name"), t.get("expires_at")) for t in tokens or []]], sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


async def scope_for(db: asyncpg.Pool, instance: str, project_id: int) -> tuple[set[str], set[str]]:
    rows = await db.fetch(
        "SELECT target, target_id, decision, reason, instance, project_id FROM scope_decisions"
        " WHERE instance IS NULL OR (instance = $1 AND (project_id IS NULL OR project_id = $2))",
        instance, project_id,
    )
    return excluded((ScopeDecision(**dict(r)) for r in rows), instance, project_id)


async def analyse(db: asyncpg.Pool, gl: GitLab, run_id: int, *, enterprise: bool) -> None:
    run = await runs.claim(db, run_id)
    if run is None:
        return
    bound = log.bind(run_id=run_id, project=run["path"], branch=run["branch"])
    calls = [0]
    run_calls.set(calls)
    try:
        async with asyncio.timeout(RUN_TIMEOUT_S):
            await _analyse(db, gl, run, enterprise, calls, bound)
    except SourceDown as e:
        bound.warning("run_failed", error=str(e))
        await runs.fail(db, run_id, str(e))
    except TimeoutError:
        await runs.fail(db, run_id, f"analyse interrompue après {RUN_TIMEOUT_S // 60} minutes")
    except Exception as e:
        bound.exception("run_crashed")
        await runs.fail(db, run_id, f"erreur interne : {type(e).__name__}")
        raise


async def _analyse(db: asyncpg.Pool, gl: GitLab, run: asyncpg.Record, enterprise: bool, calls: list[int], log: Any) -> None:
    ctx = Context(gl, run["path"], run["gitlab_id"], run["branch"], sha="", enterprise=enterprise)
    project = await ctx.project()
    if project is None:
        raise SourceDown("projet introuvable ou illisible avec le jeton de service")
    commit = ((project.get("repository") or {}).get("commit") or {}).get("sha")
    if not commit:
        await runs.fail(db, run["id"], f"branche {run['branch']} introuvable ou vide")
        return
    ctx.sha = commit

    prior = await runs.reusable(db, run["project_id"], commit)
    reused_ids = {i for i, r in REGISTRY.items() if r.depends_on == Depends.COMMIT} if prior else set()
    outcomes = await run_all(ctx, [i for i in REGISTRY if i not in reused_ids])
    approvals, tokens = await ctx.approvals(), await ctx.access_tokens()
    s_hash = settings_hash(project, approvals, tokens)

    # The step to take travels with the result: the API never imports the checks.
    results: dict[str, Any] = {
        i: {"status": o.status, "message": o.message, **({"action": REGISTRY[i].action} if o.status != CheckStatus.PASS else {})}
        for i, o in outcomes.items()
    }
    for i in reused_ids:
        results[i] = {**prior["results"][i], "reused": True}
    excluded_checks, excluded_activities = await scope_for(db, run["instance"], run["project_id"])
    s = score({i: CheckStatus(r["status"]) for i, r in results.items()}, target_level=run["target_level"],
              excluded_checks=excluded_checks, excluded_activities=excluded_activities)
    same = prior is not None and await db.fetchval(
        "SELECT run_id FROM fingerprints WHERE project_id = $1 AND commit_sha = $2 AND settings_hash = $3", run["project_id"], commit, s_hash)
    await runs.succeed(
        db, run["id"], commit_sha=commit, settings_hash=s_hash, results=results,
        evidence={i: o.evidence for i, o in outcomes.items() if o.evidence},
        score=s.score, coverage=s.coverage, by_dimension=s.by_dimension,
        statuses={a.activity: {"status": a.status, "to_confirm": a.to_confirm} for a in s.activities},
        reused_from=same or None, gitlab_calls=calls[0], fingerprint_reused=bool(same),
    )
    log.info("run_succeeded", score=s.score, coverage=s.coverage, reused=len(reused_ids), calls=calls[0])
