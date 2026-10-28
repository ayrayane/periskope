"""Scheduler: receives every instance's webhooks and runs the nightly tasks. One active replica (Valkey lock)."""
from __future__ import annotations

import asyncio
import hmac
import os
from contextlib import asynccontextmanager
from datetime import datetime, time, timedelta
from zoneinfo import ZoneInfo

import structlog
from arq import create_pool
from arq.connections import ArqRedis, RedisSettings
from fastapi import FastAPI, Header, HTTPException, Request
from periskope_core.settings import env, instances, queue, secret
from periskope_db import connect
from periskope_db.bootstrap import bootstrap

log = structlog.get_logger()
TZ = ZoneInfo(env("TIMEZONE", "Europe/Paris"))
# Absorbs a burst of pushes: the project is analysed once, 10 minutes after the first event.
QUIET = timedelta(minutes=10)
LOCK_KEY, LOCK_TTL_S = "scheduler:lock", 60
EVIDENCE_DAYS, BRANCH_RUN_DAYS = 14, 30
TASKS = {"sync_projects": time(0, 30), "catch_up": time(1, 0), "rollup_history": time(5, 0)}
SYSTEM_EVENTS = {"project_create", "project_rename", "project_transfer", "project_destroy"}

state: dict = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    state["instances"] = instances()
    state["db"] = await connect(min_size=1, max_size=5)
    await bootstrap(state["db"], state["instances"])
    state["arq"] = await create_pool(RedisSettings.from_dsn(env("VALKEY_URL", "redis://localhost:6379")))
    loop = asyncio.create_task(cron_loop())
    yield
    loop.cancel()
    await state["arq"].aclose()
    await state["db"].close()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


def webhook_secret(instance: str) -> str:
    return (secret(f"gitlab-webhook-{instance}") / "token").read_text().strip()


@app.post("/hooks/gitlab/{instance}", status_code=202)
async def gitlab_hook(instance: str, request: Request, x_gitlab_token: str = Header("")) -> dict:
    if instance not in state["instances"]:
        raise HTTPException(404)
    if not hmac.compare_digest(x_gitlab_token.encode(), webhook_secret(instance).encode()):
        raise HTTPException(401)
    event = await request.json()
    arq: ArqRedis = state["arq"]
    name = event.get("event_name") or event.get("object_kind")
    if name in SYSTEM_EVENTS:
        await arq.enqueue_job("run_sync", _queue_name=queue(instance), _job_id=f"sync:{instance}", _defer_by=timedelta(minutes=2))
        return {"queued": "sync"}
    gitlab_id = (event.get("project") or {}).get("id") or event.get("project_id")
    if not gitlab_id or not relevant(name, event):
        return {"queued": None}
    project_id = await state["db"].fetchval("SELECT id FROM projects WHERE instance = $1 AND gitlab_id = $2 AND enabled", instance, gitlab_id)
    if project_id is None:
        return {"queued": None}
    # shortcut: the job id dedupes events within the quiet window instead of sliding it; a sliding window needs a debounce key.
    await arq.enqueue_job("analyse_project", project_id, "webhook", _queue_name=queue(instance),
                          _job_id=f"hook:{project_id}:{int(datetime.now().timestamp() // QUIET.total_seconds())}", _defer_by=QUIET)
    return {"queued": "analysis"}


def relevant(name: str | None, event: dict) -> bool:
    """Push or merge on the default branch, finished pipeline, project settings change."""
    default = (event.get("project") or {}).get("default_branch")
    if name == "push":
        return event.get("ref") == f"refs/heads/{default}"
    if name == "merge_request":
        attrs = event.get("object_attributes") or {}
        return attrs.get("action") == "merge" and attrs.get("target_branch") == default
    if name == "pipeline":
        attrs = event.get("object_attributes") or {}
        return attrs.get("ref") == default and attrs.get("status") in ("success", "failed")
    return name in ("project_update", "repository_update")


async def cron_loop() -> None:
    """Fires each task at its local time on the replica that holds the lock."""
    me = os.environ.get("HOSTNAME", "scheduler")
    redis = state["arq"]
    while True:
        try:
            held = await redis.set(LOCK_KEY, me, nx=True, ex=LOCK_TTL_S) or await redis.get(LOCK_KEY) == me.encode()
            if held:
                await redis.expire(LOCK_KEY, LOCK_TTL_S)
                now = datetime.now(TZ)
                for task, at in TASKS.items():
                    key = f"scheduler:done:{task}:{now.date()}"
                    if now.time() >= at and await redis.set(key, 1, nx=True, ex=2 * 86400):
                        log.info("task_start", task=task)
                        await globals()[task]()
        except Exception:
            log.exception("cron_error")
        await asyncio.sleep(20)


async def sync_projects() -> None:
    for slug in state["instances"]:
        await state["arq"].enqueue_job("run_sync", _queue_name=queue(slug), _job_id=f"sync:{slug}")


async def catch_up() -> None:
    """Every active project not already checked today, instance by instance on its own queue."""
    rows = await state["db"].fetch(
        "SELECT p.id, p.instance FROM projects p JOIN project_state s ON s.project_id = p.id"
        " WHERE p.enabled AND s.next_due_at <= now() ORDER BY s.next_due_at")
    today = datetime.now(TZ).date()
    for r in rows:
        await state["arq"].enqueue_job("analyse_project", r["id"], "nightly", _queue_name=queue(r["instance"]), _job_id=f"night:{r['id']}:{today}")
    log.info("catch_up_queued", projects=len(rows))


async def rollup_history() -> None:
    """Monthly points, purge of raw evidence and branch runs, partitions ahead, and the morning report."""
    db = state["db"]
    await db.execute(
        "INSERT INTO history_monthly (project_id, month, score, coverage, by_dimension)"
        " SELECT project_id, date_trunc('month', now())::date, score, coverage, by_dimension FROM project_state WHERE last_run_id IS NOT NULL"
        " ON CONFLICT (project_id, month) DO UPDATE SET score = excluded.score, coverage = excluded.coverage, by_dimension = excluded.by_dimension")
    await db.execute("SELECT periskope_partitions(current_date, 7)")
    old = await db.fetch(
        "SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid JOIN pg_class p ON p.oid = i.inhparent"
        " WHERE p.relname = 'run_evidence' AND c.relname < 'run_evidence_' || to_char(current_date - $1::int, 'YYYYMMDD')", EVIDENCE_DAYS)
    for r in old:
        await db.execute(f'DROP TABLE "{r["relname"]}"')
    await db.execute(
        "DELETE FROM runs r USING projects p WHERE p.id = r.project_id AND r.branch <> p.default_branch"
        " AND r.created_at < now() - make_interval(days => $1) AND NOT EXISTS (SELECT 1 FROM runs x WHERE x.reused_from = r.id)"
        " AND NOT EXISTS (SELECT 1 FROM fingerprints f WHERE f.run_id = r.id)", BRANCH_RUN_DAYS)
    report = await db.fetch(
        "SELECT status, count(*) AS n, count(reused_from) AS reused, coalesce(sum(gitlab_calls), 0) AS calls FROM runs"
        " WHERE created_at > now() - interval '1 day' GROUP BY status")
    log.info("daily_report", **{r["status"]: {"runs": r["n"], "reused": r["reused"], "gitlab_calls": r["calls"]} for r in report},
             dropped_partitions=len(old))


@app.get("/health")
async def health() -> dict:
    await state["db"].fetchval("SELECT 1")
    await state["arq"].ping()
    return {"status": "ok"}
