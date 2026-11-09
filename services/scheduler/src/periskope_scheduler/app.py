"""Scheduler: receives every instance's webhooks and runs the nightly tasks. One active replica (Valkey lock)."""
from __future__ import annotations

import asyncio
import hmac
import os
from contextlib import asynccontextmanager
from datetime import datetime, time, timedelta
from zoneinfo import ZoneInfo

import httpx
import structlog
from arq import create_pool
from arq.connections import ArqRedis, RedisSettings
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse
from periskope_core.settings import env, instances, queue, secret
from periskope_db import connect
from periskope_db import settings as hot
from periskope_db.bootstrap import bootstrap

from periskope_scheduler import feeds

log = structlog.get_logger()
TZ = ZoneInfo(env("TIMEZONE", "Europe/Paris"))
# Absorbs a burst of pushes: the project is analysed once, 10 minutes after the first event.
QUIET = timedelta(minutes=10)
LOCK_KEY, LOCK_TTL_S = "scheduler:lock", 60
TASKS = {"vuln_feeds": "feeds_at", "sync_projects": "sync_at", "catch_up": "catch_up_at", "rollup_history": "rollup_at"}
SYSTEM_EVENTS = {"project_create", "project_rename", "project_transfer", "project_destroy"}
ALERTS_EVERY_S = 300

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
    expected = webhook_secret(instance)
    # An empty secret file must not accept requests that send no token at all.
    if not expected or not hmac.compare_digest(x_gitlab_token.encode(), expected.encode()):
        raise HTTPException(401)
    event = await request.json()
    arq: ArqRedis = state["arq"]
    await arq.set(f"webhook:last:{instance}", int(datetime.now().timestamp()))
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
                # Read every loop: an admin's new hours apply without a restart.
                conf = await hot.load(state["db"])
                if await redis.set(f"scheduler:alerts:{int(now.timestamp() // ALERTS_EVERY_S)}", 1, nx=True, ex=2 * ALERTS_EVERY_S):
                    await alerts()
                for task, field in TASKS.items():
                    key = f"scheduler:done:{task}:{now.date()}"
                    if now.time() >= time.fromisoformat(getattr(conf, field)) and await redis.set(key, 1, nx=True, ex=2 * 86400):
                        log.info("task_start", task=task)
                        try:
                            await globals()[task]()
                        except Exception:
                            # Not done after all: the next loop, 20 s later, tries again.
                            await redis.delete(key)
                            raise
        except Exception:
            log.exception("cron_error")
        await asyncio.sleep(20)


async def vuln_feeds() -> None:
    await feeds.refresh(state["db"])


async def sync_projects() -> None:
    for slug in state["instances"]:
        await state["arq"].enqueue_job("run_sync", _queue_name=queue(slug), _job_id=f"sync:{slug}")


async def catch_up() -> None:
    """Every active project not already checked today, instance by instance on its own queue."""
    # A collector killed mid-run leaves its run active, and the one-active-run index then blocks the project for good.
    # Running: well past the 10 min job timeout. Queued: a day, so a long nightly backlog is never cut.
    stuck = await state["db"].execute(
        "UPDATE runs SET status = 'failed', finished_at = now(), error = 'analyse interrompue (collecteur arrêté)'"
        " WHERE (status = 'running' AND started_at < now() - interval '2 hours') OR (status = 'queued' AND created_at < now() - interval '1 day')")
    log.info("stuck_runs_failed", runs=int(stuck.split()[-1]))
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
    conf = await hot.load(db)
    await db.execute(
        "INSERT INTO history_monthly (project_id, month, score, coverage, by_dimension)"
        " SELECT project_id, date_trunc('month', now())::date, score, coverage, by_dimension FROM project_state WHERE last_run_id IS NOT NULL"
        " ON CONFLICT (project_id, month) DO UPDATE SET score = excluded.score, coverage = excluded.coverage, by_dimension = excluded.by_dimension")
    await db.execute("SELECT periskope_partitions(current_date, 7)")
    old = await db.fetch(
        "SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid JOIN pg_class p ON p.oid = i.inhparent"
        " WHERE p.relname = 'run_evidence' AND c.relname < 'run_evidence_' || to_char(current_date - $1::int, 'YYYYMMDD')", conf.evidence_days)
    for r in old:
        await db.execute(f'DROP TABLE "{r["relname"]}"')
    await db.execute(
        "DELETE FROM runs r USING projects p WHERE p.id = r.project_id AND r.branch <> p.default_branch"
        " AND r.created_at < now() - make_interval(days => $1) AND NOT EXISTS (SELECT 1 FROM runs x WHERE x.reused_from = r.id)"
        " AND NOT EXISTS (SELECT 1 FROM fingerprints f WHERE f.run_id = r.id)", conf.branch_run_days)
    report = await db.fetch(
        "SELECT status, count(*) AS n, count(reused_from) AS reused, coalesce(sum(gitlab_calls), 0) AS calls FROM runs"
        " WHERE created_at > now() - interval '1 day' GROUP BY status")
    log.info("daily_report", **{r["status"]: {"runs": r["n"], "reused": r["reused"], "gitlab_calls": r["calls"]} for r in report},
             dropped_partitions=len(old))


@app.get("/metrics/queue/{instance}")
async def queue_depth(instance: str) -> dict:
    """Depth of an instance's collector queue, read by KEDA to scale its collectors (in-cluster only, no data exposed)."""
    if instance not in state["instances"]:
        raise HTTPException(404)
    return {"depth": await state["arq"].zcard(queue(instance))}


@app.get("/health")
async def health() -> dict:
    await state["db"].fetchval("SELECT 1")
    await state["arq"].ping()
    return {"status": "ok"}


async def alerts() -> None:
    """Each score drop on a default branch, posted once to the alert webhook: Mattermost reads `text`, other tools read `props`."""
    url_file = secret("periskope-alerts") / "url"
    if not url_file.exists():
        return
    url = url_file.read_text().strip()
    conf = await hot.load(state["db"])
    rows = await state["db"].fetch(
        "SELECT r.id, p.instance, p.path, r.score, prev.score AS before FROM runs r JOIN projects p ON p.id = r.project_id"
        " JOIN LATERAL (SELECT x.score FROM runs x WHERE x.project_id = r.project_id AND x.branch = r.branch AND x.status = 'succeeded'"
        " AND x.score IS NOT NULL AND x.created_at < r.created_at ORDER BY x.created_at DESC LIMIT 1) prev ON true"
        " WHERE r.branch = p.default_branch AND r.status = 'succeeded' AND r.finished_at > now() - interval '1 day'"
        " AND r.score <= prev.score - $1 ORDER BY r.id", conf.alert_drop)
    base = env("PUBLIC_URL", "").rstrip("/")
    async with httpx.AsyncClient(timeout=10) as client:
        for r in rows:
            key = f"alerted:{r['id']}"
            if not await state["arq"].set(key, 1, nx=True, ex=7 * 86400):
                continue
            link = f" {base}/p/{r['instance']}/{r['path']}" if base else ""
            text = f"Periskope : le score de {r['path']} ({r['instance']}) est passé de {round(r['before'])} à {round(r['score'])}/100.{link}"
            props = {"instance": r["instance"], "project": r["path"], "before": r["before"], "score": r["score"], "run": r["id"]}
            try:
                resp = await client.post(url, json={"username": "Periskope", "text": text, "props": props})
                resp.raise_for_status()
                log.info("alert_sent", run=r["id"], project=r["path"])
            except httpx.HTTPError as e:
                await state["arq"].delete(key)  # retried on the next pass
                log.warning("alert_failed", run=r["id"], error=type(e).__name__)


@app.get("/metrics", response_class=PlainTextResponse)
async def metrics() -> str:
    """The operating picture in Prometheus text format, read from the database and Valkey at each scrape."""
    db, arq = state["db"], state["arq"]
    out: list[str] = []

    def gauge(name: str, help_: str, samples: list[tuple[dict[str, str], float]]) -> None:
        out.extend([f"# HELP {name} {help_}", f"# TYPE {name} gauge"])
        for labels, value in samples:
            tags = ",".join(f'{k}="{v}"' for k, v in labels.items())
            out.append(f"{name}{{{tags}}} {value}" if tags else f"{name} {value}")

    now = datetime.now().timestamp()
    gauge("periskope_queue_depth", "Analyses waiting in each instance's queue",
          [({"instance": s}, await arq.zcard(queue(s))) for s in state["instances"]])
    hooks = [(s, await arq.get(f"webhook:last:{s}")) for s in state["instances"]]
    gauge("periskope_last_webhook_age_seconds", "Seconds since the last webhook of each instance (absent: none since Valkey started)",
          [({"instance": s}, now - int(v)) for s, v in hooks if v])
    runs_ = await db.fetch("SELECT status, trigger, count(*) AS n FROM runs WHERE created_at > now() - interval '1 hour' GROUP BY 1, 2")
    gauge("periskope_runs_last_hour", "Analyses created in the last hour, by status and trigger",
          [({"status": r["status"], "trigger": r["trigger"]}, r["n"]) for r in runs_])
    done = {r["status"]: r["n"] for r in await db.fetch(
        "SELECT status, count(*) AS n FROM runs WHERE finished_at > now() - interval '1 hour' AND status IN ('succeeded', 'failed') GROUP BY 1")}
    finished = done.get("succeeded", 0) + done.get("failed", 0)
    gauge("periskope_failed_ratio_last_hour", "Share of analyses finished in the last hour that failed", [({}, done.get("failed", 0) / finished if finished else 0)])
    reuse = await db.fetchrow("SELECT count(*) FILTER (WHERE reused_from IS NOT NULL) AS reused, count(*) AS n FROM runs"
                              " WHERE status = 'succeeded' AND finished_at > now() - interval '1 day'")
    gauge("periskope_reused_ratio_last_day", "Share of successful analyses of the last day that reused unchanged results",
          [({}, reuse["reused"] / reuse["n"] if reuse["n"] else 0)])
    overdue = await db.fetch(
        "SELECT p.instance, count(*) FILTER (WHERE s.next_due_at < date_trunc('day', now())) AS late, extract(epoch FROM now() - min(s.next_due_at)) AS oldest"
        " FROM projects p JOIN project_state s ON s.project_id = p.id WHERE p.enabled AND s.next_due_at <= now() GROUP BY 1")
    gauge("periskope_overdue_projects", "Projects due before today began and still not analysed (the nightly catch-up is late)",
          [({"instance": r["instance"]}, r["late"]) for r in overdue])
    gauge("periskope_overdue_oldest_seconds", "Age of the oldest passed next_due_at", [({"instance": r["instance"]}, float(r["oldest"] or 0)) for r in overdue])
    return "\n".join(out) + "\n"
