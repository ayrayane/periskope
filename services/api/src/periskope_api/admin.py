"""Administration routes: instances and their queues, hot settings, excluded projects, audit log. Admins only.

No `from __future__ import annotations` here: FastAPI resolves the closure-local dependencies from real annotations."""

import re
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from periskope_core.settings import queue
from periskope_db import Viewer
from periskope_db import settings as hot
from pydantic import BaseModel, Field


def router(state: dict[str, Any], current, audit) -> APIRouter:
    async def admin(me: Annotated[Viewer, Depends(current)]) -> Viewer:
        if not me.admin:
            # Same answer as a missing page: the admin area's existence tells nothing to others.
            raise HTTPException(404, "introuvable")
        return me

    Admin = Annotated[Viewer, Depends(admin)]
    r = APIRouter(prefix="/api/v1/admin")

    @r.get("/overview")
    async def overview(me: Admin) -> dict:
        db, arq = state["db"], state["arq"]
        instances = []
        for i in await db.fetch(
            "SELECT i.slug, i.name, i.url, i.enterprise, i.space_dormant, i.last_sync_at,"
            " count(p.id) FILTER (WHERE p.enabled) AS tracked, count(p.id) FILTER (WHERE NOT p.enabled) AS excluded,"
            " min(s.next_due_at) FILTER (WHERE p.enabled AND s.next_due_at < now()) AS oldest_overdue"
            " FROM gitlab_instances i LEFT JOIN projects p ON p.instance = i.slug LEFT JOIN project_state s ON s.project_id = p.id"
            " WHERE i.enabled GROUP BY i.slug ORDER BY i.slug"):
            health = await arq.get(f"{queue(i['slug'])}:health-check")
            instances.append({**dict(i), "queued": await arq.zcard(queue(i["slug"])), "collector": worker_health(health)})
        runs = await db.fetch(
            "SELECT status, trigger, count(*) AS n, count(reused_from) AS reused, coalesce(sum(gitlab_calls), 0) AS calls"
            " FROM runs WHERE created_at > now() - interval '24 hours' GROUP BY status, trigger ORDER BY status, trigger")
        active = await db.fetch(
            "SELECT r.id, r.branch, r.trigger, r.requested_by, r.status, r.created_at, r.started_at, p.instance, p.path"
            " FROM runs r JOIN projects p ON p.id = r.project_id WHERE r.status IN ('queued', 'running') ORDER BY r.id LIMIT 200")
        failures = await db.fetch(
            "SELECT error, count(*) AS n FROM runs WHERE status = 'failed' AND created_at > now() - interval '24 hours'"
            " GROUP BY error ORDER BY n DESC LIMIT 10")
        return {"instances": instances, "runs_24h": [dict(x) for x in runs], "active": [dict(x) for x in active],
                "failures_24h": [dict(x) for x in failures]}

    @r.post("/instances/{instance}/sync", status_code=202)
    async def sync(instance: str, me: Admin) -> dict:
        if not await state["db"].fetchval("SELECT 1 FROM gitlab_instances WHERE slug = $1 AND enabled", instance):
            raise HTTPException(404, "instance inconnue")
        job = await state["arq"].enqueue_job("run_sync", _queue_name=queue(instance), _job_id=f"sync:{instance}")
        await audit(me, "instance.sync", instance)
        return {"queued": job is not None}

    @r.get("/settings")
    async def get_settings(me: Admin) -> dict:
        rows = await state["db"].fetch("SELECT key, updated_by, updated_at FROM settings")
        return {"values": (await hot.load(state["db"])).model_dump(), "changed": {x["key"]: dict(x) for x in rows}}

    class SettingsPatch(BaseModel):
        sync_at: str | None = None
        catch_up_at: str | None = None
        rollup_at: str | None = None
        feeds_at: str | None = None
        epss_high_pct: int | None = Field(None, ge=1, le=100)
        on_demand_per_hour: int | None = Field(None, ge=1, le=1000)
        evidence_days: int | None = Field(None, ge=1, le=90)
        branch_run_days: int | None = Field(None, ge=1, le=365)
        alert_drop: int | None = Field(None, ge=1, le=100)
        sla_immediate_days: int | None = Field(None, ge=1, le=90)
        sla_out_of_cycle_days: int | None = Field(None, ge=1, le=365)
        sla_scheduled_days: int | None = Field(None, ge=1, le=730)
        exception_days: int | None = Field(None, ge=1, le=365)

    @r.put("/settings")
    async def put_settings(body: SettingsPatch, me: Admin) -> dict:
        changes = body.model_dump(exclude_none=True)
        before = (await hot.load(state["db"])).model_dump()
        try:
            after = await hot.save(state["db"], changes, me.username)
        except ValueError as e:
            raise HTTPException(422, str(e)) from None
        await audit(me, "settings.update", "settings", before={k: before[k] for k in changes}, after=changes)
        return after.model_dump()

    @r.get("/projects/excluded")
    async def excluded(me: Admin, instance: str | None = None, cursor: int | None = None, limit: int = Query(100, ge=1, le=500)) -> dict:
        rows = await state["db"].fetch(
            "SELECT id, instance, path, namespace_kind, excluded_reason, archived, default_branch FROM projects"
            " WHERE NOT enabled AND ($1::text IS NULL OR instance = $1) AND ($2::bigint IS NULL OR id > $2) ORDER BY id LIMIT $3",
            instance, cursor, limit + 1)
        items = [dict(x) for x in rows[:limit]]
        return {"items": items, "next_cursor": items[-1]["id"] if len(rows) > limit else None}

    @r.get("/audit")
    async def audit_log(me: Admin, actor: str | None = None, action: str | None = None,
                        before: datetime | None = None, limit: int = Query(50, ge=1, le=200)) -> dict:
        rows = await state["db"].fetch(
            "SELECT at, actor, action, target, before, after FROM audit_log WHERE ($1::text IS NULL OR actor = $1)"
            " AND ($2::text IS NULL OR action LIKE $2 || '%') AND ($3::timestamptz IS NULL OR at < $3) ORDER BY at DESC LIMIT $4",
            actor, action, before, limit + 1)
        items = [dict(x) for x in rows[:limit]]
        return {"items": items, "next_before": items[-1]["at"] if len(rows) > limit else None}

    return r


def worker_health(raw: bytes | None) -> dict | None:
    """ARQ's health line ("… j_complete=5 j_failed=0 j_ongoing=1 queued=0"), expired when no collector is alive."""
    if raw is None:
        return None
    text = raw.decode()
    return {"line": text, **{k: int(v) for k, v in re.findall(r"(j_complete|j_failed|j_retried|j_ongoing|queued)=(\d+)", text)}}
