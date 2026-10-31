"""Periskope REST API: reads PostgreSQL only; writes are limited to launches, scope and project settings."""
from __future__ import annotations

import asyncio
import base64
import json
import time
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Annotated, Any, Literal

from arq import create_pool
from arq.connections import RedisSettings
from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from periskope_core.catalog import CHECKS, FIXES
from periskope_core.diff import diff
from periskope_core.referential import ACTIVITIES, REFERENTIAL_VERSION
from periskope_core.roadmap import roadmap
from periskope_core.scope import ScopeDecision, Target, effective
from periskope_core.settings import env, queue
from periskope_db import Viewer, connect, runs
from periskope_db import scope as scope_db
from periskope_db import settings as hot
from pydantic import BaseModel, Field

from periskope_api import admin as admin_routes
from periskope_api.auth import Settings, Verifier, viewer

BRANCH_WAIT_S = 3.0
state: dict[str, Any] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    state["db"] = await connect(min_size=2, max_size=20)
    state["arq"] = await create_pool(RedisSettings.from_dsn(env("VALKEY_URL", "redis://localhost:6379")))
    state["verifier"] = Verifier(Settings.from_env(), env("OIDC_CA_FILE", "") or None)
    yield
    await state["arq"].aclose()
    await state["db"].close()


app = FastAPI(title="Periskope", lifespan=lifespan, openapi_url="/api/v1/openapi.json", docs_url="/api/v1/docs", redoc_url=None)
app.add_middleware(GZipMiddleware, minimum_size=1024)
api = APIRouter(prefix="/api/v1")


def problem(status: int, detail: Any) -> JSONResponse:
    titles = {400: "Requête invalide", 401: "Non authentifié", 403: "Interdit", 404: "Introuvable", 409: "Conflit",
              422: "Données invalides", 429: "Trop de requêtes", 503: "Indisponible"}
    body = {"type": "about:blank", "title": titles.get(status, "Erreur"), "status": status,
            "detail": detail if isinstance(detail, str) else json.dumps(detail, default=str)}
    return JSONResponse(body, status_code=status, media_type="application/problem+json")


@app.exception_handler(HTTPException)
async def http_error(_: Request, e: HTTPException) -> JSONResponse:
    return problem(e.status_code, e.detail)


@app.exception_handler(RequestValidationError)
async def validation_error(_: Request, e: RequestValidationError) -> JSONResponse:
    return problem(422, [{"loc": err["loc"], "msg": err["msg"]} for err in e.errors()])


VIEWER_TTL_S = 60


async def current(authorization: Annotated[str | None, Header()] = None) -> Viewer:
    """The token is checked on every call; the scope built from it is kept a minute per token (well under the 15 min rule)."""
    claims = await state["verifier"].claims(authorization)
    cache = state.setdefault("viewers", {})
    key = (claims["sub"], claims.get("iat"), claims.get("exp"))
    hit = cache.get(key)
    if hit and hit[0] > time.monotonic():
        return hit[1]
    v = await viewer(state["db"], state["arq"], state["verifier"], claims)
    # An empty scope may only mean memberships were still resolving (slow collector): recompute it rather than hold it a minute.
    if not (v.admin or v.namespaces or v.projects):
        return v
    if len(cache) > 10_000:
        cache.clear()
    cache[key] = (time.monotonic() + VIEWER_TTL_S, v)
    return v


Me = Annotated[Viewer, Depends(current)]


async def audit(actor: Viewer, action: str, target: str, before: Any = None, after: Any = None) -> None:
    await state["db"].execute("INSERT INTO audit_log (actor, action, target, before, after) VALUES ($1, $2, $3, $4, $5)",
                              actor.username, action, target, before, after)


async def project_row(me: Viewer, instance: str, path: str) -> dict:
    """A project the viewer may see; anything else is 404, since existence itself is information."""
    where, params = me.where("p", 3)
    row = await state["db"].fetchrow(
        f"SELECT p.*, s.score, s.coverage, s.last_run_id, s.last_success_at, s.last_error, s.by_dimension, s.statuses"
        f" FROM projects p LEFT JOIN project_state s ON s.project_id = p.id WHERE p.instance = $1 AND p.path = $2 AND {where}",
        instance, path, *params)
    if row is None or (not row["enabled"] and not me.admin):
        raise HTTPException(404, "projet introuvable")
    return dict(row)


@api.get("/health")
async def health() -> dict:
    await state["db"].fetchval("SELECT 1")
    await state["arq"].ping()
    instances = await state["db"].fetch("SELECT slug, last_sync_at FROM gitlab_instances WHERE enabled ORDER BY slug")
    return {"status": "ok", "instances": [{"slug": i["slug"], "last_sync_at": i["last_sync_at"],
                                           "queued": await state["arq"].zcard(queue(i["slug"]))} for i in instances]}


@api.get("/me")
async def me_(me: Me) -> dict:
    return {"sub": me.sub, "username": me.username, "admin": me.admin,
            "namespaces": sorted(f"{i}:{n}" for i, n in me.namespaces),
            "maintains": sorted(f"{i}:{n}" for i, n in me.maintains)}


@api.get("/instances")
async def list_instances(me: Me) -> list[dict]:
    """Admins see every instance; others only the instances where they can see a project, so names and URLs do not leak."""
    rows = await state["db"].fetch("SELECT slug, name, url, enterprise, last_sync_at FROM gitlab_instances WHERE enabled ORDER BY slug")
    if me.admin:
        return [dict(r) for r in rows]
    where, params = scoped(me, None, None)
    mine = {r["instance"] for r in await state["db"].fetch(f"SELECT DISTINCT p.instance FROM projects p WHERE {where}", *params)}
    return [dict(r) for r in rows if r["slug"] in mine]


SORTS = {"score": "s.score", "name": "p.path", "last_run": "s.last_success_at"}


def scoped(me: Viewer, instance: str | None, namespace: str | None) -> tuple[str, list]:
    """The viewer's enabled projects, narrowed to one GitLab instance and one group with its subgroups."""
    where, params = me.where("p", 1)
    conds = [where, "p.enabled"]
    if instance:
        params.append(instance)
        conds.append(f"p.instance = ${len(params)}")
    if namespace:
        params.append(namespace)
        n = f"${len(params)}"
        conds.append(f"(p.namespace_path = {n} OR left(p.namespace_path, length({n}) + 1) = {n} || '/')")
    return " AND ".join(conds), params


@api.get("/groups")
async def list_groups(me: Me) -> list[dict]:
    """Groups holding visible projects, per instance, with what the tree needs to roll counts and scores up to parents."""
    where, params = scoped(me, None, None)
    rows = await state["db"].fetch(
        "SELECT p.instance, p.namespace_path AS path, count(*) AS projects, count(s.score) AS analysed, coalesce(sum(s.score), 0) AS score_sum"
        f" FROM projects p LEFT JOIN project_state s ON s.project_id = p.id WHERE {where} GROUP BY 1, 2 ORDER BY 1, 2", *params)
    return [dict(r) for r in rows]


@api.get("/projects")
async def list_projects(
    me: Me,
    instance: str | None = None,
    namespace: str | None = None,
    q: str | None = Query(None, max_length=100),
    below_target: bool = False,
    failed: bool = False,
    stale: bool = False,
    never: bool = False,
    sort: Literal["score", "name", "last_run"] = "name",
    cursor: str | None = None,
    limit: int = Query(50, ge=1, le=200),
) -> dict:
    """The portfolio reads project_state, never runs: it pages on an index."""
    where, params = scoped(me, instance, namespace)
    conds = [where]
    def arg(value: Any) -> str:
        params.append(value)
        return f"${len(params)}"
    if q:
        conds.append(f"strpos(lower(p.path), lower({arg(q)})) > 0")
    if below_target:
        conds.append("s.score < 100")
    if failed:
        conds.append("s.last_error IS NOT NULL")
    if stale:
        conds.append("s.last_success_at < now() - interval '7 days'")
    if never:
        conds.append("s.last_run_id IS NULL")
    key = SORTS[sort]
    # Keyset on (sort key, id); NULL keys sort last.
    order = f"{key} {'DESC' if sort != 'name' else 'ASC'} NULLS LAST, p.id"
    if cursor:
        last_key, last_id = json.loads(base64.urlsafe_b64decode(cursor))
        if sort == "name":
            conds.append(f"(p.path, p.id) > ({arg(last_key)}, {arg(last_id)})")
        elif last_key is None:
            conds.append(f"{key} IS NULL AND p.id > {arg(last_id)}")
        else:
            conds.append(f"({key} < {arg(last_key)} OR ({key} = {arg(last_key)} AND p.id > {arg(last_id)}) OR {key} IS NULL)")
    # The page first, then the latest run of its rows only: never one lookup per project of the whole portfolio.
    rows = await state["db"].fetch(
        f"SELECT page.*, (SELECT status FROM runs WHERE project_id = page.id AND branch = page.default_branch ORDER BY created_at DESC LIMIT 1)"
        f" AS last_status FROM (SELECT p.id, p.instance, p.path, p.namespace_path, p.default_branch, p.target_level, s.score, s.coverage,"
        f" s.last_success_at, s.last_error, s.last_run_id FROM projects p LEFT JOIN project_state s ON s.project_id = p.id"
        f" WHERE {' AND '.join(conds)} ORDER BY {order} LIMIT {limit + 1}) page", *params)
    items = [dict(r) for r in rows[:limit]]
    nxt = None
    if len(rows) > limit:
        last = items[-1]
        sort_value = {"score": last["score"], "name": last["path"], "last_run": last["last_success_at"]}[sort]
        nxt = base64.urlsafe_b64encode(json.dumps([sort_value, last["id"]], default=str).encode()).decode()
    return {"items": items, "next_cursor": nxt}


@api.get("/projects/summary")
async def projects_summary(me: Me, instance: str | None = None, namespace: str | None = None) -> dict:
    """The portfolio's headline figures over the viewer's scope (or one instance or group of it), with the same definitions as the list filters."""
    where, params = scoped(me, instance, namespace)
    row = await state["db"].fetchrow(
        "SELECT count(*) AS total, count(s.last_run_id) AS analysed, avg(s.score) AS score, avg(s.coverage) AS coverage,"
        " count(*) FILTER (WHERE s.score < 100) AS below_target, count(*) FILTER (WHERE s.last_error IS NOT NULL) AS failed,"
        " count(*) FILTER (WHERE s.last_run_id IS NULL) AS never, count(*) FILTER (WHERE s.score >= 75) AS high,"
        " count(*) FILTER (WHERE s.score >= 50 AND s.score < 75) AS mid, count(*) FILTER (WHERE s.score < 50) AS low"
        f" FROM projects p LEFT JOIN project_state s ON s.project_id = p.id WHERE {where}", *params)
    dims = await state["db"].fetch(
        "SELECT d.key AS dimension, avg(d.value::text::float) AS score FROM projects p JOIN project_state s ON s.project_id = p.id,"
        f" jsonb_each(s.by_dimension) d WHERE {where} AND jsonb_typeof(d.value) = 'number' GROUP BY d.key ORDER BY d.key", *params)
    # Most missing practices across the scope, each counted only up to its project's target level.
    names, levels = [a.name for a in ACTIVITIES.values()], [a.level for a in ACTIVITIES.values()]
    n, lv = len(params) + 1, len(params) + 2
    gaps = await state["db"].fetch(
        "SELECT d.key AS activity, max(lv.level) AS level,"
        " count(*) FILTER (WHERE d.value->>'status' IN ('not_implemented', 'partial')) AS missing,"
        " count(*) FILTER (WHERE d.value->>'status' IN ('implemented', 'not_implemented', 'partial')) AS measured"
        f" FROM projects p JOIN project_state s ON s.project_id = p.id, jsonb_each(s.statuses) d, unnest(${n}::text[], ${lv}::int[]) AS lv(name, level)"
        f" WHERE {where} AND lv.name = d.key AND lv.level <= p.target_level"
        " GROUP BY d.key HAVING count(*) FILTER (WHERE d.value->>'status' IN ('not_implemented', 'partial')) > 0"
        " ORDER BY missing DESC, level, d.key LIMIT 5", *params, names, levels)
    lowest = await state["db"].fetch(
        "SELECT p.instance, p.path, s.score, s.coverage, s.last_success_at FROM projects p JOIN project_state s ON s.project_id = p.id"
        f" WHERE {where} AND s.score IS NOT NULL ORDER BY s.score, p.path LIMIT 3", *params)
    return {**dict(row), "dimensions": {d["dimension"]: d["score"] for d in dims},
            "gaps": [dict(g) for g in gaps], "lowest": [dict(r) for r in lowest]}


class RunRequest(BaseModel):
    branch: str | None = Field(None, max_length=255)


class ProjectPatch(BaseModel):
    target_level: int | None = Field(None, ge=1, le=5)
    sonar_key: str | None = Field(None, max_length=400)
    enabled: bool | None = None


async def branches_of(project: dict, fresh: bool = False) -> list[dict] | None:
    """Branches as the instance's collector last read them (2 min cache); asks it on a miss and waits up to 3 s."""
    arq, key = state["arq"], f"branches:{project['id']}"
    if not fresh and (raw := await arq.get(key)) is not None:
        return json.loads(raw)
    if fresh:
        await arq.delete(key)
    await arq.enqueue_job("list_branches", project["id"], _queue_name=queue(project["instance"]), _job_id=key, _defer_by=timedelta(hours=-1))
    for _ in range(int(BRANCH_WAIT_S / 0.1)):
        await asyncio.sleep(0.1)
        if (raw := await arq.get(key)) is not None:
            return json.loads(raw)
    return None


# Routes with a suffix come before the bare project route: the GitLab path holds slashes.
@api.get("/projects/{instance}/{path:path}/branches")
async def project_branches(instance: str, path: str, me: Me, q: str | None = Query(None, max_length=100)) -> list[dict]:
    project = await project_row(me, instance, path)
    found = await branches_of(project)
    if found is None:
        raise HTTPException(503, "liste des branches indisponible pour le moment, réessayez")
    found = [b for b in found if not q or q.lower() in b["name"].lower()]
    return sorted(found, key=lambda b: (not b["default"], b["name"]))[:100]

@api.post("/projects/{instance}/{path:path}/runs", status_code=202)
async def launch(instance: str, path: str, body: RunRequest, me: Me, idempotency_key: Annotated[str | None, Header()] = None) -> dict:
    project = await project_row(me, instance, path)
    if not me.can_maintain(instance, path):
        raise HTTPException(403, "lancement réservé aux mainteneurs du projet")
    arq = state["arq"]
    if idempotency_key and (seen := await arq.get(f"idem:{me.sub}:{idempotency_key}")):
        return json.loads(seen)
    branch = body.branch or project["default_branch"]
    if branch != project["default_branch"]:
        # The branch must exist in GitLab at launch time: read fresh, never from a stale cache.
        found = await branches_of(project, fresh=True)
        if found is None:
            raise HTTPException(503, "liste des branches indisponible pour le moment, réessayez")
        if branch not in {b["name"] for b in found}:
            raise HTTPException(422, f"la branche {branch} n'existe pas dans GitLab")
    count = await arq.incr(f"quota:{me.sub}")
    if count == 1:
        await arq.expire(f"quota:{me.sub}", 3600)
    per_hour = (await hot.load(state["db"])).on_demand_per_hour
    if count > per_hour and not me.admin:
        raise HTTPException(429, f"{per_hour} analyses à la demande par heure au plus")
    try:
        run_id = await runs.create(state["db"], project["id"], branch, "user", me.username)
    except runs.AlreadyActive as e:
        return JSONResponse({"id": e.run_id, "status": "already_active"}, status_code=409)
    # shortcut: a negative defer puts user runs ahead of the nightly backlog; a second queue per priority would be cleaner.
    await arq.enqueue_job("run_analysis", run_id, _queue_name=queue(instance), _job_id=f"run:{run_id}", _defer_by=timedelta(hours=-1))
    await audit(me, "run.launch", f"{instance}:{path}", after={"run": run_id, "branch": branch})
    result = {"id": run_id, "status": "queued"}
    if idempotency_key:
        await arq.set(f"idem:{me.sub}:{idempotency_key}", json.dumps(result), ex=600)
    return result


@api.get("/projects/{instance}/{path:path}/roadmap")
async def project_roadmap(instance: str, path: str, me: Me) -> list[dict]:
    """Retained activities not in place up to the target level, with the step to take for each failing check."""
    p = await project_row(me, instance, path)
    if not p["last_run_id"]:
        return []
    results = await state["db"].fetchval("SELECT results FROM runs WHERE id = $1", p["last_run_id"])
    return roadmap(p["statuses"] or {}, results or {}, p["target_level"])


@api.get("/projects/{instance}/{path:path}/runs")
async def project_runs(instance: str, path: str, me: Me, branch: str | None = None, status: str | None = None,
                       cursor: int | None = None, limit: int = Query(50, ge=1, le=200)) -> dict:
    project = await project_row(me, instance, path)
    rows = await state["db"].fetch(
        "SELECT id, branch, commit_sha, trigger, requested_by, status, created_at, started_at, finished_at, error, score, coverage, reused_from"
        " FROM runs WHERE project_id = $1 AND ($2::text IS NULL OR branch = $2) AND ($3::text IS NULL OR status = $3)"
        " AND ($4::bigint IS NULL OR id < $4) ORDER BY id DESC LIMIT $5",
        project["id"], branch, status, cursor, limit + 1)
    items = [dict(r) for r in rows[:limit]]
    return {"items": items, "next_cursor": items[-1]["id"] if len(rows) > limit else None}


@api.get("/projects/{instance}/{path:path}")
async def project(instance: str, path: str, me: Me) -> dict:
    p = await project_row(me, instance, path)
    p["can_launch"] = me.can_maintain(instance, path)
    if p["last_run_id"]:
        p["last_run"] = dict(await state["db"].fetchrow(
            "SELECT id, commit_sha, finished_at, results, reused_from FROM runs WHERE id = $1", p["last_run_id"]))
    p["active_run"] = await state["db"].fetchval(
        "SELECT id FROM runs WHERE project_id = $1 AND branch = $2 AND status IN ('queued', 'running') ORDER BY id DESC LIMIT 1",
        p["id"], p["default_branch"])
    return p


@api.patch("/projects/{instance}/{path:path}")
async def patch_project(instance: str, path: str, body: ProjectPatch, me: Me) -> dict:
    p = await project_row(me, instance, path)
    if not me.can_maintain(instance, path):
        raise HTTPException(403, "réservé aux mainteneurs du projet")
    changes = body.model_dump(exclude_unset=True)
    if "enabled" in changes and not me.admin:
        raise HTTPException(403, "seul un admin réintègre ou écarte un projet")
    if not changes:
        return {}
    await state["db"].execute(
        "UPDATE projects SET target_level = coalesce($2, target_level), sonar_key = coalesce($3, sonar_key),"
        " sonar_key_manual = sonar_key_manual OR $3 IS NOT NULL, enabled = coalesce($4, enabled),"
        " reinstated = CASE WHEN $4 THEN true ELSE reinstated END, excluded_reason = CASE WHEN $4 THEN NULL ELSE excluded_reason END"
        " WHERE id = $1", p["id"], changes.get("target_level"), changes.get("sonar_key"), changes.get("enabled"))
    await audit(me, "project.update", f"{instance}:{path}", before={k: p[k] for k in changes}, after=changes)
    if "target_level" in changes:
        await scope_db.rescore(state["db"], project_id=p["id"])
    return changes


async def run_row(me: Viewer, run_id: int) -> dict:
    where, params = me.where("p", 2)
    row = await state["db"].fetchrow(
        f"SELECT r.*, p.instance, p.path, p.default_branch FROM runs r JOIN projects p ON p.id = r.project_id WHERE r.id = $1 AND {where}",
        run_id, *params)
    if row is None:
        raise HTTPException(404, "analyse introuvable")
    return dict(row)


@api.get("/runs/{run_id}")
async def get_run(run_id: int, me: Me) -> dict:
    return await run_row(me, run_id)


@api.get("/runs/{run_id}/evidence")
async def run_evidence(run_id: int, me: Me) -> dict:
    """Raw evidence, kept 14 days; a reused analysis points to the original's."""
    run = await run_row(me, run_id)
    evidence = await state["db"].fetchval(
        "SELECT evidence FROM run_evidence WHERE run_id = $1 AND created_at >= $2::timestamptz - interval '1 day'",
        run["reused_from"] or run_id, run["created_at"])
    return {"evidence": evidence}


@api.get("/runs/{run_id}/diff")
async def run_diff(run_id: int, me: Me, against: int | Literal["previous"] | None = None) -> dict:
    """Changes from `against` to this run: a run id, "previous" (the run before it on its branch) or, by default, the reference run."""
    run = await run_row(me, run_id)
    if against == "previous":
        against = await state["db"].fetchval(
            "SELECT id FROM runs WHERE project_id = $1 AND branch = $2 AND status = 'succeeded' AND id < $3 ORDER BY id DESC LIMIT 1",
            run["project_id"], run["branch"], run_id)
        if against is None:
            raise HTTPException(404, "pas d'analyse précédente sur cette branche")
    elif against is None:
        # A branch is compared with the reference; the reference with its own previous analysis.
        if run["branch"] == run["default_branch"]:
            return await run_diff(run_id, me, "previous")
        against = await state["db"].fetchval("SELECT last_run_id FROM project_state WHERE project_id = $1", run["project_id"])
        if against is None:
            raise HTTPException(404, "aucune analyse de référence pour ce projet")
    base = await run_row(me, against)
    if base["project_id"] != run["project_id"]:
        raise HTTPException(422, "les deux analyses doivent porter sur le même projet")
    return {
        "before": {k: base[k] for k in ("id", "branch", "commit_sha", "finished_at", "score", "coverage")},
        "after": {k: run[k] for k in ("id", "branch", "commit_sha", "finished_at", "score", "coverage")},
        **diff(base["results"] or {}, run["results"] or {}),
    }


@api.delete("/runs/{run_id}", status_code=204)
async def cancel_run(run_id: int, me: Me) -> None:
    if not me.admin:
        raise HTTPException(403, "réservé aux admins")
    await run_row(me, run_id)
    done = await state["db"].execute("UPDATE runs SET status = 'cancelled', finished_at = now() WHERE id = $1 AND status IN ('queued', 'running')", run_id)
    if done.endswith(" 1"):
        await audit(me, "run.cancel", str(run_id))


@api.get("/checks")
async def checks(me: Me) -> list[dict]:
    decisions = {r["target_id"]: dict(r) for r in await state["db"].fetch(
        "SELECT target_id, decision, reason, author, updated_at FROM scope_decisions WHERE target = 'check' AND instance IS NULL")}
    return [{**c._asdict(), "scope": decisions.get(c.id), "fix": FIXES.get(c.id)} for c in CHECKS]


@api.get("/activities")
async def activities(me: Me) -> dict:
    return {"version": REFERENTIAL_VERSION, "items": [a.model_dump() for a in ACTIVITIES.values()]}


class ScopeItem(BaseModel):
    target: Literal["check", "activity"]
    target_id: str = Field(max_length=200)
    decision: Literal["retained", "excluded"]
    reason: str = Field(min_length=3, max_length=500)


class ScopeRequest(BaseModel):
    # Neither: the organisation. instance: that instance. Both: that project.
    instance: str | None = None
    project: str | None = Field(None, description="GitLab path of the project")
    items: list[ScopeItem] = Field(min_length=1, max_length=500)


async def scope_target(me: Viewer, instance: str | None, project: str | None) -> int | None:
    """The project id the decision is for, after checking the viewer may decide at that level."""
    if project is not None:
        if instance is None:
            raise HTTPException(422, "un projet se désigne avec son instance")
        p = await project_row(me, instance, project)
        if not me.can_maintain(instance, project):
            raise HTTPException(403, "dérogation réservée aux mainteneurs du projet")
        return p["id"]
    if not me.admin:
        raise HTTPException(403, "le cadrage de l'organisation ou d'une instance est réservé aux admins")
    if instance and not await state["db"].fetchval("SELECT 1 FROM gitlab_instances WHERE slug = $1", instance):
        raise HTTPException(404, "instance inconnue")
    return None


async def after_scope_change(instance: str | None, project_id: int | None) -> None:
    if project_id is not None:
        await scope_db.rescore(state["db"], project_id=project_id)
    else:
        # The whole organisation or an instance: recomputed in the background, the request does not wait.
        task = asyncio.create_task(scope_db.rescore(state["db"], instance=instance))
        state.setdefault("tasks", set()).add(task)
        task.add_done_callback(state["tasks"].discard)


@api.get("/scope")
async def scope(me: Me, instance: str | None = None, project: str | None = None) -> list[dict]:
    """The scope in force for every check and activity at that level, and where each decision comes from."""
    project_id = (await project_row(me, instance, project))["id"] if project and instance else None
    decisions = await scope_db.decisions_for(state["db"], instance, project_id)
    rows = {(r["target"], r["target_id"], r["instance"], r["project_id"]): r for r in await state["db"].fetch(
        "SELECT target, target_id, instance, project_id, author, updated_at FROM scope_decisions")}
    eff = effective(decisions, instance, project_id)
    here = "projet" if project_id else "instance" if instance else "organisation"
    out = []
    targets = [(Target.CHECK, c.id) for c in CHECKS] + [(Target.ACTIVITY, a) for a in ACTIVITIES]
    for target, target_id in targets:
        d = eff.get((target, target_id))
        level = None if d is None else "projet" if d.project_id else "instance" if d.instance else "organisation"
        meta = rows.get((target.value, target_id, d.instance, d.project_id)) if d else None
        out.append({"target": target, "target_id": target_id, "decision": d.decision if d else "retained",
                    "reason": d.reason if d else None, "level": level or "défaut", "inherited": level not in (None, here),
                    "author": meta["author"] if meta else None, "updated_at": meta["updated_at"] if meta else None})
    return out


@api.put("/scope")
async def put_scope(body: ScopeRequest, me: Me) -> dict:
    """Retain or exclude several targets at once (the bulk decision after filtering)."""
    project_id = await scope_target(me, body.instance, body.project)
    known = {("check", c.id) for c in CHECKS} | {("activity", a) for a in ACTIVITIES}
    if unknown := [i.target_id for i in body.items if (i.target, i.target_id) not in known]:
        raise HTTPException(422, f"cible inconnue : {', '.join(unknown[:5])}")
    where = f"{body.instance}:{body.project}" if body.project else body.instance or "organisation"
    async with state["db"].acquire() as conn, conn.transaction():
        for i in body.items:
            d = ScopeDecision(target=i.target, target_id=i.target_id, decision=i.decision, reason=i.reason, instance=body.instance, project_id=project_id)
            before = await scope_db.put(conn, d, me.username)
            await conn.execute("INSERT INTO audit_log (actor, action, target, before, after) VALUES ($1, 'scope.put', $2, $3, $4)",
                               me.username, f"{where}/{i.target}:{i.target_id}", before, i.model_dump())
    await after_scope_change(body.instance, project_id)
    return {"updated": len(body.items)}


@api.put("/scope/{target_id}")
async def put_one(target_id: str, body: ScopeItem, me: Me, instance: str | None = None, project: str | None = None) -> dict:
    if body.target_id != target_id:
        raise HTTPException(422, "l'identifiant de l'URL et celui du corps diffèrent")
    return await put_scope(ScopeRequest(instance=instance, project=project, items=[body]), me)


@api.delete("/scope/{target_id}", status_code=204)
async def delete_scope(target_id: str, me: Me, target: Literal["check", "activity"] = "check",
                       instance: str | None = None, project: str | None = None) -> None:
    """Withdraw the decision at this level: the inherited one applies again."""
    project_id = await scope_target(me, instance, project)
    async with state["db"].acquire() as conn, conn.transaction():
        before = await scope_db.remove(conn, target, target_id, instance, project_id)
        if before is None:
            raise HTTPException(404, "aucune décision à ce niveau")
        await conn.execute("INSERT INTO audit_log (actor, action, target, before) VALUES ($1, 'scope.delete', $2, $3)",
                           me.username, f"{project or instance or 'organisation'}/{target}:{target_id}", before)
    await after_scope_change(instance, project_id)


app.include_router(api)
app.include_router(admin_routes.router(state, current, audit))
