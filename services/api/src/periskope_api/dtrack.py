"""Dependency-Track views: delivered versions and their comparison, the follow-up sheet of a CVE, exceptions and VEX,
DT's work items, and the indicators for management. A viewer sees only the bricks of the projects they may see.

No `from __future__ import annotations` here: FastAPI resolves the closure-local dependencies from real annotations."""

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from periskope_core.settings import env
from periskope_db import Viewer
from periskope_db import settings as hot

# Status of a DT finding: open, not concerned (VEX: not affected, false positive), an accepted exception, or resolved.
STATUS = ("CASE WHEN f.state = 'RESOLVED' THEN 'resolved' WHEN f.state IN ('NOT_AFFECTED', 'FALSE_POSITIVE') THEN 'not_concerned'"
          " WHEN f.suppressed OR f.response IN ('WILL_NOT_FIX', 'CAN_NOT_FIX') THEN 'exception' ELSE 'open' END")
# The feeds of the finding's CVE: Periskope's mirror first, else what DT says.
JOIN_FEEDS = "LEFT JOIN vuln_kev k ON k.cve = f.key LEFT JOIN vuln_epss e ON e.cve = f.key"
SEV = "array_position(ARRAY['critical', 'high', 'medium', 'low', 'info', 'unknown'], f.severity)"
STALE_DAYS = 2


def router(state: dict[str, Any], current, scoped) -> APIRouter:
    Me = Annotated[Viewer, Depends(current)]
    Env = Annotated[Literal["prod", "test", "dev", "none"] | None, Query(alias="env")]
    r = APIRouter(prefix="/api/v1")

    async def response_sql() -> str:
        """SSVC response of DT finding f in tree t: exposed when the tree is prod or a delivered version."""
        threshold = (await hot.load(state["db"])).epss_high_pct / 100
        return f"ssvc(f.kev OR k.cve IS NOT NULL, coalesce(e.score, f.epss), {threshold}, f.severity, f.vector, coalesce(t.env, 'prod') = 'prod')"

    def visible(me: Viewer, instance=None, namespace=None, environment=None) -> tuple[str, list]:
        """Bricks b of the viewer's projects; a brick no GitLab project matches is shown to those who read everything."""
        where, params = scoped(me, instance, namespace, environment)
        if (me.admin or me.reads_all) and not (instance or namespace or environment):
            return f"(b.project_id IS NULL OR EXISTS (SELECT 1 FROM projects p WHERE p.id = b.project_id AND {where}))", params
        return f"EXISTS (SELECT 1 FROM projects p WHERE p.id = b.project_id AND {where})", params

    @r.get("/dt/work")
    async def work(me: Me, instance: str | None = None, namespace: str | None = None, environment: Env = None) -> dict:
        """What DT says needs doing: running bricks without SBOM or deployed by tag, components without purl, lapsed exceptions, stale sources."""
        if not env("DT_URL", ""):
            return {"configured": False}
        cond, params = visible(me, instance, namespace, environment)
        brick = ("SELECT b.uuid, b.name, b.version, b.components, b.no_purl, t.name AS tree, p.instance, p.path FROM dt_projects b"
                 " JOIN dt_projects t ON t.uuid = b.root LEFT JOIN projects p ON p.id = b.project_id"
                 f" WHERE b.kind = 'brick' AND b.active AND t.active AND {cond}")
        db = state["db"]
        no_sbom = await db.fetch(f"{brick} AND b.bom_at IS NULL ORDER BY t.name, b.name LIMIT 200", *params)
        by_tag = await db.fetch(f"{brick} AND b.by_tag ORDER BY t.name, b.name LIMIT 200", *params)
        no_purl = await db.fetch(f"{brick} AND b.no_purl > 0 ORDER BY b.no_purl DESC, b.name LIMIT 200", *params)
        expired = await db.fetchval(
            f"SELECT count(*) FROM dt_findings f JOIN dt_projects b ON b.uuid = f.project WHERE {STATUS} = 'exception' AND f.expires_on < current_date AND {cond}", *params)
        stale = await db.fetch(
            f"SELECT name, completed_at, via FROM vuln_sources WHERE completed_at IS NULL OR completed_at < now() - interval '{STALE_DAYS} days'")
        synced = await db.fetchval("SELECT max(synced_at) FROM dt_projects")
        return {"configured": True, "synced_at": synced, "no_sbom": [dict(x) for x in no_sbom], "by_tag": [dict(x) for x in by_tag],
                "no_purl": [dict(x) for x in no_purl], "expired_exceptions": expired, "stale_sources": [dict(x) for x in stale]}

    @r.get("/dt/versions")
    async def versions(me: Me) -> list[dict]:
        """Every tree of DT, environments first: the visible bricks it holds and their open findings."""
        cond, params = visible(me)
        response = await response_sql()
        rows = await state["db"].fetch(
            f"SELECT t.uuid, t.name, t.env, t.active, t.synced_at, count(DISTINCT b.uuid) AS bricks,"
            f" count(DISTINCT b.uuid) FILTER (WHERE b.bom_at IS NULL) AS no_sbom,"
            f" count(DISTINCT f.key) FILTER (WHERE {STATUS} = 'open') AS open,"
            f" count(DISTINCT f.key) FILTER (WHERE {STATUS} = 'open' AND {response} = 'immediate') AS immediate"
            f" FROM dt_projects t JOIN dt_projects b ON b.root = t.uuid AND b.kind = 'brick'"
            f" LEFT JOIN dt_findings f ON f.project = b.uuid {JOIN_FEEDS}"
            f" WHERE t.kind = 'tree' AND {cond} GROUP BY t.uuid ORDER BY t.env IS NULL, t.env, t.active DESC, t.name DESC", *params)
        return [dict(x) for x in rows]

    async def tree_findings(me: Viewer, uuid: str) -> tuple[dict, list[dict], list[dict]]:
        cond, params = visible(me)
        db = state["db"]
        tree = await db.fetchrow("SELECT uuid, name, env, active, synced_at FROM dt_projects WHERE uuid = $1 AND kind = 'tree'", uuid)
        if tree is None:
            raise HTTPException(404, "version introuvable")
        params = [*params, uuid]
        n = f"${len(params)}"
        bricks = await db.fetch(
            "SELECT b.uuid, b.name, b.version, b.active, b.bom_at IS NOT NULL AS sbom, b.by_tag, b.components, b.no_purl, p.instance, p.path"
            f" FROM dt_projects b LEFT JOIN projects p ON p.id = b.project_id WHERE b.root = {n} AND b.kind = 'brick' AND {cond} ORDER BY b.name", *params)
        response = await response_sql()
        found = await db.fetch(
            f"SELECT f.key, bool_or(f.cve) AS cve, min(f.title) AS title, min({SEV}) AS rank, min(array_position(ARRAY['immediate', 'out_of_cycle', 'scheduled', 'deferred'], {response})) AS rrank,"
            f" bool_or(f.kev OR k.cve IS NOT NULL) AS kev, max(coalesce(e.score, f.epss)) AS epss,"
            f" array_agg(DISTINCT b.name || ' ' || coalesce(b.version, '') || ' · ' || coalesce(f.component_name, '') || '@' || coalesce(f.component_version, '')) AS where_"
            f" FROM dt_findings f JOIN dt_projects b ON b.uuid = f.project JOIN dt_projects t ON t.uuid = b.root {JOIN_FEEDS}"
            f" WHERE b.root = {n} AND b.active AND {STATUS} = 'open' AND {cond} GROUP BY f.key ORDER BY rrank, rank, f.key", *params)
        sev = ("critical", "high", "medium", "low", "info", "unknown")
        resp = ("immediate", "out_of_cycle", "scheduled", "deferred")
        items = [{"key": x["key"], "cve": x["cve"], "title": x["title"], "severity": sev[x["rank"] - 1], "response": resp[x["rrank"] - 1],
                  "kev": x["kev"], "epss": x["epss"], "where": sorted(x["where_"])} for x in found]
        return dict(tree), [dict(b) for b in bricks], items

    @r.get("/dt/versions/{uuid}")
    async def version(uuid: str, me: Me) -> dict:
        tree, bricks, items = await tree_findings(me, uuid)
        return {"tree": tree, "bricks": bricks, "findings": items}

    @r.get("/dt/compare")
    async def compare(me: Me, a: str = Query(..., max_length=64), b: str = Query(..., max_length=64)) -> dict:
        """Two versions side by side: brick versions that changed, CVEs only in one of them, CVEs in both."""
        ta, ba, fa = await tree_findings(me, a)
        tb, bb, fb = await tree_findings(me, b)
        ka, kb = {x["key"]: x for x in fa}, {x["key"]: x for x in fb}
        va, vb = {x["name"]: x["version"] for x in ba}, {x["name"]: x["version"] for x in bb}
        changed = [{"name": n, "a": va.get(n), "b": vb.get(n)} for n in sorted(va.keys() | vb.keys()) if va.get(n) != vb.get(n)]
        return {"a": ta, "b": tb, "bricks": changed, "only_a": [ka[k] for k in ka if k not in kb],
                "only_b": [kb[k] for k in kb if k not in ka], "both": [kb[k] for k in kb if k in ka]}

    @r.get("/dt/cve/{key}")
    async def cve(key: str, me: Me) -> dict:
        """The follow-up sheet of a CVE: every version where DT found it with its analysis, the versions of those bricks that no longer
        carry it, and the ledger of the projects (opened, closed, deadline)."""
        cond, params = visible(me)
        db = state["db"]
        params = [*params, key]
        n = f"${len(params)}"
        response = await response_sql()
        places = await db.fetch(
            f"SELECT t.uuid AS tree_uuid, t.name AS tree, t.env, t.active AS tree_active, b.name AS brick, b.version, b.active, p.instance, p.path,"
            f" f.component_name, f.component_version, f.title, f.severity, f.vector, f.kev OR k.cve IS NOT NULL AS kev, coalesce(e.score, f.epss) AS epss,"
            f" f.state, f.response AS analysis_response, f.justification, f.detail, f.analysed_at, f.expires_on, f.attributed_at,"
            f" {STATUS} AS status, {response} AS response"
            f" FROM dt_findings f JOIN dt_projects b ON b.uuid = f.project JOIN dt_projects t ON t.uuid = b.root LEFT JOIN projects p ON p.id = b.project_id"
            f" {JOIN_FEEDS} WHERE f.key = {n} AND {cond} ORDER BY t.env IS NULL, t.env, t.name DESC, b.name", *params)
        # Same bricks, in a tree or version where the CVE is absent: the versions already updated.
        fixed = await db.fetch(
            f"SELECT DISTINCT t.name AS tree, t.env, t.active AS tree_active, b.name AS brick, b.version, b.active FROM dt_projects b JOIN dt_projects t ON t.uuid = b.root"
            f" WHERE b.kind = 'brick' AND b.bom_at IS NOT NULL AND {cond} AND b.name IN (SELECT x.name FROM dt_findings g JOIN dt_projects x ON x.uuid = g.project WHERE g.key = {n})"
            f" AND NOT EXISTS (SELECT 1 FROM dt_findings g WHERE g.project = b.uuid AND g.key = {n}) ORDER BY b.name, b.version", *params)
        where, lparams = scoped(me, None, None)
        lparams = [*lparams, key]
        ledger = await db.fetch(
            f"SELECT p.instance, p.path, l.opened_at, l.closed_at, l.priority, l.response, l.deadline_at FROM vuln_ledger l JOIN projects p ON p.id = l.project_id"
            f" WHERE l.key = ${len(lparams)} AND {where} ORDER BY l.opened_at", *lparams)
        if not places and not ledger:
            raise HTTPException(404, "CVE introuvable")
        return {"key": key, "places": [dict(x) for x in places], "fixed_in": [dict(x) for x in fixed], "ledger": [dict(x) for x in ledger]}

    @r.get("/dt/exceptions")
    async def exceptions(me: Me, instance: str | None = None, namespace: str | None = None, environment: Env = None) -> dict:
        """Accepted exceptions with their end date (lapsed first), and the CVEs declared not concerned (VEX) with their justification."""
        cond, params = visible(me, instance, namespace, environment)
        rows = await state["db"].fetch(
            f"SELECT f.key, f.title, f.severity, {STATUS} AS kind, f.state, f.justification, f.response, f.detail, f.analysed_at, f.expires_on,"
            f" f.expires_on < current_date AS expired, b.name AS brick, b.version, t.name AS tree, p.instance, p.path"
            f" FROM dt_findings f JOIN dt_projects b ON b.uuid = f.project JOIN dt_projects t ON t.uuid = b.root LEFT JOIN projects p ON p.id = b.project_id"
            f" WHERE b.active AND t.active AND {STATUS} IN ('exception', 'not_concerned') AND {cond}"
            f" ORDER BY {STATUS}, f.expires_on NULLS LAST, f.key, b.name LIMIT 2000", *params)
        items = [dict(x) for x in rows]
        return {"exceptions": [x for x in items if x["kind"] == "exception"], "not_concerned": [x for x in items if x["kind"] == "not_concerned"]}

    @r.get("/indicators")
    async def indicators(me: Me, instance: str | None = None, namespace: str | None = None, environment: Env = None,
                         months: int = Query(6, ge=1, le=24)) -> dict:
        """The five indicators for management (D11), month by month from the ledger: critical CVEs fixed on time, mean time to fix
        by priority, stock past its deadline at each month's end; SBOM coverage of what runs in prod and exceptions, today."""
        where, params = scoped(me, instance, namespace, environment)
        db = state["db"]
        n = len(params) + 1
        monthly = await db.fetch(
            "SELECT m.month, count(*) FILTER (WHERE l.priority = 'critical' AND l.closed_at >= m.month AND l.closed_at < m.month + interval '1 month') AS critical_fixed,"
            " count(*) FILTER (WHERE l.priority = 'critical' AND l.closed_at >= m.month AND l.closed_at < m.month + interval '1 month'"
            "   AND (l.deadline_at IS NULL OR l.closed_at <= l.deadline_at)) AS critical_on_time,"
            + ", ".join(f" avg(extract(epoch FROM l.closed_at - l.opened_at) / 86400) FILTER (WHERE l.priority = '{k}' AND l.closed_at >= m.month"
                        f" AND l.closed_at < m.month + interval '1 month') AS days_{k}" for k in ("critical", "high", "medium", "low")) +
            f", count(*) FILTER (WHERE l.opened_at < least(m.month + interval '1 month', now()) AND (l.closed_at IS NULL OR l.closed_at >= least(m.month + interval '1 month', now()))"
            f"   AND l.deadline_at < least(m.month + interval '1 month', now())) AS overdue_stock"
            f" FROM generate_series(date_trunc('month', now()) - make_interval(months => ${n} - 1), date_trunc('month', now()), interval '1 month') AS m(month)"
            f" LEFT JOIN (vuln_ledger l JOIN projects p ON p.id = l.project_id AND {where}) ON true GROUP BY m.month ORDER BY m.month", *params, months)
        cond, bparams = visible(me, instance, namespace, environment)
        sbom = await db.fetchrow(
            f"SELECT count(*) AS bricks, count(*) FILTER (WHERE b.bom_at IS NOT NULL) AS with_sbom FROM dt_projects b JOIN dt_projects t ON t.uuid = b.root"
            f" WHERE b.kind = 'brick' AND b.active AND t.active AND coalesce(t.env, 'prod') = 'prod' AND {cond}", *bparams)
        exc = await db.fetchrow(
            f"SELECT count(*) FILTER (WHERE f.expires_on >= current_date) AS active, count(*) FILTER (WHERE f.expires_on < current_date) AS expired"
            f" FROM dt_findings f JOIN dt_projects b ON b.uuid = f.project JOIN dt_projects t ON t.uuid = b.root"
            f" WHERE b.active AND t.active AND {STATUS} = 'exception' AND {cond}", *bparams)
        return {"months": [{"month": x["month"].date().isoformat(), "critical_fixed": x["critical_fixed"], "critical_on_time": x["critical_on_time"],
                            "days": {k: None if x[f"days_{k}"] is None else round(float(x[f"days_{k}"]), 1) for k in ("critical", "high", "medium", "low")}, "overdue_stock": x["overdue_stock"]} for x in monthly],
                "sbom": dict(sbom) if env("DT_URL", "") else None, "exceptions": dict(exc) if env("DT_URL", "") else None}

    return r
