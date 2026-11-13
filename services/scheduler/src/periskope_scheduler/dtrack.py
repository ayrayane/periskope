"""Dependency-Track, read only: the trees the GitOps job (and the JAR delivery job) builds, their bricks, components and findings,
the analyses (VEX, exceptions) and the freshness of its vulnerability sources. Periskope never writes to DT."""
from __future__ import annotations

import re
from collections import defaultdict
from datetime import UTC, date, datetime, timedelta
from typing import Any

import asyncpg
import httpx
import structlog
from periskope_core.settings import env, secret
from periskope_db import settings as hot

log = structlog.get_logger()

PAGE = 500
# A tree « CMS · prod » is an environment; any other root with children is a delivered version (« CMS · 5.2.0 (livraison JAR) »).
ENV_TREE = re.compile(r"·\s*(prod|test|dev)\s*$", re.IGNORECASE)
NOT_CONCERNED = {"NOT_AFFECTED", "FALSE_POSITIVE"}
CLOSED = NOT_CONCERNED | {"RESOLVED"}
SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
# The end date of an exception, written in its DT analysis detail (from the VEX file): « expire 2027-03-01 », « échéance : … ».
EXPIRES = re.compile(r"(?:expir\w*|échéance|until|jusqu'au)\D{0,15}(\d{4}-\d{2}-\d{2})", re.IGNORECASE)


def configured() -> bool:
    return bool(env("DT_URL", ""))


def client() -> httpx.AsyncClient:
    from periskope_scheduler.feeds import trust
    key = (secret("periskope-dtrack") / "apiKey").read_text().strip()
    return httpx.AsyncClient(base_url=env("DT_URL").rstrip("/") + "/api", headers={"X-Api-Key": key},
                             timeout=httpx.Timeout(60, connect=10), verify=trust())


async def pages(dt: httpx.AsyncClient, path: str, **params: Any) -> list[dict]:
    out: list[dict] = []
    for number in range(1, 10_000):
        resp = await dt.get(path, params={**params, "pageSize": PAGE, "pageNumber": number})
        resp.raise_for_status()
        batch = resp.json()
        out += batch
        if len(batch) < PAGE:
            return out
    return out


def ms(value: Any) -> datetime | None:
    return datetime.fromtimestamp(value / 1000, UTC) if isinstance(value, (int, float)) else None


def finding_row(f: dict) -> dict:
    """One DT finding as Periskope keeps it: keyed by CVE (an alias when DT names it otherwise, e.g. a GHSA), else DT's own id."""
    c, v, a = f.get("component") or {}, f.get("vulnerability") or {}, f.get("analysis") or {}
    cve = v.get("vulnId") if str(v.get("vulnId", "")).startswith("CVE-") else next(
        (x.get("cveId") for x in v.get("aliases") or [] if x.get("cveId")), None)
    severity = str(v.get("severity") or "").lower()
    return {
        "component": c.get("uuid"), "vuln": v.get("uuid"), "key": cve or v.get("vulnId") or "?", "cve": cve is not None,
        "severity": severity if severity in SEVERITIES else "unknown",
        "title": v.get("title") or v.get("subtitle") or (v.get("description") or "")[:160] or None,
        "component_name": ":".join(filter(None, (c.get("group"), c.get("name")))), "component_version": c.get("version"), "purl": c.get("purl"),
        "vector": v.get("cvssV3Vector") or v.get("cvssV4Vector"), "kev": bool(v.get("isKev") or v.get("kev")), "epss": v.get("epssScore"),
        "state": a.get("state"), "suppressed": bool(a.get("isSuppressed")),
        "attributed_at": ms((f.get("attribution") or {}).get("attributedOn")),
    }


async def analysis(dt: httpx.AsyncClient, project: str, row: dict, exception_days: int) -> None:
    """The analysis trail of a finding someone decided on: its response, detail, date and, for an exception, its end."""
    resp = await dt.get("/v1/analysis", params={"project": project, "component": row["component"], "vulnerability": row["vuln"]})
    if resp.status_code == 404:
        return
    resp.raise_for_status()
    trail = resp.json()
    row["response"] = trail.get("analysisResponse")
    row["justification"] = trail.get("analysisJustification")
    row["detail"] = (trail.get("analysisDetails") or "")[:2000] or None
    row["analysed_at"] = max(filter(None, (ms(c.get("timestamp")) for c in trail.get("analysisComments") or [])), default=None)
    if is_exception(row):
        found = EXPIRES.search(row["detail"] or "")
        row["expires_on"] = (date.fromisoformat(found.group(1)) if found
                             else (row["analysed_at"] or datetime.now(UTC)).date() + timedelta(days=exception_days))


def is_exception(row: dict) -> bool:
    """An accepted risk: hidden or answered « will not / can not fix » without being declared not concerned or resolved."""
    return row.get("state") not in CLOSED and (row.get("suppressed") or row.get("response") in ("WILL_NOT_FIX", "CAN_NOT_FIX"))


def is_open(row: dict) -> bool:
    return row.get("state") not in CLOSED and not is_exception(row)


async def link(db: asyncpg.Pool, instance: str) -> dict[str, int]:
    """DT brick name → Periskope project: the GitLab path (« cms/brique-a »), else a last path segment unique in the instance."""
    rows = await db.fetch("SELECT id, path FROM projects WHERE instance = $1", instance)
    names = {r["path"].lower(): r["id"] for r in rows}
    last: dict[str, list[int]] = defaultdict(list)
    for r in rows:
        last[r["path"].rsplit("/", 1)[-1].lower()].append(r["id"])
    return names | {k: v[0] for k, v in last.items() if len(v) == 1 and k not in names}


async def sync(db: asyncpg.Pool, dt: httpx.AsyncClient | None = None) -> dict[str, int]:
    """Reads every tree of DT into dt_projects and dt_findings, then rebuilds each project's open findings (dt_state)."""
    if dt is None:
        async with client() as c:
            return await sync(db, c)
    conf = await hot.load(db)
    projects = await link(db, env("DT_INSTANCE", ""))
    known = {r["uuid"]: r for r in await db.fetch("SELECT uuid, bom_at, components, no_purl FROM dt_projects")}
    roots = [r for r in await pages(dt, "/v1/project", onlyRoot="true", excludeInactive="false") if r.get("hasChildren")]
    rows: list[tuple] = []
    findings: dict[str, list[dict]] = {}
    for tree in roots:
        match = ENV_TREE.search(tree["name"])
        rows.append((tree["uuid"], tree["name"], tree.get("version"), tree["uuid"], None, "tree", match.group(1).lower() if match else None,
                     tree.get("active", True), ms(tree.get("lastBomImport")), False, None, None, None))
        for brick in await pages(dt, f"/v1/project/{tree['uuid']}/children", excludeInactive="false"):
            bom_at = ms(brick.get("lastBomImport"))
            before = known.get(brick["uuid"])
            # Components change only with a new SBOM: counted again only then.
            if before and before["bom_at"] == bom_at and before["components"] is not None:
                components, no_purl = before["components"], before["no_purl"]
            elif bom_at:
                parts = await pages(dt, f"/v1/component/project/{brick['uuid']}")
                components, no_purl = len(parts), sum(1 for p in parts if not p.get("purl"))
            else:
                components = no_purl = None
            tags = {t.get("name", "").lower() for t in brick.get("tags") or []}
            rows.append((brick["uuid"], brick["name"], brick.get("version"), tree["uuid"], tree["uuid"], "brick", None, brick.get("active", True),
                         bom_at, "deploiement-par-tag" in tags, components, no_purl, projects.get(brick["name"].lower())))
            found = [finding_row(f) for f in await pages(dt, f"/v1/finding/project/{brick['uuid']}", suppressed="true")]
            for row in found:
                if row["state"] not in (None, "NOT_SET") or row["suppressed"]:
                    await analysis(dt, brick["uuid"], row, conf.exception_days)
            findings[brick["uuid"]] = found
    async with db.acquire() as conn, conn.transaction():
        await conn.execute("DELETE FROM dt_projects WHERE NOT (uuid = ANY($1::text[]))", [r[0] for r in rows])
        await conn.executemany(
            "INSERT INTO dt_projects (uuid, name, version, root, parent, kind, env, active, bom_at, by_tag, components, no_purl, project_id, synced_at)"
            " VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, now()) ON CONFLICT (uuid) DO UPDATE SET name = $2, version = $3, root = $4,"
            " parent = $5, kind = $6, env = $7, active = $8, bom_at = $9, by_tag = $10, components = $11, no_purl = $12, project_id = $13, synced_at = now()", rows)
        await conn.execute("DELETE FROM dt_findings WHERE project = ANY($1::text[])", list(findings))
        cols = ["project", "component", "vuln", "key", "cve", "severity", "title", "component_name", "component_version", "purl", "vector", "kev", "epss",
                "state", "suppressed", "response", "justification", "detail", "analysed_at", "expires_on", "attributed_at"]
        # A component in two places of one SBOM is one finding.
        records = list({(u, r["component"], r["vuln"]): tuple([u] + [r.get(c) for c in cols[1:]]) for u, rs in findings.items() for r in rs}.values())
        await conn.copy_records_to_table("dt_findings", records=records, columns=cols)
        await rebuild(conn)
    await sources(db, dt)
    log.info("dt_synced", trees=len(roots), bricks=len(rows) - len(roots), findings=sum(map(len, findings.values())))
    return {"trees": len(roots), "bricks": len(rows) - len(roots)}


async def rebuild(conn: asyncpg.Connection) -> None:
    """Each project's open findings across the running bricks of every tree, one per CVE, with the environments it runs in."""
    rows = await conn.fetch(
        "SELECT b.project_id, b.uuid, b.name, b.version, b.bom_at, b.by_tag, b.components, b.no_purl, t.name AS tree, coalesce(t.env, 'prod') AS env,"
        " t.env IS NULL AS delivery FROM dt_projects b JOIN dt_projects t ON t.uuid = b.root"
        " WHERE b.kind = 'brick' AND b.active AND t.active AND b.project_id IS NOT NULL ORDER BY t.name, b.name")
    found = defaultdict(list)
    for f in await conn.fetch("SELECT * FROM dt_findings WHERE project = ANY($1::text[])", [r["uuid"] for r in rows]):
        found[f["project"]].append(dict(f))
    state: dict[int, dict[str, Any]] = defaultdict(lambda: {"findings": {}, "bricks": []})
    for b in rows:
        s = state[b["project_id"]]
        s["bricks"].append({"tree": b["tree"], "env": None if b["delivery"] else b["env"], "uuid": b["uuid"], "version": b["version"],
                            "sbom": b["bom_at"] is not None, "by_tag": b["by_tag"], "components": b["components"], "no_purl": b["no_purl"]})
        for f in found[b["uuid"]]:
            if not is_open(f):
                continue
            seen = f["attributed_at"].isoformat() if f["attributed_at"] else None
            item = s["findings"].setdefault(f["key"], {"key": f["key"], "cve": f["cve"], "severity": f["severity"], "title": f["title"] or f["key"],
                                                       "type": "dependency_track", "detected_at": seen, "envs": [], "trees": [], "components": [],
                                                       "vector": f["vector"], "kev": False, "epss": None})
            if SEVERITIES.index(f["severity"]) < SEVERITIES.index(item["severity"]):
                item["severity"] = f["severity"]
            if seen and (item["detected_at"] is None or seen < item["detected_at"]):
                item["detected_at"] = seen
            item["kev"] |= f["kev"]
            item["epss"] = max(filter(lambda x: x is not None, (item["epss"], f["epss"])), default=None)
            item["vector"] = item["vector"] or f["vector"]
            for k, v in (("envs", b["env"]), ("trees", b["tree"]), ("components", f"{f['component_name']}@{f['component_version']}")):
                if v not in item[k]:
                    item[k].append(v)
    await conn.execute("DELETE FROM dt_state")
    await conn.executemany("INSERT INTO dt_state (project_id, findings, bricks) VALUES ($1, $2, $3)",
                           [(p, list(s["findings"].values()), s["bricks"]) for p, s in state.items()])


async def sources(db: asyncpg.Pool, dt: httpx.AsyncClient) -> None:
    """When each vulnerability source DT mirrors last completed; a source DT does not run (404) is left out."""
    for name in [n.strip() for n in env("DT_SOURCES", "nvd,github,osv").split(",") if n.strip()]:
        try:
            resp = await dt.get(f"/v2/vuln-data-sources/{name}/mirror-runs/latest")
            if resp.status_code == 404:
                await db.execute("DELETE FROM dt_sources WHERE name = $1", name)
                continue
            resp.raise_for_status()
            run = resp.json()
        except httpx.HTTPError as e:
            await db.execute("INSERT INTO dt_sources (name, error) VALUES ($1, $2) ON CONFLICT (name) DO UPDATE SET error = $2, read_at = now()",
                             name, type(e).__name__)
            continue
        # The last completed run: a failed or running one keeps the previous date and says why.
        await db.execute(
            "INSERT INTO dt_sources (name, status, completed_at, error) VALUES ($1, $2, $3, $4) ON CONFLICT (name) DO UPDATE SET status = $2,"
            " completed_at = CASE WHEN $2 = 'COMPLETED' THEN $3 ELSE dt_sources.completed_at END, error = $4, read_at = now()",
            name, run.get("status"), ms(run.get("completed_at")), run.get("failure_reason"))
