"""Dependency-Track, read only: its projects of a GitLab path, the delivered versions (projects the GitOps template builds from the
chosen brick versions) and their bricks, the components and findings of the versions that run, the analyses (VEX, exceptions) and
the freshness of its vulnerability sources. Periskope never writes to DT."""
from __future__ import annotations

import re
from datetime import UTC, date, datetime, timedelta
from typing import Any

import asyncpg
import httpx
import structlog
from periskope_core.settings import env, secret
from periskope_db import settings as hot
from periskope_db.dt import SEVERITIES, is_exception, rebuild

log = structlog.get_logger()

PAGE = 500
# The tag the GitOps template puts on the DT project of a delivered version (« CMS » version « 5.2.0 »).
DELIVERY = "version-livree"
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


async def link(db: asyncpg.Pool, instance: str) -> dict[str, int]:
    """DT project name → Periskope project: DT mirrors GitLab, each project named by its full path (« cms/back/brique-a »)."""
    return {r["path"].lower(): r["id"] for r in await db.fetch("SELECT id, path FROM projects WHERE instance = $1", instance)}


async def sync(db: asyncpg.Pool, dt: httpx.AsyncClient | None = None) -> dict[str, int]:
    """Reads the delivered versions into dt_collections, their bricks and the DT projects of a GitLab path into dt_projects, which
    delivered versions hold which brick into dt_members, the findings of the versions that run (the bricks of the delivered versions,
    else the project's latest SBOM) into dt_findings, then rebuilds each project's open findings."""
    if dt is None:
        async with client() as c:
            return await sync(db, c)
    conf = await hot.load(db)
    projects = await link(db, env("DT_INSTANCE", ""))
    known = {r["uuid"]: r for r in await db.fetch("SELECT uuid, bom_at, components, no_purl FROM dt_projects")}
    every = {p["uuid"]: p for p in await pages(dt, "/v1/project", excludeInactive="false")}
    # A delivered version: a DT project tagged « version-livree », named after the product, its version the delivery's. Its SBOM is
    # the chosen brick versions merged, each brick a component named and versioned as its own DT project.
    deliveries = [p for p in every.values() if DELIVERY in {t.get("name", "").lower() for t in p.get("tags") or []}]
    own = {(p["name"].lower(), p.get("version")): p for p in every.values() if DELIVERY not in {t.get("name", "").lower() for t in p.get("tags") or []}}
    # A brick: a component of a delivered version that is also a DT project of its own (same name, same version), whatever its name.
    # Its findings and analyses are read there, once, however many delivered versions hold it.
    # shortcut: every component of every delivered version is listed each hour; the bricks alone (onlyDirect) once DT's dependency graph is relied on.
    members: dict[tuple[str, str], None] = {}
    for d in deliveries:
        for c in await pages(dt, f"/v1/component/project/{d['uuid']}"):
            names = [c["name"].lower()] + ([f"{c['group']}/{c['name']}".lower()] if c.get("group") else [])
            if hit := next((own[(n, c.get("version"))] for n in names if (n, c.get("version")) in own), None):
                members[(d["uuid"], hit["uuid"])] = None
    bricks = {u: every[u] for _, u in members}
    delivered = {d["uuid"] for d in deliveries}
    kept = bricks | {u: p for u, p in every.items() if p["name"].lower() in projects and u not in bricks and u not in delivered}
    latest: dict[int, dict] = {}
    for p in kept.values():
        pid = projects.get(p["name"].lower())
        if pid and p["uuid"] not in bricks and p.get("active", True) and p.get("lastBomImport") and p["lastBomImport"] > (latest.get(pid) or {}).get("lastBomImport", 0):
            latest[pid] = p
    in_links = {projects.get(c["name"].lower()) for c in bricks.values()}
    rows: list[tuple] = []
    findings: dict[str, list[dict]] = {}
    for p in kept.values():
        pid = projects.get(p["name"].lower())
        bom_at = ms(p.get("lastBomImport"))
        tags = {t.get("name", "").lower() for t in p.get("tags") or []}
        components = no_purl = None
        runs = p["uuid"] in bricks or (pid not in in_links and latest.get(pid) is p)
        if runs and bom_at:
            before = known.get(p["uuid"])
            # Components change only with a new SBOM: counted again only then.
            if before and before["bom_at"] == bom_at and before["components"] is not None:
                components, no_purl = before["components"], before["no_purl"]
            else:
                parts = await pages(dt, f"/v1/component/project/{p['uuid']}")
                components, no_purl = len(parts), sum(1 for c in parts if not c.get("purl"))
            found = [finding_row(f) for f in await pages(dt, f"/v1/finding/project/{p['uuid']}", suppressed="true")]
            for row in found:
                if row["state"] not in (None, "NOT_SET") or row["suppressed"]:
                    await analysis(dt, p["uuid"], row, conf.exception_days)
            findings[p["uuid"]] = found
        rows.append((p["uuid"], p["name"], p.get("version"), p.get("active", True), bom_at,
                     "deploiement-par-tag" in tags, components, no_purl, pid))
    async with db.acquire() as conn, conn.transaction():
        await conn.execute("DELETE FROM dt_collections")
        await conn.executemany("INSERT INTO dt_collections (uuid, name, version, active) VALUES ($1, $2, $3, $4)",
                               [(k["uuid"], k["name"], k.get("version"), k.get("active", True)) for k in deliveries])
        await conn.execute("DELETE FROM dt_projects WHERE NOT (uuid = ANY($1::text[]))", [r[0] for r in rows])
        await conn.executemany(
            "INSERT INTO dt_projects (uuid, name, version, active, bom_at, by_tag, components, no_purl, project_id, synced_at)"
            " VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now()) ON CONFLICT (uuid) DO UPDATE SET name = $2, version = $3,"
            " active = $4, bom_at = $5, by_tag = $6, components = $7, no_purl = $8, project_id = $9, synced_at = now()", rows)
        # Emptied with dt_collections above (cascade): which delivered versions hold which brick, as read now.
        await conn.executemany("INSERT INTO dt_members (tree, project) VALUES ($1, $2)", list(members))
        # Findings of the versions no longer read are dropped with the others: only what runs is kept.
        await conn.execute("DELETE FROM dt_findings")
        cols = ["project", "component", "vuln", "key", "cve", "severity", "title", "component_name", "component_version", "purl", "vector", "kev", "epss",
                "state", "suppressed", "response", "justification", "detail", "analysed_at", "expires_on", "attributed_at"]
        # A component in two places of one SBOM is one finding.
        records = list({(u, r["component"], r["vuln"]): tuple([u] + [r.get(c) for c in cols[1:]]) for u, rs in findings.items() for r in rs}.values())
        await conn.copy_records_to_table("dt_findings", records=records, columns=cols)
        await rebuild(conn)
    await sources(db, dt)
    log.info("dt_synced", deliveries=len(deliveries), projects=len(rows), read=len(findings), findings=sum(map(len, findings.values())))
    return {"deliveries": len(deliveries), "projects": len(rows), "read": len(findings)}


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
        done = ms(run.get("completed_at")) if run.get("status") == "COMPLETED" else None
        await db.execute(
            "INSERT INTO dt_sources (name, status, completed_at, error) VALUES ($1, $2, $3, $4) ON CONFLICT (name) DO UPDATE SET status = $2,"
            " completed_at = COALESCE($3, dt_sources.completed_at), error = $4, read_at = now()",
            name, run.get("status"), done, run.get("failure_reason"))
