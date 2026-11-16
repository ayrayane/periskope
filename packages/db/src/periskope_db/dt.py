"""Each project's Dependency-Track state (dt_state) from what DT holds: its bricks in the delivered versions (collection projects)
and, outside them, its latest SBOM."""
from __future__ import annotations

from collections import defaultdict
from typing import Any

import asyncpg

NOT_CONCERNED = {"NOT_AFFECTED", "FALSE_POSITIVE"}
CLOSED = NOT_CONCERNED | {"RESOLVED"}
SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
OUTSIDE = "Dependency-Track (hors version livrée)"


def is_exception(row: dict) -> bool:
    """An accepted risk: hidden or answered « will not / can not fix » without being declared not concerned or resolved."""
    return row.get("state") not in CLOSED and (row.get("suppressed") or row.get("response") in ("WILL_NOT_FIX", "CAN_NOT_FIX"))


def is_open(row: dict) -> bool:
    return row.get("state") not in CLOSED and not is_exception(row)


async def running(conn: asyncpg.Pool | asyncpg.Connection, project_id: int | None = None) -> list[asyncpg.Record]:
    """The versions that run (of one project, or all): the bricks of the delivered versions, without environment (production); for a
    project in none of them, its latest SBOM in DT, environment « none » (its topics then tell the exposure)."""
    return await conn.fetch(
        "SELECT * FROM (SELECT b.project_id, b.uuid, b.version, b.bom_at, b.by_tag, b.components, b.no_purl, t.name AS tree, t.env"
        " FROM dt_bricks b JOIN dt_trees t ON t.uuid = b.root WHERE b.active AND t.active AND b.project_id IS NOT NULL"
        " UNION ALL (SELECT DISTINCT ON (d.project_id) d.project_id, d.uuid, d.version, d.bom_at, d.by_tag, d.components, d.no_purl, $1, 'none'"
        "  FROM dt_projects d WHERE d.project_id IS NOT NULL AND d.active AND d.bom_at IS NOT NULL"
        "  AND NOT EXISTS (SELECT 1 FROM dt_bricks x WHERE x.project_id = d.project_id) ORDER BY d.project_id, d.bom_at DESC)) r"
        " WHERE $2::bigint IS NULL OR r.project_id = $2 ORDER BY tree, project_id", OUTSIDE, project_id)


def brick(b: asyncpg.Record) -> dict[str, Any]:
    return {"tree": b["tree"], "env": b["env"], "uuid": b["uuid"], "version": b["version"], "running": True,
            "sbom": b["bom_at"] is not None, "by_tag": b["by_tag"], "components": b["components"], "no_purl": b["no_purl"]}


async def rebuild(conn: asyncpg.Connection) -> None:
    """Each project's open findings across its running versions, one per CVE, with the environments it runs in."""
    rows = await running(conn)
    found = defaultdict(list)
    for f in await conn.fetch("SELECT * FROM dt_findings WHERE project = ANY($1::text[])", [r["uuid"] for r in rows]):
        found[f["project"]].append(dict(f))
    state: dict[int, dict[str, Any]] = defaultdict(lambda: {"findings": {}, "bricks": []})
    for b in rows:
        s = state[b["project_id"]]
        s["bricks"].append(brick(b))
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
            # A delivered version runs in production; a version outside them, in no known environment.
            env = {None: "prod", "none": None}.get(b["env"], b["env"])
            for k, v in (("envs", env), ("trees", b["tree"]), ("components", f"{f['component_name']}@{f['component_version']}")):
                if v is not None and v not in item[k]:
                    item[k].append(v)
    await conn.execute("DELETE FROM dt_state")
    await conn.executemany("INSERT INTO dt_state (project_id, findings, bricks) VALUES ($1, $2, $3)",
                           [(p, list(s["findings"].values()), s["bricks"]) for p, s in state.items()])
