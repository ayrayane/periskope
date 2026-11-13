"""Priority, SSVC response and correction deadline of an open finding: one definition for the API, the ledger and the alerts."""
from __future__ import annotations

from dataclasses import dataclass

import asyncpg

from periskope_db import settings as hot

# A finding f of project p (project_status s) with the exploitation feeds of its CVE: k (KEV) and e (EPSS), empty without a mirror.
FINDINGS = ("jsonb_array_elements(s.vuln_findings) f LEFT JOIN vuln_kev k ON k.cve = f->>'key'"
            " LEFT JOIN vuln_epss e ON e.cve = f->>'key'")
# Periskope's own feeds first, else what Dependency-Track says of its finding.
KEV = "(k.cve IS NOT NULL OR coalesce((f->>'kev')::boolean, false))"
EPSS = "coalesce(e.score, (f->>'epss')::real)"
RESPONSES = ("immediate", "out_of_cycle", "scheduled", "deferred")


@dataclass(frozen=True)
class Rules:
    priority: str
    response: str
    deadline: str
    # Hours by response; « deferred » has none.
    hours: dict[str, int]


async def rules(db: asyncpg.Pool | asyncpg.Connection) -> Rules:
    """Priority: exploited (KEV) is critical; a likely exploitation (EPSS at or above the threshold) raises the severity one level,
    an unlikely one brings a critical down to high; without EPSS, the severity.
    Response: SSVC from exploitation, exposure (environment) and automatability (CVSS vector); its deadline runs from the first detection."""
    conf = await hot.load(db)
    threshold = conf.epss_high_pct / 100
    priority = (f"(CASE WHEN {KEV} THEN 'critical'"
                f" WHEN {EPSS} >= {threshold} THEN (CASE f->>'severity' WHEN 'medium' THEN 'high' WHEN 'low' THEN 'medium' ELSE 'critical' END)"
                f" WHEN {EPSS} IS NOT NULL AND f->>'severity' = 'critical' THEN 'high' ELSE f->>'severity' END)")
    response = f"ssvc({KEV}, {EPSS}, {threshold}, f->>'severity', f->>'vector', exposed(f, p.topics))"
    hours = {"immediate": conf.sla_immediate_days * 24, "out_of_cycle": conf.sla_out_of_cycle_days * 24, "scheduled": conf.sla_scheduled_days * 24}
    return Rules(priority, response, f"CASE {response} " + " ".join(f"WHEN '{k}' THEN {v}" for k, v in hours.items()) + " END", hours)


def overdue(deadline: str) -> str:
    """Open past its deadline; a finding without a detection date, or deferred, counts as neither late nor on time."""
    return f"((f->>'detected_at')::timestamptz + make_interval(hours => {deadline}) < now())"


async def ledger(db: asyncpg.Pool) -> dict[str, int]:
    """Opens a ledger row for each open finding not yet in it, keeps its priority and deadline current, closes those gone."""
    r = await rules(db)
    current = (f"SELECT p.id AS project_id, f->>'key' AS key, coalesce((f->>'detected_at')::timestamptz, now()) AS opened_at,"
               f" {r.priority} AS priority, {r.response} AS response,"
               f" coalesce((f->>'detected_at')::timestamptz, now()) + make_interval(hours => {r.deadline}) AS deadline_at"
               f" FROM projects p JOIN project_status s ON s.project_id = p.id, {FINDINGS} WHERE p.enabled AND s.vuln_findings IS NOT NULL")
    async with db.acquire() as conn, conn.transaction():
        opened = await conn.execute(
            # Reopened after a fix with its old detection date: opened now, so the earlier row stays as it was.
            "INSERT INTO vuln_ledger (project_id, key, opened_at, priority, response, deadline_at) SELECT DISTINCT ON (c.project_id, c.key) c.project_id, c.key,"
            " CASE WHEN EXISTS (SELECT 1 FROM vuln_ledger x WHERE x.project_id = c.project_id AND x.key = c.key AND x.opened_at = c.opened_at AND x.closed_at IS NOT NULL)"
            f" THEN now() ELSE c.opened_at END, c.priority, c.response, c.deadline_at FROM ({current}) c"
            " ON CONFLICT (project_id, key) WHERE closed_at IS NULL DO UPDATE SET priority = excluded.priority, response = excluded.response,"
            " deadline_at = excluded.deadline_at")
        # Closed: gone from a project still measured. A project that is no longer measured keeps its rows open (unknown, not fixed).
        closed = await conn.execute(
            "UPDATE vuln_ledger l SET closed_at = now() FROM project_status s WHERE l.closed_at IS NULL AND s.project_id = l.project_id"
            " AND s.vuln_findings IS NOT NULL AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(s.vuln_findings) f WHERE f->>'key' = l.key)")
    return {"upserted": int(opened.split()[-1]), "closed": int(closed.split()[-1])}
