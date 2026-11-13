"""Dependency-Track, read through a fake server answering as DT 5.2.1's OpenAPI describes it (v1 projects, components, findings,
analysis trail; v2 mirror runs): trees, merge with GitLab's findings, SSVC, access, versions, CVE sheet, exceptions, ledger, alerts."""
import asyncio
import os
import sys
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from periskope_db import Viewer, connect

sys.path.insert(0, os.path.dirname(__file__))
from test_integration import client, db  # noqa: F401 (fixtures)

NOW = datetime.now(UTC)
ms = lambda d: int(d.timestamp() * 1000)
RCE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"


def tree(u, name, children=True):
    return {"uuid": u, "name": name, "version": None, "active": True, "hasChildren": children, "lastBomImport": None, "tags": []}


def brick(u, name, version, bom=True, tags=()):
    return {"uuid": u, "name": name, "version": version, "active": True, "lastBomImport": ms(NOW - timedelta(days=1)) if bom else None,
            "tags": [{"name": t} for t in tags]}


def finding(comp, vuln_id, severity, *, vector=None, kev=False, alias=None, state=None, suppressed=False, days=30):
    return {"component": {"uuid": f"c-{comp}", "name": comp, "group": "org.example", "version": "1.0", "purl": f"pkg:maven/org.example/{comp}@1.0"},
            "vulnerability": {"uuid": f"v-{vuln_id}", "vulnId": vuln_id, "source": "NVD" if vuln_id.startswith("CVE") else "GITHUB",
                              "title": f"faille {vuln_id}", "severity": severity, "cvssV3Vector": vector, "isKev": kev, "epssScore": 0.01,
                              "aliases": [{"cveId": alias}] if alias else []},
            "analysis": {"state": state, "isSuppressed": suppressed}, "attribution": {"attributedOn": ms(NOW - timedelta(days=days))}}


ROOTS = [tree("t-prod", "CMS · prod"), tree("t-test", "CMS · test"), tree("t-510", "CMS · 5.1.0 (livraison JAR)"), tree("build-1", "cms-core", children=False)]
CHILDREN = {
    "t-prod": [brick("b-app-12", "team-a/app", "1.2"), brick("b-lib", "lib", "3.0", bom=False, tags=("deploiement-par-tag",)), brick("b-x", "mystery", "9")],
    "t-test": [brick("b-app-13", "team-a/app", "1.3")],
    "t-510": [brick("b-app-11", "team-a/app", "1.1")],
}
FINDINGS = {
    "b-app-12": [finding("log4j-core", "CVE-2021-44228", "CRITICAL", vector=RCE, kev=True, days=400),
                 finding("jackson", "GHSA-aaaa-bbbb-cccc", "MEDIUM", alias="CVE-2099-0001"),
                 finding("netty", "CVE-2099-0002", "HIGH", state="NOT_AFFECTED", suppressed=True),
                 finding("snappy", "CVE-2099-0003", "HIGH", state="EXPLOITABLE", suppressed=True)],
    "b-app-13": [finding("commons-text", "CVE-2099-0004", "LOW")],
    "b-app-11": [finding("log4j-core", "CVE-2021-44228", "CRITICAL", vector=RCE, kev=True, days=400), finding("xstream", "CVE-2099-0005", "MEDIUM")],
    "b-x": [finding("secret-lib", "CVE-2099-0009", "CRITICAL")],
    "b-lib": [],
}
TRAILS = {"v-CVE-2099-0002": {"analysisState": "NOT_AFFECTED", "analysisJustification": "CODE_NOT_REACHABLE", "analysisResponse": "NOT_SET",
                              "analysisDetails": "classe jamais chargée", "isSuppressed": True, "analysisComments": [{"timestamp": ms(NOW - timedelta(days=3))}]},
          "v-CVE-2099-0003": {"analysisState": "EXPLOITABLE", "analysisResponse": "WILL_NOT_FIX", "analysisDetails": "risque accepté, expire 2026-01-01",
                              "isSuppressed": True, "analysisComments": [{"timestamp": ms(NOW - timedelta(days=200))}]}}
SOURCES = {"nvd": {"status": "COMPLETED", "completed_at": ms(NOW - timedelta(days=5))}, "github": {"status": "COMPLETED", "completed_at": ms(NOW)}}


def fake_dt(findings=FINDINGS):
    def handle(req: httpx.Request) -> httpx.Response:
        assert req.headers["X-Api-Key"] == "k"
        path, q = req.url.path, req.url.params
        page = lambda items: httpx.Response(200, json=items if q.get("pageNumber") == "1" else [])
        if path == "/api/v1/project":
            assert q["onlyRoot"] == "true"
            return page(ROOTS)
        if path.startswith("/api/v1/project/") and path.endswith("/children"):
            return page(CHILDREN[path.split("/")[4]])
        if path.startswith("/api/v1/component/project/"):
            u = path.rsplit("/", 1)[1]
            return page([{"uuid": "c1", "purl": "pkg:maven/a/b@1"}, {"uuid": "c2", "purl": None if u == "b-app-12" else "pkg:npm/x@1"}])
        if path.startswith("/api/v1/finding/project/"):
            return page(findings[path.rsplit("/", 1)[1]])
        if path == "/api/v1/analysis":
            return httpx.Response(200, json=TRAILS[q["vulnerability"]]) if q["vulnerability"] in TRAILS else httpx.Response(404)
        if path.startswith("/api/v2/vuln-data-sources/"):
            name = path.split("/")[4]
            return httpx.Response(200, json=SOURCES[name]) if name in SOURCES else httpx.Response(404)
        return httpx.Response(404)
    return httpx.AsyncClient(base_url="https://dt.test/api", headers={"X-Api-Key": "k"}, transport=httpx.MockTransport(handle))


async def setup(database_url, findings=FINDINGS):
    from periskope_db import vulns
    from periskope_scheduler import dtrack
    pool = await connect(database_url)
    app = await pool.fetchval("SELECT id FROM projects WHERE path = 'team-a/app'")
    # GitLab's own report of the project: its dependency finding is replaced by DT's, its SAST one stays.
    await pool.execute("UPDATE project_state SET vuln_findings = $2, vulns = $3 WHERE project_id = $1", app, [
        {"key": "CVE-2021-44228", "cve": True, "severity": "critical", "title": "log4j", "type": "dependency_scanning", "detected_at": "2021-12-10T00:00:00Z"},
        {"key": "Injection SQL", "cve": False, "severity": "high", "title": "Injection SQL", "type": "sast", "detected_at": NOW.isoformat()}],
        {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0, "unknown": 0})
    async with fake_dt(findings) as dt:
        done = await dtrack.sync(pool, dt)
    await vulns.ledger(pool)
    await pool.close()
    return done


@pytest.fixture
def dt_env(client, database_url, monkeypatch):  # noqa: F811
    monkeypatch.setenv("PERISKOPE_DT_URL", "https://dt.test")
    monkeypatch.setenv("PERISKOPE_DT_INSTANCE", "gl")

    async def states():
        pool = await connect(database_url)
        await pool.execute("INSERT INTO project_state (project_id) SELECT id FROM projects ON CONFLICT DO NOTHING")
        await pool.execute("TRUNCATE dt_projects, dt_sources, vuln_ledger, alerts_sent, vuln_feeds CASCADE")
        await pool.close()
    asyncio.run(states())
    return client


def test_trees_merge_and_access(dt_env, database_url):
    api = dt_env
    assert asyncio.run(setup(database_url)) == {"trees": 3, "bricks": 5}   # the « build » project, without children, is left out
    api.who["v"] = Viewer(f"s-{uuid.uuid4().hex}", "alice", namespaces=frozenset({("gl", "team-a")}))

    # One list: GitLab's SAST finding plus DT's open findings of the running bricks; GitLab's log4j copy is gone, not counted twice.
    items = {v["key"]: v for v in api.get("/api/v1/vulnerabilities?instance=gl").json()["items"]}
    assert set(items) == {"CVE-2021-44228", "CVE-2099-0001", "CVE-2099-0004", "CVE-2099-0005", "Injection SQL"}
    assert items["CVE-2021-44228"]["projects"] == 1 and items["CVE-2021-44228"]["kev"] is True   # KEV from DT, no Periskope feed
    # SSVC: exploited and in prod → Immédiat; low, only in test → Différé; a GHSA is keyed by its CVE alias.
    assert items["CVE-2021-44228"]["response"] == "immediate" and items["CVE-2099-0004"]["response"] == "deferred"
    assert items["CVE-2099-0005"]["response"] == "scheduled"   # a delivered JAR version counts as prod; medium, not automatable
    assert next(iter(items)) == "CVE-2021-44228" and items["CVE-2021-44228"]["overdue"] == 1
    where = api.get("/api/v1/vulnerabilities/projects?key=CVE-2021-44228").json()[0]
    assert where["type"] == "dependency_track" and sorted(where["trees"]) == ["CMS · 5.1.0 (livraison JAR)", "CMS · prod"]
    summary = api.get("/api/v1/projects/summary?instance=gl").json()
    assert summary["vulns"]["by_response"]["immediate"] == 1 and set(summary["vulns"]["sla_hours"]) == {"immediate", "out_of_cycle", "scheduled"}
    assert {s["name"] for s in summary["sources"]} >= {"NVD", "GITHUB"}
    project = api.get("/api/v1/projects/gl/team-a/app").json()
    assert {(b["tree"], b["version"]) for b in project["dt"]} == {("CMS · prod", "1.2"), ("CMS · test", "1.3"), ("CMS · 5.1.0 (livraison JAR)", "1.1")}

    # DT's work: lib (team-a/sub/lib by its last segment) runs without SBOM and by tag; app has one component without purl.
    work = api.get("/api/v1/dt/work").json()
    assert [(w["path"], w["name"]) for w in work["no_sbom"]] == [("team-a/sub/lib", "lib")] and len(work["by_tag"]) == 1
    assert [(w["name"], w["no_purl"]) for w in work["no_purl"]] == [("team-a/app", 1)]
    assert work["expired_exceptions"] == 1 and [s["name"] for s in work["stale_sources"]] == ["NVD"]

    # Versions, a comparison, a CVE's sheet: alice never sees « mystery », a brick no project of hers matches.
    trees = api.get("/api/v1/dt/versions").json()
    assert [t["name"] for t in trees] == ["CMS · prod", "CMS · test", "CMS · 5.1.0 (livraison JAR)"] and trees[0]["bricks"] == 2
    prod = api.get("/api/v1/dt/versions/t-prod").json()
    assert {b["name"] for b in prod["bricks"]} == {"team-a/app", "lib"} and "CVE-2099-0009" not in {f["key"] for f in prod["findings"]}
    diff = api.get("/api/v1/dt/compare?a=t-510&b=t-prod").json()
    assert [f["key"] for f in diff["only_a"]] == ["CVE-2099-0005"] and [f["key"] for f in diff["both"]] == ["CVE-2021-44228"]
    assert {(b["name"], b["a"], b["b"]) for b in diff["bricks"]} == {("team-a/app", "1.1", "1.2"), ("lib", None, "3.0")}
    sheet = api.get("/api/v1/dt/cve/CVE-2021-44228").json()
    assert {(p["tree"], p["version"], p["response"]) for p in sheet["places"]} == {("CMS · prod", "1.2", "immediate"), ("CMS · 5.1.0 (livraison JAR)", "1.1", "immediate")}
    assert [(f["tree"], f["version"]) for f in sheet["fixed_in"]] == [("CMS · test", "1.3")]   # already updated there
    assert [(row["path"], row["closed_at"]) for row in sheet["ledger"]] == [("team-a/app", None)]
    exc = api.get("/api/v1/dt/exceptions").json()
    assert [(e["key"], e["expired"], e["expires_on"]) for e in exc["exceptions"]] == [("CVE-2099-0003", True, "2026-01-01")]
    assert [(e["key"], e["justification"]) for e in exc["not_concerned"]] == [("CVE-2099-0002", "CODE_NOT_REACHABLE")]

    # Another team: nothing of team-a, not even that a version holds a CVE.
    api.who["v"] = Viewer(f"s-{uuid.uuid4().hex}", "bob", namespaces=frozenset({("gl", "team-ab")}))
    assert api.get("/api/v1/dt/versions").json() == [] and api.get("/api/v1/dt/cve/CVE-2021-44228").status_code == 404
    assert api.get("/api/v1/dt/versions/t-prod").json()["bricks"] == [] and api.get("/api/v1/dt/exceptions").json()["exceptions"] == []
    assert api.get("/api/v1/dt/work").json()["no_sbom"] == []
    api.who["v"] = Viewer(f"s-{uuid.uuid4().hex}", "root", admin=True)
    assert {b["name"] for b in api.get("/api/v1/dt/versions/t-prod").json()["bricks"]} == {"team-a/app", "lib", "mystery"}


def test_ledger_indicators_and_alerts(dt_env, database_url, monkeypatch, tmp_path):
    import respx
    from periskope_db import vulns
    from periskope_scheduler import app as scheduler
    from periskope_scheduler import dtrack

    api = dt_env
    asyncio.run(setup(database_url))
    # Fixed in the next prod version: log4j leaves every running brick, its ledger row closes.
    fixed = {**FINDINGS, "b-app-12": FINDINGS["b-app-12"][1:], "b-app-11": FINDINGS["b-app-11"][1:]}

    async def fix():
        pool = await connect(database_url)
        async with fake_dt(fixed) as dt:
            await dtrack.sync(pool, dt)
        done = await vulns.ledger(pool)
        rows = await pool.fetch("SELECT key, priority, response, closed_at FROM vuln_ledger ORDER BY key")
        await pool.close()
        return done, rows
    done, rows = asyncio.run(fix())
    assert done["closed"] == 1 and [(r["key"], r["closed_at"] is not None) for r in rows if r["key"] == "CVE-2021-44228"] == [("CVE-2021-44228", True)]
    api.who["v"] = Viewer(f"s-{uuid.uuid4().hex}", "root", admin=True)
    ind = api.get("/api/v1/indicators?months=3").json()
    this = ind["months"][-1]
    # Detected 400 days ago, fixed today: a critical fixed late, open 400 days.
    assert (this["critical_fixed"], this["critical_on_time"]) == (1, 0) and this["days"]["critical"] == pytest.approx(400, abs=1)
    assert ind["sbom"] == {"bricks": 4, "with_sbom": 3}   # prod tree (3) and the JAR delivery (1); lib has none and ind["exceptions"] == {"active": 0, "expired": 1}

    # Alerts: each new critical (here the SAST-free DT critical of « mystery » has no project) once, the stale NVD mirror once a day.
    (tmp_path / "periskope-alerts").mkdir()
    (tmp_path / "periskope-alerts" / "url").write_text("https://chat.test/hooks/x")
    monkeypatch.setenv("PERISKOPE_SECRETS_DIR", str(tmp_path))

    async def alerts():
        pool = await connect(database_url)
        await pool.execute("INSERT INTO vuln_ledger (project_id, key, opened_at, priority, response, deadline_at)"
                           " SELECT id, 'CVE-2099-7777', now(), 'critical', 'immediate', now() + interval '7 days' FROM projects WHERE path = 'team-a/app'")
        scheduler.state["db"] = pool
        with respx.mock:
            hook = respx.post("https://chat.test/hooks/x").mock(return_value=httpx.Response(200))
            await scheduler.alerts()
            await scheduler.alerts()
        await pool.close()
        return [c.request.content.decode() for c in hook.calls]
    sent = asyncio.run(alerts())
    assert len(sent) == 2   # second pass sends nothing again
    assert any("CVE-2099-7777" in s and "team-a/app" in s and "aucun référent" in s for s in sent)
    assert any("NVD" in s and "plus à jour" in s for s in sent)
    assert os.environ["PERISKOPE_DT_URL"] == "https://dt.test"
