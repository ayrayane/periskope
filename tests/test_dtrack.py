"""Dependency-Track, read through a fake server answering as DT 5.2.1's OpenAPI describes it (v1 projects, components, findings,
analysis trail; v2 mirror runs), with delivered versions as projects tagged version-livree whose components are the chosen brick
versions: merge with GitLab's findings, SSVC, access, versions,
CVE sheet, exceptions, ledger, alerts."""
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


def brick(u, name, version, bom=True, tags=()):
    return {"uuid": u, "name": name, "version": version, "active": True, "lastBomImport": ms(NOW - timedelta(days=1)) if bom else None,
            "tags": [{"name": t} for t in tags]}


def finding(comp, vuln_id, severity, *, vector=None, kev=False, alias=None, state=None, suppressed=False, days=30):
    return {"component": {"uuid": f"c-{comp}", "name": comp, "group": "org.example", "version": "1.0", "purl": f"pkg:maven/org.example/{comp}@1.0"},
            "vulnerability": {"uuid": f"v-{vuln_id}", "vulnId": vuln_id, "source": "NVD" if vuln_id.startswith("CVE") else "GITHUB",
                              "title": f"faille {vuln_id}", "severity": severity, "cvssV3Vector": vector, "isKev": kev, "epssScore": 0.01,
                              "aliases": [{"cveId": alias}] if alias else []},
            "analysis": {"state": state, "isSuppressed": suppressed}, "attribution": {"attributedOn": ms(NOW - timedelta(days=days))}}


U = lambda n: f"00000000-0000-0000-0000-{n:012d}"
PROD, TEST, PORTAIL = U(1), U(2), U(3)
# DT mirrors GitLab (groups, then one project per path and version); the GitOps template builds one project per delivered version,
# tagged version-livree, whose components are the chosen brick versions (named and versioned as their own DT project) and their
# dependencies. « team-a/app » 1.0 is delivered nowhere; « mystery » is a brick of no GitLab path; « team-ab/other » is in no delivery.
BRICKS = [brick("b-app-12", "team-a/app", "1.2"), brick("b-lib", "team-a/sub/lib", "3.0", bom=False, tags=("deploiement-par-tag",)),
          brick("b-x", "mystery", "9"), brick("b-app-13", "team-a/app", "1.3"), brick("b-app-11", "team-a/app", "1.1")]
# The components of each delivered version: its bricks, then dependencies that are no DT project (ignored).
CONTENTS = {PROD: ["b-app-12", "b-lib", "b-x"], TEST: ["b-app-13"], PORTAIL: ["b-app-11"]}
DELIVERED = ("version-livree",)
PROJECTS = [brick(PROD, "CMS", "5.2.0", tags=DELIVERED), brick(TEST, "CMS", "5.3.0-rc", tags=DELIVERED), brick(PORTAIL, "Portail", "1.0", tags=DELIVERED),
            brick("g-team-a", "team-a", None, bom=False), brick("b-app-10", "team-a/app", "1.0"), brick("b-other", "team-ab/other", "2.0"), *BRICKS]

FINDINGS = {
    "b-app-12": [finding("log4j-core", "CVE-2021-44228", "CRITICAL", vector=RCE, kev=True, days=400),
                 finding("jackson", "GHSA-aaaa-bbbb-cccc", "MEDIUM", alias="CVE-2099-0001"),
                 finding("netty", "CVE-2099-0002", "HIGH", state="NOT_AFFECTED", suppressed=True),
                 finding("snappy", "CVE-2099-0003", "HIGH", state="EXPLOITABLE", suppressed=True)],
    "b-app-13": [finding("commons-text", "CVE-2099-0004", "LOW")],
    "b-app-11": [finding("log4j-core", "CVE-2021-44228", "CRITICAL", vector=RCE, kev=True, days=400), finding("xstream", "CVE-2099-0005", "MEDIUM")],
    "b-x": [finding("secret-lib", "CVE-2099-0009", "CRITICAL")],
    "b-other": [finding("guava", "CVE-2099-0008", "MEDIUM")],
}
TRAILS = {"v-CVE-2099-0002": {"analysisState": "NOT_AFFECTED", "analysisJustification": "CODE_NOT_REACHABLE", "analysisResponse": "NOT_SET",
                              "analysisDetails": "classe jamais chargée", "isSuppressed": True, "analysisComments": [{"timestamp": ms(NOW - timedelta(days=3))}]},
          "v-CVE-2099-0003": {"analysisState": "EXPLOITABLE", "analysisResponse": "WILL_NOT_FIX", "analysisDetails": "risque accepté, expire 2026-01-01",
                              "isSuppressed": True, "analysisComments": [{"timestamp": ms(NOW - timedelta(days=200))}]}}
SOURCES = {"nvd": {"status": "COMPLETED", "completed_at": ms(NOW - timedelta(days=5))}, "github": {"status": "COMPLETED", "completed_at": ms(NOW)},
           "osv": {"status": "FAILED", "completed_at": ms(NOW), "failure_reason": "miroir injoignable"}}   # never completed: no date, stale


def fake_dt(findings=FINDINGS):
    def handle(req: httpx.Request) -> httpx.Response:
        assert req.headers["X-Api-Key"] == "k"
        path, q = req.url.path, req.url.params
        page = lambda items: httpx.Response(200, json=items if q.get("pageNumber") == "1" else [])
        if path == "/api/v1/project":
            return page(PROJECTS)
        if path.startswith("/api/v1/component/project/"):
            u = path.rsplit("/", 1)[1]
            if u in CONTENTS:
                # A brick written group + name, as a merge tool may split a path; a dependency that is no DT project.
                bricks = [next(p for p in PROJECTS if p["uuid"] == b) for b in CONTENTS[u]]
                return page([{"uuid": f"cmp-{b['uuid']}", "group": b["name"].rsplit("/", 1)[0] if b["name"] == "team-a/sub/lib" else None,
                              "name": b["name"].rsplit("/", 1)[-1] if b["name"] == "team-a/sub/lib" else b["name"], "version": b["version"],
                              "purl": None} for b in bricks] + [{"uuid": "cmp-dep", "name": "jackson-databind", "version": "2.17.0", "purl": "pkg:maven/x/y@1"}])
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
        await pool.execute("TRUNCATE dt_projects, dt_state, dt_sources, dt_collections, dt_members, vuln_ledger, alerts_sent, vuln_feeds CASCADE")
        await pool.close()
    asyncio.run(states())
    return client


def test_trees_merge_and_access(dt_env, database_url):
    api = dt_env
    # Delivered versions and the group are not bricks; only the versions that run are read: the delivered bricks with an SBOM, and other's latest.
    assert asyncio.run(setup(database_url)) == {"deliveries": 3, "projects": 7, "read": 5}
    api.who["v"] = Viewer(f"s-{uuid.uuid4().hex}", "alice", namespaces=frozenset({("gl", "team-a")}))

    # One list: GitLab's SAST finding plus DT's open findings of the running bricks; GitLab's log4j copy is gone, not counted twice.
    items = {v["key"]: v for v in api.get("/api/v1/vulnerabilities?instance=gl").json()["items"]}
    assert set(items) == {"CVE-2021-44228", "CVE-2099-0001", "CVE-2099-0004", "CVE-2099-0005", "Injection SQL"}
    assert items["CVE-2021-44228"]["projects"] == 1 and items["CVE-2021-44228"]["kev"] is True   # KEV from DT, no Periskope feed
    # SSVC: exploited and delivered (prod) → Immédiat; low, delivered → Planifié; a GHSA is keyed by its CVE alias.
    assert items["CVE-2021-44228"]["response"] == "immediate" and items["CVE-2099-0004"]["response"] == "scheduled"
    assert items["CVE-2099-0005"]["response"] == "scheduled"   # 1.1 is delivered in Portail; medium, not automatable
    assert next(iter(items)) == "CVE-2021-44228" and items["CVE-2021-44228"]["overdue"] == 1
    # The severity is filtered by the API, over every CVE and not over the 1 000 first.
    assert [v["key"] for v in api.get("/api/v1/vulnerabilities?instance=gl&severity=low").json()["items"]] == ["CVE-2099-0004"]
    where = api.get("/api/v1/vulnerabilities/projects?key=CVE-2021-44228").json()[0]
    assert where["type"] == "dependency_track" and sorted(where["trees"]) == ["CMS 5.2.0", "Portail 1.0"]
    summary = api.get("/api/v1/projects/summary?instance=gl").json()
    assert summary["vulns"]["by_response"]["immediate"] == 1 and set(summary["vulns"]["sla_hours"]) == {"immediate", "out_of_cycle", "scheduled"}
    assert {s["name"] for s in summary["sources"]} >= {"NVD", "GITHUB"}
    project = api.get("/api/v1/projects/gl/team-a/app").json()
    assert {(b["tree"], b["version"]) for b in project["dt"]} == {("CMS 5.2.0", "1.2"), ("CMS 5.3.0-rc", "1.3"), ("Portail 1.0", "1.1")}

    # DT's work: lib runs without SBOM and by tag; app has one component without purl.
    work = api.get("/api/v1/dt/work").json()
    assert [(w["path"], w["name"]) for w in work["no_sbom"]] == [("team-a/sub/lib", "team-a/sub/lib")] and len(work["by_tag"]) == 1
    assert [(w["name"], w["no_purl"]) for w in work["no_purl"]] == [("team-a/app", 1)]
    assert work["expired_exceptions"] == 1 and sorted(s["name"] for s in work["stale_sources"]) == ["NVD", "OSV"]

    # Versions, a comparison, a CVE's sheet: alice never sees « mystery », a brick no project of hers matches.
    trees = api.get("/api/v1/dt/versions").json()
    assert [t["name"] for t in trees] == ["Portail 1.0", "CMS 5.3.0-rc", "CMS 5.2.0"] and trees[2]["bricks"] == 2 and trees[2]["env"] is None
    prod = api.get(f"/api/v1/dt/versions/{PROD}").json()
    assert {b["name"] for b in prod["bricks"]} == {"team-a/app", "team-a/sub/lib"} and "CVE-2099-0009" not in {f["key"] for f in prod["findings"]}
    diff = api.get(f"/api/v1/dt/compare?a={PORTAIL}&b={PROD}").json()
    assert [f["key"] for f in diff["only_a"]] == ["CVE-2099-0005"] and [f["key"] for f in diff["both"]] == ["CVE-2021-44228"]
    assert {(b["name"], b["a"], b["b"]) for b in diff["bricks"]} == {("team-a/app", "1.1", "1.2"), ("team-a/sub/lib", None, "3.0")}
    sheet = api.get("/api/v1/dt/cve/CVE-2021-44228").json()
    assert {(p["tree"], p["version"], p["response"]) for p in sheet["places"]} == {("CMS 5.2.0", "1.2", "immediate"), ("Portail 1.0", "1.1", "immediate")}
    assert [(f["tree"], f["version"]) for f in sheet["fixed_in"]] == [("CMS 5.3.0-rc", "1.3")]   # already updated there
    assert [(row["path"], row["closed_at"]) for row in sheet["ledger"]] == [("team-a/app", None)]
    exc = api.get("/api/v1/dt/exceptions").json()
    assert [(e["key"], e["expired"], e["expires_on"]) for e in exc["exceptions"]] == [("CVE-2099-0003", True, "2026-01-01")]
    assert [(e["key"], e["justification"]) for e in exc["not_concerned"]] == [("CVE-2099-0002", "CODE_NOT_REACHABLE")]

    # Another team: nothing of team-a, not even that a version holds a CVE; its own project, in no aggregate, counts its latest SBOM.
    api.who["v"] = Viewer(f"s-{uuid.uuid4().hex}", "bob", namespaces=frozenset({("gl", "team-ab")}))
    assert api.get("/api/v1/dt/versions").json() == [] and api.get("/api/v1/dt/cve/CVE-2021-44228").status_code == 404
    assert api.get(f"/api/v1/dt/versions/{PROD}").status_code == 404 and api.get("/api/v1/dt/exceptions").json()["exceptions"] == []
    assert api.get("/api/v1/dt/work").json()["no_sbom"] == []
    other = api.get("/api/v1/vulnerabilities/projects?key=CVE-2099-0008").json()
    assert [(w["path"], w["trees"], w["envs"]) for w in other] == [("team-ab/other", ["Dependency-Track (hors version livrée)"], [])]
    assert [p["tree"] for p in api.get("/api/v1/dt/cve/CVE-2099-0008").json()["places"]] == ["Dependency-Track (hors version livrée)"]
    api.who["v"] = Viewer(f"s-{uuid.uuid4().hex}", "root", admin=True)
    assert {b["name"] for b in api.get(f"/api/v1/dt/versions/{PROD}").json()["bricks"]} == {"team-a/app", "team-a/sub/lib", "mystery"}


def test_a_retired_version_counts_the_same_everywhere(dt_env, database_url, monkeypatch):
    """CMS 5.2.0 marked inactive in DT: its lapsed exception leaves the work items, the exceptions and the indicators alike.
    A brick marked inactive: the list of versions no longer counts its findings, as the version page does not show them."""
    monkeypatch.setitem(globals(), "PROJECTS", [p | {"active": False} if p["uuid"] == PROD else p for p in PROJECTS])
    monkeypatch.setitem(globals(), "PROJECTS", [p | {"active": False} if p["uuid"] == "b-app-13" else p for p in PROJECTS])   # 1.3 withdrawn
    asyncio.run(setup(database_url))
    api = dt_env
    api.who["v"] = Viewer(f"s-{uuid.uuid4().hex}", "root", admin=True)
    assert api.get("/api/v1/dt/work").json()["expired_exceptions"] == 0
    assert api.get("/api/v1/dt/exceptions").json()["exceptions"] == []
    assert api.get("/api/v1/indicators").json()["exceptions"] == {"active": 0, "expired": 0}
    # The list announces what the version page shows.
    listed = {t["uuid"]: t["open"] for t in api.get("/api/v1/dt/versions").json()}
    assert listed[TEST] == 0 and all(listed[u] == len(api.get(f"/api/v1/dt/versions/{u}").json()["findings"]) for u in listed)



def test_a_brick_in_several_delivered_versions(dt_env, database_url, monkeypatch):
    """team-a/app 1.2 delivered in CMS 5.2.0 and in Portail 1.0: one DT project, two delivered versions, its findings read once and
    counted once, shown in each version and on the CVE sheet once per version."""
    monkeypatch.setitem(CONTENTS, PORTAIL, ["b-app-11", "b-app-12"])
    assert asyncio.run(setup(database_url)) == {"deliveries": 3, "projects": 7, "read": 5}
    api = dt_env
    api.who["v"] = Viewer(f"s-{uuid.uuid4().hex}", "root", admin=True)
    for tree in (PROD, PORTAIL):
        assert "1.2" in {b["version"] for b in api.get(f"/api/v1/dt/versions/{tree}").json()["bricks"] if b["name"] == "team-a/app"}
    places = api.get("/api/v1/dt/cve/CVE-2099-0003").json()["places"]
    assert sorted(p["tree"] for p in places) == ["CMS 5.2.0", "Portail 1.0"]
    exc = api.get("/api/v1/dt/exceptions").json()["exceptions"]
    assert [(e["key"], e["tree"]) for e in exc] == [("CVE-2099-0003", "CMS 5.2.0, Portail 1.0")]
    assert api.get("/api/v1/dt/work").json()["expired_exceptions"] == 1
    assert api.get("/api/v1/indicators").json()["sbom"] == {"bricks": 5, "with_sbom": 4}
    where = api.get("/api/v1/vulnerabilities/projects?key=CVE-2021-44228").json()[0]
    assert sorted(where["trees"]) == ["CMS 5.2.0", "Portail 1.0"]


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
    assert ind["sbom"] == {"bricks": 5, "with_sbom": 4} and ind["exceptions"] == {"active": 0, "expired": 1}   # every delivered brick; lib has none

    # Alerts: each new critical (here the DT critical of « mystery » has no project) once, the stale NVD mirror once a day.
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
    assert len(sent) == 3   # second pass sends nothing again
    assert any("CVE-2099-7777" in s and "team-a/app" in s and "aucun référent" in s for s in sent)
    assert all(any(name in s and "plus à jour" in s for s in sent) for name in ("NVD", "OSV"))   # late, and never completed
    assert os.environ["PERISKOPE_DT_URL"] == "https://dt.test"


def test_checks_read_the_stored_trees_and_ledger(dt_env, database_url, tmp_path):
    """The checks without a source of their own judge what the collector loads for them: the project's bricks in the delivered versions and its ledger."""
    from fake_gitlab import context, good
    from periskope_checks import REGISTRY, run_all
    from periskope_collector.analysis import tracking
    from periskope_core.models import CheckStatus

    async def scenario():
        await setup(database_url)
        pool = await connect(database_url)
        app = await pool.fetchval("SELECT id FROM projects WHERE path = 'team-a/app'")
        loaded = await tracking(pool, "gl", app), await tracking(pool, "another-gitlab", app)
        await pool.close()
        ids = [i for i in REGISTRY if i.startswith(("dt.", "ledger."))]
        return [{i: o.status for i, o in (await run_all(context(good() | {"tracking": t}, tmp_path), ids)).items()} for t in loaded]
    here, elsewhere = asyncio.run(scenario())
    # 1.1, 1.2 and 1.3 are delivered with their SBOM, by digest (DT cannot say whether they went through test); log4j is long past its deadline.
    assert here == {"dt.sca": CheckStatus.PASS, "dt.prod_component": CheckStatus.PASS, "dt.prod_artifact": CheckStatus.PASS,
                    "dt.prod_dependencies": CheckStatus.PASS, "dt.same_artifact": CheckStatus.UNKNOWN,
                    "ledger.sla": CheckStatus.FAIL, "ledger.fix_rate": CheckStatus.PASS}
    # Dependency-Track follows no project of that instance: not measured, never a failure.
    assert {elsewhere[i] for i in ("dt.prod_component", "dt.prod_artifact", "dt.prod_dependencies", "dt.same_artifact")} == {CheckStatus.UNKNOWN}
