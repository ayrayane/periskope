"""Scope filter, run lifecycle and API rules against a real PostgreSQL (and Valkey for the API)."""
import os
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "packages/checks/tests"))

from fake_gitlab import context, good
from periskope_core.settings import Instance
from periskope_db import Viewer, connect, runs
from periskope_db.bootstrap import bootstrap

INSTANCE = Instance(slug="gl", name="GitLab", url="https://gitlab.test", tracked_namespaces=["team-a"])
PROJECTS = [(7, "team-a/app", "team-a"), (8, "team-a/sub/lib", "team-a/sub"), (9, "team-ab/other", "team-ab"), (10, "teamxa/x", "teamxa")]


@pytest.fixture
async def db(database_url):
    pool = await connect(database_url)
    await bootstrap(pool, {"gl": INSTANCE})
    # CASCADE also empties scope_decisions (it references projects): bootstrap again for the default decisions.
    await pool.execute("TRUNCATE projects, runs, project_state, fingerprints, run_evidence CASCADE")
    await bootstrap(pool, {"gl": INSTANCE})
    await pool.executemany(
        "INSERT INTO projects (instance, gitlab_id, path, namespace_path, namespace_kind, default_branch, sonar_key)"
        " VALUES ('gl', $1, $2, $3, 'group', 'main', replace($2, '/', '_'))",
        PROJECTS)
    yield pool
    await pool.close()


async def visible(db, viewer):
    where, params = viewer.where("p", 1)
    return sorted(r["path"] for r in await db.fetch(f"SELECT path FROM projects p WHERE {where}", *params))


async def test_scope_filter(db):
    member = Viewer("s1", "alice", namespaces=frozenset({("gl", "team-a")}))
    assert await visible(db, member) == ["team-a/app", "team-a/sub/lib"]
    # A namespace is a path prefix up to a slash, never a string prefix or a LIKE pattern.
    assert await visible(db, Viewer("s2", "bob", namespaces=frozenset({("gl", "team_a")}))) == []
    assert await visible(db, Viewer("s3", "carol", projects=frozenset({("gl", 9)}))) == ["team-ab/other"]
    assert await visible(db, Viewer("s4", "dan", namespaces=frozenset({("other", "team-a")}))) == []
    assert await visible(db, Viewer("s5", "eve")) == []
    assert len(await visible(db, Viewer("s6", "root", admin=True))) == 4


async def test_run_lifecycle_and_reuse(db, tmp_path):
    from periskope_collector.analysis import analyse

    project_id = await db.fetchval("SELECT id FROM projects WHERE gitlab_id = 7")
    first = await runs.create(db, project_id, "main", "user", "alice")
    with pytest.raises(runs.AlreadyActive):
        await runs.create(db, project_id, "main", "user", "bob")
    ctx = context(good(), tmp_path)
    await analyse(db, ctx.gl, first, enterprise=True, sonar=ctx.sonar)
    state = await db.fetchrow("SELECT score, coverage, last_run_id, last_error FROM project_state WHERE project_id = $1", project_id)
    assert state["last_run_id"] == first and state["score"] == 100 and state["last_error"] is None
    assert await db.fetchval("SELECT count(*) FROM run_evidence WHERE run_id = $1", first) == 1

    second = await runs.create(db, project_id, "main", "nightly", None)
    calls = ctx.gl.calls
    await analyse(db, ctx.gl, second, enterprise=True, sonar=ctx.sonar)
    row = await db.fetchrow("SELECT status, reused_from, gitlab_calls, results FROM runs WHERE id = $1", second)
    # The same SonarQube analysis: its checks are taken over too.
    assert row["results"]["sonar.metrics"].get("reused") and row["results"]["repo.gitignore"].get("reused")
    # Same commit and settings: commit checks reused, no copy of the evidence, fewer calls.
    assert row["status"] == "succeeded" and row["reused_from"] == first
    assert await db.fetchval("SELECT count(*) FROM run_evidence WHERE run_id = $1", second) == 0
    assert row["gitlab_calls"] == ctx.gl.calls - calls <= 3

    # Seen on the lab: a fixed check must not keep its stale result because the commit did not move.
    from periskope_collector import analysis
    analysis.ENGINE_VERSION = "another-engine"
    try:
        third = await runs.create(db, project_id, "main", "nightly", None)
        await analyse(db, ctx.gl, third, enterprise=True, sonar=ctx.sonar)
        results = await db.fetchval("SELECT results FROM runs WHERE id = $1", third)
        assert not results["repo.gitignore"].get("reused") and results["repo.gitignore"]["engine"] == "another-engine"
    finally:
        analysis.ENGINE_VERSION = analysis.engine_version()


async def test_failed_source_keeps_last_score(db, tmp_path):
    from periskope_collector.analysis import analyse

    project_id = await db.fetchval("SELECT id FROM projects WHERE gitlab_id = 7")
    data = good()
    run = await runs.create(db, project_id, "main", "user", "alice")
    await analyse(db, context(data, tmp_path).gl, run, enterprise=True)
    data["project"] = None
    broken = await runs.create(db, project_id, "main", "user", "alice")
    await analyse(db, context(data, tmp_path).gl, broken, enterprise=True)
    state = await db.fetchrow("SELECT score, last_error FROM project_state WHERE project_id = $1", project_id)
    assert state["score"] == 100 and "introuvable" in state["last_error"]


@pytest.fixture
def client(db, database_url, monkeypatch):
    from fastapi.testclient import TestClient
    from periskope_api import app as api

    monkeypatch.setenv("PERISKOPE_DATABASE_URL", database_url)
    monkeypatch.setenv("PERISKOPE_VALKEY_URL", os.environ.get("PERISKOPE_TEST_VALKEY_URL", "redis://localhost:56379"))
    for k in ("OIDC_ISSUER", "OIDC_AUDIENCE", "OIDC_CLIENT_ID"):
        monkeypatch.setenv(f"PERISKOPE_{k}", "https://kc.test/realms/x" if k == "OIDC_ISSUER" else "periskope")
    who = {"v": None}
    api.app.dependency_overrides[api.current] = lambda: who["v"]
    with TestClient(api.app) as c:
        c.who = who
        yield c
    api.app.dependency_overrides.clear()


def test_api_scope_and_launch_rules(client):
    sub = f"s-{uuid.uuid4().hex}"  # the hourly quota lives in Valkey, across test sessions
    client.who["v"] = Viewer(sub, "alice", namespaces=frozenset({("gl", "team-a")}))
    paths = [p["path"] for p in client.get("/api/v1/projects").json()["items"]]
    # A tampered cursor is a bad request, not a crash.
    assert all(client.get(f"/api/v1/projects?cursor={c}").status_code == 400 for c in ("xx", "NQ==", "W10="))
    summary = client.get("/api/v1/projects/summary").json()
    assert summary["total"] == len(paths) and isinstance(summary["dimensions"], dict)
    assert all(g["missing"] <= g["measured"] for g in summary["gaps"]) and len(summary["lowest"]) <= 3
    assert [i["slug"] for i in client.get("/api/v1/instances").json()] == ["gl"]
    client.who["v"] = Viewer(sub, "nobody")
    assert client.get("/api/v1/instances").json() == [] and client.get("/api/v1/groups").json() == []
    assert client.get("/api/v1/projects/summary").json()["total"] == 0
    client.who["v"] = Viewer(sub, "alice", namespaces=frozenset({("gl", "team-a")}))
    groups = client.get("/api/v1/groups").json()
    assert {(g["instance"], g["path"]) for g in groups} == {("gl", "team-a"), ("gl", "team-a/sub")}
    assert client.get("/api/v1/projects/summary?instance=gl&namespace=team-a/sub").json()["total"] == 1
    assert client.get("/api/v1/projects/summary?instance=gl&namespace=team-a").json()["total"] == 2
    assert paths == ["team-a/app", "team-a/sub/lib"]
    hidden = client.get("/api/v1/projects/gl/team-ab/other")
    assert hidden.status_code == 404 and hidden.headers["content-type"] == "application/problem+json"
    assert client.post("/api/v1/projects/gl/team-a/app/runs", json={}).status_code == 403

    client.who["v"] = Viewer(sub, "alice", namespaces=frozenset({("gl", "team-a")}), maintains=frozenset({("gl", "team-a")}))
    # Valkey outlives a test session: a fresh key, or a cached answer from a previous run comes back.
    key = uuid.uuid4().hex
    first = client.post("/api/v1/projects/gl/team-a/app/runs", json={}, headers={"Idempotency-Key": key})
    assert first.status_code == 202
    assert client.post("/api/v1/projects/gl/team-a/app/runs", json={}, headers={"Idempotency-Key": key}).json() == first.json()
    again = client.post("/api/v1/projects/gl/team-a/app/runs", json={})
    assert again.status_code == 409 and again.json()["id"] == first.json()["id"]
    from periskope_api import app as api

    async def branches(project, fresh=False):
        return [{"name": "main", "default": True, "protected": True, "committed_at": "2026-10-28T10:00:00Z"},
                {"name": "feat/login", "default": False, "protected": False, "committed_at": "2026-10-28T11:00:00Z"}]
    api.branches_of = branches
    assert [b["name"] for b in client.get("/api/v1/projects/gl/team-a/app/branches?q=log").json()] == ["feat/login"]
    unknown = client.post("/api/v1/projects/gl/team-a/app/runs", json={"branch": "feat/x"})
    assert unknown.status_code == 422 and "feat/x" in unknown.json()["detail"]
    assert client.post("/api/v1/projects/gl/team-a/app/runs", json={"branch": "feat/login"}).status_code == 202
    assert client.get(f"/api/v1/runs/{first.json()['id']}").json()["status"] == "queued"
    project = client.get("/api/v1/projects/gl/team-a/app").json()
    assert project["active_run"] == first.json()["id"] and project["can_launch"]


async def test_sync_projects_applies_exclusions(db, tmp_path):
    import httpx
    from periskope_clients.gitlab import GitLab
    from periskope_collector.sync import sync_projects

    def p(pid, path, kind="group", **kw):
        ns = path.rsplit("/", 1)[0]
        return {"id": pid, "path_with_namespace": path, "namespace": {"full_path": ns, "kind": kind}, "default_branch": "main",
                "archived": False, "empty_repo": False, "last_activity_at": "2026-10-27T10:00:00Z", **kw}

    listing = [p(7, "team-a/app"), p(8, "team-a/sub/lib"), p(11, "team-a/old", archived=True), p(12, "team-a/empty", default_branch=None),
               p(13, "team-a/sandbox/try")]
    gl = GitLab("https://gitlab.test", tmp_path / "t", transport=httpx.MockTransport(lambda r: httpx.Response(200, json=listing)))
    (tmp_path / "t").write_text("x")
    instance = INSTANCE.model_copy(update={"excluded_namespaces": ["team-a/sandbox"]})
    result = await sync_projects(db, gl, instance)
    rows = {r["path"]: (r["enabled"], r["excluded_reason"]) for r in await db.fetch("SELECT path, enabled, excluded_reason FROM projects")}
    assert rows["team-a/app"] == (True, None)
    assert rows["team-a/old"] == (False, "projet archivé")
    assert rows["team-a/empty"] == (False, "projet vide")
    assert rows["team-a/sandbox/try"] == (False, "namespace exclu")
    # Projects no longer listed are disabled, their history kept.
    assert rows["team-ab/other"] == (False, "supprimé ou sorti des groupes suivis")
    assert result["seen"] == 5

    # A listing cut short (page limit reached) retires none of the projects it did not reach.
    async def cut(*a, **kw):
        return [p(7, "team-a/app")], True
    gl.pages = cut
    assert (await sync_projects(db, gl, instance))["truncated"]
    assert await db.fetchval("SELECT enabled FROM projects WHERE path = 'team-a/sub/lib'")


def test_scope_api(client, db, tmp_path):
    import asyncio

    from periskope_collector.analysis import analyse

    async def analysed():
        pool = await connect(os.environ["PERISKOPE_DATABASE_URL"])
        project_id = await pool.fetchval("SELECT id FROM projects WHERE gitlab_id = 7")
        run = await runs.create(pool, project_id, "main", "user", "alice")
        ctx = context(good(), tmp_path)
        await analyse(pool, ctx.gl, run, enterprise=True, sonar=ctx.sonar)
        # An older, better analysis: the project now counts as declining over 30 days.
        await pool.execute("INSERT INTO runs (project_id, branch, trigger, status, score, created_at, referential_version)"
                           " VALUES ($1, 'main', 'nightly', 'succeeded', 100, now() - interval '40 days', '5.0.2')", project_id)
        await pool.close()
    asyncio.run(analysed())

    member = Viewer(f"s-{uuid.uuid4().hex}", "alice", namespaces=frozenset({("gl", "team-a")}), maintains=frozenset({("gl", "team-a")}))
    client.who["v"] = member
    item = {"target": "activity", "target_id": "Version control", "decision": "excluded", "reason": "dépôt miroir"}
    assert client.put("/api/v1/scope", json={"items": [item]}).status_code == 403  # organisation level: admins only
    assert client.put("/api/v1/scope", json={"instance": "gl", "project": "team-a/app", "items": [{**item, "reason": "x"}]}).status_code == 422
    assert client.put("/api/v1/scope", json={"instance": "gl", "project": "team-a/app", "items": [item]}).status_code == 200
    project = client.get("/api/v1/projects/gl/team-a/app").json()
    assert project["statuses"]["Version control"]["status"] == "out_of_scope"
    rows = {(r["target"], r["target_id"]): r for r in client.get("/api/v1/scope?instance=gl&project=team-a/app").json()}
    assert rows[("activity", "Version control")]["level"] == "projet" and not rows[("activity", "Version control")]["inherited"]
    # The Scorecard checks come from the organisation's default decision.
    assert rows[("check", "scorecard.code_review")]["inherited"] and rows[("check", "scorecard.code_review")]["decision"] == "excluded"
    assert client.delete("/api/v1/scope/Version control?target=activity&instance=gl&project=team-a/app").status_code == 204
    assert client.get("/api/v1/projects/gl/team-a/app").json()["statuses"]["Version control"]["status"] == "implemented"
    summary = client.get("/api/v1/projects/summary").json()
    assert "Version control" not in [g["activity"] for g in summary["gaps"]]
    assert [r["path"] for r in summary["lowest"]] and all(g["level"] <= 3 for g in summary["gaps"])

    heat = client.get("/api/v1/groups/heatmap?instance=gl&namespace=team-a").json()
    assert heat["dimensions"] and {r["key"] for r in heat["rows"]} <= {"", "sub"} and heat["rows"][0]["cells"]
    assert [r["key"] for r in client.get("/api/v1/groups/heatmap").json()["rows"]] == ["gl"]
    async def dropped():
        pool = await connect(os.environ["PERISKOPE_DATABASE_URL"])
        await pool.execute("UPDATE project_state SET score = 60 WHERE project_id = (SELECT id FROM projects WHERE gitlab_id = 7)")
        await pool.close()
    asyncio.run(dropped())
    trend = client.get("/api/v1/projects/trend?instance=gl").json()
    assert [d["path"] for d in trend["declining"]] == ["team-a/app"] and trend["declining"][0]["before"] == 100
    assert client.get("/api/v1/projects/trend?instance=gl&days=60").json()["declining"] == []
    flat = client.get("/api/v1/projects/export.csv?instance=gl").text.lstrip("\ufeff").splitlines()
    assert flat[0].startswith("instance;groupe;projet") and {line.split(";")[2] for line in flat[1:]} == {"team-a/app", "team-a/sub/lib"}
    detail = client.get("/api/v1/projects/export.csv?instance=gl&detail=true")
    assert "attachment" in detail.headers["content-disposition"] and "Version control" in detail.text
    client.who["v"] = Viewer(f"s-{uuid.uuid4().hex}", "nobody")
    assert client.get("/api/v1/projects/export.csv").text.lstrip("\ufeff").count("\n") == 1  # header only
    assert client.get("/api/v1/groups/heatmap").json()["rows"] == [] and client.get("/api/v1/projects/trend").json()["declining"] == []


async def test_dormant_projects_are_spaced_when_the_instance_asks(db):
    from datetime import UTC, datetime, timedelta

    project_id = await db.fetchval("SELECT id FROM projects WHERE gitlab_id = 7")
    async with db.acquire() as conn:
        assert await runs.next_due(conn, project_id) - datetime.now(UTC) < timedelta(days=1)
        await conn.execute("UPDATE gitlab_instances SET space_dormant = true")
        await conn.execute("UPDATE projects SET last_activity_at = now() - interval '20 days' WHERE id = $1", project_id)
        assert timedelta(days=6) < await runs.next_due(conn, project_id) - datetime.now(UTC) < timedelta(days=7)
        await conn.execute("UPDATE projects SET last_activity_at = now() - interval '1 year' WHERE id = $1", project_id)
        assert timedelta(days=29) < await runs.next_due(conn, project_id) - datetime.now(UTC) < timedelta(days=30)
        await conn.execute("UPDATE gitlab_instances SET space_dormant = false")


def test_admin_routes(client):
    client.who["v"] = Viewer(f"s-{uuid.uuid4().hex}", "alice", namespaces=frozenset({("gl", "team-a")}))
    assert client.get("/api/v1/admin/overview").status_code == 404  # not even told the area exists
    client.who["v"] = Viewer(f"s-{uuid.uuid4().hex}", "root", admin=True)
    overview = client.get("/api/v1/admin/overview").json()
    assert overview["instances"][0]["slug"] == "gl" and overview["instances"][0]["tracked"] == 4
    assert client.put("/api/v1/admin/settings", json={"catch_up_at": "25:00"}).status_code == 422
    assert client.put("/api/v1/admin/settings", json={"catch_up_at": "02:15", "on_demand_per_hour": 5}).json()["catch_up_at"] == "02:15"
    assert client.get("/api/v1/admin/settings").json()["changed"]["catch_up_at"]["updated_by"] == "root"
    assert client.get("/api/v1/admin/audit?action=settings").json()["items"][0]["after"] == {"catch_up_at": "02:15", "on_demand_per_hour": 5}
    client.put("/api/v1/admin/settings", json={"catch_up_at": "01:00", "on_demand_per_hour": 10})


def test_score_drop_alert_is_posted_once(database_url, tmp_path, monkeypatch):
    import asyncio

    import httpx
    import respx
    from periskope_scheduler import app as scheduler

    (tmp_path / "periskope-alerts").mkdir()
    (tmp_path / "periskope-alerts" / "url").write_text("https://chat.example.org/hooks/abc\n")
    monkeypatch.setenv("PERISKOPE_SECRETS_DIR", str(tmp_path))
    monkeypatch.setenv("PERISKOPE_PUBLIC_URL", "https://periskope.example.org")

    class Keys:
        def __init__(self):
            self.seen = set()

        async def set(self, key, value, nx=False, ex=None):
            if nx and key in self.seen:
                return None
            self.seen.add(key)
            return True

        async def delete(self, key):
            self.seen.discard(key)

    async def scenario():
        pool = await connect(database_url)
        await bootstrap(pool, {"gl": INSTANCE})
        pid = await pool.fetchval("INSERT INTO projects (instance, gitlab_id, path, namespace_path, namespace_kind, default_branch)"
                                  " VALUES ('gl', 9901, 'team-z/api', 'team-z', 'group', 'main') RETURNING id")
        for score, ago in ((90, "2 days"), (70, "1 hour")):
            await pool.execute("INSERT INTO runs (project_id, branch, trigger, status, score, created_at, finished_at, referential_version)"
                               f" VALUES ($1, 'main', 'nightly', 'succeeded', $2, now() - interval '{ago}', now() - interval '{ago}', '5.0.2')", pid, score)
        scheduler.state.update(db=pool, arq=Keys())
        with respx.mock:
            route = respx.post("https://chat.example.org/hooks/abc").mock(return_value=httpx.Response(200))
            await scheduler.alerts()
            await scheduler.alerts()  # already sent: not posted again
        await pool.close()
        return route

    route = asyncio.run(scenario())
    assert route.call_count == 1
    body = route.calls[0].request.content.decode()
    assert "team-z/api" in body and "90" in body and "70" in body and "https://periskope.example.org/p/gl/team-z/api" in body


def test_stuck_run_no_longer_blocks_its_project(database_url):
    import asyncio

    from periskope_db import runs
    from periskope_scheduler import app as scheduler

    class Queue:
        async def enqueue_job(self, *a, **kw):
            return None

    async def scenario():
        pool = await connect(database_url)
        await bootstrap(pool, {"gl": INSTANCE})
        pid = await pool.fetchval("INSERT INTO projects (instance, gitlab_id, path, namespace_path, namespace_kind, default_branch)"
                                  " VALUES ('gl', 9902, 'team-z/stuck', 'team-z', 'group', 'main') RETURNING id")
        # Its collector died three hours ago, mid-run.
        await pool.execute("INSERT INTO runs (project_id, branch, trigger, status, created_at, started_at, referential_version)"
                           " VALUES ($1, 'main', 'nightly', 'running', now() - interval '3 hours', now() - interval '3 hours', '5.0.2')", pid)
        scheduler.state.update(db=pool, arq=Queue())
        await scheduler.catch_up()
        run_id = await runs.create(pool, pid, "main", "user", "alice")  # would raise AlreadyActive before
        await pool.close()
        return run_id

    assert asyncio.run(scenario())


def test_scheduler_metrics(database_url):
    import asyncio

    from periskope_scheduler import app as scheduler

    class Redis:
        async def zcard(self, key):
            return 3 if key == "collect:gl" else 0

        async def get(self, key):
            return b"1700000000" if key == "webhook:last:gl" else None

    async def scrape():
        pool = await connect(database_url)
        await bootstrap(pool, {"gl": INSTANCE})
        scheduler.state.update(db=pool, arq=Redis(), instances={"gl": INSTANCE})
        text = await scheduler.metrics()
        await pool.close()
        return text

    text = asyncio.run(scrape())
    assert 'periskope_queue_depth{instance="gl"} 3' in text
    assert 'periskope_last_webhook_age_seconds{instance="gl"}' in text
    for name in ("periskope_failed_ratio_last_hour", "periskope_reused_ratio_last_day", "periskope_runs_last_hour", "periskope_overdue_projects"):
        assert f"# TYPE {name} gauge" in text


def test_other_team_reaches_nothing(client, db, tmp_path):
    """v1 audit: every route, not only the list, must hide a sibling team's project (team-ab vs team-a) behind a 404."""
    import asyncio

    from periskope_collector.analysis import analyse

    async def analysed(gitlab_id):
        pool = await connect(os.environ["PERISKOPE_DATABASE_URL"])
        project_id = await pool.fetchval("SELECT id FROM projects WHERE gitlab_id = $1", gitlab_id)
        run = await runs.create(pool, project_id, "main", "user", "x")
        ctx = context(good(), tmp_path)
        await analyse(pool, ctx.gl, run, enterprise=True, sonar=ctx.sonar)
        await pool.close()
        return run
    theirs, mine = asyncio.run(analysed(9)), asyncio.run(analysed(7))   # team-ab/other, team-a/app

    client.who["v"] = Viewer(f"s-{uuid.uuid4().hex}", "alice", namespaces=frozenset({("gl", "team-a")}), maintains=frozenset({("gl", "team-a")}))
    for url in (f"/api/v1/runs/{theirs}", f"/api/v1/runs/{theirs}/evidence", f"/api/v1/runs/{theirs}/diff",
                f"/api/v1/runs/{mine}/diff?against={theirs}", "/api/v1/projects/gl/team-ab/other/roadmap",
                "/api/v1/projects/gl/team-ab/other/runs", "/api/v1/projects/gl/team-ab/other/branches",
                "/api/v1/scope?instance=gl&project=team-ab/other"):
        assert client.get(url).status_code == 404, url
    assert client.patch("/api/v1/projects/gl/team-ab/other", json={"target_level": 1}).status_code == 404
    # Cancelling is for admins: the same 403 for any id, so it reveals nothing about another team's runs.
    assert client.delete(f"/api/v1/runs/{theirs}").status_code == client.delete("/api/v1/runs/999999").status_code == 403
    item = {"target": "check", "target_id": "repo.gitignore", "decision": "excluded", "reason": "test de cloisonnement"}
    assert client.put("/api/v1/scope", json={"instance": "gl", "project": "team-ab/other", "items": [item]}).status_code == 404

    # The aggregates, seen from the sibling team: only its own project.
    client.who["v"] = Viewer(f"s-{uuid.uuid4().hex}", "bob", namespaces=frozenset({("gl", "team-ab")}))
    rows = client.get("/api/v1/projects/export.csv?detail=true").text
    assert "team-ab/other" in rows and "team-a/app" not in rows
    assert [r["key"] for r in client.get("/api/v1/groups/heatmap?instance=gl").json()["rows"]] == ["team-ab"]
    summary = client.get("/api/v1/projects/summary").json()
    assert summary["total"] == 1
    # Open vulnerabilities add up over the viewer's scope only, and name only their projects.
    assert summary["vulns"]["total"] == 4 and summary["vulns"]["projects"] == 1
    assert [e["path"] for e in summary["vulns"]["exposed"]] == ["team-ab/other"]
    vulns = client.get("/api/v1/vulnerabilities").json()
    assert vulns["measured"] == 1 and [(v["key"], v["severity"], v["projects"]) for v in vulns["items"]] == [("CVE-2021-44228", "critical", 1), ("Weak hash", "low", 1)]
    assert [v["key"] for v in client.get("/api/v1/vulnerabilities?q=log4").json()["items"]] == ["CVE-2021-44228"]
    assert [r["path"] for r in client.get("/api/v1/vulnerabilities/projects?key=CVE-2021-44228").json()] == ["team-ab/other"]
    client.who["v"] = Viewer(f"s-{uuid.uuid4().hex}", "root", admin=True)
    assert client.get("/api/v1/projects/summary").json()["vulns"]["critical"] == 2
    assert [r["path"] for r in client.get("/api/v1/vulnerabilities/projects?key=CVE-2021-44228").json()] == ["team-a/app", "team-ab/other"]
    assert client.get("/api/v1/vulnerabilities?instance=gl&namespace=teamxa").json() == {"measured": 0, "items": []}
    assert client.get("/api/v1/projects/summary?instance=gl&namespace=teamxa").json()["vulns"] is None  # never measured: unknown, not 0
    client.who["v"] = Viewer(f"s-{uuid.uuid4().hex}", "bob", namespaces=frozenset({("gl", "team-ab")}))

    # A project no longer tracked stays out of reach, its analyses included.
    async def disable():
        pool = await connect(os.environ["PERISKOPE_DATABASE_URL"])
        await pool.execute("UPDATE projects SET enabled = false WHERE gitlab_id = 7")
        await pool.close()
    asyncio.run(disable())
    client.who["v"] = Viewer(f"s-{uuid.uuid4().hex}", "alice", namespaces=frozenset({("gl", "team-a")}))
    assert client.get(f"/api/v1/runs/{mine}").status_code == 404


def test_small_leaks_closed(client, db):
    import asyncio
    assert client.get("/api/v1/health").json() == {"status": "ok"}
    client.who["v"] = Viewer(f"s-{uuid.uuid4().hex}", "alice", namespaces=frozenset({("gl", "team-a")}))
    assert client.get("/api/v1/scope?instance=gl").status_code == 200
    assert client.get("/api/v1/scope?instance=elsewhere").status_code == 404

    async def drift():
        pool = await connect(os.environ["PERISKOPE_DATABASE_URL"])
        pid = await pool.fetchval("SELECT id FROM projects WHERE gitlab_id = 7")
        await pool.execute("INSERT INTO project_state (project_id, score, statuses) VALUES ($1, 40, $2)"
                           " ON CONFLICT (project_id) DO UPDATE SET statuses = $2",
                           pid, {"Version control": {"status": "implemented"}, "Pratique retirée du référentiel": {"status": "partial"}})
        await pool.close()
    asyncio.run(drift())
    for detail in ("false", "true"):
        text = client.get(f"/api/v1/projects/export.csv?detail={detail}").text
        assert "team-a/app" in text and "retirée" not in text


def test_empty_webhook_secret_accepts_nothing(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from periskope_scheduler import app as scheduler

    (tmp_path / "gitlab-webhook-gl").mkdir()
    (tmp_path / "gitlab-webhook-gl" / "token").write_text("")
    monkeypatch.setenv("PERISKOPE_SECRETS_DIR", str(tmp_path))
    scheduler.state["instances"] = {"gl": INSTANCE}
    hook = TestClient(scheduler.app)  # no lifespan: the check happens before any database or queue access
    assert hook.post("/hooks/gitlab/gl", json={"object_kind": "push"}).status_code == 401
    assert hook.post("/hooks/gitlab/gl", json={"object_kind": "push"}, headers={"X-Gitlab-Token": ""}).status_code == 401
