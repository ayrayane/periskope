"""Scope filter, run lifecycle and API rules against a real PostgreSQL (and Valkey for the API)."""
import os
import sys
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
    await pool.execute("TRUNCATE projects, runs, project_state, fingerprints, run_evidence CASCADE")
    await pool.executemany(
        "INSERT INTO projects (instance, gitlab_id, path, namespace_path, namespace_kind, default_branch) VALUES ('gl', $1, $2, $3, 'group', 'main')",
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
    await analyse(db, ctx.gl, first, enterprise=True)
    state = await db.fetchrow("SELECT score, coverage, last_run_id, last_error FROM project_state WHERE project_id = $1", project_id)
    assert state["last_run_id"] == first and state["score"] == 100 and state["last_error"] is None
    assert await db.fetchval("SELECT count(*) FROM run_evidence WHERE run_id = $1", first) == 1

    second = await runs.create(db, project_id, "main", "nightly", None)
    calls = ctx.gl.calls
    await analyse(db, ctx.gl, second, enterprise=True)
    row = await db.fetchrow("SELECT status, reused_from, gitlab_calls FROM runs WHERE id = $1", second)
    # Same commit and settings: commit checks reused, no copy of the evidence, fewer calls.
    assert row["status"] == "succeeded" and row["reused_from"] == first
    assert await db.fetchval("SELECT count(*) FROM run_evidence WHERE run_id = $1", second) == 0
    assert row["gitlab_calls"] == ctx.gl.calls - calls <= 3


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
    client.who["v"] = Viewer("s1", "alice", namespaces=frozenset({("gl", "team-a")}))
    paths = [p["path"] for p in client.get("/api/v1/projects").json()["items"]]
    assert paths == ["team-a/app", "team-a/sub/lib"]
    hidden = client.get("/api/v1/projects/gl/team-ab/other")
    assert hidden.status_code == 404 and hidden.headers["content-type"] == "application/problem+json"
    assert client.post("/api/v1/projects/gl/team-a/app/runs", json={}).status_code == 403

    client.who["v"] = Viewer("s1", "alice", namespaces=frozenset({("gl", "team-a")}), maintains=frozenset({("gl", "team-a")}))
    first = client.post("/api/v1/projects/gl/team-a/app/runs", json={}, headers={"Idempotency-Key": "k1"})
    assert first.status_code == 202
    assert client.post("/api/v1/projects/gl/team-a/app/runs", json={}, headers={"Idempotency-Key": "k1"}).json() == first.json()
    again = client.post("/api/v1/projects/gl/team-a/app/runs", json={})
    assert again.status_code == 409 and again.json()["id"] == first.json()["id"]
    assert client.post("/api/v1/projects/gl/team-a/app/runs", json={"branch": "feat/x"}).status_code == 422
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
