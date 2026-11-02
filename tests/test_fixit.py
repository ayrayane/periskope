"""« Corriger dans GitLab »: the person's own GitLab login, Maintainers only, a preview before anything changes, an audit line."""
import asyncio
import json
import os
import sys
import uuid
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx
from cryptography.fernet import Fernet
from periskope_db import Viewer, connect

sys.path.insert(0, str(Path(__file__).parent))  # importlib mode: the shared fixtures live in test_integration
from test_integration import client, db  # noqa: F401

GITLAB = "https://gitlab.test"


@pytest.fixture
def fixit(tmp_path, monkeypatch):
    registry = tmp_path / "instances.json"
    registry.write_text(json.dumps([{"slug": "gl", "name": "GitLab", "url": GITLAB, "tracked_namespaces": ["team-a"], "fixes": True, "enterprise": False}]))
    for name, values in {"gitlab-oauth-gl": {"client_id": "app-id", "client_secret": "app-secret"}, "periskope-fixit": {"key": Fernet.generate_key().decode()}}.items():
        (tmp_path / name).mkdir()
        for k, v in values.items():
            (tmp_path / name / k).write_text(v)
    monkeypatch.setenv("PERISKOPE_INSTANCES_FILE", str(registry))
    monkeypatch.setenv("PERISKOPE_SECRETS_DIR", str(tmp_path))
    monkeypatch.setenv("PERISKOPE_PUBLIC_URL", "https://periskope.test")

    async def failing_run():
        pool = await connect(os.environ["PERISKOPE_DATABASE_URL"])
        pid = await pool.fetchval("SELECT id FROM projects WHERE gitlab_id = 7")
        run = await pool.fetchval(
            "INSERT INTO runs (project_id, branch, trigger, status, score, referential_version, results) VALUES ($1, 'main', 'nightly', 'succeeded', 50, '5.0.2', $2) RETURNING id",
            pid, {"gitlab.pipeline_must_succeed": {"status": "fail", "message": "merge possible avec un pipeline en échec"},
                  "gitlab.approvals_required": {"status": "fail", "message": "x"}, "repo.gitignore": {"status": "pass", "message": "ok"}})
        await pool.execute("INSERT INTO project_state (project_id, score, last_run_id) VALUES ($1, 50, $2) ON CONFLICT (project_id) DO UPDATE SET last_run_id = $2", pid, run)
        await pool.close()
    asyncio.run(failing_run())


def maintainer():
    return Viewer(f"s-{uuid.uuid4().hex}", "alice", namespaces=frozenset({("gl", "team-a")}), maintains=frozenset({("gl", "team-a")}))


def connect_gitlab(api):
    started = api.post("/api/v1/fixit/gl/login", json={"return_to": "/p/gl/team-a/app?vue=preuves"}).json()["url"]
    q = parse_qs(urlparse(started).query)
    assert started.startswith(f"{GITLAB}/oauth/authorize") and q["client_id"] == ["app-id"] and q["code_challenge_method"] == ["S256"]
    with respx.mock(assert_all_called=False) as gl:
        token = gl.post(f"{GITLAB}/oauth/token").mock(return_value=httpx.Response(200, json={"access_token": "user-token", "expires_in": 7200}))
        back = api.get(f"/api/v1/fixit/gl/callback?state={q['state'][0]}&code=abc", follow_redirects=False)
    assert back.status_code == 302 and back.headers["location"] == "/p/gl/team-a/app?vue=preuves"
    sent = parse_qs(token.calls[0].request.content.decode())
    assert sent["code_verifier"][0] and sent["client_secret"] == ["app-secret"]
    # The single-use state cannot be replayed.
    assert api.get(f"/api/v1/fixit/gl/callback?state={q['state'][0]}&code=abc", follow_redirects=False).status_code == 400


def test_fix_flow(client, db, fixit):  # noqa: F811
    client.who["v"] = maintainer()
    listed = client.get("/api/v1/projects/gl/team-a/app/fixes").json()
    # CE: the Premium approval fix is not offered; passing checks are not either.
    assert listed["enabled"] and listed["can_fix"] and not listed["connected"]
    assert [i["check"] for i in listed["items"]] == ["gitlab.pipeline_must_succeed"]
    assert client.post("/api/v1/projects/gl/team-a/app/fixes/gitlab.pipeline_must_succeed/preview").status_code == 428

    connect_gitlab(client)
    assert client.get("/api/v1/fixit/gl/status").json() == {"connected": True}
    with respx.mock(assert_all_called=False) as gl:
        gl.get(f"{GITLAB}/api/v4/user").mock(return_value=httpx.Response(200, json={"username": "alice"}))
        gl.get(f"{GITLAB}/api/v4/projects/7").mock(return_value=httpx.Response(200, json={"only_allow_merge_if_pipeline_succeeds": False}))
        put = gl.put(f"{GITLAB}/api/v4/projects/7").mock(return_value=httpx.Response(200, json={}))
        preview = client.post("/api/v1/projects/gl/team-a/app/fixes/gitlab.pipeline_must_succeed/preview").json()
        assert preview["changes"] == [{"what": "Merge avec un pipeline en échec", "before": "possible", "after": "bloqué"}]
        assert not put.called  # a preview changes nothing
        done = client.post("/api/v1/projects/gl/team-a/app/fixes/gitlab.pipeline_must_succeed").json()
    assert put.called and put.calls[0].request.headers["authorization"] == "Bearer user-token"
    assert json.loads(put.calls[0].request.content) == {"only_allow_merge_if_pipeline_succeeds": True} and done["run"]

    async def audited():
        pool = await connect(os.environ["PERISKOPE_DATABASE_URL"])
        row = await pool.fetchrow("SELECT actor, after FROM audit_log WHERE action = 'fix.apply' ORDER BY at DESC LIMIT 1")
        await pool.close()
        return row
    row = asyncio.run(audited())
    assert row["actor"] == "alice" and row["after"]["check"] == "gitlab.pipeline_must_succeed"


def test_who_may_fix(client, db, fixit):  # noqa: F811
    client.who["v"] = Viewer(f"s-{uuid.uuid4().hex}", "bob", namespaces=frozenset({("gl", "team-a")}))  # member, not Maintainer
    assert not client.get("/api/v1/projects/gl/team-a/app/fixes").json()["can_fix"]
    assert client.post("/api/v1/projects/gl/team-a/app/fixes/gitlab.pipeline_must_succeed").status_code == 403
    client.who["v"] = Viewer(f"s-{uuid.uuid4().hex}", "eve", namespaces=frozenset({("gl", "team-ab")}), maintains=frozenset({("gl", "team-ab")}))
    assert client.post("/api/v1/projects/gl/team-a/app/fixes/gitlab.pipeline_must_succeed").status_code == 404
    client.who["v"] = maintainer()
    # Never an open redirect after the GitLab login.
    started = client.post("/api/v1/fixit/gl/login", json={"return_to": "//evil.test/x"}).json()["url"]
    nonce = parse_qs(urlparse(started).query)["state"][0]
    with respx.mock:
        respx.post(f"{GITLAB}/oauth/token").mock(return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 7200}))
        assert client.get(f"/api/v1/fixit/gl/callback?state={nonce}&code=x", follow_redirects=False).headers["location"] == "/"


def test_disabled_instance_offers_nothing(client, db, tmp_path, monkeypatch):  # noqa: F811
    registry = tmp_path / "instances.json"
    registry.write_text(json.dumps([{"slug": "gl", "name": "GitLab", "url": GITLAB, "tracked_namespaces": ["team-a"]}]))
    monkeypatch.setenv("PERISKOPE_INSTANCES_FILE", str(registry))
    monkeypatch.setenv("PERISKOPE_SECRETS_DIR", str(tmp_path))
    client.who["v"] = maintainer()
    assert client.get("/api/v1/projects/gl/team-a/app/fixes").json() == {"enabled": False, "can_fix": False, "connected": False, "items": []}
    assert client.post("/api/v1/fixit/gl/login", json={}).status_code == 404
