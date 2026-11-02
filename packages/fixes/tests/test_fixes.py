"""Each fix sends exactly the GitLab calls it announces, refuses to overwrite what exists, and never leaves a branch unprotected."""
import json

import httpx
import pytest
from periskope_core.catalog import CHECKS
from periskope_fixes import FIXES, LOCAL_CI, FixError, Target, UserGitLab, with_include


class FakeGitLab:
    """Answers from a dict of (METHOD, path) -> response; records every call."""

    def __init__(self, routes, files=None):
        self.routes, self.files, self.calls = routes, files or {}, []

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/api/v4")
        body = json.loads(request.content) if request.content else None
        self.calls.append((request.method, path, body))
        if "/repository/files/" in path and path.endswith("/raw"):
            name = httpx.URL(path).path.split("/repository/files/")[1].removesuffix("/raw").replace("%2F", "/")
            return httpx.Response(200, text=self.files[name]) if name in self.files else httpx.Response(404)
        answer = self.routes.get((request.method, path), httpx.Response(200, json={}))
        return answer(request) if callable(answer) else answer

    def client(self):
        return UserGitLab("https://gitlab.test", "user-token", transport=httpx.MockTransport(self.handle))

    def sent(self, method):
        return [(p, b) for m, p, b in self.calls if m == method]


T = Target(project_id=7, path="team/app", default_branch="main", username="alice", link="https://periskope.test/p/gl/team/app", enterprise=False)
PB = "/projects/7/protected_branches/main"
PROTECTED = {"name": "main", "push_access_levels": [{"id": 1, "access_level": 40}], "merge_access_levels": [{"id": 2, "access_level": 40}], "allow_force_push": True}


def test_every_fix_answers_a_known_check():
    assert set(FIXES) <= {c.id for c in CHECKS}
    assert {f.kind for f in FIXES.values()} == {"setting", "mr"}


async def test_close_pushes_on_ce_recreates_the_protection():
    gl = FakeGitLab({("GET", PB): httpx.Response(200, json=PROTECTED)})
    preview = await FIXES["gitlab.protected_branch_no_push"].preview(gl.client(), T)
    assert preview["changes"][0]["before"] == "push direct : Maintainers"
    await FIXES["gitlab.protected_branch_no_push"].apply(gl.client(), T)
    assert gl.sent("DELETE") == [(PB, None)]
    assert gl.sent("POST") == [("/projects/7/protected_branches", {"name": "main", "push_access_level": 0, "merge_access_level": 40, "allow_force_push": False})]


async def test_close_pushes_on_enterprise_edits_in_place():
    gl = FakeGitLab({("GET", PB): httpx.Response(200, json=PROTECTED)})
    await FIXES["gitlab.protected_branch_no_push"].apply(gl.client(), Target(**{**T.__dict__, "enterprise": True}))
    assert not gl.sent("DELETE")
    assert gl.sent("PATCH") == [(PB, {"allow_force_push": False, "allowed_to_push": [{"id": 1, "_destroy": True}, {"access_level": 0}]})]


async def test_a_failed_recreation_restores_the_previous_protection():
    attempts = []

    def protect(request):
        attempts.append(json.loads(request.content))
        return httpx.Response(400, json={"message": "refused"}) if len(attempts) == 1 else httpx.Response(201, json={})
    gl = FakeGitLab({("GET", PB): httpx.Response(200, json=PROTECTED), ("POST", "/projects/7/protected_branches"): protect})
    with pytest.raises(FixError):
        await FIXES["gitlab.protected_branch_no_push"].apply(gl.client(), T)
    assert attempts[1] == {"name": "main", "push_access_level": 40, "merge_access_level": 40, "allow_force_push": True}


async def test_gitlab_refusal_is_explained():
    gl = FakeGitLab({("PUT", "/projects/7"): httpx.Response(403, json={"message": "403 Forbidden"})})
    with pytest.raises(FixError, match="Maintainer"):
        await FIXES["gitlab.pipeline_must_succeed"].apply(gl.client(), T)


async def test_mask_reports_what_gitlab_refused():
    variables = [{"key": "API_TOKEN", "masked": False, "variable_type": "env_var"}, {"key": "DB_PASSWORD", "masked": False, "variable_type": "env_var"},
                 {"key": "REGION", "masked": False, "variable_type": "env_var"}, {"key": "SECRET_FILE", "masked": False, "variable_type": "file"}]
    gl = FakeGitLab({("GET", "/projects/7/variables"): httpx.Response(200, json=variables),
                     ("PUT", "/projects/7/variables/DB_PASSWORD"): httpx.Response(400, json={"message": "value invalid"})})
    done = await FIXES["gitlab.masked_secrets"].apply(gl.client(), T)
    assert [p for p, _ in gl.sent("PUT")] == ["/projects/7/variables/API_TOKEN", "/projects/7/variables/DB_PASSWORD"]
    assert "API_TOKEN" in done["done"] and "refuse de masquer DB_PASSWORD" in done["done"]


def test_ci_include_editing():
    assert with_include("stages: [test]\n").startswith(f"include:\n  - local: {LOCAL_CI}\n")
    assert with_include("include:\n  - template: Jobs/SAST.gitlab-ci.yml\nstages: [test]\n") == (
        f"include:\n  - local: {LOCAL_CI}\n  - template: Jobs/SAST.gitlab-ci.yml\nstages: [test]\n")
    assert with_include("include: 'ci/base.yml'\n") is None


async def test_ci_fix_opens_a_merge_request_and_keeps_earlier_jobs():
    files = {".gitlab-ci.yml": "stages: [test]\n", LOCAL_CI: "include:\n  # periskope: gitlab.sast\n  - template: Jobs/SAST.gitlab-ci.yml\n"}
    gl = FakeGitLab({("GET", "/projects/7/merge_requests"): httpx.Response(200, json=[]),
                     ("GET", "/projects/7/repository/branches/periskope%2Fgitlab-secret_detection"): httpx.Response(404),
                     ("POST", "/projects/7/merge_requests"): httpx.Response(201, json={"web_url": "https://gitlab.test/team/app/-/merge_requests/3"})}, files)
    done = await FIXES["gitlab.secret_detection"].apply(gl.client(), T)
    assert done["url"].endswith("/merge_requests/3")
    commit = next(b for p, b in gl.sent("POST") if p == "/projects/7/repository/commits")
    assert commit["branch"] == "periskope/gitlab-secret_detection" and commit["start_branch"] == "main"
    local = next(a for a in commit["actions"] if a["file_path"] == LOCAL_CI)
    assert "Jobs/SAST.gitlab-ci.yml" in local["content"] and "Jobs/Secret-Detection.gitlab-ci.yml" in local["content"] and local["action"] == "update"
    assert next(a for a in commit["actions"] if a["file_path"] == ".gitlab-ci.yml")["content"].startswith("include:")
    assert not any(p.endswith("/repository/files") for p, _ in gl.sent("PUT"))  # nothing pushed to main


async def test_an_open_merge_request_is_returned_not_duplicated():
    gl = FakeGitLab({("GET", "/projects/7/merge_requests"): httpx.Response(200, json=[{"web_url": "https://gitlab.test/mr/1"}])})
    done = await FIXES["repo.gitignore"].apply(gl.client(), T)
    assert done["url"] == "https://gitlab.test/mr/1" and not gl.sent("POST")


async def test_existing_files_are_never_overwritten():
    gl = FakeGitLab({}, {"SECURITY.md": "# déjà là"})
    with pytest.raises(FixError) as e:
        await FIXES["repo.patch_policy"].preview(gl.client(), T)
    assert e.value.status == 409


async def test_codeowners_names_the_person_who_clicked():
    preview = await FIXES["repo.security_champion"].preview(FakeGitLab({}).client(), T)
    assert "@alice" in preview["files"][0]["content"] and "@referent-securite" not in preview["files"][0]["content"]


async def test_automerge_adds_a_rule_to_an_existing_renovate_config():
    gl = FakeGitLab({}, {"renovate.json": '{"extends": ["config:recommended"]}'})
    preview = await FIXES["gitlab.automerge"].preview(gl.client(), T)
    config = json.loads(preview["files"][0]["content"])
    assert config["extends"] == ["config:recommended"] and config["packageRules"][0]["automerge"] is True
