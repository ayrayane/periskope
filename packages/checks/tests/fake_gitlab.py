"""A GitLab answering from a dict of recorded responses, and a project where every check passes."""
from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from periskope_checks.context import Context
from periskope_clients.gitlab import GitLab

NOW = datetime(2026, 10, 28, 12, tzinfo=UTC)


def good() -> dict[str, Any]:
    """Responses for a project that passes all 40 checks (shapes as GitLab returns them)."""
    mr = lambda branch, author, bot=False, approver="bob", auto=True: {
        "createdAt": "2026-10-20T10:00:00Z", "mergedAt": "2026-10-22T10:00:00Z", "sourceBranch": branch,
        "author": {"username": author, "bot": bot}, "mergeUser": {"username": author, "bot": bot},
        "autoMergeEnabled": auto, "mergeWhenPipelineSucceeds": False,
        "labels": {"nodes": []}, "approvedBy": {"nodes": [{"username": approver}]},
    }
    return {
        "project": {
            "id": "gid://gitlab/Project/7", "archived": False, "visibility": "internal", "topics": ["criticite-c2"],
            "lastActivityAt": "2026-10-27T10:00:00Z", "onlyAllowMergeIfPipelineSucceeds": True, "secretPushProtectionEnabled": True,
            "repository": {"empty": False, "rootRef": "main", "commit": {"sha": "abc123"}},
            "complianceFrameworks": {"nodes": []},
            "branchRules": {"nodes": [{"name": "main", "isDefault": True, "branchProtection": {
                "allowForcePush": False, "pushAccessLevels": {"nodes": [{"accessLevel": 0}]}, "mergeAccessLevels": {"nodes": [{"accessLevel": 40}]}},
                "approvalRules": {"nodes": [{"approvalsRequired": 1}]}}]},
            "ciVariables": {"nodes": [{"key": "DEPLOY_TOKEN", "masked": True, "hidden": False, "variableType": "ENV_VAR"}]},
            "pipelineSchedules": {"nodes": [{"active": True, "cron": "0 2 * * *", "ref": "main"}]},
            "projectMembers": {"nodes": [
                {"accessLevel": {"integerValue": 50}, "user": {"username": "alice", "bot": False}},
                {"accessLevel": {"integerValue": 30}, "user": {"username": "bob", "bot": False}},
                {"accessLevel": {"integerValue": 30}, "user": {"username": "carol", "bot": False}}]},
            "mergeRequests": {"nodes": [mr("renovate/lodash-4.x", "renovate-bot", bot=True), mr("feat/login", "carol")]},
            "pipelines": {"nodes": [{
                "status": "SUCCESS", "createdAt": "2026-10-27T01:00:00Z", "finishedAt": "2026-10-27T01:10:00Z",
                "jobArtifacts": [{"fileType": t} for t in ("SAST", "DAST", "DEPENDENCY_SCANNING", "CYCLONEDX", "JUNIT", "SECRET_DETECTION")],
                "testReportSummary": {"total": {"count": 42}, "testSuites": {"nodes": [{"name": "unit", "totalCount": 30}, {"name": "integration", "totalCount": 12}]}}}]},
            "vulnerabilities": {"nodes": [{"reportType": "SAST", "severity": "LOW", "title": "Weak hash", "identifiers": [{"externalType": "cwe", "externalId": "328"}]}]},
        },
        "approvals": {"approvals_before_merge": 1, "merge_requests_author_approval": False, "reset_approvals_on_push": True},
        "access_tokens": [{"name": "release-bot", "expires_at": "2027-01-01"}],
        "lint": {"valid": True, "errors": [], "merged_yaml": json.dumps({
            "include": [{"template": "Jobs/SAST.gitlab-ci.yml"}],
            "semgrep-sast": {"script": ["semgrep"]}, "secret_detection": {"script": ["gitleaks"]},
            "container_scanning": {"script": ["trivy image"]}, "hadolint": {"image": "hadolint/hadolint", "script": ["hadolint Dockerfile"]},
            "vulture": {"script": ["vulture src"]}, "test": {"script": ["pytest"]}})},
        "tree": [{"path": p, "type": "blob"} for p in (
            ".gitignore", ".pre-commit-config.yaml", "SECURITY.md", "CODEOWNERS", "Dockerfile", "pyproject.toml", "uv.lock",
            "tests/test_auth.py", "tests/integration/test_access_control.py", "src/app.py")],
        "blobs": {
            "SECURITY.md": "Security fixes are released within 30 days.",
            "CODEOWNERS": "[Security]\n/auth/ @appsec-team",
            "Dockerfile": "FROM python:3.12-slim AS build\nFROM build\n",
            ".pre-commit-config.yaml": "repos:\n- repo: https://github.com/gitleaks/gitleaks\n",
        },
    }


def transport(data: dict[str, Any]) -> httpx.MockTransport:
    def handle(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/graphql":
            body = json.loads(request.content)
            if "blobs(" in body["query"]:
                wanted = body["variables"]["paths"]
                blobs = [{"path": p, "rawSize": len(t), "rawTextBlob": t} for p, t in data["blobs"].items() if p in wanted]
                return httpx.Response(200, json={"data": {"project": {"repository": {"blobs": {"nodes": blobs}}}}})
            return httpx.Response(200, json={"data": {"project": data["project"]}})
        routes = {"/approvals": "approvals", "/access_tokens": "access_tokens", "/ci/lint": "lint", "/repository/tree": "tree"}
        key = next((v for k, v in routes.items() if path.endswith(k)), None)
        if key is None or data.get(key) is None:
            return httpx.Response(403, json={"message": "403 Forbidden"})
        return httpx.Response(200, json=data[key])
    return httpx.MockTransport(handle)


def context(data: dict[str, Any], tmp: Path, enterprise: bool = True) -> Context:
    token = tmp / "token"
    token.write_text("glpat-test")
    gl = GitLab("https://gitlab.test", token, transport=transport(copy.deepcopy(data)))
    return Context(gl, "team/app", 7, "main", "abc123", enterprise=enterprise, now=NOW)
