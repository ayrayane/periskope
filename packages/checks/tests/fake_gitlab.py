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
from periskope_clients.sonar import SonarQube

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
            "vulnerabilities": {"nodes": [{"reportType": "SAST", "severity": "LOW", "title": "Weak hash", "detectedAt": "2099-01-01T00:00:00Z", "identifiers": [{"externalType": "cwe", "externalId": "328"}]},
                                            {"reportType": "DEPENDENCY_SCANNING", "severity": "CRITICAL", "title": "Log4Shell in log4j-core", "detectedAt": "2021-12-10T00:00:00Z", "identifiers": [{"externalType": "cve", "externalId": "CVE-2021-44228"}]}]},
            "vulnerabilitySeveritiesCount": {"critical": 1, "high": 2, "medium": 0, "low": 1, "info": 0, "unknown": 0},
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
        "sonar": {
            "measures": {"component": {"measures": [
                {"metric": "ncloc", "value": "12000"}, {"metric": "vulnerabilities", "value": "2"}, {"metric": "security_hotspots", "value": "4"},
                {"metric": "security_hotspots_reviewed", "value": "100.0"}, {"metric": "duplicated_lines_density", "value": "2.1"}]}},
            "analyses": {"analyses": [{"key": "AY-1", "date": "2026-10-27T01:20:00+0000"}]},
            "gate": {"qualityGate": {"name": "Plateforme"}},
            "gate_detail": {"conditions": [{"metric": "new_security_rating", "op": "GT", "error": "1"}]},
            "treated": {"total": 3},
        },
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


def sonar_transport(data: dict[str, Any]) -> httpx.MockTransport:
    routes = {"/api/measures/component": "measures", "/api/project_analyses/search": "analyses", "/api/qualitygates/get_by_project": "gate",
              "/api/qualitygates/show": "gate_detail", "/api/issues/search": "treated"}

    def handle(request: httpx.Request) -> httpx.Response:
        body = (data.get("sonar") or {}).get(routes.get(request.url.path, ""))
        return httpx.Response(404, json={"errors": [{"msg": "not found"}]}) if body is None else httpx.Response(200, json=body)
    return httpx.MockTransport(handle)


def context(data: dict[str, Any], tmp: Path, enterprise: bool = True, sonar: bool = True) -> Context:
    token = tmp / "token"
    token.write_text("glpat-test")
    data = copy.deepcopy(data)
    gl = GitLab("https://gitlab.test", token, transport=transport(data))
    sq = SonarQube("https://sonar.test", token, transport=sonar_transport(data)) if sonar else None
    return Context(gl, "team/app", 7, "main", "abc123", enterprise=enterprise, sonar=sq, sonar_key="team_app", now=NOW)
