"""Everything a run reads from GitLab, loaded once and in batches: ~5 calls per analysis."""
from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from functools import wraps
from typing import Any, TypeVar

import yaml
from periskope_clients.gitlab import GitLab

T = TypeVar("T")
MAX_FILE_BYTES = 512 * 1024
MAX_FILES = 30
# The files repository checks read: security docs, Dockerfiles, CODEOWNERS, pre-commit config.
READ_FILES = r"(^|/)(SECURITY|PATCH[_-]?POLICY|security[_-]policy)(\.md|\.rst|\.txt)?$|(^|/)(Docker|Container)file[^/]*$|^(\.gitlab/|docs/)?CODEOWNERS$|^\.pre-commit-config\.yaml$"
LIVE_DAYS = 90

# One query for the project's settings, protections, variables, members, MRs, pipelines and vulnerabilities.
PROJECT_QUERY = """
query($path: ID!, $branch: String!, $since: Time!) {
  project(fullPath: $path) {
    id archived visibility topics lastActivityAt
    onlyAllowMergeIfPipelineSucceeds
    secretPushProtectionEnabled # ee
    repository { empty rootRef commit(ref: $branch) { sha } }
    complianceFrameworks { nodes { name } } # ee
    branchRules { nodes { name isDefault branchProtection {
      allowForcePush pushAccessLevels { nodes { accessLevel } } mergeAccessLevels { nodes { accessLevel } } }
      approvalRules { nodes { approvalsRequired } } # ee
    } }
    ciVariables(first: 100) { nodes { key masked hidden variableType } }
    pipelineSchedules(first: 20) { nodes { active cron ref } }
    projectMembers(first: 100) { nodes { accessLevel { integerValue } user { username bot } } }
    mergeRequests(state: merged, mergedAfter: $since, first: 100, sort: MERGED_AT_DESC) { nodes {
      createdAt mergedAt sourceBranch author { username bot } mergeUser { username bot }
      autoMergeEnabled mergeWhenPipelineSucceeds labels { nodes { title } } approvedBy { nodes { username } } } }
    pipelines(ref: $branch, first: 20) { nodes {
      status createdAt finishedAt
      jobArtifacts { fileType }
      testReportSummary { total { count } testSuites { nodes { name totalCount } } } } }
    vulnerabilities(state: [DETECTED, CONFIRMED], first: 100) { nodes { reportType severity title identifiers { externalType externalId } } } # ee
  }
}
"""



def project_query(enterprise: bool) -> str:
    """Fields marked `# ee` exist only on GitLab EE; a CE instance rejects the whole query with them."""
    return PROJECT_QUERY if enterprise else "\n".join(line for line in PROJECT_QUERY.splitlines() if not line.endswith("# ee"))


BLOBS_QUERY = """
query($path: ID!, $ref: String!, $paths: [String!]!) {
  project(fullPath: $path) { repository { blobs(ref: $ref, paths: $paths) { nodes { path rawSize rawTextBlob } } } }
}
"""


def once[T](fn: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
    """Memoize an accessor per Context: concurrent checks share one in-flight call."""
    @wraps(fn)
    def wrapper(self: Context) -> Awaitable[T]:
        cache = self._cache
        if fn.__name__ not in cache:
            cache[fn.__name__] = asyncio.ensure_future(fn(self))
        return cache[fn.__name__]
    return wrapper


def nodes(obj: dict[str, Any] | None, key: str) -> list[dict[str, Any]] | None:
    """A connection's nodes; None when GitLab returned nothing for it (not licensed, no right)."""
    conn = (obj or {}).get(key)
    return None if conn is None else conn.get("nodes") or []


def strip_disabled(ci: dict[str, Any]) -> dict[str, Any]:
    """Drop jobs a variable disables (SAST_DISABLED: "true" and the like) and hidden templates."""
    variables = {k: str(v.get("value", v) if isinstance(v, dict) else v).lower() for k, v in (ci.get("variables") or {}).items()}
    disabled = {k.removesuffix("_DISABLED").lower() for k, v in variables.items() if k.endswith("_DISABLED") and v in ("true", "1", "yes")}
    jobs = {}
    for name, job in ci.items():
        if not isinstance(job, dict) or name.startswith(".") or "script" not in job and "trigger" not in job and "extends" not in job:
            continue
        if any(d and (d in name.lower() or d.replace("_", "-") in name.lower()) for d in disabled):
            continue
        jobs[name] = job
    return jobs


class Context:
    def __init__(self, gl: GitLab, path: str, project_id: int, branch: str, sha: str, *, enterprise: bool = True, now: datetime | None = None):
        self.gl, self.path, self.project_id, self.branch, self.sha, self.enterprise = gl, path, project_id, branch, sha, enterprise
        self.now = now or datetime.now(UTC)
        self._cache: dict[str, asyncio.Future[Any]] = {}

    @property
    def api(self) -> str:
        return f"/projects/{self.project_id}"

    @once
    async def project(self) -> dict[str, Any] | None:
        since = (self.now - timedelta(days=LIVE_DAYS)).isoformat()
        data = await self.gl.graphql(project_query(self.enterprise), path=self.path, branch=self.branch, since=since)
        return (data or {}).get("project")

    @once
    async def approvals(self) -> dict[str, Any] | None:
        return await self.gl.get(f"{self.api}/approvals")

    @once
    async def access_tokens(self) -> list[dict[str, Any]] | None:
        return await self.gl.get(f"{self.api}/access_tokens", state="active")

    @once
    async def ci_jobs(self) -> dict[str, Any] | None:
        """The merged CI of the branch, as jobs; {} when there is no CI, None when unreadable."""
        lint = await self.gl.get(f"{self.api}/ci/lint", content_ref=self.sha, dry_run="false", include_jobs="false")
        if lint is None:
            return None
        merged = lint.get("merged_yaml")
        if not merged:
            return {} if not lint.get("valid") and any("does not exist" in e or "Please provide content" in e for e in lint.get("errors", [])) else None
        # Never executed: read in safe mode, size capped by GitLab's own limit.
        return strip_disabled(yaml.safe_load(merged) or {})

    @once
    async def tree(self) -> tuple[list[str], bool] | None:
        """Blob paths at the commit, and whether the listing was cut short."""
        res = await self.gl.pages(f"{self.api}/repository/tree", recursive="true", ref=self.sha, pagination="keyset", max_pages=10)
        if res is None:
            return None
        items, truncated = res
        return [i["path"] for i in items if i["type"] == "blob"], truncated

    @once
    async def repo_files(self) -> dict[str, str]:
        """Every file a repository check reads, fetched in one call; files over the size cap are left out."""
        tree = await self.tree()
        rx = re.compile(READ_FILES, re.IGNORECASE)
        paths = [p for p in (tree[0] if tree else []) if rx.search(p)][:MAX_FILES]
        if not paths:
            return {}
        data = await self.gl.graphql(BLOBS_QUERY, path=self.path, ref=self.sha, paths=paths)
        blobs = nodes(((data or {}).get("project") or {}).get("repository"), "blobs") or []
        return {b["path"]: b["rawTextBlob"] or "" for b in blobs if int(b.get("rawSize") or 0) <= MAX_FILE_BYTES}

    async def files(self, paths: list[str]) -> dict[str, str]:
        files = await self.repo_files()
        return {p: files[p] for p in paths if p in files}

    async def find(self, pattern: str) -> list[str] | None:
        tree = await self.tree()
        if tree is None:
            return None
        rx = re.compile(pattern, re.IGNORECASE)
        return [p for p in tree[0] if rx.search(p)]

    # Shortcuts over the main query.
    async def default_rule(self) -> dict[str, Any] | None:
        rules = nodes(await self.project(), "branchRules")
        if rules is None:
            return None
        return next((r for r in rules if r["name"] == self.branch), None) or next((r for r in rules if r.get("isDefault")), None)

    async def pipelines(self) -> list[dict[str, Any]] | None:
        return nodes(await self.project(), "pipelines")

    async def merged_mrs(self) -> list[dict[str, Any]] | None:
        return nodes(await self.project(), "mergeRequests")

    async def artifact_types(self) -> set[str] | None:
        """Report types produced by the branch's recent pipelines (sast, dast, cyclonedx, junit…)."""
        pipelines = await self.pipelines()
        if pipelines is None:
            return None
        return {a["fileType"].lower() for p in pipelines for a in p.get("jobArtifacts") or []}

