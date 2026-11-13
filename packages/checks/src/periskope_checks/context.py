"""Everything a run reads from GitLab, loaded once and in batches: ~5 calls per analysis."""
from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from functools import wraps
from typing import Any, NamedTuple, TypeVar

import yaml
from periskope_clients.gitlab import GitLab
from periskope_clients.sonar import SonarQube
from periskope_core.models import Outcome

T = TypeVar("T")
MAX_FILE_BYTES = 512 * 1024
MAX_FILES = 40
# The whole listing, read again only when the commit changes: up to 50 000 entries (100 per request) and 120 seconds,
# well inside the analysis' own 300 s. GitLab lists folders before files, so a cut listing misses files first.
MAX_TREE_ENTRIES = 50_000
MAX_TREE_SECONDS = 120
# Files whose path is fixed are read by name: a cut listing never hides them.
FIXED_FILES = (".gitignore", ".pre-commit-config.yaml", ".editorconfig", "lefthook.yml", ".husky/pre-commit",
               "CODEOWNERS", ".gitlab/CODEOWNERS", "docs/CODEOWNERS", "SECURITY.md", ".gitlab/SECURITY.md", "docs/SECURITY.md")
SONAR_METRICS = "ncloc,vulnerabilities,security_hotspots,security_hotspots_reviewed,duplicated_lines_density"
# The files repository checks read: security docs, Dockerfiles, CODEOWNERS, pre-commit config.
READ_FILES = r"(^|/)(SECURITY|PATCH[_-]?POLICY|security[_-]policy)(\.md|\.rst|\.txt)?$|(^|/)(Docker|Container)file[^/]*$|^(\.gitlab/|docs/)?CODEOWNERS$|^\.pre-commit-config\.yaml$"
LIVE_DAYS = 90
# Sample, vendored and generated code is not the product: repository checks never judge the project on it.
NOT_PRODUCT = re.compile(r"(^|/)(examples?|samples?|demos?|vendor|third[_-]?party|node_modules|testdata|fixtures)/", re.IGNORECASE)

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
    vulnerabilities(state: [DETECTED, CONFIRMED], first: 100) { nodes { reportType severity title detectedAt identifiers { externalType externalId } } } # ee
    vulnerabilitySeveritiesCount(state: [DETECTED, CONFIRMED]) { critical high medium low info unknown } # ee
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


class Tree(NamedTuple):
    """Blob paths at the commit, whether the listing was cut short, and how many entries (files and folders) were read."""
    paths: list[str]
    truncated: bool
    entries: int


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
    def __init__(self, gl: GitLab, path: str, project_id: int, branch: str, sha: str, *, enterprise: bool = True,
                 sonar: SonarQube | None = None, sonar_key: str | None = None, now: datetime | None = None):
        self.gl, self.path, self.project_id, self.branch, self.sha, self.enterprise = gl, path, project_id, branch, sha, enterprise
        self.sonar, self.sonar_key = sonar, sonar_key
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
    async def tree(self) -> Tree | None:
        res = await self.gl.pages(f"{self.api}/repository/tree", recursive="true", ref=self.sha, pagination="keyset",
                                  max_pages=MAX_TREE_ENTRIES // 100, max_seconds=MAX_TREE_SECONDS)
        if res is None:
            return None
        items, truncated = res
        return Tree([i["path"] for i in items if i["type"] == "blob"], truncated, len(items))

    @once
    async def blobs(self) -> dict[str, str] | None:
        """Every file a repository check reads, in one call: the fixed paths by name, the others found in the listing.
        Files over the size cap come back empty. None when GitLab does not answer."""
        tree = await self.tree()
        rx = re.compile(READ_FILES, re.IGNORECASE)
        listed = [p for p in (tree.paths if tree else []) if rx.search(p) and p not in FIXED_FILES]
        data = await self.gl.graphql(BLOBS_QUERY, path=self.path, ref=self.sha, paths=[*FIXED_FILES, *listed][:MAX_FILES])
        found = nodes(((data or {}).get("project") or {}).get("repository"), "blobs")
        if found is None:
            return None
        return {b["path"]: (b["rawTextBlob"] or "") if int(b.get("rawSize") or 0) <= MAX_FILE_BYTES else "" for b in found}

    async def files(self, paths: list[str]) -> dict[str, str]:
        files = await self.blobs() or {}
        return {p: files[p] for p in paths if p in files}

    async def has(self, path: str) -> bool | None:
        """Whether a file at one of FIXED_FILES exists, read by name whatever the size of the repository."""
        files = await self.blobs()
        return None if files is None else path in files

    async def find(self, pattern: str) -> list[str] | None:
        """Paths matching the pattern in the listing, plus the fixed paths read by name (found even past a cut)."""
        tree = await self.tree()
        if tree is None:
            return None
        rx = re.compile(pattern, re.IGNORECASE)
        named = [p for p in await self.blobs() or {} if p not in tree.paths]
        return [p for p in [*tree.paths, *named] if rx.search(p) and not NOT_PRODUCT.search(p)]

    async def partial(self, absent: str) -> Outcome | None:
        """When the listing was cut, what was not found may be in the part not read: unknown, saying how much was read.
        None when the listing is whole, and the absence can be concluded."""
        tree = await self.tree()
        if tree is None:
            return Outcome.unknown("arborescence illisible")
        if not tree.truncated:
            return None
        n = f"{tree.entries:,}".replace(",", " ")
        return Outcome.unknown(f"{absent} dans la partie lue de l'arborescence : {n} entrées lues ({len(tree.paths):,} fichiers), "
                               f"la suite n'a pas été lue (limite de {MAX_TREE_ENTRIES:,} entrées ou {MAX_TREE_SECONDS} s)".replace(",", " "),
                               entries_read=tree.entries, files_read=len(tree.paths), truncated=True)

    # SonarQube of the instance, when it has one and the project has a key.
    @once
    async def sonar_measures(self) -> dict[str, float] | None:
        data = await self.sonar.get("/measures/component", component=self.sonar_key, metricKeys=SONAR_METRICS)
        if data is None:
            return None
        return {m["metric"]: float(m["value"]) for m in data["component"].get("measures", []) if "value" in m}

    @once
    async def sonar_analysis(self) -> dict[str, Any] | None:
        """The latest analysis {key, date}; {} when never analysed, None when the project is absent from SonarQube."""
        data = await self.sonar.get("/project_analyses/search", project=self.sonar_key, ps=1)
        if data is None:
            return None
        return (data.get("analyses") or [{}])[0]

    @once
    async def sonar_gate(self) -> list[dict[str, Any]] | None:
        gate = await self.sonar.get("/qualitygates/get_by_project", project=self.sonar_key)
        if gate is None:
            return None
        detail = await self.sonar.get("/qualitygates/show", name=gate["qualityGate"]["name"])
        return None if detail is None else detail.get("conditions", [])

    @once
    async def sonar_treated(self) -> int | None:
        """Issues marked false positive or accepted: proof that findings are triaged."""
        data = await self.sonar.get("/issues/search", componentKeys=self.sonar_key, resolutions="FALSE-POSITIVE,WONTFIX", ps=1)
        return None if data is None else int(data.get("total", data.get("paging", {}).get("total", 0)))

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

