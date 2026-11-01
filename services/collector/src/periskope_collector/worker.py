"""ARQ worker for one GitLab instance: it only takes its own queue, collect:<instance>."""
from __future__ import annotations

import json
from typing import Any

from arq.connections import RedisSettings
from arq.worker import func
from periskope_clients.gitlab import GitLab
from periskope_clients.sonar import SonarQube
from periskope_core.settings import env, instances, queue, secret
from periskope_db import connect, runs
from periskope_db.bootstrap import bootstrap
from prometheus_client import Counter, start_http_server

from periskope_collector.analysis import analyse
from periskope_collector.ratelimit import Bucket
from periskope_collector.sync import memberships, sync_projects

MEMBERSHIP_TTL_S = 900
BRANCHES_TTL_S = 120
INSTANCE = env("INSTANCE", "")
RESPONSES = Counter("periskope_gitlab_responses", "GitLab API responses by HTTP status (0: unreachable)", ["instance", "code"])


async def startup(ctx: dict[str, Any]) -> None:
    registry = instances()
    instance = registry[INSTANCE]
    ctx["instance"] = instance
    ctx["db"] = await connect(min_size=2, max_size=10)
    await bootstrap(ctx["db"], registry)
    bucket = Bucket(ctx["redis"], instance.slug, instance.rate_per_min)
    start_http_server(int(env("METRICS_PORT", "9100")))
    ctx["gl"] = GitLab(instance.url, secret(f"gitlab-token-{instance.slug}") / "token", acquire=bucket.acquire, verify=instance.ca_file or True,
                       on_response=lambda code: RESPONSES.labels(instance.slug, str(code)).inc())
    ctx["sonar"] = SonarQube(instance.sonar_url, secret(f"sonar-token-{instance.slug}") / "token", verify=instance.ca_file or True) if instance.sonar_url else None


async def shutdown(ctx: dict[str, Any]) -> None:
    await ctx["gl"].aclose()
    if ctx["sonar"]:
        await ctx["sonar"].aclose()
    await ctx["db"].close()


async def run_analysis(ctx: dict[str, Any], run_id: int) -> None:
    await analyse(ctx["db"], ctx["gl"], run_id, enterprise=ctx["instance"].enterprise, sonar=ctx["sonar"])


async def analyse_project(ctx: dict[str, Any], project_id: int, trigger: str) -> int | None:
    """Webhook and nightly runs: create the run on the default branch when it fires, then analyse."""
    branch = await ctx["db"].fetchval("SELECT default_branch FROM projects WHERE id = $1 AND enabled", project_id)
    if not branch:
        return None
    try:
        run_id = await runs.create(ctx["db"], project_id, branch, trigger, None)
    except runs.AlreadyActive:
        return None
    await run_analysis(ctx, run_id)
    return run_id


async def run_sync(ctx: dict[str, Any]) -> dict[str, int]:
    return await sync_projects(ctx["db"], ctx["gl"], ctx["instance"])


async def resolve_memberships(ctx: dict[str, Any], sub: str, username: str, email: str | None) -> None:
    found = await memberships(ctx["gl"], username, email, match=env("IDENTITY_MATCH", "verified_email"),
                              ldap_only=env("GITLAB_LDAP_ONLY", "false") == "true")
    value = found or {"groups": [], "projects": []}
    await ctx["redis"].set(f"members:{sub}:{ctx['instance'].slug}", json.dumps(value), ex=MEMBERSHIP_TTL_S)


async def list_branches(ctx: dict[str, Any], project_id: int) -> None:
    """The repository's real branches, for the branch picker and the 422 on an unknown branch."""
    gitlab_id = await ctx["db"].fetchval("SELECT gitlab_id FROM projects WHERE id = $1", project_id)
    found = await ctx["gl"].pages(f"/projects/{gitlab_id}/repository/branches", max_pages=5) if gitlab_id else None
    branches = [{"name": b["name"], "default": b["default"], "protected": b["protected"], "committed_at": b["commit"]["committed_date"]}
                for b in (found[0] if found else [])]
    await ctx["redis"].set(f"branches:{project_id}", json.dumps(branches), ex=BRANCHES_TTL_S)


class WorkerSettings:
    # Sync, memberships and branches are queued under fixed job ids; a kept result would block the next refresh once the cache expires.
    functions = (run_analysis, analyse_project, func(run_sync, keep_result=0), func(resolve_memberships, keep_result=0), func(list_branches, keep_result=0))
    on_startup = startup
    on_shutdown = shutdown
    queue_name = queue(INSTANCE)
    redis_settings = RedisSettings.from_dsn(env("VALKEY_URL", "redis://localhost:6379"))
    max_jobs = int(env("COLLECTOR_CONCURRENCY", "20"))
    job_timeout = 600
    # A run's own deadline is 5 minutes; ARQ only retries a job that crashed the worker.
    max_tries = 2
