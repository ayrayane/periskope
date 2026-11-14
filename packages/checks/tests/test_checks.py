"""Every check passes on the good project, fails on a broken one and is unknown when its source is unreadable."""
import json
from datetime import UTC, datetime

import pytest
from fake_gitlab import context, good
from periskope_checks import REGISTRY, run_all
from periskope_core.models import CheckStatus


def p(d):
    return d["project"]


def no_project(d):
    d["project"] = None


def no_ci(d):
    d["lint"] = None


def no_tree(d):
    d["tree"] = None


def no_blobs(d):
    d["blobs"] = None


def ci(jobs):
    def apply(d):
        d["lint"]["merged_yaml"] = json.dumps(jobs)
    return apply


def drop_paths(*names):
    def apply(d):
        d["tree"] = [t for t in d["tree"] if t["path"] not in names]
        d["blobs"] = {k: v for k, v in d["blobs"].items() if k not in names}  # a deleted file has no content either
    return apply


def no_dep_mrs(d):
    p(d)["mergeRequests"]["nodes"] = [m for m in p(d)["mergeRequests"]["nodes"] if "renovate" not in m["sourceBranch"]]


def artifacts(*types):
    def apply(d):
        p(d)["pipelines"]["nodes"][0]["jobArtifacts"] = [{"fileType": t} for t in types]
    return apply


def vuln(cwe, report="SAST", title="Finding"):
    def apply(d):
        p(d)["vulnerabilities"]["nodes"].append({"reportType": report, "severity": "HIGH", "title": title,
                                                 "identifiers": [{"externalType": "cwe", "externalId": cwe}]})
    return apply


def set_(path, value):
    """Set a nested key: set_(("project", "visibility"), "public")."""
    def apply(d):
        target = d
        for k in path[:-1]:
            target = target[k]
        target[path[-1]] = value
    return apply


def rule(**changes):
    def apply(d):
        p(d)["branchRules"]["nodes"][0]["branchProtection"].update(changes)
    return apply


def blob(name, text):
    def apply(d):
        d["blobs"][name] = text
    return apply


def no_suites(d):
    p(d)["pipelines"]["nodes"][0]["testReportSummary"] = {"total": {"count": 0}, "testSuites": {"nodes": []}}


def measure(metric, value):
    def apply(d):
        ms = d["sonar"]["measures"]["component"]["measures"]
        d["sonar"]["measures"]["component"]["measures"] = [m for m in ms if m["metric"] != metric] + ([{"metric": metric, "value": value}] if value is not None else [])
    return apply


def no_sonar_project(d):
    d["sonar"] = {}


def both(*changes):
    def apply(d):
        for change in changes:
            change(d)
    return apply


def track(**changes):
    def apply(d):
        d["tracking"].update(changes)
    return apply


def brick(i, **changes):
    def apply(d):
        d["tracking"]["bricks"][i].update(changes)
    return apply


no_bricks = track(bricks=[])


# check id → (how to make it fail, how to make it unknown)
CASES = {
    "gitlab.version_control": (set_(("project", "repository", "empty"), True), no_project),
    "gitlab.visibility": (set_(("project", "visibility"), "public"), no_project),
    "gitlab.ci_defined": (set_(("lint",), {"valid": False, "errors": ["Please provide content of .gitlab-ci.yml"], "merged_yaml": None}), no_ci),
    "gitlab.ci_recent_success": (set_(("project", "pipelines", "nodes", 0, "status"), "FAILED"), no_project),
    "gitlab.renovate": (no_dep_mrs, no_project),
    "gitlab.xss_open": (vuln("79"), artifacts("JUNIT")),
    "gitlab.injection_open": (vuln("89"), artifacts("JUNIT")),
    "gitlab.secret_detection": (ci({"test": {"script": ["pytest"]}}), no_ci),
    "gitlab.image_secret_scan": (ci({"test": {"script": ["pytest"]}}), no_ci),
    "gitlab.sbom_artifact": (both(artifacts("SAST"), no_bricks), both(no_project, no_bricks)),
    "gitlab.masked_secrets": (set_(("project", "ciVariables", "nodes", 0, "masked"), False), no_project),
    "gitlab.automerge": (lambda d: p(d)["mergeRequests"]["nodes"][0].update(autoMergeEnabled=False, mergeUser={"username": "alice", "bot": False}), no_project),
    "gitlab.nightly_schedule": (set_(("project", "pipelineSchedules", "nodes", 0, "cron"), "0 2 * * 1"), no_project),
    "gitlab.protection_requirement": (set_(("project", "topics"), ["python"]), no_project),
    "gitlab.approvals_required": (set_(("approvals", "merge_requests_author_approval"), True), set_(("approvals",), None)),
    "gitlab.protected_branch_no_push": (rule(pushAccessLevels={"nodes": [{"accessLevel": 30}]}), None),
    "gitlab.account_inventory": (set_(("access_tokens", 0, "expires_at"), None), set_(("access_tokens",), None)),
    "gitlab.least_privilege": (lambda d: [m["accessLevel"].update(integerValue=40) for m in p(d)["projectMembers"]["nodes"]] and None or
                               p(d)["projectMembers"]["nodes"].extend({"accessLevel": {"integerValue": 40}, "user": {"username": f"m{i}", "bot": False}} for i in range(3)), no_project),
    "gitlab.vuln_layers": (both(artifacts("SAST", "JUNIT"), no_bricks), no_project),
    "gitlab.patch_mttr": (set_(("project", "mergeRequests", "nodes", 0, "createdAt"), "2026-08-01T00:00:00Z"), no_dep_mrs),
    "gitlab.tests_run": (no_suites, no_project),
    "gitlab.integration_suite": (set_(("project", "pipelines", "nodes", 0, "testReportSummary", "testSuites", "nodes", 1, "name"), "lint"), no_project),
    "gitlab.dockerfile_lint": (ci({"test": {"script": ["pytest"]}}), no_ci),
    "gitlab.secure_headers": (vuln("693", report="DAST", title="Missing X-Frame-Options header"), artifacts("SAST")),
    "gitlab.no_force_push": (rule(allowForcePush=True), None),
    "gitlab.secret_push_protection": (set_(("project", "secretPushProtectionEnabled"), False), set_(("project", "secretPushProtectionEnabled"), None)),
    "gitlab.reset_approvals_on_push": (set_(("approvals", "reset_approvals_on_push"), False), set_(("approvals",), None)),
    "gitlab.pipeline_must_succeed": (set_(("project", "onlyAllowMergeIfPipelineSucceeds"), False), no_project),
    "gitlab.approved_mrs": (set_(("project", "mergeRequests", "nodes", 1, "approvedBy", "nodes"), [{"username": "carol"}]), no_project),
    "gitlab.sast": (ci({"test": {"script": ["pytest"]}}), no_ci),
    "gitlab.dead_code": (ci({"test": {"script": ["pytest"]}}), no_ci),
    "repo.patch_policy": (blob("SECURITY.md", "Report issues to sec@example.com"), no_tree),
    "repo.lockfiles": (drop_paths("uv.lock"), no_tree),
    "repo.pinning_images": (blob("Dockerfile", "FROM python:latest\n"), no_tree),
    "repo.security_champion": (blob("CODEOWNERS", "* @alice"), no_tree),
    "repo.security_unit_tests": (drop_paths("tests/test_auth.py", "tests/integration/test_access_control.py"), no_tree),
    "repo.security_integration_tests": (drop_paths("tests/integration/test_access_control.py"), no_tree),
    "repo.precommit_security": (blob(".pre-commit-config.yaml", "repos:\n- repo: https://github.com/psf/black\n"), no_blobs),
    "repo.gitignore": (drop_paths(".gitignore"), no_blobs),
    "repo.precommit_lint": (drop_paths(".pre-commit-config.yaml"), no_blobs),
    "sonar.false_positive": (lambda d: (set_(("sonar", "treated", "total"), 0)(d), measure("security_hotspots_reviewed", "0")(d)), no_sonar_project),
    "sonar.security_gate": (set_(("sonar", "gate_detail", "conditions"), [{"metric": "coverage", "op": "LT", "error": "80"}]), no_sonar_project),
    "sonar.hotspots_reviewed": (measure("security_hotspots_reviewed", "40.0"), no_sonar_project),
    "sonar.metrics": (measure("vulnerabilities", None), no_sonar_project),
    "sonar.recent_analysis": (set_(("sonar", "analyses", "analyses", 0, "date"), "2026-06-01T00:00:00+0000"), no_sonar_project),
    "sonar.all_components": (measure("ncloc", "0"), no_sonar_project),
    "sonar.duplication": (measure("duplicated_lines_density", "12.5"), no_sonar_project),
    "dt.sca": (both(artifacts("SAST"), no_bricks), both(no_project, no_bricks)),
    "dt.prod_component": (both(no_bricks, set_(("project", "topics"), ["prod"])), track(dt=False)),
    "dt.prod_artifact": (brick(0, version=None), track(dt=False)),
    "dt.prod_dependencies": (brick(0, sbom=False), set_(("tracking",), None)),
    "dt.same_artifact": (brick(0, by_tag=True), brick(0, env=None)),
    "ledger.sla": (set_(("tracking", "ledger", 1, "deadline_at"), datetime(2026, 10, 27, tzinfo=UTC)), track(followed=False)),
    # A measurement: nothing makes it fail.
    "ledger.fix_rate": (None, track(followed=False)),
}


def test_every_registered_check_has_cases():
    assert set(CASES) == set(REGISTRY)


async def test_all_pass_on_good_project(tmp_path):
    outcomes = await run_all(context(good(), tmp_path))
    assert {k: o.message for k, o in outcomes.items() if o.status != CheckStatus.PASS} == {}


async def test_good_project_stays_under_call_budget(tmp_path):
    ctx = context(good(), tmp_path)
    await run_all(ctx)
    # GraphQL project + report types + blobs + executed jobs, approvals, tokens, CI lint, tree: the spec's target is 5 on average, 15 at worst.
    assert ctx.gl.calls <= 8


async def test_unreadable_reports_only_touch_the_checks_that_need_them(tmp_path):
    """On a large monorepo GitLab may give up listing the pipelines' artifacts: the analysis goes on, those checks are unknown."""
    normal = await run_all(context(good(), tmp_path))
    data = good()
    data["artifacts_down"] = True
    down = await run_all(context(data, tmp_path))
    changed = {k for k in normal if down[k].status != normal[k].status}
    assert "gitlab.vuln_layers" in changed and all(down[k].status == CheckStatus.UNKNOWN for k in changed), {k: down[k].message for k in changed}


async def test_sonar_absent_is_unknown_never_fail(tmp_path):
    ids = [i for i in REGISTRY if i.startswith("sonar.")]
    outcomes = await run_all(context(good(), tmp_path, sonar=False), ids)
    assert {o.status for o in outcomes.values()} == {CheckStatus.UNKNOWN}
    assert "non configuré" in outcomes["sonar.metrics"].message


@pytest.mark.parametrize("check_id", sorted(k for k, (f, _) in CASES.items() if f))
async def test_fails(check_id, tmp_path):
    data = good()
    CASES[check_id][0](data)
    outcome = (await run_all(context(data, tmp_path), [check_id]))[check_id]
    assert outcome.status == CheckStatus.FAIL, outcome.message


@pytest.mark.parametrize("check_id", sorted(k for k, (_, u) in CASES.items() if u))
async def test_unknown(check_id, tmp_path):
    data = good()
    CASES[check_id][1](data)
    outcome = (await run_all(context(data, tmp_path), [check_id]))[check_id]
    assert outcome.status == CheckStatus.UNKNOWN, outcome.message


async def test_ce_instance_marks_ultimate_checks_unknown(tmp_path):
    ids = ["gitlab.xss_open", "gitlab.secret_push_protection", "gitlab.secure_headers", "gitlab.approvals_required", "gitlab.reset_approvals_on_push"]
    outcomes = await run_all(context(good(), tmp_path, enterprise=False), ids)
    assert {o.status for o in outcomes.values()} == {CheckStatus.UNKNOWN}


def add_paths(*names):
    def apply(d):
        d["tree"] += [{"path": n, "type": "blob"} for n in names]
    return apply


async def test_sample_code_is_not_the_project(tmp_path):
    # Seen on flask: manifests and an auth test under examples/ judged as if they were the product.
    data = good()
    add_paths("examples/celery/pyproject.toml", "samples/demo/package.json", "vendor/lib/pyproject.toml")(data)
    drop_paths("tests/test_auth.py", "tests/integration/test_access_control.py")(data)
    add_paths("examples/tutorial/tests/test_auth.py", "demo/tests/integration/test_access_control.py")(data)
    outcomes = await run_all(context(data, tmp_path), ["repo.lockfiles", "repo.security_unit_tests", "repo.security_integration_tests"])
    assert outcomes["repo.lockfiles"].status == CheckStatus.PASS, outcomes["repo.lockfiles"].message
    assert outcomes["repo.security_unit_tests"].status == CheckStatus.FAIL
    assert outcomes["repo.security_integration_tests"].status == CheckStatus.FAIL


async def test_client_reports_every_status_for_metrics(tmp_path):
    import httpx
    from periskope_clients.gitlab import GitLab

    token = tmp_path / "token"
    token.write_text("t")
    replies = iter([httpx.Response(429, headers={"Retry-After": "0"}), httpx.Response(200, json={"ok": True})])
    seen: list[int] = []
    gl = GitLab("https://gitlab.test", token, transport=httpx.MockTransport(lambda req: next(replies)), on_response=seen.append)
    assert (await gl.get("/api/v4/x")) == {"ok": True} and seen == [429, 200]


def test_security_referents_from_codeowners():
    """The critical-vulnerability alerts name the handles of the security lines only, never the whole CODEOWNERS."""
    from periskope_checks.repo_checks import security_lines
    text = "* @everyone\n[Security]\n/auth/ @alice @appsec-team\n[Docs]\n/docs/ @bob\nSECURITY.md @carol\n"
    assert security_lines(text) == ["[Security]", "/auth/ @alice @appsec-team", "SECURITY.md @carol"]


def big_repo(d, folders=900, files=4100):
    """A repository like the large ones: folders listed first (GitLab's keyset order), the useful files deep in the last pages."""
    deep = ["services/api/Dockerfile", "services/web/package.json", "services/web/package-lock.json",
            "services/api/tests/test_auth_permissions.py", "services/api/tests/integration/test_access_e2e.py"]
    d["tree"] = ([{"path": f"dir{i}", "type": "tree"} for i in range(folders)]
                 + [{"path": f"src/mod{i}/file{i}.py", "type": "blob"} for i in range(files - len(deep) - 4)]
                 + [{"path": x, "type": "blob"} for x in deep + [".gitignore", "SECURITY.md", "CODEOWNERS", ".pre-commit-config.yaml"]])
    d["blobs"]["services/api/Dockerfile"] = "FROM python:3.12-slim\n"
    d["blobs"].pop("Dockerfile")


REPO_IDS = ["repo.patch_policy", "repo.lockfiles", "repo.pinning_images", "repo.security_champion", "repo.security_unit_tests",
            "repo.security_integration_tests", "repo.precommit_security", "repo.gitignore", "repo.precommit_lint", "gitlab.dockerfile_lint"]


async def test_large_repository_is_read_whole(tmp_path):
    """5 000 entries over 50 pages, the files after the folders: every check concludes from the whole listing."""
    data = good()
    big_repo(data)
    ctx = context(data, tmp_path)
    outcomes = await run_all(ctx, REPO_IDS)
    assert {k: o.message for k, o in outcomes.items() if o.status != CheckStatus.PASS} == {}
    tree = await ctx.tree()
    assert (tree.entries, tree.truncated) == (5000, False)


async def test_cut_listing_never_concludes_absence(tmp_path, monkeypatch):
    """Past the limit nothing is « not applicable » or « absent » for want of reading: unknown, saying how much was read.
    Fixed-path files (.gitignore, CODEOWNERS, SECURITY.md, pre-commit) are read by name and still conclude."""
    from periskope_checks import context as ctx_mod
    monkeypatch.setattr(ctx_mod, "MAX_TREE_ENTRIES", 1000)
    data = good()
    big_repo(data)
    outcomes = await run_all(context(data, tmp_path), REPO_IDS)
    status = {k: o.status for k, o in outcomes.items()}
    assert CheckStatus.NOT_APPLICABLE not in status.values()
    assert {k for k, v in status.items() if v == CheckStatus.UNKNOWN} == {
        "repo.lockfiles", "repo.pinning_images", "repo.security_unit_tests", "repo.security_integration_tests", "gitlab.dockerfile_lint"}
    for k in ("repo.patch_policy", "repo.security_champion", "repo.precommit_security", "repo.gitignore", "repo.precommit_lint"):
        assert status[k] == CheckStatus.PASS, (k, outcomes[k].message)
    msg = outcomes["repo.pinning_images"].message
    assert "aucun Dockerfile" in msg and "1 000 entrées lues" in msg and "100 fichiers), la suite n'a pas été lue" in msg
    assert outcomes["repo.pinning_images"].evidence == {"entries_read": 1000, "files_read": 100, "truncated": True}


SCANNERS = ["gitlab.secret_detection", "gitlab.image_secret_scan", "gitlab.dockerfile_lint", "gitlab.sast", "gitlab.dead_code"]


@pytest.mark.parametrize(("change", "status", "said"), [
    (set_(("ran",), ["test"]), CheckStatus.FAIL, "jamais exécuté"),
    (both(set_(("ran",), ["test"]), set_(("cut",), True)), CheckStatus.UNKNOWN, "partie lue"),
    (set_(("ran",), None), CheckStatus.UNKNOWN, "illisibles"),
    # Parallel and matrix runs carry the declared job's name with a suffix; another job starting alike is not a run of it.
    (set_(("ran",), ["semgrep-sast 1/2", "secret_detection: [api]", "container_scanning 2/2", "hadolint: [web]", "vulture 1/3"]), CheckStatus.PASS, "CI"),
    (set_(("ran",), ["semgrep-sast-report", "secret_detection2", "container_scanning_old", "hadolint-fix", "vultures", "semgrep-sast:report", "hadolint report"]), CheckStatus.FAIL, "jamais exécuté"),
])
async def test_declared_scanner_must_have_run(change, status, said, tmp_path):
    """A job in the CI file that is never played (manual, rules never met, skipped) proves nothing."""
    data = good()
    change(data)
    outcomes = await run_all(context(data, tmp_path), SCANNERS)
    assert {o.status for o in outcomes.values()} == {status}, {k: o.message for k, o in outcomes.items()}
    assert all(said in o.message for o in outcomes.values())
    # Only a declared job without a run may change at the same commit.
    assert all(o.pending == (status != CheckStatus.PASS) for o in outcomes.values())


async def test_sbom_in_dependency_track_counts_without_gitlab_report(tmp_path):
    data = good()
    artifacts("SAST", "DAST")(data)
    outcomes = await run_all(context(data, tmp_path), ["gitlab.sbom_artifact", "gitlab.vuln_layers", "dt.sca"])
    assert {o.status for o in outcomes.values()} == {CheckStatus.PASS}
    assert "Dependency-Track" in outcomes["gitlab.sbom_artifact"].message and "Dependency-Track" in outcomes["dt.sca"].message
    # A stopped version no longer counts: its SBOM describes nothing that runs.
    brick(0, running=False)(data)
    assert (await run_all(context(data, tmp_path), ["gitlab.sbom_artifact"]))["gitlab.sbom_artifact"].status == CheckStatus.FAIL


INVENTORY = ["dt.prod_component", "dt.prod_artifact", "dt.prod_dependencies"]


@pytest.mark.parametrize(("topics", "status"), [(["prod"], CheckStatus.FAIL), (["test", "python"], CheckStatus.NOT_APPLICABLE), (["python"], CheckStatus.UNKNOWN)])
async def test_project_absent_from_production_trees_is_judged_on_its_topic(topics, status, tmp_path):
    data = good()
    both(no_bricks, set_(("project", "topics"), topics))(data)
    outcomes = await run_all(context(data, tmp_path), INVENTORY)
    assert {o.status for o in outcomes.values()} == {status}, {k: o.message for k, o in outcomes.items()}


async def test_delivery_is_production_but_has_no_environment_to_compare(tmp_path):
    data = good()
    track(bricks=[{"tree": "CMS · 5.1.0 (livraison)", "env": None, "version": "1.1", "running": True, "by_tag": False, "sbom": True}])(data)
    outcomes = await run_all(context(data, tmp_path), [*INVENTORY, "dt.same_artifact"])
    assert [outcomes[i].status for i in INVENTORY] == [CheckStatus.PASS] * 3
    assert outcomes["dt.same_artifact"].status == CheckStatus.UNKNOWN


async def test_production_version_never_seen_in_test_fails(tmp_path):
    data = good()
    brick(0, version="1.3")(data)
    outcome = (await run_all(context(data, tmp_path), ["dt.same_artifact"]))["dt.same_artifact"]
    assert outcome.status == CheckStatus.FAIL and outcome.evidence == {"versions": ["CMS · prod : 1.3"]}


async def test_ledger_measures(tmp_path):
    data = good()
    outcomes = await run_all(context(data, tmp_path), ["ledger.sla", "ledger.fix_rate"])
    assert outcomes["ledger.fix_rate"].message == "taux de correction mesuré : 1 corrigée(s) en 90 jours, 1 ouverte(s) (50 %)"
    # Late rows are counted by priority; a closed one, or one without deadline (deferred), is never late.
    late = datetime(2026, 10, 1, tzinfo=UTC)
    track(ledger=[{"priority": "critical", "opened_at": late, "closed_at": None, "deadline_at": late},
                  {"priority": "critical", "opened_at": late, "closed_at": late, "deadline_at": late},
                  {"priority": "low", "opened_at": late, "closed_at": None, "deadline_at": None}])(data)
    outcome = (await run_all(context(data, tmp_path), ["ledger.sla"]))["ledger.sla"]
    assert outcome.status == CheckStatus.FAIL and outcome.evidence == {"by_priority": {"critical": 1}}
    track(ledger=[])(data)
    outcomes = await run_all(context(data, tmp_path), ["ledger.sla", "ledger.fix_rate"])
    assert (outcomes["ledger.sla"].status, outcomes["ledger.fix_rate"].status) == (CheckStatus.PASS, CheckStatus.NOT_APPLICABLE)
