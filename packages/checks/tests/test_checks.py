"""Every check passes on the good project, fails on a broken one and is unknown when its source is unreadable."""
import json

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


def ci(jobs):
    def apply(d):
        d["lint"]["merged_yaml"] = json.dumps(jobs)
    return apply


def drop_paths(*names):
    def apply(d):
        d["tree"] = [t for t in d["tree"] if t["path"] not in names]
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
    "gitlab.sbom_artifact": (artifacts("SAST"), no_project),
    "gitlab.masked_secrets": (set_(("project", "ciVariables", "nodes", 0, "masked"), False), no_project),
    "gitlab.automerge": (lambda d: p(d)["mergeRequests"]["nodes"][0].update(autoMergeEnabled=False, mergeUser={"username": "alice", "bot": False}), no_project),
    "gitlab.nightly_schedule": (set_(("project", "pipelineSchedules", "nodes", 0, "cron"), "0 2 * * 1"), no_project),
    "gitlab.protection_requirement": (set_(("project", "topics"), ["python"]), no_project),
    "gitlab.approvals_required": (set_(("approvals", "merge_requests_author_approval"), True), set_(("approvals",), None)),
    "gitlab.protected_branch_no_push": (rule(pushAccessLevels={"nodes": [{"accessLevel": 30}]}), None),
    "gitlab.account_inventory": (set_(("access_tokens", 0, "expires_at"), None), set_(("access_tokens",), None)),
    "gitlab.least_privilege": (lambda d: [m["accessLevel"].update(integerValue=40) for m in p(d)["projectMembers"]["nodes"]] and None or
                               p(d)["projectMembers"]["nodes"].extend({"accessLevel": {"integerValue": 40}, "user": {"username": f"m{i}", "bot": False}} for i in range(3)), no_project),
    "gitlab.vuln_layers": (artifacts("SAST", "JUNIT"), no_project),
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
    "repo.precommit_security": (blob(".pre-commit-config.yaml", "repos:\n- repo: https://github.com/psf/black\n"), no_tree),
    "repo.gitignore": (drop_paths(".gitignore"), no_tree),
    "repo.precommit_lint": (drop_paths(".pre-commit-config.yaml"), no_tree),
}


def test_every_registered_check_has_cases():
    assert set(CASES) == set(REGISTRY)


async def test_all_pass_on_good_project(tmp_path):
    outcomes = await run_all(context(good(), tmp_path))
    assert {k: o.message for k, o in outcomes.items() if o.status != CheckStatus.PASS} == {}


async def test_good_project_stays_under_call_budget(tmp_path):
    ctx = context(good(), tmp_path)
    await run_all(ctx)
    # GraphQL project + blobs, approvals, tokens, CI lint, tree: the spec's target is 5 on average, 15 at worst.
    assert ctx.gl.calls <= 6


@pytest.mark.parametrize("check_id", sorted(CASES))
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
    ids = ["gitlab.xss_open", "gitlab.secret_push_protection", "gitlab.secure_headers"]
    outcomes = await run_all(context(good(), tmp_path, enterprise=False), ids)
    assert {o.status for o in outcomes.values()} == {CheckStatus.UNKNOWN}
