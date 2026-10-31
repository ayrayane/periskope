"""The 31 checks read from the GitLab API."""
from __future__ import annotations

import re
import statistics
from datetime import datetime, timedelta

from periskope_core.models import Outcome

from periskope_checks.context import Context, nodes
from periskope_checks.registry import Depends, check

DEP_MR = re.compile(r"^(renovate|dependabot)[/-]|renovate|dependabot", re.IGNORECASE)
SECRETISH = re.compile(r"TOKEN|PASSWORD|PASSWD|SECRET|API_?KEY|PRIVATE_?KEY|CREDENTIAL", re.IGNORECASE)
NO_ONE, MAINTAINER = 0, 40


def ts(value: str) -> datetime:
    return datetime.fromisoformat(value)


async def ci_match(ctx: Context, pattern: str) -> list[str] | None:
    """Names of the merged CI's enabled jobs whose name, extends, image or script matches."""
    jobs = await ctx.ci_jobs()
    if jobs is None:
        return None
    rx = re.compile(pattern, re.IGNORECASE)
    return [name for name, job in jobs.items() if rx.search(name) or rx.search(str(job.get("extends", ""))) or rx.search(str(job.get("image", ""))) or rx.search(str(job.get("script", "")))]


async def dependency_mrs(ctx: Context) -> list[dict] | None:
    mrs = await ctx.merged_mrs()
    if mrs is None:
        return None
    return [m for m in mrs if DEP_MR.search(m["sourceBranch"]) or DEP_MR.search((m.get("author") or {}).get("username", ""))
            or any(label["title"].lower() == "dependencies" for label in nodes(m, "labels") or [])]


async def open_vulns(ctx: Context, cwes: set[str], reports: set[str]) -> Outcome:
    if not ctx.enterprise:
        return Outcome.unknown("rapport de vulnérabilités indisponible (GitLab sans licence Ultimate)")
    vulns, types = nodes(await ctx.project(), "vulnerabilities"), await ctx.artifact_types()
    if vulns is None or types is None:
        return Outcome.unknown("rapport de vulnérabilités illisible")
    if not types & reports:
        return Outcome.unknown(f"aucun scanner {'/'.join(sorted(reports))} n'a produit de rapport récent")
    hits = [v["title"] for v in vulns if {f"CWE-{i['externalId']}" for i in v.get("identifiers") or [] if i["externalType"].lower() == "cwe"} & cwes]
    if hits:
        return Outcome.fail(f"{len(hits)} vulnérabilité(s) ouverte(s)", titles=hits[:10])
    return Outcome.ok("aucune vulnérabilité ouverte de ce type", scanners=sorted(types & reports))


@check("gitlab.version_control", Depends.SETTINGS, "Pousser le code du projet dans son dépôt GitLab.")
async def version_control(ctx: Context) -> Outcome:
    p = await ctx.project()
    if p is None:
        return Outcome.unknown("projet illisible")
    if (p.get("repository") or {}).get("empty", True):
        return Outcome.fail("dépôt vide")
    return Outcome.ok("code versionné dans GitLab")


@check("gitlab.visibility", Depends.SETTINGS, "Passer le projet en visibilité interne ou privée.")
async def visibility(ctx: Context) -> Outcome:
    p = await ctx.project()
    if p is None:
        return Outcome.unknown("projet illisible")
    if p["visibility"] == "public":
        return Outcome.fail("projet public", visibility="public")
    return Outcome.ok(f"projet {p['visibility']}", visibility=p["visibility"])


@check("gitlab.ci_defined", Depends.COMMIT, "Ajouter un .gitlab-ci.yml, idéalement à partir des composants CI de la plateforme.")
async def ci_defined(ctx: Context) -> Outcome:
    jobs = await ctx.ci_jobs()
    if jobs is None:
        return Outcome.unknown("CI illisible")
    if not jobs:
        return Outcome.fail("aucun pipeline CI défini")
    return Outcome.ok(f"{len(jobs)} job(s) définis", jobs=len(jobs))


@check("gitlab.ci_recent_success", Depends.LIVE, "Réparer le pipeline de la branche par défaut pour qu'il passe au moins une fois par mois.")
async def ci_recent_success(ctx: Context) -> Outcome:
    pipelines = await ctx.pipelines()
    if pipelines is None:
        return Outcome.unknown("pipelines illisibles")
    recent = [p for p in pipelines if p["status"] == "SUCCESS" and ts(p["createdAt"]) > ctx.now - timedelta(days=30)]
    if recent:
        return Outcome.ok("pipeline réussi dans les 30 derniers jours", last=recent[0]["createdAt"])
    return Outcome.fail("aucun pipeline réussi sur la branche depuis 30 jours", pipelines=len(pipelines))


@check("gitlab.renovate", Depends.LIVE, "Activer Renovate sur le projet pour recevoir les MR de mise à jour.")
async def renovate(ctx: Context) -> Outcome:
    mrs = await dependency_mrs(ctx)
    if mrs is None:
        return Outcome.unknown("merge requests illisibles")
    if mrs:
        return Outcome.ok(f"{len(mrs)} MR de dépendances mergées en 90 jours", count=len(mrs))
    return Outcome.fail("aucune MR automatique de mise à jour en 90 jours")


@check("gitlab.xss_open", Depends.LIVE, "Corriger ou trier les vulnérabilités XSS ouvertes du rapport de vulnérabilités.")
async def xss_open(ctx: Context) -> Outcome:
    return await open_vulns(ctx, {"CWE-79"}, {"sast", "dast"})


@check("gitlab.injection_open", Depends.LIVE, "Corriger ou trier les injections SQL ou de commande ouvertes.")
async def injection_open(ctx: Context) -> Outcome:
    return await open_vulns(ctx, {"CWE-89", "CWE-78", "CWE-77"}, {"sast", "dast"})


@check("gitlab.secret_detection", Depends.COMMIT, "Inclure le template ou le composant Secret-Detection dans la CI.")
async def secret_detection(ctx: Context) -> Outcome:
    jobs = await ci_match(ctx, r"secret[_-]detection|gitleaks|trufflehog|detect-secrets")
    if jobs is None:
        return Outcome.unknown("CI illisible")
    return Outcome.ok("détection de secrets dans la CI", jobs=jobs) if jobs else Outcome.fail("aucun job de détection de secrets")


@check("gitlab.image_secret_scan", Depends.COMMIT, "Scanner les images construites à la recherche de secrets oubliés.")
async def image_secret_scan(ctx: Context) -> Outcome:
    jobs = await ci_match(ctx, r"container[_-]scanning|trivy")
    if jobs is None:
        return Outcome.unknown("CI illisible")
    return Outcome.ok("scan d'images présent dans la CI", jobs=jobs) if jobs else Outcome.fail("aucun scan des images construites")


@check("gitlab.sbom_artifact", Depends.LIVE, "Publier un rapport CycloneDX dans les artefacts du pipeline (artifacts:reports:cyclonedx).")
async def sbom_artifact(ctx: Context) -> Outcome:
    types = await ctx.artifact_types()
    if types is None:
        return Outcome.unknown("artefacts illisibles")
    return Outcome.ok("SBOM CycloneDX publié") if "cyclonedx" in types else Outcome.fail("aucun artefact CycloneDX récent")


@check("gitlab.masked_secrets", Depends.SETTINGS, "Masquer (ou cacher) les variables CI/CD qui portent un secret.")
async def masked_secrets(ctx: Context) -> Outcome:
    variables = nodes(await ctx.project(), "ciVariables")
    if variables is None:
        return Outcome.unknown("variables CI illisibles")
    sensitive = [v for v in variables if SECRETISH.search(v["key"]) and v.get("variableType") != "FILE"]
    if not sensitive:
        return Outcome.not_applicable("aucune variable sensible")
    clear = [v["key"] for v in sensitive if not (v.get("masked") or v.get("hidden"))]
    if clear:
        return Outcome.fail(f"{len(clear)} variable(s) sensible(s) non masquée(s)", keys=clear)
    return Outcome.ok(f"{len(sensitive)} variable(s) sensible(s) masquée(s)")


@check("gitlab.automerge", Depends.LIVE, "Autoriser Renovate à merger seul les mises à jour mineures (automerge).")
async def automerge(ctx: Context) -> Outcome:
    mrs = await dependency_mrs(ctx)
    if mrs is None:
        return Outcome.unknown("merge requests illisibles")
    if not mrs:
        return Outcome.fail("aucune MR de dépendances à merger")
    auto = [m for m in mrs if m.get("autoMergeEnabled") or m.get("mergeWhenPipelineSucceeds") or ((m.get("mergeUser") or {}).get("bot"))]
    return Outcome.ok(f"{len(auto)} MR de dépendances mergées automatiquement") if auto else Outcome.fail("MR de dépendances mergées à la main")


@check("gitlab.nightly_schedule", Depends.SETTINGS, "Créer un pipeline planifié quotidien sur la branche par défaut.")
async def nightly_schedule(ctx: Context) -> Outcome:
    schedules = nodes(await ctx.project(), "pipelineSchedules")
    if schedules is None:
        return Outcome.unknown("planifications illisibles")
    daily = [s["cron"] for s in schedules if s["active"] and len(s["cron"].split()) == 5 and s["cron"].split()[2:] == ["*", "*", "*"]]
    return Outcome.ok("pipeline planifié quotidien actif", cron=daily) if daily else Outcome.fail("aucun pipeline planifié quotidien actif")


@check("gitlab.protection_requirement", Depends.SETTINGS, "Classer le projet : framework de conformité ou topic de criticité.")
async def protection_requirement(ctx: Context) -> Outcome:
    p = await ctx.project()
    if p is None:
        return Outcome.unknown("projet illisible")
    frameworks = [f["name"] for f in nodes(p, "complianceFrameworks") or []]
    topics = [t for t in p.get("topics") or [] if re.search(r"critic|classif|protection|sensib|^c[1-4]$", t, re.IGNORECASE)]
    if frameworks or topics:
        return Outcome.ok("projet classé", frameworks=frameworks, topics=topics)
    return Outcome.fail("aucune classification du projet")


@check("gitlab.approvals_required", Depends.SETTINGS, "Exiger au moins une approbation et interdire à l'auteur d'approuver sa MR.")
async def approvals_required(ctx: Context) -> Outcome:
    if not ctx.enterprise:
        return Outcome.unknown("règles d'approbation indisponibles (GitLab sans licence Premium)")
    settings, rule = await ctx.approvals(), await ctx.default_rule()
    if settings is None:
        return Outcome.unknown("réglages d'approbation illisibles")
    required = max([settings.get("approvals_before_merge") or 0] + [r["approvalsRequired"] for r in nodes(rule, "approvalRules") or []])
    if required < 1:
        return Outcome.fail("aucune approbation requise")
    if settings.get("merge_requests_author_approval"):
        return Outcome.fail("l'auteur peut approuver sa propre MR", required=required)
    return Outcome.ok(f"{required} approbation(s) requise(s), auteur exclu", required=required)


@check("gitlab.protected_branch_no_push", Depends.SETTINGS, "Protéger la branche par défaut avec « Allowed to push : No one ».")
async def protected_branch_no_push(ctx: Context) -> Outcome:
    rule = await ctx.default_rule()
    if rule is None or not rule.get("branchProtection"):
        return Outcome.fail("branche par défaut non protégée")
    push = [a["accessLevel"] for a in nodes(rule["branchProtection"], "pushAccessLevels") or []]
    if push and all(level == NO_ONE for level in push):
        return Outcome.ok("push direct interdit")
    return Outcome.fail("push direct autorisé sur la branche par défaut", push_levels=push)


@check("gitlab.account_inventory", Depends.SETTINGS, "Nommer chaque jeton d'accès du projet et lui donner une date d'expiration.")
async def account_inventory(ctx: Context) -> Outcome:
    tokens = await ctx.access_tokens()
    if tokens is None:
        return Outcome.unknown("jetons d'accès illisibles")
    if not tokens:
        return Outcome.not_applicable("aucun jeton d'accès de projet")
    bad = [t["name"] for t in tokens if not t.get("expires_at") or re.fullmatch(r"(token|test|tmp|ci)\d*", t["name"], re.IGNORECASE)]
    if bad:
        return Outcome.fail(f"{len(bad)} jeton(s) sans expiration ou au nom générique", tokens=bad)
    return Outcome.ok(f"{len(tokens)} jeton(s) nommés et à durée limitée")


@check("gitlab.least_privilege", Depends.SETTINGS, "Réduire les rôles Maintainer et Owner au strict nécessaire.")
async def least_privilege(ctx: Context) -> Outcome:
    members = nodes(await ctx.project(), "projectMembers")
    if members is None:
        return Outcome.unknown("membres illisibles")
    humans = [m for m in members if not (m.get("user") or {}).get("bot")]
    high = [m["user"]["username"] for m in humans if m["accessLevel"]["integerValue"] >= MAINTAINER]
    limit = max(3, len(humans) // 5)
    if len(high) > limit:
        return Outcome.fail(f"{len(high)} comptes Maintainer/Owner sur {len(humans)} (max {limit})", high=high)
    return Outcome.ok(f"{len(high)} compte(s) à privilèges élevés sur {len(humans)}")


@check("gitlab.vuln_layers", Depends.LIVE, "Scanner au moins deux couches : code (SAST), dépendances, conteneurs ou application (DAST).")
async def vuln_layers(ctx: Context) -> Outcome:
    types = await ctx.artifact_types()
    if types is None:
        return Outcome.unknown("artefacts illisibles")
    layers = sorted(types & {"sast", "dependency_scanning", "container_scanning", "dast"})
    if len(layers) >= 2:
        return Outcome.ok(f"{len(layers)} couches mesurées", layers=layers)
    return Outcome.fail("moins de deux couches scannées", layers=layers)


@check("gitlab.patch_mttr", Depends.LIVE, "Merger les MR de dépendances en moins de 14 jours.")
async def patch_mttr(ctx: Context) -> Outcome:
    mrs = await dependency_mrs(ctx)
    if mrs is None:
        return Outcome.unknown("merge requests illisibles")
    if not mrs:
        return Outcome.unknown("aucune MR de dépendances mergée en 90 jours")
    days = statistics.median((ts(m["mergedAt"]) - ts(m["createdAt"])).total_seconds() / 86400 for m in mrs)
    out = Outcome.ok if days <= 14 else Outcome.fail
    return out(f"délai médian de merge : {days:.1f} jours", median_days=round(days, 1), count=len(mrs))


async def test_suites(ctx: Context) -> list[dict] | None:
    pipelines = await ctx.pipelines()
    if pipelines is None:
        return None
    for p in pipelines:
        summary = p.get("testReportSummary") or {}
        if (summary.get("total") or {}).get("count"):
            return nodes(summary, "testSuites") or []
    return []


@check("gitlab.tests_run", Depends.LIVE, "Publier les résultats de tests en JUnit (artifacts:reports:junit).")
async def tests_run(ctx: Context) -> Outcome:
    suites = await test_suites(ctx)
    if suites is None:
        return Outcome.unknown("pipelines illisibles")
    if not suites:
        return Outcome.fail("aucun rapport de tests publié")
    return Outcome.ok(f"{sum(s['totalCount'] for s in suites)} tests publiés", suites=[s["name"] for s in suites])


@check("gitlab.integration_suite", Depends.LIVE, "Ajouter une suite d'intégration publiée en JUnit, nommée « integration ».")
async def integration_suite(ctx: Context) -> Outcome:
    suites = await test_suites(ctx)
    if suites is None:
        return Outcome.unknown("pipelines illisibles")
    found = [s["name"] for s in suites if re.search(r"integ|e2e|end.to.end", s["name"], re.IGNORECASE)]
    return Outcome.ok("suite d'intégration publiée", suites=found) if found else Outcome.fail("aucune suite d'intégration dans le rapport de tests")


@check("gitlab.dockerfile_lint", Depends.COMMIT, "Ajouter hadolint ou l'analyse IaC (KICS) à la CI.")
async def dockerfile_lint(ctx: Context) -> Outcome:
    dockerfiles = await ctx.find(r"(^|/)(Docker|Container)file[^/]*$")
    if dockerfiles is None:
        return Outcome.unknown("arborescence illisible")
    if not dockerfiles:
        return Outcome.not_applicable("aucun Dockerfile")
    jobs = await ci_match(ctx, r"hadolint|kics|iac[_-]sast|trivy.*config")
    if jobs is None:
        return Outcome.unknown("CI illisible")
    return Outcome.ok("Dockerfile analysés", jobs=jobs) if jobs else Outcome.fail(f"{len(dockerfiles)} Dockerfile non analysés")


@check("gitlab.secure_headers", Depends.LIVE, "Lancer le DAST et corriger les alertes d'en-têtes de sécurité.")
async def secure_headers(ctx: Context) -> Outcome:
    if not ctx.enterprise:
        return Outcome.unknown("DAST indisponible (GitLab sans licence Ultimate)")
    vulns, types = nodes(await ctx.project(), "vulnerabilities"), await ctx.artifact_types()
    if vulns is None or types is None:
        return Outcome.unknown("rapport de vulnérabilités illisible")
    if "dast" not in types:
        return Outcome.unknown("aucun rapport DAST récent")
    hits = [v["title"] for v in vulns if v["reportType"] == "DAST" and re.search(r"header|en-tête|hsts|csp|x-frame|x-content", v["title"], re.IGNORECASE)]
    return Outcome.fail(f"{len(hits)} alerte(s) d'en-têtes", titles=hits[:10]) if hits else Outcome.ok("DAST sans alerte d'en-têtes")


@check("gitlab.no_force_push", Depends.SETTINGS, "Désactiver « Allowed to force push » sur la branche par défaut.")
async def no_force_push(ctx: Context) -> Outcome:
    rule = await ctx.default_rule()
    if rule is None or not rule.get("branchProtection"):
        return Outcome.fail("branche par défaut non protégée")
    if rule["branchProtection"]["allowForcePush"]:
        return Outcome.fail("force push autorisé", allow_force_push=True)
    return Outcome.ok("force push interdit", allow_force_push=False)


@check("gitlab.secret_push_protection", Depends.SETTINGS, "Activer Secret push protection dans la configuration de sécurité du projet.")
async def secret_push_protection(ctx: Context) -> Outcome:
    if not ctx.enterprise:
        return Outcome.unknown("indisponible (GitLab sans licence Ultimate)")
    p = await ctx.project()
    enabled = (p or {}).get("secretPushProtectionEnabled")
    if enabled is None:
        return Outcome.unknown("réglage illisible")
    return Outcome.ok("secret push protection activée") if enabled else Outcome.fail("secret push protection désactivée")


@check("gitlab.reset_approvals_on_push", Depends.SETTINGS, "Cocher « Remove all approvals when commits are added ».")
async def reset_approvals_on_push(ctx: Context) -> Outcome:
    if not ctx.enterprise:
        return Outcome.unknown("règles d'approbation indisponibles (GitLab sans licence Premium)")
    settings = await ctx.approvals()
    if settings is None or "reset_approvals_on_push" not in settings:
        return Outcome.unknown("réglages d'approbation illisibles")
    if settings["reset_approvals_on_push"]:
        return Outcome.ok("approbations réinitialisées à chaque push")
    return Outcome.fail("les approbations survivent à un nouveau push")


@check("gitlab.pipeline_must_succeed", Depends.SETTINGS, "Cocher « Pipelines must succeed » dans les réglages de merge.")
async def pipeline_must_succeed(ctx: Context) -> Outcome:
    p = await ctx.project()
    if p is None:
        return Outcome.unknown("projet illisible")
    if p["onlyAllowMergeIfPipelineSucceeds"]:
        return Outcome.ok("merge seulement si le pipeline réussit")
    return Outcome.fail("merge possible avec un pipeline en échec")


@check("gitlab.approved_mrs", Depends.LIVE, "Faire approuver chaque MR par une autre personne que son auteur.")
async def approved_mrs(ctx: Context) -> Outcome:
    mrs = await ctx.merged_mrs()
    if mrs is None:
        return Outcome.unknown("merge requests illisibles")
    humans = [m for m in mrs if not (m.get("author") or {}).get("bot")]
    if not humans:
        return Outcome.not_applicable("aucune MR mergée en 90 jours")
    ok = [m for m in humans if {a["username"] for a in nodes(m, "approvedBy") or []} - {(m.get("author") or {}).get("username")}]
    share = len(ok) / len(humans)
    out = Outcome.ok if share >= 0.9 else Outcome.fail
    return out(f"{len(ok)}/{len(humans)} MR approuvées par un tiers", share=round(share, 2))


@check("gitlab.sast", Depends.COMMIT, "Inclure le template ou le composant SAST dans la CI.")
async def sast(ctx: Context) -> Outcome:
    jobs = await ci_match(ctx, r"(^|[-_])sast($|[-_])|semgrep|sonar|bandit|gosec|spotbugs|codeql")
    if jobs is None:
        return Outcome.unknown("CI illisible")
    return Outcome.ok("analyse statique dans la CI", jobs=jobs) if jobs else Outcome.fail("aucune analyse statique dans la CI")


@check("gitlab.dead_code", Depends.COMMIT, "Ajouter un détecteur de code mort à la CI (vulture, knip, deadcode…).")
async def dead_code(ctx: Context) -> Outcome:
    jobs = await ci_match(ctx, r"vulture|knip|ts-prune|deadcode|unused|dead[_-]code")
    if jobs is None:
        return Outcome.unknown("CI illisible")
    return Outcome.ok("détection de code mort dans la CI", jobs=jobs) if jobs else Outcome.fail("aucune détection de code mort")
