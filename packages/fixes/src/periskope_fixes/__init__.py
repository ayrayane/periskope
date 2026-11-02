"""Fixes a person applies with one click, as themselves: a GitLab setting changed in place, or files proposed in a merge
request (never a push to the default branch). Each fix shows what it will change before anything is changed."""
from __future__ import annotations

import json
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import quote

from periskope_core.catalog import FIXES as GUIDES
from periskope_core.patterns import SECRETISH

from periskope_fixes.gitlab import FixError, UserGitLab

__all__ = ["FIXES", "Fix", "FixError", "Target", "UserGitLab"]


@dataclass(frozen=True)
class Target:
    project_id: int          # GitLab id
    path: str
    default_branch: str
    username: str            # GitLab login of the person who clicked (CODEOWNERS)
    link: str                # the project's page in Periskope, quoted in merge requests
    enterprise: bool = True  # CE recreates a protection instead of editing it in place


Preview = dict[str, Any]


@dataclass(frozen=True)
class Fix:
    check: str
    kind: Literal["setting", "mr"]
    label: str
    needs: str | None
    preview: Callable[[UserGitLab, Target], Awaitable[Preview]]
    apply: Callable[[UserGitLab, Target], Awaitable[dict[str, Any]]]


FIXES: dict[str, Fix] = {}


def fix(check: str, kind: Literal["setting", "mr"], label: str, needs: str | None = None):
    def register(pair: tuple) -> tuple:
        FIXES[check] = Fix(check, kind, label, needs, *pair)
        return pair
    return register


# ---------------------------------------------------------------------------------------------------------------- settings

LEVELS = {0: "personne", 30: "Developers et Maintainers", 40: "Maintainers", 60: "Admins"}


def who(levels: list[dict]) -> str:
    return ", ".join(LEVELS.get(level.get("access_level"), str(level.get("access_level"))) for level in levels) or "personne"


async def protection(gl: UserGitLab, t: Target) -> dict | None:
    return await gl.call("GET", f"/projects/{t.project_id}/protected_branches/{quote(t.default_branch, safe='')}", ok_404=True)


async def protect(gl: UserGitLab, t: Target, current: dict | None, *, push_none: bool) -> None:
    """Protect the default branch with pushes closed (or as they were) and force push off. CE cannot edit a protection in
    place, so it is recreated; a failed recreation puts the previous one back."""
    branch = quote(t.default_branch, safe="")
    if current and t.enterprise:
        body: dict[str, Any] = {"allow_force_push": False}
        if push_none:
            body["allowed_to_push"] = [{"id": lv["id"], "_destroy": True} for lv in current.get("push_access_levels", []) if lv.get("access_level") != 0]
            if not any(lv.get("access_level") == 0 for lv in current.get("push_access_levels", [])):
                body["allowed_to_push"].append({"access_level": 0})
        await gl.call("PATCH", f"/projects/{t.project_id}/protected_branches/{branch}", json=body)
        return
    push = 0 if push_none or not current else min((lv["access_level"] for lv in current.get("push_access_levels", [])), default=40)
    merge = min((lv["access_level"] for lv in (current or {}).get("merge_access_levels", [])), default=40)
    if current:
        await gl.call("DELETE", f"/projects/{t.project_id}/protected_branches/{branch}")
    try:
        await gl.call("POST", f"/projects/{t.project_id}/protected_branches",
                      json={"name": t.default_branch, "push_access_level": push, "merge_access_level": merge, "allow_force_push": False})
    except FixError:
        if current:  # never leave the branch unprotected
            await gl.call("POST", f"/projects/{t.project_id}/protected_branches", json={
                "name": t.default_branch, "push_access_level": min((lv["access_level"] for lv in current.get("push_access_levels", [])), default=40),
                "merge_access_level": merge, "allow_force_push": bool(current.get("allow_force_push"))})
        raise


async def _push_preview(gl: UserGitLab, t: Target) -> Preview:
    pb = await protection(gl, t)
    before = "branche non protégée" if pb is None else f"push direct : {who(pb.get('push_access_levels', []))}"
    return {"summary": f"Protéger « {t.default_branch} » : plus aucun push direct, les changements passent par des merge requests.",
            "changes": [{"what": f"Push direct sur {t.default_branch}", "before": before, "after": "personne (merge : Maintainers)"}]}


async def _push_apply(gl: UserGitLab, t: Target) -> dict:
    await protect(gl, t, await protection(gl, t), push_none=True)
    return {"done": f"« {t.default_branch} » est protégée : plus de push direct."}


fix("gitlab.protected_branch_no_push", "setting", "Interdire le push direct sur la branche principale")((_push_preview, _push_apply))


async def _force_preview(gl: UserGitLab, t: Target) -> Preview:
    pb = await protection(gl, t)
    before = "branche non protégée" if pb is None else ("autorisé" if pb.get("allow_force_push") else "interdit")
    return {"summary": f"Interdire le force push sur « {t.default_branch} ».", "changes": [{"what": "Force push", "before": before, "after": "interdit"}]}


async def _force_apply(gl: UserGitLab, t: Target) -> dict:
    await protect(gl, t, await protection(gl, t), push_none=False)
    return {"done": f"Le force push est interdit sur « {t.default_branch} »."}


fix("gitlab.no_force_push", "setting", "Interdire le force push")((_force_preview, _force_apply))


def project_setting(check: str, label: str, field: str, value: Any, what: str, shown: Callable[[Any], str], needs: str | None = None) -> None:
    async def preview(gl: UserGitLab, t: Target) -> Preview:
        p = await gl.call("GET", f"/projects/{t.project_id}")
        return {"summary": label + ".", "changes": [{"what": what, "before": shown(p.get(field)), "after": shown(value)}]}

    async def apply(gl: UserGitLab, t: Target) -> dict:
        await gl.call("PUT", f"/projects/{t.project_id}", json={field: value})
        return {"done": f"{what} : {shown(value)}."}
    fix(check, "setting", label, needs)((preview, apply))


project_setting("gitlab.pipeline_must_succeed", "N'autoriser le merge que si le pipeline réussit", "only_allow_merge_if_pipeline_succeeds", True,
                "Merge avec un pipeline en échec", lambda v: "bloqué" if v else "possible")
project_setting("gitlab.visibility", "Passer le projet en privé", "visibility", "private", "Visibilité",
                lambda v: {"private": "privé", "internal": "interne", "public": "public"}.get(v, str(v)))


async def _approvals_preview(gl: UserGitLab, t: Target) -> Preview:
    a = await gl.call("GET", f"/projects/{t.project_id}/approvals")
    return {"summary": "Remettre à zéro les approbations dès qu'un commit est ajouté à la merge request.",
            "changes": [{"what": "Approbations après un nouveau commit", "before": "remises à zéro" if a.get("reset_approvals_on_push") else "conservées", "after": "remises à zéro"}]}


async def _approvals_apply(gl: UserGitLab, t: Target) -> dict:
    await gl.call("POST", f"/projects/{t.project_id}/approvals", json={"reset_approvals_on_push": True})
    return {"done": "Les approbations sont remises à zéro à chaque nouveau commit."}


fix("gitlab.reset_approvals_on_push", "setting", "Remettre à zéro les approbations à chaque push", "Premium")((_approvals_preview, _approvals_apply))


async def _required_preview(gl: UserGitLab, t: Target) -> Preview:
    a = await gl.call("GET", f"/projects/{t.project_id}/approvals")
    return {"summary": "Exiger une approbation par une autre personne que l'auteur de la merge request.",
            "changes": [{"what": "Approbations requises", "before": str(a.get("approvals_before_merge") or 0), "after": "1, auteur exclu"}]}


async def _required_apply(gl: UserGitLab, t: Target) -> dict:
    await gl.call("POST", f"/projects/{t.project_id}/approvals", json={"merge_requests_author_approval": False})
    await gl.call("POST", f"/projects/{t.project_id}/approval_rules", json={"name": "Relecture (Periskope)", "approvals_required": 1})
    return {"done": "Chaque merge request demande l'approbation d'une autre personne que son auteur."}


fix("gitlab.approvals_required", "setting", "Exiger une approbation, auteur exclu", "Premium")((_required_preview, _required_apply))


async def _spp_preview(gl: UserGitLab, t: Target) -> Preview:
    return {"summary": "Refuser tout push qui contient un secret connu.",
            "changes": [{"what": "Secret push protection", "before": "désactivée", "after": "activée"}]}


async def _spp_apply(gl: UserGitLab, t: Target) -> dict:
    await gl.call("PUT", f"/projects/{t.project_id}/security_settings", json={"secret_push_protection_enabled": True})
    return {"done": "Les push contenant un secret sont désormais refusés."}


fix("gitlab.secret_push_protection", "setting", "Activer la secret push protection", "Ultimate")((_spp_preview, _spp_apply))


async def _schedule_preview(gl: UserGitLab, t: Target) -> Preview:
    return {"summary": f"Lancer le pipeline de « {t.default_branch} » chaque nuit à 2 h (heure de Paris).",
            "changes": [{"what": "Pipeline planifié", "before": "aucun pipeline quotidien actif", "after": "chaque jour à 02:00"}]}


async def _schedule_apply(gl: UserGitLab, t: Target) -> dict:
    await gl.call("POST", f"/projects/{t.project_id}/pipeline_schedules", json={
        "description": "Pipeline nocturne (ajouté depuis Periskope)", "ref": t.default_branch, "cron": "0 2 * * *",
        "cron_timezone": "Europe/Paris", "active": True})
    return {"done": "Le pipeline tourne désormais chaque nuit à 2 h."}


fix("gitlab.nightly_schedule", "setting", "Planifier un pipeline chaque nuit")((_schedule_preview, _schedule_apply))


async def clear_secrets(gl: UserGitLab, t: Target) -> list[str]:
    variables = await gl.call("GET", f"/projects/{t.project_id}/variables", params={"per_page": 100}) or []
    return [v["key"] for v in variables if SECRETISH.search(v["key"]) and v.get("variable_type") != "file" and not (v.get("masked") or v.get("hidden"))]


async def _mask_preview(gl: UserGitLab, t: Target) -> Preview:
    keys = await clear_secrets(gl, t)
    return {"summary": "Masquer dans les journaux de CI les variables qui portent un secret.",
            "changes": [{"what": f"Variable {k}", "before": "visible dans les journaux", "after": "masquée"} for k in keys]
            or [{"what": "Variables", "before": "toutes déjà masquées", "after": "inchangé"}]}


async def _mask_apply(gl: UserGitLab, t: Target) -> dict:
    masked, refused = [], []
    for key in await clear_secrets(gl, t):
        try:
            await gl.call("PUT", f"/projects/{t.project_id}/variables/{quote(key, safe='')}", json={"masked": True})
            masked.append(key)
        except FixError:
            refused.append(key)
    text = f"Masquées : {', '.join(masked) or 'aucune'}."
    if refused:
        text += f" GitLab refuse de masquer {', '.join(refused)} (valeur trop courte ou caractères non masquables) : régénérez-les."
    return {"done": text}


fix("gitlab.masked_secrets", "setting", "Masquer les variables sensibles")((_mask_preview, _mask_apply))


# ------------------------------------------------------------------------------------------------------- merge requests

LOCAL_CI = ".gitlab/ci/periskope-security.yml"
TEMPLATES = {"gitlab.secret_detection": "Jobs/Secret-Detection.gitlab-ci.yml", "gitlab.sast": "Jobs/SAST.gitlab-ci.yml",
             "gitlab.dockerfile_lint": "Jobs/SAST-IaC.gitlab-ci.yml"}
JOBS = {"gitlab.image_secret_scan": GUIDES["gitlab.image_secret_scan"]["snippet"]["code"], "gitlab.sbom_artifact": GUIDES["gitlab.sbom_artifact"]["snippet"]["code"]}


def security_ci(enabled: set[str]) -> str:
    """The CI file Periskope owns in the repository: every security job a fix added, regenerated as a whole."""
    out = ["# Security jobs added from Periskope. Each block says which check it answers; edit freely.", ""]
    templates = [c for c in TEMPLATES if c in enabled]
    if templates:
        out.append("include:")
        out += [f"  # periskope: {c}\n  - template: {TEMPLATES[c]}" for c in templates]
        out.append("")
    for c, job in JOBS.items():
        if c in enabled:
            out += [f"# periskope: {c}", job.rstrip(), ""]
    return "\n".join(out)


def with_include(ci: str) -> str | None:
    """The project's .gitlab-ci.yml including the security file, or None when its include cannot be edited safely."""
    line = f"  - local: {LOCAL_CI}"
    if LOCAL_CI in ci:
        return ci
    if re.search(r"(?m)^include:\s*$", ci):
        return re.sub(r"(?m)^include:\s*$", "include:\n" + line, ci, count=1)
    if re.search(r"(?m)^include:", ci):
        return None  # a single string or a flow list: leave the edit to a human
    return f"include:\n{line}\n\n{ci}"


async def ci_files(gl: UserGitLab, t: Target, add: set[str]) -> tuple[dict[str, str], str]:
    current = await gl.raw_file(t.project_id, LOCAL_CI, t.default_branch) or ""
    enabled = set(re.findall(r"# periskope: (\S+)", current)) | add
    files = {LOCAL_CI: security_ci(enabled)}
    ci = await gl.raw_file(t.project_id, ".gitlab-ci.yml", t.default_branch)
    note = ""
    if ci is None:
        files[".gitlab-ci.yml"] = f"stages: [build, test]\n\ninclude:\n  - local: {LOCAL_CI}\n"
    elif (edited := with_include(ci)) is None:
        note = f"Votre .gitlab-ci.yml a déjà un include sur une seule ligne : ajoutez-y `local: {LOCAL_CI}` à la main."
    elif edited != ci:
        files[".gitlab-ci.yml"] = edited
    return files, note


async def open_mr(gl: UserGitLab, t: Target, check: str, files: dict[str, str], title: str, why: str, note: str = "") -> dict:
    """One merge request per fix, on its own branch; an open one for the same fix is returned instead of a second."""
    branch = "periskope/" + check.replace(".", "-")
    opened = await gl.call("GET", f"/projects/{t.project_id}/merge_requests", params={"state": "opened", "source_branch": branch})
    if opened:
        return {"done": "Une merge request est déjà ouverte pour cette correction.", "url": opened[0]["web_url"]}
    if await gl.call("GET", f"/projects/{t.project_id}/repository/branches/{quote(branch, safe='')}", ok_404=True):
        branch += "-" + datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    actions = []
    for path, content in files.items():
        exists = await gl.raw_file(t.project_id, path, t.default_branch) is not None
        actions.append({"action": "update" if exists else "create", "file_path": path, "content": content})
    await gl.call("POST", f"/projects/{t.project_id}/repository/commits", json={
        "branch": branch, "start_branch": t.default_branch, "commit_message": f"{title}\n\nProposé depuis Periskope : {t.link}", "actions": actions})
    description = f"{why}\n\n{note}\n\nProposée par @{t.username} depuis Periskope ({t.link}). Relisez, adaptez si besoin, puis mergez.".replace("\n\n\n", "\n\n")
    mr = await gl.call("POST", f"/projects/{t.project_id}/merge_requests", json={
        "source_branch": branch, "target_branch": t.default_branch, "title": title, "description": description, "remove_source_branch": True})
    return {"done": "Merge request ouverte : relisez-la puis mergez-la.", "url": mr["web_url"]}


def mr_fix(check: str, label: str, title: str, why: str, build: Callable[[UserGitLab, Target], Awaitable[tuple[dict[str, str], str]]]) -> None:
    async def preview(gl: UserGitLab, t: Target) -> Preview:
        files, note = await build(gl, t)
        return {"summary": why, "files": [{"path": p, "content": c} for p, c in files.items()], "note": note}

    async def apply(gl: UserGitLab, t: Target) -> dict:
        files, note = await build(gl, t)
        return await open_mr(gl, t, check, files, title, why, note)
    fix(check, "mr", label)((preview, apply))


def ci_fix(check: str, label: str, why: str, add: set[str] | None = None) -> None:
    async def build(gl: UserGitLab, t: Target) -> tuple[dict[str, str], str]:
        return await ci_files(gl, t, add or {check})
    mr_fix(check, label, f"CI : {label.lower()}", why, build)


ci_fix("gitlab.secret_detection", "Ajouter la détection de secrets", "Ajoute le job de détection de secrets de GitLab à la CI.")
ci_fix("gitlab.sast", "Ajouter l'analyse statique (SAST)", "Ajoute l'analyse statique de GitLab à la CI.")
ci_fix("gitlab.dockerfile_lint", "Analyser les Dockerfile et l'IaC", "Ajoute l'analyse IaC de GitLab (KICS), qui couvre aussi les Dockerfile.")
ci_fix("gitlab.image_secret_scan", "Scanner les images à la recherche de secrets", "Ajoute un job Trivy qui cherche des secrets dans l'image construite.")
ci_fix("gitlab.sbom_artifact", "Publier un SBOM CycloneDX", "Ajoute un job qui produit le SBOM CycloneDX du dépôt et le publie comme rapport.")
ci_fix("gitlab.ci_defined", "Créer une CI de sécurité minimale", "Crée une CI avec la détection de secrets et l'analyse statique, à compléter par le build et les tests du projet.",
       {"gitlab.secret_detection", "gitlab.sast"})


def new_file(check: str, label: str, path: str, why: str, content: Callable[[Target], str], also: tuple[str, ...] = ()) -> None:
    async def build(gl: UserGitLab, t: Target) -> tuple[dict[str, str], str]:
        for p in (path, *also):
            if await gl.raw_file(t.project_id, p, t.default_branch) is not None:
                raise FixError(f"{p} existe déjà dans le dépôt : complétez-le à la main avec le guide « Comment corriger ».", 409)
        return {path: content(t)}, ""
    mr_fix(check, label, f"Ajouter {path}", why, build)


def snippet(check: str) -> str:
    return GUIDES[check]["snippet"]["code"]


new_file("repo.patch_policy", "Ajouter une politique de sécurité (SECURITY.md)", "SECURITY.md",
         "Ajoute une politique de sécurité : comment signaler une faille et en combien de temps elle est corrigée. Adaptez l'adresse et les délais.",
         lambda t: snippet("repo.patch_policy"), also=("docs/SECURITY.md", ".gitlab/SECURITY.md"))
new_file("repo.security_champion", "Désigner un référent sécurité (CODEOWNERS)", ".gitlab/CODEOWNERS",
         "Désigne un référent sécurité qui relit les fichiers sensibles. Remplacez la personne proposée si besoin.",
         lambda t: snippet("repo.security_champion").replace("@referent-securite", f"@{t.username}"), also=("CODEOWNERS", "docs/CODEOWNERS"))
new_file("repo.gitignore", "Ajouter un .gitignore", ".gitignore", "Ajoute un .gitignore qui écarte les secrets locaux et les dossiers de build.",
         lambda t: "# Secrets and local settings\n.env\n.env.*\n*.pem\n*.key\n\n# Build output and dependencies\nnode_modules/\ndist/\nbuild/\n__pycache__/\n.venv/\n")
new_file("gitlab.renovate", "Configurer Renovate", "renovate.json",
         "Ajoute la configuration Renovate. Il faut aussi que le runner Renovate de la plateforme couvre ce projet.", lambda t: snippet("gitlab.renovate"))
new_file("repo.precommit_lint", "Ajouter un .editorconfig", ".editorconfig",
         "Ajoute un .editorconfig pour un style de code commun à toute l'équipe.",
         lambda t: "root = true\n\n[*]\ncharset = utf-8\nend_of_line = lf\ninsert_final_newline = true\ntrim_trailing_whitespace = true\nindent_style = space\nindent_size = 2\n")


async def _automerge_build(gl: UserGitLab, t: Target) -> tuple[dict[str, str], str]:
    current = await gl.raw_file(t.project_id, "renovate.json", t.default_branch)
    if current is None:
        return {"renovate.json": snippet("gitlab.automerge")}, ""
    try:
        config = json.loads(current)
    except ValueError as e:
        raise FixError("renovate.json n'est pas du JSON valide (commentaires ?) : modifiez-le à la main.", 409) from e
    rule = {"matchUpdateTypes": ["minor", "patch"], "automerge": True, "platformAutomerge": True}
    if any(r.get("automerge") for r in config.get("packageRules", [])):
        raise FixError("renovate.json prévoit déjà un automerge.", 409)
    config.setdefault("packageRules", []).append(rule)
    return {"renovate.json": json.dumps(config, indent=2, ensure_ascii=False) + "\n"}, ""


mr_fix("gitlab.automerge", "Autoriser Renovate à merger les mises à jour mineures", "Renovate : automerge des mises à jour mineures",
       "Laisse Renovate merger seul les mises à jour mineures et correctives, une fois le pipeline vert.", _automerge_build)


async def _precommit_build(gl: UserGitLab, t: Target) -> tuple[dict[str, str], str]:
    current = await gl.raw_file(t.project_id, ".pre-commit-config.yaml", t.default_branch)
    block = snippet("repo.precommit_security").split("repos:\n", 1)[1]
    if current is None:
        return {".pre-commit-config.yaml": snippet("repo.precommit_security")}, ""
    if "gitleaks" in current:
        raise FixError("gitleaks est déjà dans .pre-commit-config.yaml.", 409)
    if not re.search(r"(?m)^repos:\s*$", current):
        raise FixError(".pre-commit-config.yaml n'a pas de liste repos: éditable sans risque : ajoutez gitleaks à la main.", 409)
    return {".pre-commit-config.yaml": re.sub(r"(?m)^repos:\s*$", "repos:\n" + block.rstrip("\n"), current, count=1)}, ""


mr_fix("repo.precommit_security", "Ajouter gitleaks aux hooks pre-commit", "pre-commit : détection de secrets (gitleaks)",
       "Ajoute gitleaks aux hooks pre-commit : un secret est bloqué avant même le commit.", _precommit_build)
