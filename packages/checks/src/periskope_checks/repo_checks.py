"""The 9 checks read from the repository's files at the analysed commit (read, never executed)."""
from __future__ import annotations

import re

from periskope_core.models import Outcome

from periskope_checks.context import NOT_PRODUCT, Context
from periskope_checks.registry import Depends, check

# Manifest → lock files that pin it.
LOCKS = {
    "package.json": ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json", "bun.lockb", "bun.lock"),
    "pyproject.toml": ("poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock", "requirements.txt"),
    "Pipfile": ("Pipfile.lock",),
    "go.mod": ("go.sum",),
    "Gemfile": ("Gemfile.lock",),
    "Cargo.toml": ("Cargo.lock",),
    "composer.json": ("composer.lock",),
    "build.gradle": ("gradle.lockfile",),
    "build.gradle.kts": ("gradle.lockfile",),
}
DOCKERFILE = r"(^|/)(Docker|Container)file[^/]*$"
PRECOMMIT = ".pre-commit-config.yaml"
SECURITY_HOOKS = re.compile(r"gitleaks|detect-secrets|trufflehog|bandit|semgrep|talisman|ggshield", re.IGNORECASE)
SECURITY_TEST = r"(auth|secur|crypt|permission|access|csrf|xss|sanitiz|password|token|session)"


@check("repo.patch_policy", Depends.COMMIT, "Décrire dans SECURITY.md comment et en combien de temps les failles sont corrigées.")
async def patch_policy(ctx: Context) -> Outcome:
    docs = await ctx.find(r"(^|/)(SECURITY|PATCH[_-]?POLICY|security[_-]policy)(\.md|\.rst|\.txt)?$")
    if docs is None:
        return Outcome.unknown("arborescence illisible")
    if not docs:
        return await ctx.partial("aucune politique de sécurité ou de patch") or Outcome.fail("aucune politique de sécurité ou de patch")
    texts = await ctx.files(docs[:3])
    hits = [p for p, t in texts.items() if re.search(r"patch|correctif|mise à jour|update|fix|délai|within|days|jours", t, re.IGNORECASE)]
    return Outcome.ok("politique de patch documentée", files=hits) if hits else Outcome.fail("SECURITY.md sans politique de patch", files=docs)


@check("repo.lockfiles", Depends.COMMIT, "Committer le fichier de verrouillage de chaque gestionnaire de dépendances.")
async def lockfiles(ctx: Context) -> Outcome:
    tree = await ctx.tree()
    if tree is None:
        return Outcome.unknown("arborescence illisible")
    paths = set(tree.paths)
    manifests = [p for p in paths if p.rsplit("/", 1)[-1] in LOCKS and not NOT_PRODUCT.search(p)]
    if not manifests:
        return await ctx.partial("aucun manifeste de dépendances") or Outcome.not_applicable("aucun manifeste de dépendances")
    missing = [m for m in manifests if not any(f"{m.rsplit('/', 1)[0] + '/' if '/' in m else ''}{lock}" in paths for lock in LOCKS[m.rsplit('/', 1)[-1]])]
    # A cut listing may hide a lock file (fail unsure) or another manifest (pass unsure).
    if missing:
        return await ctx.partial(f"verrouillage de {len(missing)} manifeste(s) non trouvé") or Outcome.fail(f"{len(missing)} manifeste(s) sans verrouillage")
    return await ctx.partial(f"{len(manifests)} manifeste(s) verrouillés, d'autres possibles") or Outcome.ok(
        f"{len(manifests)} manifeste(s) verrouillés", manifests=sorted(manifests)[:10])


@check("repo.pinning_images", Depends.COMMIT, "Épingler les images de base par tag de version ou par digest, jamais :latest.")
async def pinning_images(ctx: Context) -> Outcome:
    dockerfiles = await ctx.find(DOCKERFILE)
    if dockerfiles is None:
        return Outcome.unknown("arborescence illisible")
    if not dockerfiles:
        return await ctx.partial("aucun Dockerfile") or Outcome.not_applicable("aucun Dockerfile")
    texts = await ctx.files(dockerfiles[:10])
    stages: set[str] = set()
    loose = []
    for path, text in texts.items():
        for m in re.finditer(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", text, re.IGNORECASE | re.MULTILINE):
            image, alias = m.group(1), m.group(2)
            if image.lower() in stages or image == "scratch" or "$" in image:
                pass
            elif "@sha256:" not in image and (":" not in image.rsplit("/", 1)[-1] or image.endswith(":latest")):
                loose.append(f"{path}: {image}")
            if alias:
                stages.add(alias.lower())
    if not texts:
        return Outcome.unknown("Dockerfile illisibles")
    if loose:
        return Outcome.fail(f"{len(loose)} image(s) non épinglée(s)", images=loose[:10])
    return await ctx.partial(f"{len(texts)} Dockerfile épinglés, d'autres possibles") or Outcome.ok("images de base épinglées")


@check("repo.security_champion", Depends.COMMIT, "Désigner un référent sécurité dans CODEOWNERS (section [Security] ou fichiers sensibles).")
async def security_champion(ctx: Context) -> Outcome:
    owners = await ctx.find(r"^(\.gitlab/|docs/)?CODEOWNERS$")
    if owners is None:
        return Outcome.unknown("arborescence illisible")
    if not owners:
        # CODEOWNERS has fixed paths, read by name: its absence is certain unless that read failed.
        return Outcome.fail("aucun fichier CODEOWNERS") if await ctx.has("CODEOWNERS") is not None else Outcome.unknown("fichiers du dépôt illisibles")
    text = "\n".join((await ctx.files(owners)).values())
    if re.search(r"secur|sécu|appsec|champion|SECURITY\.md", text, re.IGNORECASE):
        # The handles of the security lines (or of the [Security] section): the critical-vulnerability alerts name them.
        handles = sorted(set(re.findall(r"@[\w.\-/]+", "\n".join(security_lines(text)))))
        return Outcome.ok(f"référent sécurité désigné dans CODEOWNERS{' : ' + ', '.join(handles[:5]) if handles else ''}", referents=handles)
    return Outcome.fail("CODEOWNERS sans référent sécurité")


def security_lines(text: str) -> list[str]:
    """The CODEOWNERS lines about security: those of a [Security…] section, and any line naming security itself."""
    out, section = [], False
    for line in text.splitlines():
        if line.lstrip().startswith("["):
            section = bool(re.search(r"secur|sécu|appsec", line, re.IGNORECASE))
        if section or re.search(r"secur|sécu|appsec|champion|SECURITY\.md", line, re.IGNORECASE):
            out.append(line)
    return out


async def test_files(ctx: Context, kind: str) -> Outcome:
    tests = await ctx.find(rf"(^|/)(tests?|spec|__tests__|{kind})(/|_).*{SECURITY_TEST}|{SECURITY_TEST}[^/]*[._-](test|spec)\.\w+$|(^|/)test_[^/]*{SECURITY_TEST}")
    if tests is None:
        return Outcome.unknown("arborescence illisible")
    if kind != "unit":
        tests = [t for t in tests if re.search(r"integ|e2e|end.to.end|functional", t, re.IGNORECASE)]
    if tests:
        return Outcome.ok(f"{len(tests)} fichier(s) de test de sécurité", files=tests[:10])
    return await ctx.partial("aucun test visant les composants de sécurité") or Outcome.fail("aucun test visant les composants de sécurité")


@check("repo.security_unit_tests", Depends.COMMIT, "Écrire des tests unitaires sur l'authentification, les droits et la validation des entrées.")
async def security_unit_tests(ctx: Context) -> Outcome:
    return await test_files(ctx, "unit")


@check("repo.security_integration_tests", Depends.COMMIT, "Écrire des tests d'intégration qui vérifient les contrôles d'accès de bout en bout.")
async def security_integration_tests(ctx: Context) -> Outcome:
    return await test_files(ctx, "integration")


@check("repo.precommit_security", Depends.COMMIT, "Ajouter gitleaks ou detect-secrets à .pre-commit-config.yaml.")
async def precommit_security(ctx: Context) -> Outcome:
    present = await ctx.has(PRECOMMIT)
    if present is None:
        return Outcome.unknown("fichiers du dépôt illisibles")
    if not present:
        return Outcome.fail("aucun .pre-commit-config.yaml")
    text = (await ctx.files([PRECOMMIT])).get(PRECOMMIT, "")
    hooks = sorted({m.lower() for m in SECURITY_HOOKS.findall(text)})
    return Outcome.ok("hooks pre-commit de sécurité", hooks=hooks) if hooks else Outcome.fail("pre-commit sans hook de sécurité")


@check("repo.gitignore", Depends.COMMIT, "Ajouter un .gitignore à la racine du dépôt.")
async def gitignore(ctx: Context) -> Outcome:
    present = await ctx.has(".gitignore")
    if present is None:
        return Outcome.unknown("fichiers du dépôt illisibles")
    return Outcome.ok(".gitignore présent") if present else Outcome.fail("aucun .gitignore à la racine")


@check("repo.precommit_lint", Depends.COMMIT, "Ajouter un .pre-commit-config.yaml avec un linter, ou un .editorconfig.")
async def precommit_lint(ctx: Context) -> Outcome:
    if await ctx.has(PRECOMMIT) is None:
        return Outcome.unknown("fichiers du dépôt illisibles")
    found = [f for f in (PRECOMMIT, ".editorconfig", "lefthook.yml", ".husky/pre-commit") if await ctx.has(f)]
    return Outcome.ok("linting local configuré", files=found) if found else Outcome.fail("aucun linting local configuré")
