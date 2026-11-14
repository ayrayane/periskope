"""The 7 checks read from what Periskope already stores: the Dependency-Track trees and the vulnerability ledger."""
from __future__ import annotations

from collections import Counter
from datetime import timedelta
from typing import Any

from periskope_core.models import Outcome

from periskope_checks.context import LIVE_DAYS, Context
from periskope_checks.registry import Depends, check


def unlinked(ctx: Context) -> Outcome | None:
    """Never a failure: Dependency-Track not read, or following no project of this instance, is said plainly."""
    if ctx.tracking is None:
        return Outcome.unknown("suivi des versions non lu")
    if not ctx.tracking["dt"]:
        return Outcome.unknown("Dependency-Track non relié à cette instance")
    return None


def ledger(ctx: Context) -> tuple[list[dict[str, Any]], Outcome | None]:
    if ctx.tracking is None:
        return [], Outcome.unknown("registre des vulnérabilités non lu")
    if not ctx.tracking["followed"]:
        return [], Outcome.unknown("vulnérabilités du projet non mesurées : ni Dependency-Track, ni rapport GitLab")
    return ctx.tracking["ledger"], None


def label(b: dict[str, Any]) -> str:
    return f"{b['tree']} : {b['version'] or 'sans version'}"


async def production(ctx: Context) -> tuple[list[dict[str, Any]], Outcome | None]:
    """The project's versions running in production: in a « prod » tree or in a delivery (a tree without environment).
    Without any, the GitLab topic says whether one was expected."""
    if (skip := unlinked(ctx)) is not None:
        return [], skip
    bricks = [b for b in ctx.tracking["bricks"] if b["running"] and b["env"] in ("prod", None)]
    if bricks:
        return bricks, None
    topics = {"prod", "test", "dev"} & set((await ctx.project() or {}).get("topics") or [])
    if "prod" in topics:
        return [], Outcome.fail("déclaré en production (topic prod) mais absent des arbres de production de Dependency-Track")
    if topics:
        return [], Outcome.not_applicable("projet hors production", topics=sorted(topics))
    return [], Outcome.unknown("ni version en production dans Dependency-Track, ni topic prod, test ou dev sur le projet")


@check("dt.sca", Depends.LIVE, "Envoyer le SBOM de chaque version à Dependency-Track, ou activer Dependency Scanning dans la CI.")
async def sca(ctx: Context) -> Outcome:
    if sboms := ctx.dt_sboms():
        return Outcome.ok("dépendances analysées par Dependency-Track", versions=sboms)
    types = await ctx.artifact_types()
    if types and "dependency_scanning" in types:
        return Outcome.ok("dépendances analysées par Dependency Scanning")
    if types is None or ctx.tracking is None:
        return Outcome.unknown("artefacts ou suivi des versions illisibles")
    return Outcome.fail("aucune analyse des dépendances : ni SBOM dans Dependency-Track, ni rapport Dependency Scanning récent")


@check("ledger.sla", Depends.LIVE, "Corriger, ou traiter dans Dependency-Track ou GitLab, les vulnérabilités dont le délai est dépassé.")
async def sla(ctx: Context) -> Outcome:
    rows, skip = ledger(ctx)
    if skip:
        return skip
    late = Counter(r["priority"] or "?" for r in rows if r["closed_at"] is None and r["deadline_at"] and r["deadline_at"] < ctx.now)
    if late:
        return Outcome.fail(f"{late.total()} vulnérabilité(s) ouverte(s) hors délai", by_priority=dict(late))
    return Outcome.ok("aucune vulnérabilité ouverte hors délai", open=sum(r["closed_at"] is None for r in rows))


@check("ledger.fix_rate", Depends.LIVE, "Faire mesurer les vulnérabilités du projet : SBOM dans Dependency-Track ou rapports de sécurité GitLab.")
async def fix_rate(ctx: Context) -> Outcome:
    """A measurement, not a threshold: the deadlines are judged by ledger.sla."""
    rows, skip = ledger(ctx)
    if skip:
        return skip
    since = ctx.now - timedelta(days=LIVE_DAYS)
    fixed = sum(r["closed_at"] is not None and r["closed_at"] >= since for r in rows)
    still = sum(r["closed_at"] is None for r in rows)
    if not fixed + still:
        return Outcome.not_applicable(f"aucune vulnérabilité sur {LIVE_DAYS} jours")
    return Outcome.ok(f"taux de correction mesuré : {fixed} corrigée(s) en {LIVE_DAYS} jours, {still} ouverte(s) ({round(100 * fixed / (fixed + still))} %)",
                      fixed=fixed, open=still)


@check("dt.prod_component", Depends.LIVE, "Déclarer la version en production du projet dans l'arbre de production de Dependency-Track.")
async def prod_component(ctx: Context) -> Outcome:
    bricks, skip = await production(ctx)
    return skip or Outcome.ok("composant suivi en production", versions=sorted(map(label, bricks)))


@check("dt.prod_artifact", Depends.LIVE, "Donner sa version à chaque brique en production dans Dependency-Track.")
async def prod_artifact(ctx: Context) -> Outcome:
    bricks, skip = await production(ctx)
    if skip:
        return skip
    if missing := sorted(b["tree"] for b in bricks if not b["version"]):
        return Outcome.fail("brique en production sans version", trees=missing)
    return Outcome.ok("version en production connue", versions=sorted(map(label, bricks)))


@check("dt.prod_dependencies", Depends.LIVE, "Envoyer à Dependency-Track le SBOM de chaque version en production.")
async def prod_dependencies(ctx: Context) -> Outcome:
    bricks, skip = await production(ctx)
    if skip:
        return skip
    if missing := sorted(label(b) for b in bricks if not b["sbom"]):
        return Outcome.fail("version en production sans SBOM", versions=missing)
    return Outcome.ok("dépendances des versions en production connues", versions=sorted(map(label, bricks)))


@check("dt.same_artifact", Depends.LIVE, "Déployer en production, par digest, la version déjà déployée en test ou en dev.")
async def same_artifact(ctx: Context) -> Outcome:
    """A delivery has no test environment of its own: only the « prod » trees are judged."""
    if (skip := unlinked(ctx)) is not None:
        return skip
    bricks = ctx.tracking["bricks"]
    prod = [b for b in bricks if b["running"] and b["env"] == "prod"]
    if not prod:
        return Outcome.unknown("aucune version du projet dans un arbre de production de Dependency-Track")
    if by_tag := sorted(label(b) for b in prod if b["by_tag"]):
        return Outcome.fail("déployé par tag en production : l'image peut changer sans changer de version", versions=by_tag)
    # Stopped versions count: the test tree has usually moved on when production catches up.
    tested = {b["version"] for b in bricks if b["env"] in ("test", "dev")}
    if untested := sorted(label(b) for b in prod if not b["version"] or b["version"] not in tested):
        return Outcome.fail("version en production jamais vue en test ni en dev", versions=untested)
    return Outcome.ok("les versions en production sont passées par test ou dev", versions=sorted(map(label, prod)))
