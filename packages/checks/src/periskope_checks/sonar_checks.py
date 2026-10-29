"""The 7 checks read from the instance's SonarQube."""
from __future__ import annotations

from datetime import datetime, timedelta

from periskope_core.models import Outcome

from periskope_checks.context import Context
from periskope_checks.registry import Depends, check

RECENT_DAYS = 30
MAX_DUPLICATION = 5.0
MIN_HOTSPOTS_REVIEWED = 80.0
SECURITY_METRICS = {"security_rating", "new_security_rating", "vulnerabilities", "new_vulnerabilities",
                    "security_hotspots_reviewed", "new_security_hotspots_reviewed", "security_review_rating", "new_security_review_rating"}


def unconfigured(ctx: Context) -> Outcome | None:
    """Never a failure: SonarQube absent for the instance or the project is said plainly."""
    if ctx.sonar is None:
        return Outcome.unknown("SonarQube non configuré pour cette instance")
    if not ctx.sonar_key:
        return Outcome.unknown("SonarQube non configuré pour ce projet")
    return None


async def measures(ctx: Context) -> tuple[dict[str, float] | None, Outcome | None]:
    if (skip := unconfigured(ctx)) is not None:
        return None, skip
    found = await ctx.sonar_measures()
    if found is None:
        return None, Outcome.unknown(f"projet {ctx.sonar_key} absent de SonarQube")
    return found, None


@check("sonar.false_positive", Depends.SONAR, "Trier les résultats SonarQube : marquer les faux positifs et revoir les hotspots.")
async def false_positive(ctx: Context) -> Outcome:
    found, skip = await measures(ctx)
    if skip:
        return skip
    treated = await ctx.sonar_treated()
    if treated is None:
        return Outcome.unknown("issues SonarQube illisibles")
    reviewed = found.get("security_hotspots_reviewed", 0)
    if treated or reviewed > 0:
        return Outcome.ok("résultats triés", treated_issues=treated, hotspots_reviewed=reviewed)
    if not found.get("vulnerabilities") and not found.get("security_hotspots"):
        return Outcome.not_applicable("aucun résultat de sécurité à trier")
    return Outcome.fail("aucun résultat trié (faux positif, accepté ou hotspot revu)")


@check("sonar.security_gate", Depends.SONAR, "Ajouter une condition de sécurité (security rating ou hotspots revus) à la quality gate.")
async def security_gate(ctx: Context) -> Outcome:
    if (skip := unconfigured(ctx)) is not None:
        return skip
    conditions = await ctx.sonar_gate()
    if conditions is None:
        return Outcome.unknown("quality gate illisible")
    security = sorted({c["metric"] for c in conditions} & SECURITY_METRICS)
    return Outcome.ok("quality gate avec condition de sécurité", metrics=security) if security else Outcome.fail("quality gate sans condition de sécurité")


@check("sonar.hotspots_reviewed", Depends.SONAR, "Revoir les security hotspots dans SonarQube (au moins 80 %).")
async def hotspots_reviewed(ctx: Context) -> Outcome:
    found, skip = await measures(ctx)
    if skip:
        return skip
    if not found.get("security_hotspots"):
        return Outcome.not_applicable("aucun security hotspot")
    reviewed = found.get("security_hotspots_reviewed", 0)
    out = Outcome.ok if reviewed >= MIN_HOTSPOTS_REVIEWED else Outcome.fail
    return out(f"{reviewed:.0f} % des hotspots revus", reviewed=reviewed)


@check("sonar.metrics", Depends.SONAR, "Analyser le projet avec SonarQube pour mesurer ses vulnérabilités.")
async def metrics(ctx: Context) -> Outcome:
    found, skip = await measures(ctx)
    if skip:
        return skip
    if "vulnerabilities" not in found:
        return Outcome.fail("vulnérabilités non mesurées")
    return Outcome.ok(f"{found['vulnerabilities']:.0f} vulnérabilité(s) mesurée(s)", vulnerabilities=found["vulnerabilities"])


@check("sonar.recent_analysis", Depends.SONAR, "Lancer l'analyse SonarQube dans la CI de la branche par défaut.")
async def recent_analysis(ctx: Context) -> Outcome:
    if (skip := unconfigured(ctx)) is not None:
        return skip
    analysis = await ctx.sonar_analysis()
    if analysis is None:
        return Outcome.unknown(f"projet {ctx.sonar_key} absent de SonarQube")
    if not analysis:
        return Outcome.fail("aucune analyse SonarQube")
    when = datetime.fromisoformat(analysis["date"].replace("+0000", "+00:00"))
    if when < ctx.now - timedelta(days=RECENT_DAYS):
        return Outcome.fail(f"dernière analyse SonarQube le {when:%d/%m/%Y}", date=analysis["date"])
    return Outcome.ok(f"analysé par SonarQube le {when:%d/%m/%Y}", date=analysis["date"])


@check("sonar.all_components", Depends.SONAR, "Inclure tout le code dans l'analyse SonarQube (sonar.sources, exclusions).")
async def all_components(ctx: Context) -> Outcome:
    found, skip = await measures(ctx)
    if skip:
        return skip
    lines = found.get("ncloc", 0)
    return Outcome.ok(f"{lines:.0f} lignes analysées", ncloc=lines) if lines > 0 else Outcome.fail("aucune ligne de code analysée")


@check("sonar.duplication", Depends.SONAR, "Réduire la duplication sous 5 % des lignes.")
async def duplication(ctx: Context) -> Outcome:
    found, skip = await measures(ctx)
    if skip:
        return skip
    if "duplicated_lines_density" not in found:
        return Outcome.unknown("duplication non mesurée")
    density = found["duplicated_lines_density"]
    out = Outcome.ok if density <= MAX_DUPLICATION else Outcome.fail
    return out(f"{density:.1f} % de lignes dupliquées", density=density)
