"""Scope decisions: a check or activity retained or excluded for the organisation, an instance or a project."""
from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum

from pydantic import BaseModel

from periskope_core.catalog import CHECKS


class Target(StrEnum):
    CHECK = "check"
    ACTIVITY = "activity"


class Decision(StrEnum):
    RETAINED = "retained"
    EXCLUDED = "excluded"


class ScopeDecision(BaseModel):
    target: Target
    target_id: str
    decision: Decision
    reason: str
    # Both None: the whole organisation. instance only: that instance. Both: that project.
    instance: str | None = None
    project_id: int | None = None


# Seeded at install: Scorecard calls external services and collectors have no Internet access.
DEFAULTS = [
    ScopeDecision(target=Target.CHECK, target_id=c.id, decision=Decision.EXCLUDED,
                  reason="Scorecard interroge des services externes : les collecteurs n'ont pas d'accès Internet")
    for c in CHECKS if c.id.startswith("scorecard.")
]


def effective(decisions: Iterable[ScopeDecision], instance: str | None = None, project_id: int | None = None) -> dict[tuple[Target, str], ScopeDecision]:
    """The decision in force for each target: the most precise one that applies wins."""
    def rank(d: ScopeDecision) -> int | None:
        if d.project_id is not None:
            return 2 if (d.instance, d.project_id) == (instance, project_id) else None
        if d.instance is not None:
            return 1 if d.instance == instance else None
        return 0

    best: dict[tuple[Target, str], tuple[int, ScopeDecision]] = {}
    for d in decisions:
        r = rank(d)
        key = (d.target, d.target_id)
        if r is not None and (key not in best or r >= best[key][0]):
            best[key] = (r, d)
    return {k: d for k, (_, d) in best.items()}


def excluded(decisions: Iterable[ScopeDecision], instance: str | None = None, project_id: int | None = None) -> tuple[set[str], set[str]]:
    """(excluded check ids, excluded activity names) for a project, ready for scoring.score."""
    eff = effective(decisions, instance, project_id).values()
    pick = lambda t: {d.target_id for d in eff if d.target == t and d.decision == Decision.EXCLUDED}
    return pick(Target.CHECK), pick(Target.ACTIVITY)
