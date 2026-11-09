"""From check results to activity statuses, score and coverage: the only place this rule lives."""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping

from periskope_core.catalog import CHECKS
from periskope_core.models import (
    Activity,
    ActivityResult,
    ActivityStatus,
    Check,
    CheckStatus,
    Kind,
    Score,
)
from periskope_core.referential import ACTIVITIES

POINTS = {ActivityStatus.IMPLEMENTED: 1.0, ActivityStatus.PARTIAL: 0.5, ActivityStatus.NOT_IMPLEMENTED: 0.0}


def activity_status(checks: list[Check], results: Mapping[str, CheckStatus]) -> tuple[ActivityStatus, bool]:
    """Status of one activity from its retained checks' results, and whether a hint decided it."""
    def pick(kinds: set[Kind]) -> list[Check]:
        return [c for c in checks if c.kind in kinds and results.get(c.id) != CheckStatus.NOT_APPLICABLE]

    decisive = pick({Kind.PROOF, Kind.HINT})
    if not decisive:
        return ActivityStatus.NOT_APPLICABLE, False
    # Unknown is never a failure: the activity is decided on the checks that concluded.
    concluded = [c for c in decisive if results.get(c.id, CheckStatus.UNKNOWN) != CheckStatus.UNKNOWN]
    if not concluded:
        return ActivityStatus.UNKNOWN, False
    passed = [c for c in concluded if results[c.id] == CheckStatus.PASS]
    to_confirm = any(c.kind == Kind.HINT for c in passed)
    if len(passed) == len(concluded):
        return ActivityStatus.IMPLEMENTED, to_confirm
    if passed:
        return ActivityStatus.PARTIAL, to_confirm
    return ActivityStatus.NOT_IMPLEMENTED, False


def score(
    results: Mapping[str, CheckStatus],
    *,
    target_level: int = 5,
    excluded_checks: Iterable[str] = (),
    excluded_activities: Iterable[str] = (),
    checks: Iterable[Check] = CHECKS,
    activities: Mapping[str, Activity] = ACTIVITIES,
) -> Score:
    excluded_checks, excluded_activities = set(excluded_checks), set(excluded_activities)
    by_activity: dict[str, list[Check]] = defaultdict(list)
    for c in checks:
        by_activity[c.activity].append(c)

    statuses: dict[str, ActivityResult] = {}
    for name, cs in by_activity.items():
        kept = [c for c in cs if c.id not in excluded_checks]
        if name in excluded_activities or not kept:
            statuses[name] = ActivityResult(activity=name, status=ActivityStatus.OUT_OF_SCOPE)
            continue
        status, to_confirm = activity_status(kept, results)
        statuses[name] = ActivityResult(activity=name, status=status, to_confirm=to_confirm)

    # A missing DSOMM prerequisite caps the activity at partial; prerequisites Periskope does not measure are ignored.
    uuid_to_name = {a.uuid: a.name for a in activities.values()}
    for name, r in statuses.items():
        if r.status != ActivityStatus.IMPLEMENTED:
            continue
        for dep in activities[name].depends_on:
            d = statuses.get(uuid_to_name.get(dep, ""))
            if d and d.status in (ActivityStatus.NOT_IMPLEMENTED, ActivityStatus.PARTIAL):
                r.status = ActivityStatus.PARTIAL
                break

    def total(names: list[str]) -> tuple[float | None, float]:
        counted = [statuses[n].status for n in names if statuses[n].status not in (ActivityStatus.NOT_APPLICABLE, ActivityStatus.OUT_OF_SCOPE)]
        measured = [s for s in counted if s != ActivityStatus.UNKNOWN]
        # Unknown is never a failure: it lowers coverage, not the score.
        value = round(100 * sum(POINTS[s] for s in measured) / len(measured), 1) if measured else None
        return value, round(100 * len(measured) / len(counted), 1) if counted else 0.0

    in_target = [n for n in statuses if activities[n].level <= target_level]
    by_dim: dict[str, list[str]] = defaultdict(list)
    for n in in_target:
        by_dim[activities[n].dimension].append(n)
    value, coverage = total(in_target)
    return Score(
        score=value,
        coverage=coverage,
        by_dimension={d: total(ns)[0] for d, ns in sorted(by_dim.items())},
        activities=[statuses[n] for n in sorted(statuses)],
    )
