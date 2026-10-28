from periskope_core.catalog import CHECKS
from periskope_core.models import ActivityStatus as A
from periskope_core.models import Check, Kind
from periskope_core.models import CheckStatus as S
from periskope_core.referential import ACTIVITIES
from periskope_core.scoring import activity_status, score

P = lambda i: Check(i, "", "", "x", 1, Kind.PROOF)
H = lambda i: Check(i, "", "", "x", 1, Kind.HINT)
SEC = lambda i: Check(i, "", "", "x", 1, Kind.SECONDARY)


def test_catalog_matches_spec():
    assert len(CHECKS) == 53 and len(ACTIVITIES) == 41
    assert len({c.id for c in CHECKS}) == 53


def test_activity_rules():
    assert activity_status([P("a"), P("b")], {"a": S.PASS, "b": S.PASS}) == (A.IMPLEMENTED, False)
    assert activity_status([P("a"), P("b")], {"a": S.PASS, "b": S.FAIL}) == (A.PARTIAL, False)
    assert activity_status([P("a"), P("b")], {"a": S.FAIL, "b": S.UNKNOWN}) == (A.NOT_IMPLEMENTED, False)
    assert activity_status([P("a"), P("b")], {"a": S.PASS, "b": S.UNKNOWN}) == (A.IMPLEMENTED, False)
    assert activity_status([P("a")], {}) == (A.UNKNOWN, False)
    assert activity_status([P("a")], {"a": S.NOT_APPLICABLE}) == (A.NOT_APPLICABLE, False)
    # A hint that decides flags the activity "to confirm".
    assert activity_status([P("a"), H("h")], {"a": S.PASS, "h": S.PASS}) == (A.IMPLEMENTED, True)


def test_secondary_only_when_main_inconclusive():
    assert activity_status([P("a"), SEC("s")], {"a": S.FAIL, "s": S.PASS}) == (A.NOT_IMPLEMENTED, False)
    assert activity_status([P("a"), SEC("s")], {"a": S.UNKNOWN, "s": S.PASS}) == (A.IMPLEMENTED, False)


def test_unknown_lowers_coverage_not_score():
    everything = {c.id: S.PASS for c in CHECKS}
    full = score(everything)
    assert full.score == 100 and full.coverage == 100
    half = score({**everything, **{c.id: S.UNKNOWN for c in CHECKS if c.source == "SonarQube"}})
    assert half.score == 100 and half.coverage < 100


def test_scope_and_target_level():
    everything = {c.id: S.FAIL for c in CHECKS}
    s = score(everything, target_level=1, excluded_activities={"Version control"})
    statuses = {a.activity: a.status for a in s.activities}
    assert statuses["Version control"] == A.OUT_OF_SCOPE and s.score == 0
    assert score({}, excluded_checks={c.id for c in CHECKS}).score is None


def test_missing_prerequisite_caps_at_partial():
    name, act = next((n, a) for n, a in ACTIVITIES.items() if any(d in {x.uuid for x in ACTIVITIES.values()} for d in a.depends_on))
    dep = next(x.name for x in ACTIVITIES.values() if x.uuid in act.depends_on)
    results = {c.id: S.PASS for c in CHECKS}
    results.update({c.id: S.FAIL for c in CHECKS if c.activity == dep})
    statuses = {a.activity: a.status for a in score(results).activities}
    assert statuses[name] == A.PARTIAL
