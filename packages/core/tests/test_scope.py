from periskope_core.scope import DEFAULTS, Decision, ScopeDecision, Target, excluded


def d(decision, instance=None, project_id=None, target_id="gitlab.renovate"):
    return ScopeDecision(target=Target.CHECK, target_id=target_id, decision=decision, reason="r", instance=instance, project_id=project_id)


def test_most_precise_wins():
    decisions = [d(Decision.EXCLUDED), d(Decision.RETAINED, "gl", 7)]
    assert excluded(decisions, "gl", 7)[0] == set()
    assert excluded(decisions, "gl", 8)[0] == {"gitlab.renovate"}
    assert excluded([d(Decision.EXCLUDED, "other")], "gl", 7)[0] == set()


def test_scorecard_excluded_by_default():
    assert len(excluded(DEFAULTS)[0]) == 6
