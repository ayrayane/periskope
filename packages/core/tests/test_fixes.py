from periskope_core.catalog import CHECKS, FIXES


def test_every_check_has_a_fix_with_steps_and_docs():
    for c in CHECKS:
        fix = FIXES[c.id]
        assert fix["steps"] and fix["docs"], c.id
        assert all(d["url"].startswith("https://") for d in fix["docs"]), c.id
    assert set(FIXES) == {c.id for c in CHECKS}
