from periskope_core.diff import diff


def r(status, message="m"):
    return {"status": status, "message": message}


def test_diff_sorts_gains_losses_and_changes():
    before = {"a": r("fail"), "b": r("pass"), "c": r("fail", "2 Dockerfile"), "d": r("pass")}
    after = {"a": r("pass"), "b": r("fail"), "c": r("fail", "1 Dockerfile"), "d": r("pass")}
    d = diff(before, after)
    assert [x["check"] for x in d["gained"]] == ["a"]
    assert [x["check"] for x in d["lost"]] == ["b"]
    assert [x["check"] for x in d["changed"]] == ["c"]


def test_missing_check_counts_as_unknown():
    assert diff({}, {"x": r("pass")})["gained"][0]["before"] == "unknown"
