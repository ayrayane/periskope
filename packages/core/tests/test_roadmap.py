from periskope_core.models import Activity
from periskope_core.roadmap import roadmap


def act(name, level, usefulness, depends=()):
    return Activity(uuid=name, name=name, dimension="D", subdimension="S", level=level, usefulness=usefulness, depends_on=list(depends))


def test_order_level_then_ready_then_usefulness():
    acts = {"a": act("a", 1, 1), "b": act("b", 1, 4, ["c"]), "c": act("c", 1, 2), "d": act("d", 2, 5), "e": act("e", 4, 5)}
    statuses = {n: {"status": "not_implemented"} for n in acts} | {"e": {"status": "partial"}}
    items = roadmap(statuses, {}, target_level=3, activities=acts)
    assert [i["activity"] for i in items] == ["c", "a", "b", "d"]  # e is above the target level
    assert items[2]["blocked_by"] == ["c"]


def test_done_activities_are_left_out():
    acts = {"a": act("a", 1, 1)}
    assert roadmap({"a": {"status": "implemented"}}, {}, 3, activities=acts) == []
