"""A project's roadmap: retained activities not in place, by level, then prerequisites met, then DSOMM usefulness."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from periskope_core.catalog import CHECKS
from periskope_core.models import Activity
from periskope_core.referential import ACTIVITIES

TODO = ("not_implemented", "partial")


def roadmap(statuses: Mapping[str, Mapping[str, Any]], results: Mapping[str, Mapping[str, Any]], target_level: int,
            activities: Mapping[str, Activity] = ACTIVITIES) -> list[dict[str, Any]]:
    """statuses: {activity: {status}} from project_state; results: the reference run's {check: {status, message, action}}."""
    uuid_to_name = {a.uuid: a.name for a in activities.values()}
    done = {n for n, s in statuses.items() if s.get("status") in ("implemented", "not_applicable", "out_of_scope")}
    items = []
    for name, s in statuses.items():
        a = activities.get(name)
        if a is None or a.level > target_level or s.get("status") not in TODO:
            continue
        missing = [uuid_to_name[d] for d in a.depends_on if d in uuid_to_name and uuid_to_name[d] in statuses and uuid_to_name[d] not in done]
        steps = [{"check": c.id, "action": results[c.id].get("action"), "message": results[c.id].get("message")}
                 for c in CHECKS if c.activity == name and results.get(c.id, {}).get("status") == "fail"]
        items.append({"activity": name, "dimension": a.dimension, "level": a.level, "usefulness": a.usefulness,
                      "status": s["status"], "blocked_by": missing, "steps": steps})
    # Ready work first within a level: an activity whose prerequisite is missing comes after the ones that can start now.
    return sorted(items, key=lambda i: (i["level"], bool(i["blocked_by"]), -i["usefulness"], i["activity"]))
