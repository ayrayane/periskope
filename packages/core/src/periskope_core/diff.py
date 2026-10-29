"""What changed between two analyses: checks gained, lost, and other changes of status or observed value."""
from __future__ import annotations

from typing import Any


def diff(before: dict[str, Any], after: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """before/after are runs' results ({check: {status, message}}); a check missing on one side is unknown there."""
    out: dict[str, list[dict[str, Any]]] = {"gained": [], "lost": [], "changed": []}
    for check in sorted(set(before) | set(after)):
        a, b = before.get(check, {"status": "unknown", "message": ""}), after.get(check, {"status": "unknown", "message": ""})
        if a["status"] == b["status"] and a["message"] == b["message"]:
            continue
        row = {"check": check, "before": a["status"], "after": b["status"], "before_message": a["message"], "after_message": b["message"]}
        if b["status"] == "pass" and a["status"] != "pass":
            out["gained"].append(row)
        elif a["status"] == "pass" and b["status"] != "pass":
            out["lost"].append(row)
        else:
            out["changed"].append(row)
    return out
