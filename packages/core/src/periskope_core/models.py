"""Shared models: the check catalog, a check's outcome, an activity's status, a run's result."""
from __future__ import annotations

from enum import StrEnum
from typing import Any, NamedTuple

from pydantic import BaseModel, Field


class Kind(StrEnum):
    PROOF = "proof"
    # A pattern in a file, not an API answer: the activity it decides is flagged "to confirm".
    HINT = "hint"


class Check(NamedTuple):
    id: str
    title: str
    source: str
    activity: str
    level: int
    kind: Kind


class CheckStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class Outcome(BaseModel):
    status: CheckStatus
    message: str
    # What was observed, kept as the run's raw evidence (never a token or file content).
    evidence: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def ok(cls, message: str, **evidence: Any) -> Outcome:
        return cls(status=CheckStatus.PASS, message=message, evidence=evidence)

    @classmethod
    def fail(cls, message: str, **evidence: Any) -> Outcome:
        return cls(status=CheckStatus.FAIL, message=message, evidence=evidence)

    @classmethod
    def unknown(cls, message: str, **evidence: Any) -> Outcome:
        return cls(status=CheckStatus.UNKNOWN, message=message, evidence=evidence)

    @classmethod
    def not_applicable(cls, message: str, **evidence: Any) -> Outcome:
        return cls(status=CheckStatus.NOT_APPLICABLE, message=message, evidence=evidence)


class ActivityStatus(StrEnum):
    IMPLEMENTED = "implemented"
    PARTIAL = "partial"
    NOT_IMPLEMENTED = "not_implemented"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"
    OUT_OF_SCOPE = "out_of_scope"


class Activity(BaseModel):
    uuid: str
    name: str
    dimension: str
    subdimension: str
    level: int
    usefulness: int
    depends_on: list[str] = []
    # Not in the DSOMM referential: defined by Periskope.
    local: bool = False


class CheckResult(BaseModel):
    check: str
    status: CheckStatus
    message: str
    # Taken from the previous run because its inputs did not change.
    reused: bool = False


class ActivityResult(BaseModel):
    activity: str
    status: ActivityStatus
    # The deciding check was a hint: a review queue, not a status.
    to_confirm: bool = False


class Score(BaseModel):
    # 0-100 over retained activities up to the target level; None when nothing was measured.
    score: float | None
    # Share of retained activities actually measured (not unknown), 0-100.
    coverage: float
    by_dimension: dict[str, float | None]
    activities: list[ActivityResult]
