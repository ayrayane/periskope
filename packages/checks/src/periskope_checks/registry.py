"""The check registry: adding a check is adding one decorated function, nothing else."""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum

from periskope_clients.gitlab import SourceDown
from periskope_clients.sonar import SonarDown
from periskope_core.catalog import CHECKS
from periskope_core.models import Check, Outcome

from periskope_checks.context import Context


class Depends(StrEnum):
    """What a check's result depends on, for reuse when it has not changed."""
    COMMIT = "commit"
    SETTINGS = "settings"
    # MRs, pipelines and open vulnerabilities age without a commit: always re-evaluated.
    LIVE = "live"
    SONAR = "sonar"


CheckFn = Callable[[Context], Awaitable[Outcome]]


@dataclass(frozen=True)
class Registered:
    meta: Check
    depends_on: Depends
    # The step a team takes when the check fails, written once.
    action: str
    fn: CheckFn


REGISTRY: dict[str, Registered] = {}
_CATALOG = {c.id: c for c in CHECKS}


def check(id: str, depends_on: Depends, action: str) -> Callable[[CheckFn], CheckFn]:
    def register(fn: CheckFn) -> CheckFn:
        if id in REGISTRY:
            raise ValueError(f"check {id} registered twice")
        REGISTRY[id] = Registered(_CATALOG[id], depends_on, action, fn)
        return fn
    return register


async def run_one(reg: Registered, ctx: Context) -> Outcome:
    """A check that raises is unknown and never stops the run; only the source going down does."""
    try:
        return await reg.fn(ctx)
    except SourceDown:
        raise
    except SonarDown as e:
        return Outcome.unknown(str(e))
    except Exception as e:  # noqa: BLE001
        return Outcome.unknown(f"erreur interne de la preuve : {type(e).__name__}")


async def run_all(ctx: Context, ids: list[str] | None = None) -> dict[str, Outcome]:
    regs = [REGISTRY[i] for i in (ids if ids is not None else REGISTRY)]
    outcomes = await asyncio.gather(*(run_one(r, ctx) for r in regs))
    return {r.meta.id: o for r, o in zip(regs, outcomes)}
