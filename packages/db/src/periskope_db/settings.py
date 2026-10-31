"""Hot settings: defaults here, overrides in the settings table; every service reads them when it needs them."""
from __future__ import annotations

from typing import Any

import asyncpg
from pydantic import BaseModel, Field


class Settings(BaseModel):
    sync_at: str = Field("00:30", pattern=r"^([01]\d|2[0-3]):[0-5]\d$")
    catch_up_at: str = Field("01:00", pattern=r"^([01]\d|2[0-3]):[0-5]\d$")
    rollup_at: str = Field("05:00", pattern=r"^([01]\d|2[0-3]):[0-5]\d$")
    on_demand_per_hour: int = Field(10, ge=1, le=1000)
    evidence_days: int = Field(14, ge=1, le=90)
    branch_run_days: int = Field(30, ge=1, le=365)
    # A drop of at least this many points between two analyses of the default branch sends an alert.
    alert_drop: int = Field(5, ge=1, le=100)


async def load(db: asyncpg.Pool | asyncpg.Connection) -> Settings:
    rows = await db.fetch("SELECT key, value FROM settings")
    return Settings(**{r["key"]: r["value"] for r in rows if r["key"] in Settings.model_fields})


async def save(db: asyncpg.Pool, changes: dict[str, Any], author: str) -> Settings:
    merged = Settings(**{**(await load(db)).model_dump(), **changes})  # validates the whole set
    async with db.acquire() as conn, conn.transaction():
        for key in changes:
            await conn.execute(
                "INSERT INTO settings (key, value, updated_by) VALUES ($1, $2, $3)"
                " ON CONFLICT (key) DO UPDATE SET value = $2, updated_by = $3, updated_at = now()",
                key, getattr(merged, key), author)
    return merged
