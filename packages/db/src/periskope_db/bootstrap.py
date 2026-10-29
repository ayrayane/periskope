"""Idempotent startup writes: the instance registry mirrors the chart values, the referential and default scope exist."""
from __future__ import annotations

import asyncpg
from periskope_core.referential import ALL_ACTIVITIES, REFERENTIAL_VERSION
from periskope_core.scope import DEFAULTS
from periskope_core.settings import Instance


async def bootstrap(db: asyncpg.Pool, instances: dict[str, Instance]) -> None:
    async with db.acquire() as conn, conn.transaction():
        # Serialise concurrent starts of several services.
        await conn.execute("SELECT pg_advisory_xact_lock(4711)")
        await conn.executemany(
            """INSERT INTO gitlab_instances (slug, name, url, rate_per_min, sonar_url, enterprise, enabled, tracked_namespaces, excluded_namespaces, space_dormant)
               VALUES ($1, $2, $3, $4, $5, $6, true, $7, $8, $9)
               ON CONFLICT (slug) DO UPDATE SET name = $2, url = $3, rate_per_min = $4, sonar_url = $5, enterprise = $6, enabled = true,
                 tracked_namespaces = $7, excluded_namespaces = $8, space_dormant = $9""",
            [(i.slug, i.name, i.url, i.rate_per_min, i.sonar_url, i.enterprise, i.tracked_namespaces, i.excluded_namespaces, i.space_dormant)
             for i in instances.values()],
        )
        await conn.execute("UPDATE gitlab_instances SET enabled = false WHERE NOT (slug = ANY($1::text[]))", list(instances))
        await conn.executemany(
            """INSERT INTO activities (uuid, referential_version, name, dimension, subdimension, level, usefulness, depends_on)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING""",
            [(a.uuid, REFERENTIAL_VERSION, a.name, a.dimension, a.subdimension, a.level, a.usefulness, a.depends_on) for a in ALL_ACTIVITIES.values()],
        )
        await conn.executemany(
            """INSERT INTO scope_decisions (target, target_id, decision, reason, author) VALUES ($1, $2, $3, $4, 'installation')
               ON CONFLICT DO NOTHING""",
            [(d.target, d.target_id, d.decision, d.reason) for d in DEFAULTS],
        )
        await conn.execute("SELECT periskope_partitions(current_date, 7)")
