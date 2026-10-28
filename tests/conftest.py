"""A throwaway PostgreSQL database per test session (PERISKOPE_TEST_DATABASE_URL, default the local dev container)."""
import os
import subprocess
import uuid
from pathlib import Path

import asyncpg
import pytest

ADMIN_URL = os.environ.get("PERISKOPE_TEST_DATABASE_URL", "postgresql://periskope:dev@localhost:55432/periskope")
ROOT = Path(__file__).parent.parent


@pytest.fixture(scope="session")
def database_url():
    import asyncio
    name = f"test_{uuid.uuid4().hex[:8]}"

    async def admin(sql):
        try:
            conn = await asyncpg.connect(ADMIN_URL)
        except OSError:
            pytest.skip("no PostgreSQL for integration tests")
        await conn.execute(sql)
        await conn.close()

    asyncio.run(admin(f"CREATE DATABASE {name}"))
    url = ADMIN_URL.rsplit("/", 1)[0] + f"/{name}"
    subprocess.run(["alembic", "-c", str(ROOT / "packages/db/src/periskope_db/alembic.ini"), "upgrade", "head"],
                   env={**os.environ, "PERISKOPE_DATABASE_URL": url}, check=True, capture_output=True)
    yield url
    asyncio.run(admin(f"DROP DATABASE {name} WITH (FORCE)"))
