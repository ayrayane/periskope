"""Scale check of the API on 10 instances × 1 000 projects. Slow: runs only with PERISKOPE_PERF=1."""
import os
import random
import statistics
import time

import pytest
from periskope_core.referential import ACTIVITIES
from periskope_core.settings import Instance
from periskope_db import Viewer, connect
from periskope_db.bootstrap import bootstrap

pytestmark = pytest.mark.skipif(os.environ.get("PERISKOPE_PERF") != "1", reason="scale test: set PERISKOPE_PERF=1")
INSTANCES = {f"gl{i}": Instance(slug=f"gl{i}", name=f"GitLab {i}", url=f"https://gl{i}.test", tracked_namespaces=["g"]) for i in range(10)}
GROUPS = ["apps", "apps/web", "apps/web/front", "apps/mobile", "data", "data/etl", "infra", "infra/ci", "secu", "secu/tools"]
DIMS = sorted({a.dimension for a in ACTIVITIES.values()})
STATUSES = ["implemented", "partial", "not_implemented", "unknown"]


@pytest.fixture(scope="module")
def seeded(database_url):
    import asyncio

    async def seed():
        rnd = random.Random(1)
        pool = await connect(database_url)
        await bootstrap(pool, INSTANCES)
        projects = [(slug, n + 1, f"{GROUPS[n % 10]}/p{n}", GROUPS[n % 10], "group", "main") for slug in INSTANCES for n in range(1000)]
        await pool.copy_records_to_table("projects", records=projects, columns=["instance", "gitlab_id", "path", "namespace_path", "namespace_kind", "default_branch"])
        ids = [r["id"] for r in await pool.fetch("SELECT id FROM projects ORDER BY id")]
        runs, states, history = [], [], []
        for pid in ids:
            score = rnd.uniform(5, 98)
            runs += [(pid, "main", "nightly", "succeeded", score + 8, "5.0.2"), (pid, "main", "nightly", "succeeded", score, "5.0.2")]
            statuses = {a: {"status": rnd.choice(STATUSES)} for a in ACTIVITIES}
            states.append((pid, score, rnd.uniform(50, 95), {d: rnd.uniform(0, 100) for d in DIMS}, statuses))
            history += [(pid, f"2026-{m:02d}-01", score - (10 - m)) for m in range(1, 11)]
        await pool.copy_records_to_table("runs", records=runs, columns=["project_id", "branch", "trigger", "status", "score", "referential_version"])
        await pool.execute("UPDATE runs SET created_at = now() - interval '40 days', finished_at = now() - interval '40 days' WHERE id % 2 = 1")
        await pool.execute("UPDATE runs SET finished_at = now() WHERE id % 2 = 0")
        await pool.executemany("INSERT INTO project_state (project_id, score, coverage, by_dimension, statuses, last_run_id, last_success_at)"
                               " VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, (SELECT max(id) FROM runs WHERE project_id = $1), now())"
                               " ON CONFLICT (project_id) DO UPDATE SET score = excluded.score, coverage = excluded.coverage, by_dimension = excluded.by_dimension,"
                               " statuses = excluded.statuses, last_run_id = excluded.last_run_id, last_success_at = excluded.last_success_at", states)
        await pool.execute("INSERT INTO history_monthly (project_id, month, score) SELECT * FROM unnest($1::bigint[], $2::date[], $3::real[])",
                           [h[0] for h in history], [__import__("datetime").date.fromisoformat(h[1]) for h in history], [h[2] for h in history])
        await pool.execute("ANALYZE")
        await pool.close()
    asyncio.run(seed())


@pytest.fixture
def client(seeded, database_url, monkeypatch):
    from fastapi.testclient import TestClient
    from periskope_api import app as api

    monkeypatch.setenv("PERISKOPE_DATABASE_URL", database_url)
    monkeypatch.setenv("PERISKOPE_VALKEY_URL", os.environ.get("PERISKOPE_TEST_VALKEY_URL", "redis://localhost:56379"))
    for k in ("OIDC_ISSUER", "OIDC_CLIENT_ID"):
        monkeypatch.setenv(f"PERISKOPE_{k}", "https://kc.test/realms/x" if k == "OIDC_ISSUER" else "periskope")
    who = {"v": None}
    api.app.dependency_overrides[api.current] = lambda: who["v"]
    with TestClient(api.app) as c:
        c.who = who
        yield c
    api.app.dependency_overrides.clear()


def timed(client, url, n=5):
    samples = []
    for _ in range(n):
        t = time.perf_counter()
        r = client.get(url)
        samples.append((time.perf_counter() - t) * 1000)
        assert r.status_code == 200, (url, r.text[:200])
    return statistics.median(samples)


def test_api_at_ten_thousand_projects(seeded, client):
    admin = Viewer("perf-admin", "admin", admin=True)
    member = Viewer("perf-member", "member", namespaces=frozenset((s, g) for s in INSTANCES for g in ("apps", "data")))
    report = {}
    for who, viewer in (("admin", admin), ("membre", member)):
        client.who["v"] = viewer
        for name, url in (("liste (50 lignes)", "/api/v1/projects?limit=50"), ("liste triée par score", "/api/v1/projects?limit=50&sort=score"),
                          ("résumé", "/api/v1/projects/summary"), ("résumé d'un groupe", "/api/v1/projects/summary?instance=gl3&namespace=apps"),
                          ("groupes", "/api/v1/groups"), ("carte de chaleur", "/api/v1/groups/heatmap"), ("tendance", "/api/v1/projects/trend"),
                          ("export CSV", "/api/v1/projects/export.csv")):
            report[f"{who} · {name}"] = round(timed(client, url, n=3 if "CSV" in name else 5))
    print("\n" + "\n".join(f"{k:45} {v:6} ms" for k, v in report.items()))
    # The spec's target: the portfolio page (50 rows, all instances) under 300 ms on the API side.
    assert report["admin · liste (50 lignes)"] < 300 and report["membre · liste (50 lignes)"] < 300

