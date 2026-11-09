"""KEV and EPSS, from the official sites or an internal mirror: read each night, a table replaced only by a feed that parsed."""
from __future__ import annotations

import csv
import gzip
import io
import json
import os
import ssl
from datetime import UTC, date, datetime, timedelta
from typing import Any

import asyncpg
import certifi
import httpx
import structlog
from periskope_core.settings import env

log = structlog.get_logger()


class FeedError(ValueError):
    """A feed that cannot be used, said in words safe to show (no address)."""


def parse_kev(raw: bytes) -> tuple[list[tuple[str, date | None, date | None, bool]], str | None]:
    """CISA's known_exploited_vulnerabilities.json: (cve, added, due, ransomware) rows and the catalogue version."""
    doc = json.loads(raw)
    day = lambda v: date.fromisoformat(v) if v else None
    rows = [(v["cveID"].strip().upper(), day(v.get("dateAdded")), day(v.get("dueDate")), v.get("knownRansomwareCampaignUse") == "Known")
            for v in doc["vulnerabilities"]]
    return rows, doc.get("catalogVersion")


def parse_epss(raw: bytes) -> tuple[list[tuple[str, float, float]], str | None]:
    """FIRST's epss_scores-current.csv, gzipped or not: (cve, score, percentile) rows and the score date of its comment line."""
    text = (gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw).decode()
    published = None
    if text.startswith("#"):
        first, text = text.split("\n", 1)
        published = dict(p.split(":", 1) for p in first.lstrip("#").split(",") if ":" in p).get("score_date")
    return [(r["cve"].strip().upper(), float(r["epss"]), float(r["percentile"])) for r in csv.DictReader(io.StringIO(text))], published


FEEDS: dict[str, Any] = {
    "kev": ("KEV_URL", parse_kev, "vuln_kev", ["cve", "date_added", "due_date", "ransomware"]),
    "epss": ("EPSS_URL", parse_epss, "vuln_epss", ["cve", "score", "percentile"]),
}


# A dated archive (a pipeline drops one file a day in Nexus): {date} is tried from today back, a missing day is skipped.
DAYS_BACK = 7


async def fetch(client: httpx.AsyncClient, url: str) -> tuple[bytes, str]:
    """The feed's content and the URL it came from; with {date}, the most recent day that exists."""
    if "{date}" not in url:
        resp = await client.get(url)
        resp.raise_for_status()
        return resp.content, url
    today = datetime.now(UTC).date()
    for back in range(DAYS_BACK):
        dated = url.replace("{date}", (today - timedelta(days=back)).isoformat())
        resp = await client.get(dated)
        if resp.status_code != 404:
            resp.raise_for_status()
            return resp.content, dated
    raise FeedError(f"aucun fichier sur les {DAYS_BACK} derniers jours")


def trust() -> ssl.SSLContext:
    """Public authorities and the platform's private CA together: the official sites and an internal Nexus both verify.
    (httpx would otherwise take SSL_CERT_FILE, the private CA alone, and refuse every public certificate.)"""
    ctx = ssl.create_default_context(cafile=certifi.where())
    if (private := os.environ.get("SSL_CERT_FILE")) and os.path.exists(private):
        ctx.load_verify_locations(cafile=private)
    return ctx


async def refresh(db: asyncpg.Pool) -> None:
    """Each configured feed; one that fails keeps yesterday's table and records why."""
    # The feeds' own proxy, if any: GitLab and Keycloak calls never go through it.
    proxy = env("FEEDS_PROXY", "") or None
    async with httpx.AsyncClient(timeout=httpx.Timeout(120, connect=10), follow_redirects=True, proxy=proxy, verify=trust()) as client:
        for name, (var, parse, table, columns) in FEEDS.items():
            url = env(var, "")
            if not url:
                continue
            try:
                content, source = await fetch(client, url)
                rows, published = parse(content)
                if not rows:
                    raise FeedError("flux vide")
            except (httpx.HTTPError, ValueError, KeyError, TypeError) as e:
                # Shown to every user: the reason, never the address (httpx messages carry the internal URL).
                # A transport error names the cause (certificate, DNS, timeout), never the URL; an HTTP error would carry it.
                reason = (str(e) if isinstance(e, FeedError) else f"HTTP {e.response.status_code}" if isinstance(e, httpx.HTTPStatusError)
                          else f"{type(e).__name__}: {e}"[:200] if isinstance(e, httpx.TransportError) else type(e).__name__)
                log.warning("feed_failed", feed=name, error=reason)
                await db.execute(
                    "INSERT INTO vuln_feeds (name, url, error) VALUES ($1, $2, $3) ON CONFLICT (name) DO UPDATE SET url = $2, error = $3",
                    name, url, reason)
                continue
            # Duplicates would break the primary key: the last line of a CVE wins.
            rows = list({r[0]: r for r in rows}.values())
            async with db.acquire() as conn, conn.transaction():
                await conn.execute(f"TRUNCATE {table}")
                await conn.copy_records_to_table(table, records=rows, columns=columns)
                await conn.execute(
                    "INSERT INTO vuln_feeds (name, url, fetched_at, rows, published, error) VALUES ($1, $2, now(), $3, $4, NULL)"
                    " ON CONFLICT (name) DO UPDATE SET url = $2, fetched_at = now(), rows = $3, published = $4, error = NULL",
                    name, source, len(rows), published)
            log.info("feed_refreshed", feed=name, rows=len(rows), published=published)
