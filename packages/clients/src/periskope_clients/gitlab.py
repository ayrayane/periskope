"""Async GitLab client for one instance: read-only, token read from a mounted file, quota-aware."""
from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import httpx

TOKEN_REFRESH_S = 300


class SourceDown(Exception):
    """GitLab itself is unusable (unreachable, 5xx, token rejected): the run fails, the last score stays."""


class GitLab:
    def __init__(
        self,
        url: str,
        token_file: Path,
        *,
        acquire: Callable[[], Awaitable[None]] | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        verify: str | bool = True,
    ):
        self.url = url.rstrip("/")
        self.token_file = token_file
        # Waits for a token from the instance's shared bucket before each call.
        self.acquire = acquire
        self.calls = 0
        self._token, self._read_at = "", 0.0
        self.http = httpx.AsyncClient(
            base_url=self.url, http2=transport is None, transport=transport, verify=verify, timeout=httpx.Timeout(30, connect=10),
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=50),
        )

    def _auth(self, force: bool = False) -> dict[str, str]:
        # Re-read on 401 and every 5 min: a rotated Secret updates the mounted file without a restart.
        if force or not self._token or time.monotonic() - self._read_at > TOKEN_REFRESH_S:
            self._token, self._read_at = self.token_file.read_text().strip(), time.monotonic()
        return {"Authorization": f"Bearer {self._token}"}

    async def request(self, method: str, path: str, **kw: Any) -> httpx.Response:
        refreshed = False
        for attempt in range(4):
            if self.acquire:
                await self.acquire()
            self.calls += 1
            try:
                r = await self.http.request(method, path, headers=self._auth(), **kw)
            except httpx.TransportError as e:
                if attempt == 3:
                    raise SourceDown(f"GitLab injoignable : {type(e).__name__}") from e
                await asyncio.sleep(2**attempt)
                continue
            if r.status_code == 401 and not refreshed:
                refreshed = True
                self._auth(force=True)
                continue
            if r.status_code == 401:
                raise SourceDown("jeton GitLab refusé (révoqué ou expiré)")
            if r.status_code == 429:
                await asyncio.sleep(float(r.headers.get("Retry-After", 2**attempt)))
                continue
            if r.status_code >= 500:
                if attempt == 3:
                    raise SourceDown(f"GitLab répond {r.status_code}")
                await asyncio.sleep(2**attempt)
                continue
            return r
        raise SourceDown("GitLab limite les appels (429) au-delà des reprises")

    async def get(self, path: str, **params: Any) -> Any | None:
        """JSON body, or None when GitLab says forbidden or not found (the check is then unknown)."""
        r = await self.request("GET", f"/api/v4{path}", params=params)
        if r.status_code in (403, 404):
            return None
        r.raise_for_status()
        return r.json()

    async def pages(self, path: str, *, max_pages: int = 10, **params: Any) -> tuple[list[Any], bool] | None:
        """Keyset or offset pagination; returns (items, truncated)."""
        items: list[Any] = []
        url: str | None = f"/api/v4{path}"
        query: dict[str, Any] | None = {"per_page": 100, **params}
        for _ in range(max_pages):
            r = await self.request("GET", url, params=query)
            if r.status_code in (403, 404):
                return None
            r.raise_for_status()
            items.extend(r.json())
            url, query = r.links.get("next", {}).get("url"), None
            if not url:
                return items, False
        return items, True

    async def graphql(self, query: str, **variables: Any) -> dict[str, Any] | None:
        r = await self.request("POST", "/api/graphql", json={"query": query, "variables": variables})
        r.raise_for_status()
        body = r.json()
        # Partial data is normal (a licensed field on a lower tier): keep what came back.
        return body.get("data")

    async def aclose(self) -> None:
        await self.http.aclose()
