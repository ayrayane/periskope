"""Async GitLab client for one instance: read-only, token read from a mounted file, quota-aware."""
from __future__ import annotations

import asyncio
import base64
import os
import signal
import tempfile
import time
from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from pathlib import Path
from typing import Any

import httpx

TOKEN_REFRESH_S = 300
# Calls made by the current run: tasks a run spawns share its counter, concurrent runs do not.
run_calls: ContextVar[list[int] | None] = ContextVar("run_calls", default=None)


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
        on_response: Callable[[int], None] | None = None,
    ):
        self.url = url.rstrip("/")
        self.token_file = token_file
        # Waits for a token from the instance's shared bucket before each call.
        self.acquire = acquire
        # Told every HTTP status (0 when unreachable), for the collector's metrics.
        self.on_response = on_response or (lambda status: None)
        self.calls = 0
        self.verify, self._transport = verify, transport
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
            if (counter := run_calls.get()) is not None:
                counter[0] += 1
            try:
                r = await self.http.request(method, path, headers=self._auth(), **kw)
            except httpx.TransportError as e:
                self.on_response(0)
                if attempt == 3:
                    raise SourceDown(f"GitLab injoignable : {type(e).__name__}") from e
                await asyncio.sleep(2**attempt)
                continue
            self.on_response(r.status_code)
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

    async def pages(self, path: str, *, max_pages: int = 10, max_seconds: float | None = None, **params: Any) -> tuple[list[Any], bool] | None:
        """Keyset or offset pagination; returns (items, truncated). Stops at max_pages, or once max_seconds have passed."""
        items: list[Any] = []
        url: str | None = f"/api/v4{path}"
        query: dict[str, Any] | None = {"per_page": 100, **params}
        until = time.monotonic() + max_seconds if max_seconds else None
        for _ in range(max_pages):
            if until and items and time.monotonic() > until:
                return items, True
            r = await self.request("GET", url, params=query)
            if r.status_code in (403, 404):
                return None
            r.raise_for_status()
            items.extend(r.json())
            url, query = r.links.get("next", {}).get("url"), None
            if not url:
                return items, False
        return items, True

    async def ls_files(self, project_path: str, sha: str, timeout: float) -> list[str] | None:
        """Every file path at the commit, from one shallow git fetch of the trees only (no file contents): a monorepo's
        100 000 files in seconds, where the paginated tree API needs over a thousand calls. None when git cannot read it."""
        if self._transport:
            return None  # a test transport has no git server behind it
        with tempfile.TemporaryDirectory() as repo:
            # The token travels in git's environment, never on its command line.
            basic = base64.b64encode(f"oauth2:{self._auth()['Authorization'].removeprefix('Bearer ')}".encode()).decode()
            # No redirect: the header would follow it to another host.
            config = {"http.extraHeader": f"Authorization: Basic {basic}", "http.followRedirects": "false", "protocol.version": "2"}
            if isinstance(self.verify, str):
                config["http.sslCAInfo"] = self.verify
            elif not self.verify:
                config["http.sslVerify"] = "false"
            env = {"PATH": os.environ.get("PATH", ""), "HOME": repo, "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1",
                   "GIT_CONFIG_COUNT": str(len(config))}
            for i, (k, v) in enumerate(config.items()):
                env[f"GIT_CONFIG_KEY_{i}"], env[f"GIT_CONFIG_VALUE_{i}"] = k, v
            steps = [["init", "-q", "--bare", repo],
                     ["-C", repo, "fetch", "-q", "--depth=1", "--filter=blob:none", "--no-tags", f"{self.url}/{project_path}.git", sha],
                     ["-C", repo, "ls-tree", "-r", "-z", "--name-only", sha]]
            until = time.monotonic() + timeout
            out = b""
            for step in steps:
                if "fetch" in step:  # the one step that calls GitLab
                    if self.acquire:
                        await self.acquire()
                    self.calls += 1
                    if (counter := run_calls.get()) is not None:
                        counter[0] += 1
                try:
                    proc = await asyncio.create_subprocess_exec("git", *step, env=env, stdout=asyncio.subprocess.PIPE,
                                                                stderr=asyncio.subprocess.DEVNULL, start_new_session=True)
                except FileNotFoundError:
                    return None
                try:
                    out, _ = await asyncio.wait_for(proc.communicate(), max(until - time.monotonic(), 1))
                except TimeoutError:
                    os.killpg(proc.pid, signal.SIGKILL)  # git and its git-remote-https child
                    await proc.wait()
                    return None
                if proc.returncode:
                    return None
            return [p for p in out.decode(errors="replace").split("\0") if p]

    async def graphql(self, query: str, **variables: Any) -> dict[str, Any] | None:
        r = await self.request("POST", "/api/graphql", json={"query": query, "variables": variables})
        r.raise_for_status()
        body = r.json()
        # Partial data is normal (a licensed field on a lower tier): keep what came back.
        return body.get("data")

    async def aclose(self) -> None:
        await self.http.aclose()
