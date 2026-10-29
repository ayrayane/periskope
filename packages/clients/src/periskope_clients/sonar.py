"""Read-only client for an instance's SonarQube; token read from a mounted file."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx


class SonarQube:
    def __init__(self, url: str, token_file: Path, *, transport: httpx.AsyncBaseTransport | None = None, verify: str | bool = True):
        self.url = url.rstrip("/")
        self.token_file = token_file
        self.http = httpx.AsyncClient(base_url=self.url, transport=transport, verify=verify, timeout=httpx.Timeout(30, connect=10))

    async def get(self, path: str, **params: Any) -> Any | None:
        """JSON body, or None when the project or the right is missing (the check is then unknown)."""
        # Re-read every call: cheap, and a rotated Secret is picked up at once.
        token = self.token_file.read_text().strip()
        try:
            r = await self.http.get(f"/api{path}", params=params, headers={"Authorization": f"Bearer {token}"})
        except httpx.TransportError as e:
            raise SonarDown(f"SonarQube injoignable : {type(e).__name__}") from e
        if r.status_code in (403, 404):
            return None
        if r.status_code == 401:
            raise SonarDown("jeton SonarQube refusé")
        if r.status_code >= 500:
            raise SonarDown(f"SonarQube répond {r.status_code}")
        r.raise_for_status()
        return r.json()

    async def aclose(self) -> None:
        await self.http.aclose()


class SonarDown(Exception):
    """SonarQube itself is unusable: its checks are unknown, the run goes on (GitLab is the run's source)."""

