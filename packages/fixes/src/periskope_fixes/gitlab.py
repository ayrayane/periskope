"""GitLab REST with the token of the person who clicked: GitLab's own rights and audit apply, never Periskope's read token."""
from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx


class FixError(Exception):
    """A fix GitLab refused or could not apply, with a message meant for the person who clicked."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


REFUSED = {
    401: "GitLab a refusé la connexion : reconnectez-vous à GitLab depuis Periskope.",
    403: "GitLab refuse cette modification : il faut être Maintainer (ou Owner) du projet.",
    404: "GitLab ne trouve pas cet élément, ou il n'est pas accessible avec votre compte.",
}


class UserGitLab:
    def __init__(self, url: str, token: str, *, transport: httpx.AsyncBaseTransport | None = None, verify: str | bool = True):
        self.http = httpx.AsyncClient(base_url=url.rstrip("/") + "/api/v4", transport=transport, verify=verify,
                                      headers={"Authorization": f"Bearer {token}"}, timeout=httpx.Timeout(30, connect=10))

    async def aclose(self) -> None:
        await self.http.aclose()

    async def call(self, method: str, path: str, *, ok_404: bool = False, **kw: Any) -> Any:
        try:
            r = await self.http.request(method, path, **kw)
        except httpx.TransportError as e:
            raise FixError(f"GitLab injoignable ({type(e).__name__}) : rien n'a été modifié.", 503) from e
        if r.status_code == 404 and ok_404:
            return None
        if r.status_code >= 400:
            detail = ""
            try:
                body = r.json()
                detail = str(body.get("message") or body.get("error") or "")[:300]
            except ValueError:
                pass
            raise FixError(REFUSED.get(r.status_code) or f"GitLab a répondu {r.status_code} : {detail}".rstrip(" :"), r.status_code)
        return r.json() if r.content else None

    async def raw_file(self, project_id: int, path: str, ref: str) -> str | None:
        """A repository file's text at a ref, or None when it does not exist."""
        try:
            r = await self.http.get(f"/projects/{project_id}/repository/files/{quote(path, safe='')}/raw", params={"ref": ref})
        except httpx.TransportError as e:
            raise FixError(f"GitLab injoignable ({type(e).__name__}) : rien n'a été modifié.", 503) from e
        if r.status_code == 404:
            return None
        if r.status_code >= 400:
            raise FixError(REFUSED.get(r.status_code) or f"GitLab a répondu {r.status_code}", r.status_code)
        return r.text
