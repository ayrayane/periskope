"""« Corriger dans GitLab »: a person connects their own GitLab account (OAuth, PKCE), previews a fix, then applies it
as themselves. Periskope's service token stays read-only; the person's token lives only as long as GitLab grants it,
encrypted in Valkey, bound to their Keycloak identity.

No `from __future__ import annotations` here: FastAPI resolves the closure-local dependencies from real annotations."""

import base64
import hashlib
import json
import re
import secrets
from datetime import timedelta
from typing import Annotated, Any
from urllib.parse import urlencode

import httpx
from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import RedirectResponse
from periskope_core.settings import Instance, env, instances, queue, secret
from periskope_db import Viewer, runs
from periskope_fixes import FIXES, FixError, Target, UserGitLab
from pydantic import BaseModel, Field

STATE_TTL_S = 600
# Premium and Ultimate fixes need a licensed instance; CE has neither feature.
NEEDS_LICENCE = {"Premium", "Ultimate"}


def _secret_text(name: str, key: str) -> str | None:
    path = secret(name) / key
    return path.read_text().strip() if path.exists() else None


def router(state: dict[str, Any], current, audit, project_row) -> APIRouter:
    Me = Annotated[Viewer, Depends(current)]
    r = APIRouter(prefix="/api/v1")

    def instance(slug: str) -> Instance:
        found = instances().get(slug)
        if found is None or not found.fixes or not _secret_text(f"gitlab-oauth-{slug}", "client_id"):
            raise HTTPException(404, "les corrections depuis Periskope ne sont pas activées pour cette instance")
        return found

    def cipher() -> Fernet:
        key = _secret_text("periskope-fixit", "key")
        if not key:
            raise HTTPException(503, "clé de chiffrement des jetons GitLab absente")
        return Fernet(key.encode())

    def redirect_uri(slug: str) -> str:
        return f"{env('PUBLIC_URL').rstrip('/')}/api/v1/fixit/{slug}/callback"

    async def user_token(me: Viewer, slug: str) -> str | None:
        raw = await state["arq"].get(f"gitlab-user:{me.sub}:{slug}")
        if raw is None:
            return None
        try:
            return cipher().decrypt(raw).decode()
        except InvalidToken:
            return None

    def client(inst: Instance, token: str) -> UserGitLab:
        return UserGitLab(inst.url, token, verify=inst.ca_file or True)

    async def target(gl: UserGitLab, project: dict, inst: Instance) -> Target:
        me_gitlab = await gl.call("GET", "/user")
        link = f"{env('PUBLIC_URL').rstrip('/')}/p/{project['instance']}/{project['path']}"
        return Target(project_id=project["gitlab_id"], path=project["path"], default_branch=project["default_branch"] or "main",
                      username=me_gitlab["username"], link=link, enterprise=inst.enterprise)

    async def fixable(me: Viewer, slug: str, path: str, check: str) -> tuple[dict, Instance, Any]:
        project = await project_row(me, slug, path)
        if not me.can_maintain(slug, path):
            raise HTTPException(403, "corriger un projet est réservé à ses Maintainers dans GitLab")
        inst = instance(slug)
        f = FIXES.get(check)
        if f is None or (f.needs in NEEDS_LICENCE and not inst.enterprise):
            raise HTTPException(404, "pas de correction automatique pour cette preuve sur cette instance")
        return project, inst, f

    async def need_login(me: Viewer, slug: str) -> str:
        token = await user_token(me, slug)
        if token is None:
            # 428, not 401 (that one means the Keycloak session) nor 409 (a fix that conflicts with the repository).
            raise HTTPException(428, "connectez-vous d'abord à GitLab pour corriger avec votre compte")
        return token

    @r.get("/fixit/{slug}/status")
    async def status(slug: str, me: Me) -> dict:
        instance(slug)
        return {"connected": await user_token(me, slug) is not None}

    class Login(BaseModel):
        return_to: str = Field("/", max_length=500)

    @r.post("/fixit/{slug}/login")
    async def login(slug: str, body: Login, me: Me) -> dict:
        inst = instance(slug)
        # Only a path of this application: never an open redirect.
        back = body.return_to if re.match(r"^/(?![/\\])", body.return_to) else "/"
        verifier = secrets.token_urlsafe(48)
        nonce = secrets.token_urlsafe(24)
        await state["arq"].set(f"oauth:{nonce}", json.dumps({"sub": me.sub, "slug": slug, "verifier": verifier, "back": back}), ex=STATE_TTL_S)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        query = urlencode({"client_id": _secret_text(f"gitlab-oauth-{slug}", "client_id"), "redirect_uri": redirect_uri(slug), "response_type": "code",
                           "scope": "api", "state": nonce, "code_challenge": challenge, "code_challenge_method": "S256"})
        return {"url": f"{inst.url.rstrip('/')}/oauth/authorize?{query}"}

    @r.get("/fixit/{slug}/callback")
    async def callback(slug: str, state_: Annotated[str, Query(alias="state")] = "", code: str = "") -> RedirectResponse:
        # No bearer here (GitLab redirects the browser): the single-use state is what ties this code to a Keycloak user.
        raw = await state["arq"].getdel(f"oauth:{state_}") if state_ else None
        if raw is None:
            raise HTTPException(400, "lien de connexion expiré ou déjà utilisé : recommencez depuis Periskope")
        pending = json.loads(raw)
        if pending["slug"] != slug or not code:
            raise HTTPException(400, "réponse GitLab incomplète")
        inst = instance(slug)
        async with httpx.AsyncClient(verify=inst.ca_file or True, timeout=20) as http:
            resp = await http.post(f"{inst.url.rstrip('/')}/oauth/token", data={
                "client_id": _secret_text(f"gitlab-oauth-{slug}", "client_id"), "client_secret": _secret_text(f"gitlab-oauth-{slug}", "client_secret"),
                "code": code, "grant_type": "authorization_code", "redirect_uri": redirect_uri(slug), "code_verifier": pending["verifier"]})
        if resp.status_code != 200:
            raise HTTPException(502, "GitLab a refusé la connexion")
        token = resp.json()
        # The refresh token is dropped: when the access token expires, the person connects again.
        ttl = max(60, int(token.get("expires_in") or 7200) - 60)
        await state["arq"].set(f"gitlab-user:{pending['sub']}:{slug}", cipher().encrypt(token["access_token"].encode()), ex=ttl)
        return RedirectResponse(pending["back"], status_code=302)

    @r.post("/fixit/{slug}/logout", status_code=204)
    async def logout(slug: str, me: Me) -> None:
        await state["arq"].delete(f"gitlab-user:{me.sub}:{slug}")

    @r.get("/projects/{slug}/{path:path}/fixes")
    async def list_fixes(slug: str, path: str, me: Me) -> dict:
        project = await project_row(me, slug, path)
        found = instances().get(slug)
        enabled = bool(found and found.fixes and _secret_text(f"gitlab-oauth-{slug}", "client_id"))
        results = {}
        if enabled and project["last_run_id"]:
            results = await state["db"].fetchval("SELECT results FROM runs WHERE id = $1", project["last_run_id"]) or {}
        items = [{"check": f.check, "kind": f.kind, "label": f.label, "needs": f.needs} for f in FIXES.values()
                 if results.get(f.check, {}).get("status") == "fail" and not (f.needs in NEEDS_LICENCE and not found.enterprise)]
        return {"enabled": enabled, "can_fix": enabled and me.can_maintain(slug, path),
                "connected": enabled and await user_token(me, slug) is not None, "items": items}

    @r.post("/projects/{slug}/{path:path}/fixes/{check}/preview")
    async def preview(slug: str, path: str, check: str, me: Me) -> dict:
        project, inst, f = await fixable(me, slug, path, check)
        gl = client(inst, await need_login(me, slug))
        try:
            return {"check": check, "kind": f.kind, "label": f.label, **await f.preview(gl, await target(gl, project, inst))}
        except FixError as e:
            raise HTTPException(e.status if e.status in (403, 404, 409) else 502, str(e)) from None
        finally:
            await gl.aclose()

    @r.post("/projects/{slug}/{path:path}/fixes/{check}")
    async def apply(slug: str, path: str, check: str, me: Me) -> dict:
        project, inst, f = await fixable(me, slug, path, check)
        gl = client(inst, await need_login(me, slug))
        try:
            result = await f.apply(gl, await target(gl, project, inst))
        except FixError as e:
            await audit(me, "fix.refused", f"{slug}:{path}", after={"check": check, "reason": str(e)})
            raise HTTPException(e.status if e.status in (403, 404, 409) else 502, str(e)) from None
        finally:
            await gl.aclose()
        await audit(me, "fix.apply", f"{slug}:{path}", after={"check": check, "kind": f.kind, "url": result.get("url")})
        if f.kind == "setting":
            # A setting changes the evidence right away: measure it again. A merge request waits for its merge (webhook).
            try:
                run_id = await runs.create(state["db"], project["id"], project["default_branch"] or "main", "user", me.username)
                await state["arq"].enqueue_job("run_analysis", run_id, _queue_name=queue(slug), _job_id=f"run:{run_id}", _defer_by=timedelta(hours=-1))
                result["run"] = run_id
            except runs.AlreadyActive as e:
                result["run"] = e.run_id
        return {"check": check, "kind": f.kind, **result}

    return r
