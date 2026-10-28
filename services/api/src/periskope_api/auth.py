"""Keycloak bearer tokens checked on every call, and the viewer's scope built from GitLab membership."""
from __future__ import annotations

import asyncio
import json
import ssl
from dataclasses import dataclass
from datetime import timedelta

import asyncpg
import jwt
from arq.connections import ArqRedis
from fastapi import HTTPException
from periskope_core.settings import env, queue
from periskope_db import Viewer

ROLES = ("viewer", "maintainer", "admin")
MEMBERSHIP_WAIT_S = 2.0


@dataclass
class Settings:
    issuer: str
    audience: str
    client_id: str

    @classmethod
    def from_env(cls) -> Settings:
        return cls(env("OIDC_ISSUER"), env("OIDC_AUDIENCE"), env("OIDC_CLIENT_ID"))


class Verifier:
    def __init__(self, settings: Settings, ca_file: str | None = None):
        self.settings = settings
        # JWKS cached 5 minutes; a new signing key triggers a refetch.
        ctx = ssl.create_default_context(cafile=ca_file) if ca_file else None
        self.jwks = jwt.PyJWKClient(f"{settings.issuer}/protocol/openid-connect/certs", cache_jwk_set=True, lifespan=300, ssl_context=ctx)

    async def claims(self, authorization: str | None) -> dict:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(401, "jeton manquant")
        token = authorization[7:]
        try:
            key = await asyncio.to_thread(self.jwks.get_signing_key_from_jwt, token)
            claims = jwt.decode(token, key.key, algorithms=["RS256", "ES256", "PS256"], audience=self.settings.audience,
                                issuer=self.settings.issuer, options={"require": ["exp", "iss", "aud", "sub"]})
        except jwt.PyJWTError as e:
            raise HTTPException(401, f"jeton refusé : {e}") from None
        if claims.get("azp") != self.settings.client_id:
            raise HTTPException(401, "jeton émis pour un autre client")
        return claims

    def role(self, claims: dict) -> str:
        roles = set((claims.get("resource_access", {}).get(self.settings.client_id) or {}).get("roles", []))
        roles |= set(claims.get("realm_access", {}).get("roles", []))
        return next((r for r in reversed(ROLES) if r in roles or f"periskope-{r}" in roles), "viewer")


async def viewer(db: asyncpg.Pool, arq: ArqRedis, verifier: Verifier, claims: dict) -> Viewer:
    """The sub is the key, never the login. Visibility is GitLab membership, cached 15 min by the collectors."""
    sub, username, email = claims["sub"], claims.get("preferred_username") or claims["sub"], claims.get("email")
    role = verifier.role(claims)
    await db.execute(
        "INSERT INTO users (sub, username, email, roles, groups, last_login) VALUES ($1, $2, $3, $4, $5, now())"
        " ON CONFLICT (sub) DO UPDATE SET username = $2, email = $3, roles = $4, groups = $5, last_login = now()",
        sub, username, email, [role], claims.get("groups", []),
    )
    if role == "admin":
        return Viewer(sub, username, admin=True)
    namespaces: set[tuple[str, str]] = set()
    projects: set[tuple[str, int]] = set()
    project_paths: set[tuple[str, str]] = set()
    slugs = [r["slug"] for r in await db.fetch("SELECT slug FROM gitlab_instances WHERE enabled")]
    for slug, found in zip(slugs, await asyncio.gather(*(membership(arq, sub, username, email, s) for s in slugs))):
        namespaces |= {(slug, g) for g in found.get("groups", [])}
        projects |= {(slug, pid) for _, pid in found.get("projects", [])}
        project_paths |= {(slug, path) for path, _ in found.get("projects", [])}
    maintains = namespaces | project_paths if role == "maintainer" else set()
    for g in await db.fetch("SELECT instance, scope_kind, scope_value, role FROM permissions WHERE subject = $1", sub):
        target = {(i, g["scope_value"] or "") for i in ([g["instance"]] if g["instance"] else slugs)}
        if g["scope_kind"] in ("namespace", "project"):
            namespaces |= target
            if g["role"] in ("maintainer", "admin"):
                maintains |= target
        elif g["scope_kind"] == "all" and g["role"] == "admin" and g["instance"] is None:
            return Viewer(sub, username, admin=True)
    return Viewer(sub, username, namespaces=frozenset(namespaces), projects=frozenset(projects), maintains=frozenset(maintains))


async def membership(arq: ArqRedis, sub: str, username: str, email: str | None, instance: str) -> dict:
    """Cached memberships; on a miss, asks the instance's collector at high priority and waits up to 2 s."""
    key = f"members:{sub}:{instance}"
    if (raw := await arq.get(key)) is not None:
        return json.loads(raw)
    # shortcut: a negative defer puts the job ahead of the queue; a second ARQ queue per priority would be cleaner.
    await arq.enqueue_job("resolve_memberships", sub, username, email, _queue_name=queue(instance), _job_id=key, _defer_by=timedelta(hours=-1))
    for _ in range(int(MEMBERSHIP_WAIT_S / 0.1)):
        await asyncio.sleep(0.1)
        if (raw := await arq.get(key)) is not None:
            return json.loads(raw)
    return {}
