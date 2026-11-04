"""From a Keycloak token to what a user may see: token checks, role, and the scope built from GitLab memberships."""
import asyncio
import json
import time
import uuid

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from periskope_api.auth import Settings, Verifier, viewer
from periskope_core.settings import Instance
from periskope_db import connect
from periskope_db.bootstrap import bootstrap

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
SETTINGS = Settings(issuer="https://kc.test/realms/periskope", audience="periskope-api", client_id="periskope")


class Keys:
    def get_signing_key_from_jwt(self, token):
        return type("K", (), {"key": KEY.public_key()})()


def verifier():
    v = Verifier.__new__(Verifier)
    v.settings, v.jwks = SETTINGS, Keys()
    return v


def token(**over):
    claims = {"iss": SETTINGS.issuer, "aud": SETTINGS.audience, "azp": "periskope", "sub": "u-1", "exp": int(time.time()) + 60,
              "preferred_username": "alice", "email": "alice@corp.test", "email_verified": True, **over}
    return "Bearer " + jwt.encode({k: v for k, v in claims.items() if v is not None}, KEY, algorithm="RS256")


@pytest.mark.parametrize("bad", [
    None, "Basic abc", token(aud="other-api"), token(iss="https://evil.test/realms/x"), token(exp=int(time.time()) - 10),
    token(azp="another-client"), token(sub=None),
])
def test_refused_tokens(bad):
    with pytest.raises(HTTPException) as e:
        asyncio.run(verifier().claims(bad))
    assert e.value.status_code == 401


def test_accepted_token_and_role():
    v = verifier()
    claims = asyncio.run(v.claims(token(resource_access={"periskope": {"roles": ["maintainer"]}})))
    assert claims["sub"] == "u-1" and v.role(claims) == "maintainer"
    assert v.role({"realm_access": {"roles": ["periskope-admin", "viewer"]}}) == "admin"
    # Another application's realm roles grant nothing here.
    assert v.role({"realm_access": {"roles": ["admin", "auditor"]}}) == "viewer"
    assert v.role({}) == "viewer"


class Arq:
    """Cached memberships per user, and a record of the resolution jobs the API asks for."""
    def __init__(self, members):
        self.members, self.jobs = members, []

    async def get(self, key):
        return json.dumps(self.members[key]).encode() if key in self.members else None

    async def enqueue_job(self, name, *args, **kw):
        self.jobs.append((name, args))


INSTANCE = Instance(slug="gl", name="GitLab", url="https://gitlab.test", tracked_namespaces=["team-a"])


def scope(database_url, claims, members=None, permissions=()):
    async def run():
        pool = await connect(database_url)
        await bootstrap(pool, {"gl": INSTANCE})
        for p in permissions:
            await pool.execute("INSERT INTO permissions (subject, instance, scope_kind, scope_value, role) VALUES ($1, $2, $3, $4, $5)", claims["sub"], *p)
        arq = Arq(members or {})
        v = await viewer(pool, arq, verifier(), claims)
        await pool.close()
        return v, arq
    return asyncio.run(run())


def test_scope_comes_from_gitlab_memberships(database_url):
    sub = f"u-{uuid.uuid4().hex}"
    v, _ = scope(database_url, {"sub": sub, "preferred_username": "alice", "email": "a@corp.test", "email_verified": True,
                                "resource_access": {"periskope": {"roles": ["maintainer"]}}},
                 {f"members:{sub}:gl": {"groups": ["team-a", "team-b"], "projects": [["x/lib", 42]], "maintains": ["team-a"]}})
    assert not v.admin and not v.reads_all and v.namespaces == frozenset({("gl", "team-a"), ("gl", "team-b")})
    # Launching follows the GitLab level, not the Keycloak role: Maintainer of team-a, a mere member of team-b.
    assert v.projects == frozenset({("gl", 42)}) and v.maintains == frozenset({("gl", "team-a")})


def test_unverified_email_never_reaches_gitlab(database_url):
    sub = f"u-{uuid.uuid4().hex}"
    v, arq = scope(database_url, {"sub": sub, "preferred_username": "mallory", "email": "victim@corp.test", "email_verified": False})
    assert v.namespaces == frozenset() and arq.jobs and arq.jobs[0][1][2] is None


def test_hand_granted_rights(database_url):
    sub = f"u-{uuid.uuid4().hex}"
    v, _ = scope(database_url, {"sub": sub, "preferred_username": "carol"}, permissions=[("gl", "namespace", "team-z", "admin")])
    # An admin right on one namespace is not an admin of everything.
    assert not v.admin and ("gl", "team-z") in v.namespaces and ("gl", "team-z") in v.maintains
    sub2 = f"u-{uuid.uuid4().hex}"
    v2, _ = scope(database_url, {"sub": sub2, "preferred_username": "dan"}, permissions=[(None, "all", None, "admin")])
    assert v2.admin


def test_hand_granted_project_and_instance(database_url):
    sub, path, gid = f"u-{uuid.uuid4().hex}", f"team-y/{uuid.uuid4().hex[:8]}", uuid.uuid4().int % 10**9

    async def run():
        pool = await connect(database_url)
        await bootstrap(pool, {"gl": INSTANCE})
        await pool.execute("INSERT INTO projects (instance, gitlab_id, path, namespace_path, namespace_kind, default_branch)"
                           " VALUES ('gl', $1, $2, 'team-y', 'group', 'main')", gid, path)
        await pool.execute("INSERT INTO permissions (subject, instance, scope_kind, scope_value, role) VALUES ($1, 'gl', 'project', $2, 'viewer'),"
                           " ($1, 'gl', 'all', NULL, 'viewer')", sub, path)
        v = await viewer(pool, Arq({}), verifier(), {"sub": sub, "preferred_username": "erin"})
        where, params = v.where()
        seen = await pool.fetchval(f"SELECT count(*) FROM projects p WHERE p.instance = 'gl' AND {where}", *params)
        total = await pool.fetchval("SELECT count(*) FROM projects WHERE instance = 'gl'")
        await pool.close()
        return v, seen, total
    v, seen, total = asyncio.run(run())
    # A project grant is that project; an instance grant without a namespace is the whole instance, read only.
    assert ("gl", gid) in v.projects and seen == total and not v.maintains


def test_workspace_roles_mapped(database_url, monkeypatch):
    monkeypatch.setenv("PERISKOPE_ROLE_MAP", '{"manager": "auditor", "user": "viewer"}')
    v = verifier()
    v.role_map = {"manager": "auditor", "user": "viewer"}
    assert v.role({"realm_access": {"roles": ["manager", "offline_access"]}}) == "auditor"
    assert v.role({"realm_access": {"roles": ["user"]}}) == "viewer"
    sub = f"u-{uuid.uuid4().hex}"

    async def run():
        pool = await connect(database_url)
        await bootstrap(pool, {"gl": INSTANCE})
        manager = await viewer(pool, Arq({}), v, {"sub": sub, "preferred_username": "marie", "realm_access": {"roles": ["manager"]}})
        await pool.close()
        return manager
    manager = asyncio.run(run())
    # A manager reads everything, administers nothing.
    assert manager.reads_all and not manager.admin and manager.where() == ("true", [])
