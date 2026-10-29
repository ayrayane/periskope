"""Who sees what: the Keycloak user is matched to exactly one active GitLab account, then to its memberships."""
import json

import httpx
from periskope_clients.gitlab import GitLab
from periskope_collector.sync import memberships

USERS = [
    {"username": "alice", "email": "alice@corp.test", "state": "active", "bot": False},
    {"username": "bob", "email": "bob@other.test", "state": "active", "bot": False},
    {"username": "bob-corp", "email": "bob@corp.test", "state": "active", "bot": False},
    {"username": "carol", "email": "carol@corp.test", "state": "blocked", "bot": False},
]


def node(level, **kw):
    return {"accessLevel": {"integerValue": level}, **kw}


def gitlab(tmp_path):
    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v4/users":
            q = request.url.params
            if "username" in q:
                return httpx.Response(200, json=[u for u in USERS if u["username"] == q["username"]])
            return httpx.Response(200, json=[u for u in USERS if q["search"] in u["email"]])
        user = json.loads(request.content)["variables"]["username"]
        return httpx.Response(200, json={"data": {"user": {
            "groupMemberships": {"pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": [
                node(30, group={"fullPath": f"team-{user}"}), node(5, group={"fullPath": "minimal-only"})]},
            "projectMemberships": {"pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": [
                node(10, project={"fullPath": "x/guest", "id": "gid://gitlab/Project/42"})]}}}})
    token = tmp_path / "t"
    token.write_text("x")
    return GitLab("https://gitlab.test", token, transport=httpx.MockTransport(handle))


async def test_same_login_same_email(tmp_path):
    found = await memberships(gitlab(tmp_path), "alice", "alice@corp.test")
    assert found["groups"] == ["team-alice"]  # minimal access does not count
    assert [tuple(p) for p in found["projects"]] == [("x/guest", 42)]


async def test_same_login_other_email_is_another_person(tmp_path):
    # Keycloak "bob" is bob@corp.test; GitLab "bob" is someone else: the e-mail picks GitLab "bob-corp".
    found = await memberships(gitlab(tmp_path), "bob", "bob@corp.test")
    assert found["groups"] == ["team-bob-corp"]


async def test_blocked_or_unknown_sees_nothing(tmp_path):
    assert await memberships(gitlab(tmp_path), "carol", "carol@corp.test") is None
    assert await memberships(gitlab(tmp_path), "dave", "dave@corp.test") is None
