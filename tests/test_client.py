"""CV-CUE client: session sign-in, re-login on expiry, retries, and errors (no network)."""
import httpx
import pytest

from cvcue_roles import client as C
from cvcue_roles.client import CvcueClient, CvcueError

BASE = "https://cv.example/wifi/api"


@pytest.fixture(autouse=True)
def no_backoff(monkeypatch):
    monkeypatch.setattr(C, "_RETRY_BACKOFF", [0, 0, 0])


def make(handler):
    calls = []

    def wrapped(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path, dict(request.url.params)))
        return handler(request, calls)

    return CvcueClient(BASE, "KEY-1", "secret", cid="ATN1", transport=httpx.MockTransport(wrapped)), calls


async def test_signs_in_once_and_sends_cid():
    def handler(req, calls):
        if req.url.path.endswith("/session") and req.method == "POST":
            assert b'"keyId":"KEY-1"' in req.content.replace(b" ", b"")
            return httpx.Response(200, json={}, headers={"set-cookie": "JSESSIONID=abc; Path=/"})
        assert req.headers.get("cookie") == "JSESSIONID=abc"
        return httpx.Response(200, json=[{"templateId": 1}])

    c, calls = make(handler)
    assert await c.get("/deviceconfiguration/roleprofiles", params={"locationid": 0, "fetchSubTreeTemplates": True})
    await c.get("/deviceconfiguration/roleprofiles")
    assert [m for m, *_ in calls].count("POST") == 1
    assert calls[1][2] == {"CID": "ATN1", "locationid": "0", "fetchSubTreeTemplates": "true"}
    await c.aclose()
    assert calls[-1][0] == "DELETE"                      # logs out on close


async def test_signs_in_again_when_the_session_expires():
    state = {"gets": 0}

    def handler(req, calls):
        if req.method == "POST":
            return httpx.Response(200, json={})
        state["gets"] += 1
        return httpx.Response(401) if state["gets"] == 1 else httpx.Response(200, json={"ok": True})

    c, calls = make(handler)
    assert await c.get("/x") == {"ok": True}
    assert [m for m, *_ in calls] == ["POST", "GET", "POST", "GET"]


async def test_get_and_put_retry_server_errors_but_post_does_not():
    def flaky(req, calls):
        if req.url.path.endswith("/session"):
            return httpx.Response(200, json={})
        tries = sum(1 for m, p, _ in calls if p == req.url.path and m == req.method)
        return httpx.Response(503) if tries < 3 else httpx.Response(200, json={"n": tries})

    c, calls = make(flaky)
    assert await c.get("/a") == {"n": 3}
    assert await c.put("/b", json={}) == {"n": 3}
    with pytest.raises(CvcueError) as err:
        await c.post("/c", json={})                      # creating twice would duplicate a role profile
    assert err.value.status == 503
    assert sum(1 for m, p, _ in calls if p.endswith("/c")) == 1


async def test_errors_are_raised_with_status_and_body():
    def handler(req, calls):
        if req.url.path.endswith("/session"):
            return httpx.Response(200, json={})
        return httpx.Response(400, text='{"errors":[{"errorCode":"INVALID_INPUT"}]}')

    c, _ = make(handler)
    with pytest.raises(CvcueError) as err:
        await c.put("/deviceconfiguration/roleprofiles", json={})
    assert err.value.status == 400 and "INVALID_INPUT" in str(err.value)


async def test_rejected_key_is_reported():
    c, _ = make(lambda req, calls: httpx.Response(401, text="bad key"))
    with pytest.raises(CvcueError, match="sign-in to CV-CUE failed"):
        await c.get("/x")


async def test_unreachable_server_is_reported():
    def handler(req, calls):
        raise httpx.ConnectError("no route")

    c, _ = make(handler)
    with pytest.raises(CvcueError, match="cannot reach CV-CUE"):
        await c.get("/x")
