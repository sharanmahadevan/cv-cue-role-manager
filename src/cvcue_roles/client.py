"""
Minimal async CV-CUE API client (session cookie auth).

POST /session with an API key returns a JSESSIONID cookie used by later calls.
The client logs in lazily, re-logs in once on HTTP 401, and retries GET/PUT on
429/5xx. POST is never retried unless the request provably wasn't sent.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

log = logging.getLogger(__name__)

_RETRY_BACKOFF = [1.0, 2.0, 4.0]


class CvcueError(Exception):
    def __init__(self, status: int, method: str, path: str, body: str) -> None:
        self.status, self.method, self.path, self.body = status, method, path, body
        super().__init__(f"CV-CUE returned HTTP {status} for {method} {path}: {body[:300]}")


class CvcueClient:
    def __init__(self, base_url: str, key_id: str, key_value: str, cid: str = "", verify_ssl: bool = True,
                 transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self._body = {"type": "apikeycredentials", "keyId": key_id, "keyValue": key_value,
                      "clientIdentifier": "cv-cue-role-manager", "timeout": 3600}
        self._cid = {"CID": cid} if cid else {}
        self._http = httpx.AsyncClient(timeout=60, verify=verify_ssl, transport=transport,
                                       headers={"Accept": "application/json", "User-Agent": "cv-cue-role-manager"})
        self._lock = asyncio.Lock()
        self._logged_in = False
        self._gen = 0

    async def aclose(self) -> None:
        if self._logged_in:
            try:
                await self._http.delete(f"{self.base_url}/session", params=self._cid)
            except Exception:  # noqa: BLE001 - best effort logout
                pass
        await self._http.aclose()

    async def _login(self, stale_gen: int | None = None) -> None:
        async with self._lock:
            if self._logged_in and (stale_gen is None or stale_gen != self._gen):
                return
            self._http.cookies.clear()
            try:
                resp = await self._http.post(f"{self.base_url}/session", json=self._body, params=self._cid)
            except httpx.RequestError as exc:
                raise CvcueError(0, "POST", "/session", f"cannot reach CV-CUE: {exc}") from exc
            if not resp.is_success:
                raise CvcueError(resp.status_code, "POST", "/session", "sign-in to CV-CUE failed: " + resp.text)
            self._logged_in = True
            self._gen += 1

    async def request(self, method: str, path: str, *, params: dict | None = None, json: Any = None) -> Any:
        await self._login()
        query = {**self._cid, **{k: _param(v) for k, v in (params or {}).items() if v is not None}}
        idempotent = method.upper() != "POST"
        relogged = False
        for attempt in range(len(_RETRY_BACKOFF)):
            gen = self._gen
            try:
                resp = await self._http.request(method, f"{self.base_url}/{path.lstrip('/')}", params=query, json=json)
            except httpx.RequestError as exc:
                unsent = isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout))
                if attempt < len(_RETRY_BACKOFF) - 1 and (idempotent or unsent):
                    await asyncio.sleep(_RETRY_BACKOFF[attempt])
                    continue
                raise CvcueError(0, method, path, str(exc)) from exc
            if resp.status_code == 401 and not relogged:
                relogged = True
                await self._login(stale_gen=gen)
                continue
            if (resp.status_code == 429 or resp.status_code >= 500) and attempt < len(_RETRY_BACKOFF) - 1 \
                    and (idempotent or resp.status_code == 429):
                log.warning("HTTP %s on %s %s, retrying", resp.status_code, method, path)
                await asyncio.sleep(_RETRY_BACKOFF[attempt])
                continue
            if not resp.is_success:
                raise CvcueError(resp.status_code, method, path, resp.text)
            return resp.json() if resp.content else None
        raise CvcueError(0, method, path, "too many retries")

    async def get(self, path: str, **kw: Any) -> Any:
        return await self.request("GET", path, **kw)

    async def put(self, path: str, **kw: Any) -> Any:
        return await self.request("PUT", path, **kw)

    async def post(self, path: str, **kw: Any) -> Any:
        return await self.request("POST", path, **kw)

    async def delete(self, path: str, **kw: Any) -> Any:
        return await self.request("DELETE", path, **kw)


def _param(v: Any) -> Any:
    if isinstance(v, bool):
        return "true" if v else "false"
    return v
