"""Client for a Shared Record log's public HTTP interface (no account needed).

Everything read from the log is checked before use: key documents against the pinned root,
receipts and checkpoints against the pinned operator key. The client itself trusts nothing.
"""

from __future__ import annotations

from typing import Any, Protocol
from urllib.parse import quote

import httpx


class LogError(RuntimeError):
    """The log refused a request or could not be reached."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class LogClient(Protocol):
    async def register(self, statement: bytes, obj: dict[str, Any] | None = None) -> dict[str, Any]: ...

    async def key_documents(self, issuer: str) -> list[dict[str, Any]]: ...

    async def latest_checkpoint(self, *, witnessed: bool = False) -> dict[str, Any] | None: ...

    async def consistency(self, old_size: int, new_size: int) -> list[str]: ...

    async def cosign(self, cosignature: dict[str, Any]) -> dict[str, Any]: ...


class HttpLogClient:
    """The log's routes under ``/v1/shared-record/log``. Pass ``client`` to reuse a connection pool
    (or, in tests, an ``httpx.AsyncClient`` bound to an ASGI app)."""

    def __init__(self, base_url: str, *, client: httpx.AsyncClient | None = None, timeout: float = 30.0) -> None:
        self._client = client or httpx.AsyncClient(base_url=base_url.rstrip("/"), timeout=timeout)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _call(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            resp = await self._client.request(method, "/v1/shared-record/log" + path, **kwargs)
        except httpx.HTTPError as exc:
            raise LogError(f"log unreachable: {type(exc).__name__}") from exc
        if resp.status_code == 404:
            return None
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("detail")
            except ValueError:
                detail = resp.text[:200]
            raise LogError(f"log refused: {detail}", resp.status_code)
        return resp.json()

    async def register(self, statement: bytes, obj: dict[str, Any] | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {"statement": statement.hex()}
        if obj is not None:
            body["object"] = obj
        answer = await self._call("POST", "/entries", json=body)
        if answer is None:
            raise LogError("the log is not enabled", 404)
        return answer

    async def key_documents(self, issuer: str) -> list[dict[str, Any]]:
        answer = await self._call("GET", f"/key-documents/{quote(issuer, safe='')}")
        return list((answer or {}).get("entries") or [])

    async def latest_checkpoint(self, *, witnessed: bool = False) -> dict[str, Any] | None:
        return await self._call("GET", "/checkpoints/latest", params={"witnessed": "true"} if witnessed else None)

    async def consistency(self, old_size: int, new_size: int) -> list[str]:
        answer = await self._call("GET", "/consistency", params={"old": old_size, "new": new_size})
        return list((answer or {}).get("path") or [])

    async def cosign(self, cosignature: dict[str, Any]) -> dict[str, Any]:
        return await self._call("POST", "/cosignatures", json=cosignature) or {}
