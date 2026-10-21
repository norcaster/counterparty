"""Adapters that report an agent framework's own boundary decisions to the local MCP proxy.

The proxy (``norcaster_counterparty.proxy``) signs a receipt for every call that reaches it. What it
cannot see is a call your agent's boundary stopped or changed before sending it. An adapter wraps
your framework's hook and tells the proxy, over its control channel:

* a call your boundary **blocked** becomes a ``blocked`` receipt, sent to the partner as a notice;
* a call your boundary **redacted** is receipted as ``redacted`` with your rule id when it arrives.

``ProxyControl`` is the control channel's client. It needs nothing beyond the base package.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import httpx

DEFAULT_URL = "http://127.0.0.1:8790"
RULE_KEY = "norcaster_rule_id"
"""A hook may name the rule behind its decision under this key; the adapter removes it before the
framework sees the output."""
HUMAN_APPROVAL = "human_approval"
"""The rule id of a call a person approved (as the Norcaster hub names it)."""
HUMAN_REJECTED = "human_rejected"
"""The rule id of a call a person rejected: it is not sent, and the partner gets a notice."""
REDACTION_UNRECORDED = ("Shared Record: the redaction could not be recorded with the local proxy, "
                        "so the call was not sent")


class ProxyControl:
    """Where the proxy listens and its bearer token (the ``token_file`` the proxy created).

    ``ProxyControl.from_env()`` reads ``NORCASTER_PROXY_URL`` and ``NORCASTER_PROXY_TOKEN`` or
    ``NORCASTER_PROXY_TOKEN_FILE``.
    """

    def __init__(self, url: str = DEFAULT_URL, *, token: str | None = None, token_file: str | Path | None = None,
                 timeout: float = 30.0) -> None:
        if token is None:
            if token_file is None:
                raise ValueError("give the proxy's token or token_file")
            token = Path(token_file).read_text().strip()
        self.url = url.rstrip("/")
        self.timeout = timeout
        self._token = token

    @classmethod
    def from_env(cls) -> ProxyControl:
        return cls(os.environ.get("NORCASTER_PROXY_URL") or DEFAULT_URL, token=os.environ.get("NORCASTER_PROXY_TOKEN"),
                   token_file=os.environ.get("NORCASTER_PROXY_TOKEN_FILE"))

    @property
    def headers(self) -> dict[str, str]:
        """The header your MCP client sends to the proxy."""
        return {"Authorization": f"Bearer {self._token}"}

    def mcp_url(self, upstream: str) -> str:
        """The URL your agent uses for the partner's MCP server, in place of the partner's own."""
        return f"{self.url}/mcp/{upstream}"

    @staticmethod
    def _body(upstream: str, tool_name: str, arguments: dict[str, Any], rule_id: str) -> dict[str, Any]:
        return {"upstream": upstream, "tool_name": tool_name, "arguments": arguments, "rule_id": rule_id}

    @staticmethod
    def _answer(resp: httpx.Response) -> Any:
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("detail")
            except ValueError:
                detail = resp.text[:200]
            raise RuntimeError(f"the proxy refused ({resp.status_code}): {detail}")
        return resp.json()

    # --- async (for hooks that run in an event loop) -------------------------------------------

    async def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            return self._answer(await client.request(method, f"{self.url}/control/v1/{path}", headers=self.headers, **kwargs))

    async def notice(self, upstream: str, tool_name: str, arguments: dict[str, Any], rule_id: str) -> dict[str, Any]:
        """Your boundary blocked this call: the proxy registers a ``blocked`` receipt and sends the notice."""
        return await self._request("POST", "notices", json=self._body(upstream, tool_name, arguments, rule_id))

    async def decision(self, upstream: str, tool_name: str, arguments: dict[str, Any], rule_id: str, *,
                       outcome: str = "redacted") -> dict[str, Any]:
        """Your boundary redacted this call (``outcome="redacted"``), or a person approved it
        (``outcome="allowed"``, rule ``human_approval``); ``arguments`` are the ones that will be sent."""
        return await self._request("POST", "decisions", json={**self._body(upstream, tool_name, arguments, rule_id),
                                                               "outcome": outcome})

    async def tool_names(self, upstream: str) -> list[str]:
        return list((await self._request("GET", f"tools/{upstream}"))["tools"])

    async def exchanges(self, limit: int = 50) -> list[dict[str, Any]]:
        return list((await self._request("GET", "exchanges", params={"limit": limit}))["exchanges"])

    # --- sync (for command hooks) --------------------------------------------------------------

    def _request_sync(self, method: str, path: str, **kwargs: Any) -> Any:
        with httpx.Client(timeout=self.timeout) as client:
            return self._answer(client.request(method, f"{self.url}/control/v1/{path}", headers=self.headers, **kwargs))

    def notice_sync(self, upstream: str, tool_name: str, arguments: dict[str, Any], rule_id: str) -> dict[str, Any]:
        return self._request_sync("POST", "notices", json=self._body(upstream, tool_name, arguments, rule_id))

    def decision_sync(self, upstream: str, tool_name: str, arguments: dict[str, Any], rule_id: str, *,
                      outcome: str = "redacted") -> dict[str, Any]:
        return self._request_sync("POST", "decisions", json={**self._body(upstream, tool_name, arguments, rule_id),
                                                              "outcome": outcome})

    def tool_names_sync(self, upstream: str) -> list[str]:
        return list(self._request_sync("GET", f"tools/{upstream}")["tools"])


__all__ = ["DEFAULT_URL", "HUMAN_APPROVAL", "HUMAN_REJECTED", "REDACTION_UNRECORDED", "RULE_KEY", "ProxyControl"]
