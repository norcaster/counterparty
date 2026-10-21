"""LangGraph (``langchain-mcp-adapters``): your tool interceptors' decisions on a partner's MCP tools,
reported to the local MCP proxy.

An interceptor can change a call's name, arguments and headers, but not its ``_meta``, so the agent
reaches the partner through the proxy (``connections``), and ``interceptors`` wraps your own tool
interceptors for the proxied servers:

* an interceptor that **answers without calling the next handler** (a ``ToolMessage`` or a
  ``CallToolResult``): the proxy registers a ``blocked`` receipt and sends the partner a notice;
* an interceptor that **passes the call on with different arguments**
  (``request.override(args=...)``): the proxy receipts the call as ``redacted`` when it arrives.
  If the proxy cannot take that decision, the call is answered with an error instead, so no
  receipt misstates your boundary;
* otherwise nothing is reported, and the proxy receipts the call as ``allowed``.

Approvals: in your approval interceptor (for example one using LangGraph's ``interrupt()``), call
``approved()`` once the person approved (``allowed``, rule ``human_approval``), and give it
``@rule(HUMAN_REJECTED)`` so its rejecting branch is receipted ``human_rejected``.

The rule id is the interceptor's ``norcaster_rule_id`` attribute (``@rule("...")``), or else its
name. Your interceptors keep their order (the first is outermost)::

    control = ProxyControl("http://127.0.0.1:8790", token_file="state/proxy-token")
    client = MultiServerMCPClient(connections(control, ["birch"]),
                                  tool_interceptors=interceptors(control, spend_limit, redact_pii, servers=["birch"]))
    tools = await client.get_tools()

Install with ``pip install "norcaster-counterparty[langgraph]"``; ``langchain-mcp-adapters`` needs
the MCP Python SDK 1.x.
"""

from __future__ import annotations

import contextvars
import copy
import logging
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from . import HUMAN_APPROVAL, REDACTION_UNRECORDED, ProxyControl

TESTED_SDK_VERSIONS = ">=0.3.2,<0.4"

log = logging.getLogger("norcaster_counterparty.hooks.langgraph")


def rule(rule_id: str) -> Callable[[Any], Any]:
    """Name the rule behind an interceptor's decisions: ``@rule("aurora.spend_limit")``."""
    def mark(interceptor: Any) -> Any:
        interceptor.norcaster_rule_id = rule_id
        return interceptor
    return mark


def _rule_of(interceptor: Any) -> str:
    return str(getattr(interceptor, "norcaster_rule_id", None) or getattr(interceptor, "__name__", None)
               or type(interceptor).__name__)


def _servers(servers: Mapping[str, str] | Iterable[str]) -> dict[str, str]:
    pairs = dict(servers) if isinstance(servers, Mapping) else {name: name for name in servers}
    if not pairs:
        raise ValueError("name at least one proxied MCP server")
    return pairs


def connections(control: ProxyControl, servers: Mapping[str, str] | Iterable[str]) -> dict[str, dict[str, Any]]:
    """``MultiServerMCPClient`` connections that reach each partner through the proxy."""
    return {name: {"transport": "streamable_http", "url": control.mcp_url(upstream), "headers": control.headers}
            for name, upstream in _servers(servers).items()}


@dataclass
class _Call:
    """What the wrapped interceptors did to one tool call."""

    original: dict[str, Any]
    blocked_by: str | None = None
    blocked_args: dict[str, Any] = field(default_factory=dict)
    redacted_by: str | None = None
    approved: bool = False


_CALL: contextvars.ContextVar[_Call | None] = contextvars.ContextVar("norcaster_shared_record_call", default=None)

Handler = Callable[[Any], Awaitable[Any]]


def approved() -> None:
    """Call from your approval interceptor once a person approved the call (for example after
    LangGraph's ``interrupt()`` returned their answer): the receipt then says ``allowed`` with rule
    ``human_approval``. A redaction of the same call shows instead. Name the interceptor's
    rejecting branch with ``@rule("human_rejected")``."""
    call = _CALL.get()
    if call is None:
        log.warning("approved() was called outside a Shared Record interceptor chain; nothing recorded")
        return
    call.approved = True


def _error(text: str) -> Any:
    from mcp.types import CallToolResult

    return CallToolResult.model_validate({"content": [{"type": "text", "text": text}], "isError": True})


def interceptors(control: ProxyControl, *yours: Any, servers: Mapping[str, str] | Iterable[str]) -> list[Any]:
    """The tool interceptors for ``MultiServerMCPClient``: yours, in order, between two of ours that
    report what yours decided for calls to the proxied servers."""
    upstreams = _servers(servers)

    async def outermost(request: Any, handler: Handler) -> Any:
        upstream = upstreams.get(request.server_name)
        if upstream is None:
            return await handler(request)
        call = _Call(original=copy.deepcopy(dict(request.args or {})))
        token = _CALL.set(call)
        try:
            result = await handler(request)
        finally:
            _CALL.reset(token)
        if call.blocked_by is not None:
            try:
                await control.notice(upstream, request.name, call.blocked_args, call.blocked_by)
            except Exception as exc:  # noqa: BLE001 - the block stands whatever happens to the notice
                log.warning("the notice for %s could not be sent: %s", request.name, exc)
        return result

    def wrap(interceptor: Any) -> Any:
        async def wrapped(request: Any, handler: Handler) -> Any:
            call = _CALL.get()
            if call is None:
                return await interceptor(request, handler)
            passed_on = False

            async def next_handler(passed: Any) -> Any:
                nonlocal passed_on
                passed_on = True
                if dict(passed.args or {}) != dict(request.args or {}) and call.redacted_by is None:
                    call.redacted_by = _rule_of(interceptor)
                return await handler(passed)

            result = await interceptor(request, next_handler)
            if not passed_on and call.blocked_by is None:
                call.blocked_by, call.blocked_args = _rule_of(interceptor), copy.deepcopy(dict(request.args or {}))
            return result

        wrapped.__name__ = f"shared_record({_rule_of(interceptor)})"
        return wrapped

    async def innermost(request: Any, handler: Handler) -> Any:
        call = _CALL.get()
        upstream = upstreams.get(request.server_name)
        arguments = dict(request.args or {})
        if call is not None and upstream is not None and arguments != call.original:
            try:
                await control.decision(upstream, request.name, arguments, call.redacted_by or "redacted")
            except Exception as exc:  # noqa: BLE001 - fail closed: refuse rather than misstate the decision
                log.warning("the redaction of %s could not be recorded: %s", request.name, exc)
                return _error(REDACTION_UNRECORDED)
        elif call is not None and upstream is not None and call.approved:
            try:
                await control.decision(upstream, request.name, arguments, HUMAN_APPROVAL, outcome="allowed")
            except Exception as exc:  # noqa: BLE001 - the call goes on; its receipt only lacks the approval rule
                log.warning("the approval of %s could not be recorded: %s", request.name, exc)
        return await handler(request)

    return [outermost, *(wrap(i) for i in yours), innermost]


__all__ = ["TESTED_SDK_VERSIONS", "approved", "connections", "interceptors", "rule"]
