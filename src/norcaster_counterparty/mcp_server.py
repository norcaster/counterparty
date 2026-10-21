"""Receiving side for an MCP server: add Shared Record to a server you already run.

``add_shared_record(server, party)`` wraps the server's ``tools/call`` and ``tools/list``
handlers. On every call it:

1. checks the receipt in the request's ``_meta["norcaster/shared-record"]`` (``Counterparty.receive``):
   the sender's logged key document under the root you pinned, the log's inclusion receipt under
   the operator key you pinned, the sequence number, and the content commitment over the call
   exactly as received;
2. applies your own boundary (``decide``), then runs your tool only when both allow it;
3. returns your signed, logged acknowledgement in the result's ``_meta``, whether or not the
   tool ran.

It also serves the notice tool (``norcaster_shared_record_notice``), through which a sender whose
boundary blocked a call tells you so, with no content (decision D8). Your own handlers never see
a notice.

Works with the MCP Python SDK 1.x (low-level ``Server`` and ``FastMCP``) and 2.x (low-level
``Server`` and ``MCPServer``), on any transport. Call it after your tools are registered::

    from norcaster_counterparty.mcp_server import add_shared_record
    add_shared_record(server, party, decide=my_boundary)

Install with ``pip install "norcaster-counterparty[mcp]"``.
"""

from __future__ import annotations

import asyncio
import inspect
import json
from collections.abc import Awaitable, Callable
from typing import Any

from .party import META_KEY, Counterparty, Decide, Inbound, Refused

NOTICE_TOOL = "norcaster_shared_record_notice"
NOTICE_DESCRIPTION = "Receives a Shared Record notice for a call the sender's boundary blocked. Carries no content."

OnInbound = Callable[[str, Inbound], Any]


def _lowlevel(server: Any) -> Any:
    """The low-level ``Server`` behind ``FastMCP`` (1.x) or ``MCPServer`` (2.x), or ``server`` itself."""
    for attr in ("_lowlevel_server", "_mcp_server"):
        inner = getattr(server, attr, None)
        if inner is not None:
            return inner
    return server


async def _handle(party: Counterparty, *, name: str, arguments: dict[str, Any], block: Any, decide: Decide | None,
                  require_receipt: bool, on_inbound: OnInbound | None, lock: asyncio.Lock, run: Callable[[], Awaitable[Any]],
                  answer: Callable[[dict[str, Any], dict[str, Any] | None, bool], Any],
                  with_meta: Callable[[Any, dict[str, Any]], Any]) -> Any:
    if block is None and not require_receipt and name != NOTICE_TOOL:
        return await run()  # a client that does not take part: served as before, nothing signed
    try:
        async with lock:  # one at a time, so two concurrent calls cannot both pass the sequence check
            inbound = await party.receive(block, tool_name=name, arguments=arguments, decide=decide)
    except Refused as exc:
        return answer({"status": "refused", "error": f"Shared Record check failed: {exc}"}, None, True)
    if on_inbound is not None:
        done = on_inbound(name, inbound)
        if inspect.isawaitable(done):
            await done
    if name == NOTICE_TOOL:
        return answer({"status": "notice recorded", "exchange_id": inbound.exchange_id,
                       "content_check": inbound.content_check}, inbound.meta, False)
    if not inbound.run_tool:
        return answer({"status": "refused", "exchange_id": inbound.exchange_id, "content_check": inbound.content_check,
                       "rule": inbound.rule_id}, inbound.meta, True)
    return with_meta(await run(), inbound.meta)


def _merge(existing: Any, meta: dict[str, Any]) -> dict[str, Any]:
    merged = dict(existing or {})
    merged.update(meta)
    return merged


def add_shared_record(server: Any, party: Counterparty, *, decide: Decide | None = None, require_receipt: bool = True,
                      on_inbound: OnInbound | None = None) -> Any:
    """Wrap ``server``'s tool handlers with Shared Record; returns ``server``.

    ``decide(tool_name, arguments)`` is your boundary for a delivered call: ``("allowed", None)``,
    ``("redacted", rule)`` or ``("blocked", rule)``; the default allows. With ``require_receipt``
    false, a call with no Shared Record block runs as before and nothing is signed (for a server
    that also serves clients outside the pair). ``on_inbound(tool_name, inbound)`` is called once
    the acknowledgement is signed and registered.
    """
    low = _lowlevel(server)
    options = {"decide": decide, "require_receipt": require_receipt, "on_inbound": on_inbound, "lock": asyncio.Lock()}
    if hasattr(low, "add_request_handler"):
        _install_v2(low, party, **options)
    else:
        _install_v1(low, party, **options)
    return server


def _install_v1(low: Any, party: Counterparty, **options: Any) -> None:
    """MCP Python SDK 1.x: handlers live in ``Server.request_handlers``, keyed by request type."""
    from mcp import types

    call_handler = low.request_handlers.get(types.CallToolRequest)
    list_handler = low.request_handlers.get(types.ListToolsRequest)
    if call_handler is None or list_handler is None:
        raise ValueError("register the server's list_tools and call_tool handlers before add_shared_record")
    notice = types.Tool(name=NOTICE_TOOL, description=NOTICE_DESCRIPTION, inputSchema={"type": "object", "properties": {}})

    def answer(payload: dict[str, Any], meta: dict[str, Any] | None, error: bool) -> Any:
        raw: dict[str, Any] = {"content": [{"type": "text", "text": json.dumps(payload)}], "isError": error}
        if meta:
            raw["_meta"] = meta
        return types.ServerResult(types.CallToolResult.model_validate(raw))

    def with_meta(result: Any, meta: dict[str, Any]) -> Any:
        inner = result.root
        return types.ServerResult(inner.model_copy(update={"meta": _merge(inner.meta, meta)}))

    async def call_tool(req: Any) -> Any:
        params = req.params
        extra = (params.meta.model_extra or {}) if params.meta is not None else {}
        return await _handle(party, name=params.name, arguments=params.arguments or {}, block=extra.get(META_KEY),
                             run=lambda: call_handler(req), answer=answer, with_meta=with_meta, **options)

    async def list_tools(req: Any) -> Any:
        result = await list_handler(req)
        tools = list(result.root.tools)
        if not any(t.name == NOTICE_TOOL for t in tools):
            tools.append(notice)
        return types.ServerResult(result.root.model_copy(update={"tools": tools}))

    low.request_handlers[types.CallToolRequest] = call_tool
    low.request_handlers[types.ListToolsRequest] = list_tools


def _install_v2(low: Any, party: Counterparty, **options: Any) -> None:
    """MCP Python SDK 2.x: ``Server.get_request_handler`` / ``add_request_handler`` by method."""
    import mcp_types as types

    call_entry = low.get_request_handler("tools/call")
    list_entry = low.get_request_handler("tools/list")
    if call_entry is None or list_entry is None:
        raise ValueError("give the server on_list_tools and on_call_tool (or register tools) before add_shared_record")
    notice = types.Tool(name=NOTICE_TOOL, description=NOTICE_DESCRIPTION, input_schema={"type": "object", "properties": {}})

    def answer(payload: dict[str, Any], meta: dict[str, Any] | None, error: bool) -> Any:
        raw: dict[str, Any] = {"content": [{"type": "text", "text": json.dumps(payload)}], "isError": error}
        if meta:
            raw["_meta"] = meta
        return types.CallToolResult.model_validate(raw)

    def with_meta(result: Any, meta: dict[str, Any]) -> Any:
        return result.model_copy(update={"meta": _merge(result.meta, meta)})

    async def call_tool(ctx: Any, params: Any) -> Any:
        return await _handle(party, name=params.name, arguments=params.arguments or {}, block=(params.meta or {}).get(META_KEY),
                             run=lambda: call_entry.handler(ctx, params), answer=answer, with_meta=with_meta, **options)

    async def list_tools(ctx: Any, params: Any) -> Any:
        result = await list_entry.handler(ctx, params)
        tools = list(result.tools)
        if not any(t.name == NOTICE_TOOL for t in tools):
            tools.append(notice)
        return result.model_copy(update={"tools": tools})

    low.add_request_handler("tools/call", call_entry.params_type, call_tool)
    low.add_request_handler("tools/list", list_entry.params_type, list_tools)
