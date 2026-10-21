"""Sending side for the OpenAI Agents SDK: receipts on your agent's calls to a partner's MCP tools.

``partner_server(...)`` returns an ``MCPServerStreamableHttp`` for the partner's MCP server,
wired to your ``Counterparty``. Give it to your ``Agent`` like any MCP server. For every call
the agent makes to one of the partner's tools:

* **before the call** (the SDK's ``tool_meta_resolver``): ``Counterparty.send`` signs and
  registers a receipt committing to the call as sent, and the exchange block goes in the
  request's ``_meta["norcaster/shared-record"]``;
* **after it** (the SDK's ``custom_data_extractor``): the partner's acknowledgement is read from
  the result's ``_meta`` and checked with ``Counterparty.accept_acknowledgement``. The status,
  ``acknowledged``, ``mismatch``, ``missing`` or ``invalid``, is put on the run's tool output
  item (``item.custom_data["norcaster/shared-record"]``; the model never sees it), on a trace
  span named ``norcaster.shared_record``, in ``server.exchanges`` and to ``on_exchange``;
* **when one of your tool input guardrails does not allow the call**: nothing is delivered. A
  receipt with ``outcome: blocked`` and ``delivered: false`` is registered and sent as a notice
  through the partner's notice tool (decision D8). The guardrail's own result stands.

The boundary decision a receipt names:

====================================================  ===========  ===================================
your boundary                                          ``outcome``  ``rule_id``
====================================================  ===========  ===================================
every tool input guardrail allows; ``redact`` changes   ``allowed``  none
nothing (or there is no ``redact``)
every guardrail allows; ``redact`` changes the          ``redacted`` the rule ``redact`` returns
arguments (the commitment covers the redacted call,                  (``"redacted"`` if none)
which is what is sent)
the first guardrail that does not allow the call        ``blocked``  ``output_info["rule_id"]`` when it
(``reject_content`` or ``raise_exception``)                          is a string, else the guardrail's
                                                                     name
a person approved the call (``require_approval``,       ``allowed``  ``human_approval``
``state.approve``) and nothing was redacted
a person rejected it with ``await server.reject(state,   ``blocked``  ``human_rejected``; the partner gets
item)`` (in place of ``state.reject``)                               a notice
====================================================  ===========  ===================================

``policy_version`` and ``policy_content_hash`` come from your ``counterparty.json``, as in every
receipt the component signs. The agent framework never sees a private key: the keys stay in the
component's ``state_dir``.

Scope: MCP tools over Streamable HTTP. Function tools and handoffs carry no MCP ``_meta`` and are
not covered; SSE and stdio servers are not covered either.

The result ``_meta`` reaches this module through ``MCPToolCustomDataContext.result_meta``, which
the SDK's source defines but its documentation does not describe. The extra pins the SDK versions
this was tested with, and the tests fail if that hook changes.

Install with ``pip install "norcaster-counterparty[openai-agents]"``.
"""

from __future__ import annotations

import asyncio
import base64
import collections
import copy
import inspect
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from agents import ToolGuardrailFunctionOutput, ToolInputGuardrail
from agents.mcp import (
    MCPServerStreamableHttp,
    MCPToolCustomDataContext,
    MCPToolMetaContext,
)
from agents.tool_guardrails import ToolInputGuardrailData
from agents.tracing import custom_span

from .exchange_status import ExchangeStatus, settle
from .hooks import HUMAN_APPROVAL, HUMAN_REJECTED
from .mcp_server import NOTICE_TOOL
from .party import META_KEY, Counterparty, Outbound, Refused

TESTED_SDK_VERSIONS = ">=0.24.0,<0.25"
SPAN_NAME = "norcaster.shared_record"

Redact = Callable[[str, dict[str, Any]], "tuple[dict[str, Any], str | None] | None"]
"""``redact(tool_name, arguments)``: return ``(arguments_to_send, rule_id)``, or None to send as is."""


@dataclass
class _Pending:
    out: Outbound
    tool_name: str
    outcome: str
    rule_id: str | None


def _approved_by_a_person(run_context: Any) -> bool:
    """Whether this tool call waited for approval and a person approved it (``state.approve``)."""
    status = getattr(run_context, "is_tool_approved", None)  # the SDK's name-only check for one call
    name, call_id = getattr(run_context, "tool_name", None), getattr(run_context, "tool_call_id", None)
    if status is None or not name or not call_id:
        return False
    try:
        return status(name, call_id) is True
    except Exception:  # noqa: BLE001 - no approval recorded for this call
        return False


async def _maybe(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


class SharedRecordMCPServer(MCPServerStreamableHttp):
    """A partner's MCP server whose every tool call carries a Shared Record receipt.

    Takes the arguments of ``MCPServerStreamableHttp`` plus the exchange's parties. Your own
    ``tool_meta_resolver`` and ``custom_data_extractor``, if you pass them, still run; their
    results are merged with this module's, and a resolver may not set ``norcaster/shared-record``.
    """

    def __init__(self, params: Any, *, party: Counterparty, partner_org: str, partner_agent: str, agent_id: str,
                 redact: Redact | None = None, notice_tool: str = NOTICE_TOOL,
                 on_exchange: Callable[[ExchangeStatus], Any] | None = None, keep_statuses: int = 1000,
                 tool_meta_resolver: Any = None, custom_data_extractor: Any = None,
                 tool_input_guardrails: list[ToolInputGuardrail[Any]] | None = None, **kwargs: Any) -> None:
        super().__init__(params, tool_meta_resolver=self._resolve_meta, custom_data_extractor=self._extract_custom_data,
                         tool_input_guardrails=[self._guard(g) for g in tool_input_guardrails or []], **kwargs)
        self.party = party
        self.partner_org, self.partner_agent, self.agent_id = partner_org, partner_agent, agent_id
        self.notice_tool = notice_tool
        self._redact = redact
        self._on_exchange = on_exchange
        self._user_resolver, self._user_extractor = tool_meta_resolver, custom_data_extractor
        self.exchanges: collections.deque[ExchangeStatus] = collections.deque(maxlen=keep_statuses)
        self._lock = asyncio.Lock()  # one send at a time: each receipt takes the next sequence number
        self._pending: dict[str, _Pending] = {}  # exchange id -> a call whose acknowledgement is due
        self._by_call: dict[Any, str] = {}  # the SDK's tool call -> exchange id
        self._noticed: collections.deque[Any] = collections.deque(maxlen=keep_statuses)  # calls already noticed
        self._tool_names: set[str] = set()

    # --- the SDK's hooks ----------------------------------------------------------------------------

    async def list_tools(self, run_context: Any = None, agent: Any = None) -> list[Any]:
        """The partner's tools, without the notice tool (only this module calls it) and without a
        static ``_meta`` entry under our key, which the SDK would otherwise send in place of the receipt."""
        tools = []
        for tool in await super().list_tools(run_context, agent):
            if tool.name == self.notice_tool:
                continue
            meta = getattr(tool, "meta", None)
            if isinstance(meta, dict) and META_KEY in meta:
                tool = tool.model_copy(update={"meta": {k: v for k, v in meta.items() if k != META_KEY} or None})
            tools.append(tool)
        self._tool_names = {t.name for t in tools}
        return tools

    async def _resolve_meta(self, context: MCPToolMetaContext) -> dict[str, Any]:
        extra = await _maybe(self._user_resolver(context)) if self._user_resolver else None
        if extra is not None and (not isinstance(extra, dict) or META_KEY in extra):
            raise Refused(f"another tool_meta_resolver may not set {META_KEY}")
        arguments = copy.deepcopy(dict(context.arguments or {}))
        outcome, rule_id = "allowed", None
        if self._redact is not None:
            redacted = self._redact(context.tool_name, copy.deepcopy(arguments))
            if redacted is not None and redacted[0] != arguments:
                arguments, outcome, rule_id = dict(redacted[0]), "redacted", redacted[1] or "redacted"
        if outcome == "allowed" and _approved_by_a_person(context.run_context):
            rule_id = HUMAN_APPROVAL  # a redaction would show instead: the receipt must show changed content
        try:
            out = await self._send(context.tool_name, arguments, outcome=outcome, rule_id=rule_id)
        except Refused as exc:
            await self._report(ExchangeStatus(None, context.tool_name, "refused", False, outcome, rule_id, detail=str(exc)))
            raise
        self._pending[out.exchange_id] = _Pending(out, context.tool_name, outcome, rule_id)
        self._by_call[self._call_key(context.run_context)] = out.exchange_id
        return {**(extra or {}), **out.meta}

    async def call_tool(self, tool_name: str, arguments: dict[str, Any] | None, meta: dict[str, Any] | None = None) -> Any:
        """Send only calls that carry the receipt this server just signed, with the arguments it
        committed to (the redacted ones, when ``redact`` changed them)."""
        block = (meta or {}).get(META_KEY)
        exchange_id = ((block or {}).get("receipt") or {}).get("exchange_id") if isinstance(block, dict) else None
        pending = self._pending.get(exchange_id) if exchange_id else None
        if pending is None or block != pending.out.meta[META_KEY]:
            raise Refused(f"refusing to call {tool_name} on the partner's server without the receipt signed for it")
        sent = json.loads(base64.b64decode(block["content_b64"]))
        if sent.get("name") != tool_name:
            raise Refused(f"the receipt is for {sent.get('name')}, not {tool_name}")
        try:
            return await super().call_tool(tool_name, sent["arguments"], meta)
        except BaseException:
            # No result, so no acknowledgement: after the deadline, record_missing_acknowledgements()
            # registers a missing-acknowledgement record for this receipt.
            if self._pending.pop(exchange_id, None) is not None:
                self._by_call = {k: v for k, v in self._by_call.items() if v != exchange_id}
                await self._report(ExchangeStatus(exchange_id, tool_name, "missing", True, pending.outcome, pending.rule_id,
                                                  detail="the call failed before a result came back"))
            raise

    async def _extract_custom_data(self, context: MCPToolCustomDataContext) -> dict[str, Any] | None:
        extra = await _maybe(self._user_extractor(context)) if self._user_extractor else None
        exchange_id = self._by_call.pop(self._call_key(context.run_context), None)
        pending = self._pending.pop(exchange_id, None) if exchange_id else None
        if pending is None:
            return extra
        status = await self._settle(pending, context.result_meta)
        return {**dict(extra or {}), META_KEY: status.as_dict()}

    # --- blocked calls --------------------------------------------------------------------------------

    def _guard(self, guardrail: ToolInputGuardrail[Any]) -> ToolInputGuardrail[Any]:
        async def run(data: ToolInputGuardrailData) -> ToolGuardrailFunctionOutput:
            result = await guardrail.run(data)
            if result.behavior.get("type") != "allow":
                await self._notify_blocked(data, guardrail, result)
            return result

        return ToolInputGuardrail(guardrail_function=run, name=guardrail.get_name())

    async def reject(self, state: Any, approval_item: Any, *, rejection_message: str | None = None,
                     always_reject: bool = False) -> ExchangeStatus | None:
        """Reject a call waiting for approval (``state.reject``) and, when it is one of this partner's
        tools, register a ``blocked`` receipt with rule ``human_rejected`` and send the partner a
        notice. Use it in place of ``state.reject``: the SDK reports a rejection to no hook."""
        state.reject(approval_item, always_reject=always_reject, rejection_message=rejection_message)
        raw = getattr(approval_item, "raw_item", None)
        name = getattr(raw, "name", None) or getattr(approval_item, "tool_name", None)
        if not name or (self._tool_names and self._mcp_name(str(name)) not in self._tool_names):
            return None
        call_id = getattr(raw, "call_id", None) or id(approval_item)
        return await self._send_notice(self._mcp_name(str(name)), getattr(raw, "arguments", None), HUMAN_REJECTED, key=call_id)

    async def _notify_blocked(self, data: ToolInputGuardrailData, guardrail: ToolInputGuardrail[Any],
                              result: ToolGuardrailFunctionOutput) -> None:
        """Register a ``blocked`` receipt and send it as a notice. Never changes the guardrail's
        result: the block stands whatever happens to the notice."""
        info = result.output_info
        rule_id = info["rule_id"] if isinstance(info, Mapping) and isinstance(info.get("rule_id"), str) else guardrail.get_name()
        await self._send_notice(self._mcp_name(data.context.tool_name), data.context.tool_arguments, rule_id,
                                key=self._call_key(data.context))

    async def _send_notice(self, tool_name: str, raw_arguments: Any, rule_id: str, *, key: Any) -> ExchangeStatus | None:
        """A ``blocked`` receipt for a call that is not sent, delivered to the partner as a notice
        (once per tool call)."""
        if key in self._noticed:
            return None
        self._noticed.append(key)
        if isinstance(raw_arguments, dict):
            arguments: Any = dict(raw_arguments)
        else:
            raw = raw_arguments or "{}"
            try:
                arguments = json.loads(raw)
            except ValueError:
                arguments = None
            if not isinstance(arguments, dict):
                arguments = {"_unparsed_arguments": raw}  # what the model asked for, kept as text
        try:
            out = await self._send(tool_name, arguments, outcome="blocked", rule_id=rule_id)
        except Refused as exc:
            status = ExchangeStatus(None, tool_name, "refused", False, "blocked", rule_id, detail=str(exc))
            await self._report(status)
            return status
        pending = _Pending(out, tool_name, "blocked", rule_id)
        try:
            answer = await MCPServerStreamableHttp.call_tool(self, self.notice_tool, {}, out.meta)
        except Exception as exc:  # noqa: BLE001 - the notice is best effort; the block is not
            status = ExchangeStatus(out.exchange_id, tool_name, "missing", False, "blocked", rule_id,
                                    detail=f"the notice did not reach the partner ({type(exc).__name__})")
            await self._report(status)
            return status
        return await self._settle(pending, getattr(answer, "meta", None))

    # --- helpers --------------------------------------------------------------------------------------

    async def _send(self, tool_name: str, arguments: dict[str, Any], *, outcome: str, rule_id: str | None) -> Outbound:
        async with self._lock:
            return await self.party.send(to_org=self.partner_org, to_agent=self.partner_agent, agent_id=self.agent_id,
                                         tool_name=tool_name, arguments=arguments, outcome=outcome, rule_id=rule_id)

    async def _settle(self, pending: _Pending, result_meta: Any) -> ExchangeStatus:
        status = await settle(self.party, pending.out, tool_name=pending.tool_name, outcome=pending.outcome,
                              rule_id=pending.rule_id, result_meta=result_meta)
        await self._report(status)
        return status

    async def _report(self, status: ExchangeStatus) -> None:
        self.exchanges.append(status)
        with custom_span(SPAN_NAME, data=status.as_dict()):
            pass
        if self._on_exchange is not None:
            await _maybe(self._on_exchange(status))

    def _mcp_name(self, public_name: str) -> str:
        """The partner's tool name behind the SDK's public name (they differ only when the agent
        prefixes tool names with the server name)."""
        if public_name in self._tool_names or not self._tool_names:
            return public_name
        matches = [n for n in self._tool_names if public_name.endswith(n)]
        return max(matches, key=len) if matches else public_name

    @staticmethod
    def _call_key(run_context: Any) -> Any:
        call_id = getattr(run_context, "tool_call_id", None)
        return call_id if isinstance(call_id, str) and call_id else id(run_context)


def partner_server(url: str, *, party: Counterparty, partner_org: str, partner_agent: str, agent_id: str,
                   headers: dict[str, str] | None = None, name: str | None = None, **kwargs: Any) -> SharedRecordMCPServer:
    """The partner's MCP server at ``url`` (Streamable HTTP), with Shared Record on every call.

    ``agent_id`` is your agent, as listed in your key document; ``partner_org`` and
    ``partner_agent`` are the partner's organisation id (pinned in your config) and receiving agent.
    Other keyword arguments go to ``MCPServerStreamableHttp`` (``tool_input_guardrails``,
    ``require_approval``, ``cache_tools_list``, ...) or set ``redact`` and ``on_exchange``.
    """
    params: dict[str, Any] = {"url": url}
    if headers:
        params["headers"] = headers
    return SharedRecordMCPServer(params, party=party, partner_org=partner_org, partner_agent=partner_agent,
                                 agent_id=agent_id, name=name or f"{partner_org} (Shared Record)", **kwargs)


__all__ = ["TESTED_SDK_VERSIONS", "ExchangeStatus", "Redact", "SharedRecordMCPServer", "partner_server"]
