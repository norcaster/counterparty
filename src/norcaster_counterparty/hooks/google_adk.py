"""Google ADK: your tool callbacks' decisions on a partner's MCP tools, reported to the local MCP proxy.

ADK's ``McpTool`` fills a request's ``_meta`` only with the OpenTelemetry trace context, so the agent
reaches the partner through the proxy (``mcp_toolset``), and this module wraps your agent's
``before_tool_callback``\\ s for the proxied tools:

* a callback that **answers the call itself** (returns a dict, so ADK skips the tool): the proxy
  registers a ``blocked`` receipt and sends the partner a notice;
* a callback that **changes** ``args`` **in place** (ADK then calls the tool with them): the proxy
  receipts the call as ``redacted`` when it arrives. If the proxy cannot take that decision, the
  call is answered with an error instead, so no receipt misstates your boundary;
* otherwise nothing is reported, and the proxy receipts the call as ``allowed``.

With ``require_confirmation``, ADK holds the call for a person and nothing is signed meanwhile. Once
confirmed, the receipt says ``allowed`` with rule ``human_approval``; if rejected, the call is not
sent and the partner gets a notice with rule ``human_rejected``.

The rule id is the returned dict's ``norcaster_rule_id`` (removed before the model sees it), the
callback's ``norcaster_rule_id`` attribute (``@rule("...")``), or else its function name. Your
callbacks run in order on the same ``args``; the first one that answers ends the chain.

ADK hands the whole MCP result, ``meta`` included, to the model. The proxy removes its
acknowledgement block anyway; with the proxy's ``include_status`` on, ``status_callback`` moves the
status out of the result into ``tool_context.state["temp:norcaster_shared_record"]``::

    control = ProxyControl("http://127.0.0.1:8790", token_file="state/proxy-token")
    agent = LlmAgent(
        name="procurement", model=...,
        tools=[mcp_toolset(control, "birch")],
        before_tool_callback=before_tool_callback(control, spend_limit, redact_pii),
        after_tool_callback=[status_callback],
    )

Decisions made by ADK plugins (``BasePlugin.before_tool_callback``) run before the agent's
callbacks and are not seen here; put boundary decisions for proxied tools on the agent.
"""

from __future__ import annotations

import collections
import copy
import inspect
import logging
from collections.abc import Callable
from typing import Any

from ..proxy import STATUS_KEY
from . import HUMAN_APPROVAL, HUMAN_REJECTED, REDACTION_UNRECORDED, RULE_KEY, ProxyControl

TESTED_SDK_VERSIONS = ">=2.12.0,<2.13"
STATE_KEY = "temp:norcaster_shared_record"
UPSTREAM_ATTR = "norcaster_upstream"

log = logging.getLogger("norcaster_counterparty.hooks.google_adk")


def rule(rule_id: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Name the rule behind a callback's decisions: ``@rule("aurora.pii.email")``."""
    def mark(fn: Callable[..., Any]) -> Callable[..., Any]:
        fn.norcaster_rule_id = rule_id  # type: ignore[attr-defined]
        return fn
    return mark


def _rule_of(callback: Any) -> str:
    return str(getattr(callback, "norcaster_rule_id", None) or getattr(callback, "__name__", None) or type(callback).__name__)


async def _maybe(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


_TOOLSET_CLASS: Any = None


async def _will_pause(tool: Any, args: dict[str, Any], tool_context: Any) -> bool:
    """Whether ADK's confirmation gate will hold this call for a person (``require_confirmation``)."""
    check = getattr(tool, "check_require_confirmation", None)
    if check is None:
        return False
    try:
        return bool(await check(args, tool_context))
    except Exception:  # noqa: BLE001 - the gate itself reports a failing check
        return False


def mcp_toolset(control: ProxyControl, upstream: str, **kwargs: Any) -> Any:
    """An ``McpToolset`` for the partner's MCP server, reached through the proxy. Its tools carry
    the upstream's name, so the callbacks know which calls to report."""
    global _TOOLSET_CLASS
    from google.adk.tools.mcp_tool.mcp_session_manager import StreamableHTTPConnectionParams
    from google.adk.tools.mcp_tool.mcp_toolset import McpToolset

    if _TOOLSET_CLASS is None:
        class SharedRecordToolset(McpToolset):
            """An ``McpToolset`` whose tools are marked with the proxy upstream they go to."""

            def __init__(self, *args: Any, norcaster_upstream: str, **kw: Any) -> None:
                super().__init__(*args, **kw)
                self.norcaster_upstream = norcaster_upstream

            async def get_tools(self, readonly_context: Any = None) -> list[Any]:
                tools = await super().get_tools(readonly_context)
                for tool in tools:
                    setattr(tool, UPSTREAM_ATTR, self.norcaster_upstream)
                return tools

        _TOOLSET_CLASS = SharedRecordToolset
    params = StreamableHTTPConnectionParams(url=control.mcp_url(upstream), headers=control.headers)
    return _TOOLSET_CLASS(connection_params=params, norcaster_upstream=upstream, **kwargs)


def _partner_tool_name(tool: Any) -> str:
    raw = getattr(tool, "raw_mcp_tool", None)
    return str(getattr(raw, "name", None) or tool.name)


def before_tool_callback(control: ProxyControl, *callbacks: Callable[..., Any]) -> Callable[..., Any]:
    """One ``before_tool_callback`` that runs ``callbacks`` in order and reports to the proxy."""
    noticed: collections.deque[str] = collections.deque(maxlen=1000)

    async def notice(upstream: str, tool: Any, tool_context: Any, args: dict[str, Any], rule_id: str) -> None:
        key = str(getattr(tool_context, "function_call_id", None) or id(tool_context))
        if key in noticed:
            return
        noticed.append(key)
        try:
            await control.notice(upstream, _partner_tool_name(tool), copy.deepcopy(args), rule_id)
        except Exception as exc:  # noqa: BLE001 - the block stands whatever happens to the notice
            log.warning("the notice for %s could not be sent: %s", tool.name, exc)

    async def callback(tool: Any, args: dict[str, Any], tool_context: Any) -> dict[str, Any] | None:
        upstream = getattr(tool, UPSTREAM_ATTR, None)
        confirmation = getattr(tool_context, "tool_confirmation", None) if upstream is not None else None
        if confirmation is not None and not getattr(confirmation, "confirmed", False):
            # A person rejected the call (require_confirmation): ADK's gate answers it, nothing is sent.
            await notice(upstream, tool, tool_context, args, HUMAN_REJECTED)
            return None
        original, redacted_by = copy.deepcopy(args), None
        for each in callbacks:
            before = copy.deepcopy(args)
            answer = await _maybe(each(tool=tool, args=args, tool_context=tool_context))
            if args != before:
                redacted_by = _rule_of(each)
            if answer is None:
                continue
            rule_id = (answer.pop(RULE_KEY, None) if isinstance(answer, dict) else None) or _rule_of(each)
            if upstream is not None:
                await notice(upstream, tool, tool_context, args, str(rule_id))
            return answer
        if upstream is None:
            return None
        if confirmation is None and await _will_pause(tool, args, tool_context):
            return None  # ADK's gate asks a person first; the decision is reported when the call resumes
        if args != original:
            try:
                await control.decision(upstream, _partner_tool_name(tool), copy.deepcopy(args), str(redacted_by))
            except Exception as exc:  # noqa: BLE001 - fail closed: refuse rather than misstate the decision
                log.warning("the redaction of %s could not be recorded: %s", tool.name, exc)
                return {"error": REDACTION_UNRECORDED}
        elif confirmation is not None:  # a person approved it (a redaction above would show instead)
            try:
                await control.decision(upstream, _partner_tool_name(tool), copy.deepcopy(args), HUMAN_APPROVAL, outcome="allowed")
            except Exception as exc:  # noqa: BLE001 - the call goes on; its receipt only lacks the approval rule
                log.warning("the approval of %s could not be recorded: %s", tool.name, exc)
        return None

    return callback


def status_callback(tool: Any, args: dict[str, Any], tool_context: Any, tool_response: Any) -> None:
    """An ``after_tool_callback`` that moves the proxy's status (``include_status``) out of the result
    the model sees and into ``tool_context.state[STATE_KEY]``. Returns None, so your own
    after-callbacks still run; put it first."""
    if getattr(tool, UPSTREAM_ATTR, None) is None or not isinstance(tool_response, dict):
        return None
    meta = tool_response.get("meta")
    if isinstance(meta, dict) and STATUS_KEY in meta:
        tool_context.state[STATE_KEY] = meta.pop(STATUS_KEY)
        if not meta:
            tool_response.pop("meta")
    return None


__all__ = ["STATE_KEY", "TESTED_SDK_VERSIONS", "before_tool_callback", "mcp_toolset", "rule", "status_callback"]
