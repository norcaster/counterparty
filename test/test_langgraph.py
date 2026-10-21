"""The LangGraph adapter (``norcaster_counterparty.hooks.langgraph``) with ``langchain-mcp-adapters``
(pinned), Aurora's local MCP proxy and Birch's MCP server on 127.0.0.1, and the quickstart sandbox as
the log. The tools are invoked as LangChain tool calls, and once by a LangGraph agent driven by a
fake chat model: no model API is called. Synthetic data."""

# ruff: noqa: F811  (pytest fixtures imported from two_companies are used as parameters)
from __future__ import annotations

import asyncio
import importlib.metadata
import inspect
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("mcp", reason="needs the mcp extra")
pytest.importorskip("langchain_mcp_adapters", reason="needs the langgraph extra")

from langchain_core.messages import AIMessage, ToolMessage  # noqa: E402
from langchain_mcp_adapters.client import MultiServerMCPClient  # noqa: E402
from mcp.types import CallToolResult, TextContent  # noqa: E402
from two_companies import (  # noqa: E402
    TOKEN,
    Birch,
    _lowlevel_app,
    aurora_party,
    birch_party,
    control,
    exchange,
    export_and_verify,
    last_status,
    start_proxy,
)
from two_companies import configs, log_url, serve  # noqa: E402,F401  (pytest fixtures, used by parameter name)

from norcaster_counterparty.hooks import REDACTION_UNRECORDED, ProxyControl  # noqa: E402
from norcaster_counterparty.hooks.langgraph import TESTED_SDK_VERSIONS, connections, interceptors, rule  # noqa: E402
from norcaster_counterparty.mcp_server import NOTICE_TOOL  # noqa: E402

ORDER = {"sku": "BRC-AX-10", "quantity": 5}


@rule("aurora.spend_limit")
async def spend_limit(request, handler):  # noqa: ANN001
    """Aurora's boundary: no order above 100 units leaves Aurora (answering skips the call)."""
    if int(request.args.get("quantity") or 0) > 100:
        return CallToolResult(content=[TextContent(type="text", text="above Aurora's spend limit")], isError=True)
    return await handler(request)


async def redact_email(request, handler):  # noqa: ANN001
    """Aurora's boundary: a buyer's e-mail address never leaves Aurora (rule id: this function's name)."""
    if "buyer_email" in request.args:
        request = request.override(args={**request.args, "buyer_email": "[redacted]"})
    return await handler(request)


def setup(tmp_path, configs, serve) -> tuple[Any, Birch, str, str, ProxyControl]:
    aurora, birch_config = configs
    birch = Birch()
    birch_url = serve(lambda: _lowlevel_app(birch, birch_party(birch_config)))
    base = start_proxy(serve, tmp_path, aurora, birch_url)
    return aurora, birch, base, birch_url, ProxyControl(base, token=TOKEN)


def invoke(ctl: ProxyControl, arguments: dict[str, Any], *, extra: dict[str, Any] | None = None, server: str = "birch") -> ToolMessage:
    async def go():
        client = MultiServerMCPClient({**connections(ctl, ["birch"]), **(extra or {})},
                                      tool_interceptors=interceptors(ctl, spend_limit, redact_email, servers=["birch"]),
                                      tool_name_prefix=True)
        tools = {t.name: t for t in await client.get_tools()}
        return await tools[f"{server}_create_order"].ainvoke({"type": "tool_call", "id": "call_1", "name": f"{server}_create_order",
                                                             "args": arguments})

    return asyncio.run(go())


def test_allowed_blocked_and_redacted_calls(tmp_path, configs, serve):
    aurora, birch, base, _, ctl = setup(tmp_path, configs, serve)

    invoke(ctl, ORDER)
    allowed = last_status(base)
    assert (allowed["status"], allowed["outcome"]) == ("acknowledged", "allowed") and birch.ran == [("create_order", ORDER)]

    message = invoke(ctl, {"sku": "BRC-AX-10", "quantity": 500})
    blocked = last_status(base)
    assert message.status == "error" and "spend limit" in str(message.content)
    assert (blocked["outcome"], blocked["rule_id"], blocked["partner_content_check"]) == ("blocked", "aurora.spend_limit", "not_delivered")
    assert len(birch.ran) == 1 and birch.inbound[-1][0] == NOTICE_TOOL

    asked = {"sku": "BRC-AX-10", "quantity": 2, "buyer_email": "buyer@aurora.example"}
    invoke(ctl, asked)
    redacted = last_status(base)
    assert (redacted["status"], redacted["outcome"], redacted["rule_id"]) == ("acknowledged", "redacted", "redact_email")
    assert birch.ran[-1] == ("create_order", {**asked, "buyer_email": "[redacted]"})

    ids = [allowed["exchange_id"], blocked["exchange_id"], redacted["exchange_id"]]
    report = export_and_verify(aurora_party(aurora), tmp_path, ids, reveal=[ids[0], ids[2]])
    assert report["ok"] is True
    assert [exchange(report, i)[0] for i in ids] == ["acknowledged", "not_delivered", "acknowledged"]
    assert {x["exchange_id"]: x["outcome"] for x in report["exchanges"]} == dict(zip(ids, ["allowed", "blocked", "redacted"]))


def test_a_langgraph_agent(tmp_path, configs, serve):
    from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
    from langgraph.prebuilt import create_react_agent

    _, birch, base, _, ctl = setup(tmp_path, configs, serve)

    class ScriptedChatModel(GenericFakeChatModel):
        """Asks for the planned tool calls, then says it is done. Calls no model API."""

        def bind_tools(self, tools, **kwargs):  # noqa: ANN001, ANN201
            return self

    calls = [ORDER, {"sku": "BRC-AX-10", "quantity": 500}, {"sku": "BRC-AX-10", "quantity": 1, "buyer_email": "b@aurora.example"}]
    model = ScriptedChatModel(messages=iter(
        [AIMessage(content="", tool_calls=[{"name": "create_order", "args": args, "id": f"call_{i}"}]) for i, args in enumerate(calls)]
        + [AIMessage(content="done")]))

    async def go():
        client = MultiServerMCPClient(connections(ctl, ["birch"]),
                                      tool_interceptors=interceptors(ctl, spend_limit, redact_email, servers=["birch"]))
        agent = create_react_agent(model, await client.get_tools())
        return await agent.ainvoke({"messages": [("user", "Order the parts from Birch.")]})

    result = asyncio.run(go())
    tool_messages = [m for m in result["messages"] if isinstance(m, ToolMessage)]
    assert [m.status for m in tool_messages] == ["success", "error", "success"]
    statuses = control(base, "GET", "exchanges").json()["exchanges"]
    assert [(s["outcome"], s["status"]) for s in statuses] == [("allowed", "acknowledged"), ("blocked", "acknowledged"),
                                                               ("redacted", "acknowledged")]
    assert [args for _, args in birch.ran] == [ORDER, {**calls[2], "buyer_email": "[redacted]"}]


def test_other_servers_pass_through_and_an_unrecorded_redaction_fails_closed(tmp_path, configs, serve):
    _, birch, base, birch_url, ctl = setup(tmp_path, configs, serve)
    direct = {"direct": {"transport": "streamable_http", "url": birch_url}}  # not through the proxy: not reported
    message = invoke(ctl, {"sku": "X", "quantity": 1, "buyer_email": "b@aurora.example"}, extra=direct, server="direct")
    assert "Shared Record check failed" in str(message.content)  # Birch refuses a call without a receipt
    assert control(base, "GET", "exchanges").json()["exchanges"] == []

    broken = ProxyControl(ctl.url, token=TOKEN)
    broken.decision = ProxyControl("http://127.0.0.1:9", token="x", timeout=2).decision  # the control channel is down
    message = invoke(broken, {"sku": "X", "quantity": 1, "buyer_email": "b@aurora.example"})
    assert message.status == "error" and REDACTION_UNRECORDED in str(message.content) and birch.ran == []


def test_the_pinned_adapters_still_have_what_the_wrapper_uses():
    version = importlib.metadata.version("langchain-mcp-adapters")
    low, high = TESTED_SDK_VERSIONS.split(",")
    as_tuple = lambda v: tuple(int(p) for p in v.split(".")[:3])  # noqa: E731
    assert as_tuple(low.lstrip(">=")) <= as_tuple(version) < as_tuple(high.lstrip("<")), (
        f"langchain-mcp-adapters {version} is outside the tested range {TESTED_SDK_VERSIONS}")
    from langchain_mcp_adapters import tools
    from langchain_mcp_adapters.interceptors import MCPToolCallRequest

    assert {"name", "args", "server_name", "headers", "runtime"} <= set(MCPToolCallRequest.__dataclass_fields__)
    assert callable(MCPToolCallRequest.override)
    source = inspect.getsource(tools._build_interceptor_chain)
    assert "for interceptor in reversed(tool_interceptors)" in source  # the first interceptor is outermost


def test_the_example_runs_end_to_end():
    """examples/proxy_two_companies.py, as the QUICKSTART runs it: the real `proxy serve` command."""
    pkg = Path(__file__).resolve().parents[1]
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(str(p) for p in (pkg / "src", pkg.parent / "norcaster-verify" / "src"))}
    done = subprocess.run([sys.executable, str(pkg / "examples" / "proxy_two_companies.py")], capture_output=True, text=True,
                          env=env, timeout=180)
    assert done.returncode == 0, done.stdout + done.stderr
    for line in ("blocked  rule=aurora.spend_limit  -> acknowledged", "redacted rule=aurora.pii.email  -> acknowledged",
                 "result: no check failed"):
        assert line in done.stdout, done.stdout



def test_a_person_approves_or_rejects_through_a_langgraph_interrupt(tmp_path, configs, serve):
    """An approval interceptor using LangGraph's interrupt(): approved, the receipt says allowed with
    rule human_approval; rejected, nothing is sent and Birch gets a notice (rule human_rejected)."""
    from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
    from langgraph.checkpoint.memory import InMemorySaver
    from langgraph.prebuilt import create_react_agent
    from langgraph.types import Command, interrupt

    from norcaster_counterparty.hooks import HUMAN_REJECTED
    from norcaster_counterparty.hooks.langgraph import approved

    aurora, birch, base, _, ctl = setup(tmp_path, configs, serve)

    @rule(HUMAN_REJECTED)
    async def ask_a_person(request, handler):  # noqa: ANN001
        if interrupt({"tool": request.name, "args": request.args}) != "approve":
            return CallToolResult(content=[TextContent(type="text", text="Rejected by a person.")], isError=True)
        approved()
        return await handler(request)

    class ScriptedChatModel(GenericFakeChatModel):
        def bind_tools(self, tools, **kwargs):  # noqa: ANN001, ANN201
            return self

    async def run(order: dict[str, Any], answer: str, thread: str) -> Any:
        model = ScriptedChatModel(messages=iter([AIMessage(content="", tool_calls=[{"name": "create_order", "args": order, "id": "c1"}]),
                                                 AIMessage(content="done")]))
        client = MultiServerMCPClient(connections(ctl, ["birch"]),
                                      tool_interceptors=interceptors(ctl, ask_a_person, servers=["birch"]))
        agent = create_react_agent(model, await client.get_tools(), checkpointer=InMemorySaver())
        config = {"configurable": {"thread_id": thread}}
        paused = await agent.ainvoke({"messages": [("user", "Order.")]}, config)
        assert "__interrupt__" in paused and birch.ran == ([] if thread == "a" else [("create_order", ORDER)])
        return await agent.ainvoke(Command(resume=answer), config)

    asyncio.run(run(ORDER, "approve", "a"))
    approved_status = last_status(base)
    asyncio.run(run({"sku": "BRC-AX-10", "quantity": 7}, "reject", "b"))
    rejected_status = last_status(base)
    assert (approved_status["outcome"], approved_status["rule_id"], approved_status["status"]) == ("allowed", "human_approval", "acknowledged")
    assert (rejected_status["outcome"], rejected_status["rule_id"], rejected_status["partner_content_check"]) == (
        "blocked", "human_rejected", "not_delivered")
    assert birch.ran == [("create_order", ORDER)] and len(control(base, "GET", "exchanges").json()["exchanges"]) == 2

    ids = [approved_status["exchange_id"], rejected_status["exchange_id"]]
    report = export_and_verify(aurora_party(aurora), tmp_path, ids, reveal=[ids[0]])
    assert report["ok"] is True and [exchange(report, i)[0] for i in ids] == ["acknowledged", "not_delivered"]
