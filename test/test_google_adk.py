"""The Google ADK adapter (``norcaster_counterparty.hooks.google_adk``) with ADK's own runner, Aurora's
local MCP proxy and Birch's MCP server on 127.0.0.1, and the quickstart sandbox as the log.

No model is called: a scripted ``BaseLlm`` asks for the tool calls, and ADK does the rest as it
would with Gemini (the callbacks, the MCP toolset, the call). Synthetic data."""

# ruff: noqa: F811  (pytest fixtures imported from two_companies are used as parameters)
from __future__ import annotations

import asyncio
import importlib.metadata
import inspect
import json
from typing import Any

import pytest

pytest.importorskip("mcp", reason="needs the mcp extra")
pytest.importorskip("google.adk", reason="needs the google-adk extra (Python 3.11 or later)")

from google.adk.agents import LlmAgent  # noqa: E402
from google.adk.models.base_llm import BaseLlm  # noqa: E402
from google.adk.models.llm_response import LlmResponse  # noqa: E402
from google.adk.runners import InMemoryRunner  # noqa: E402
from google.genai import types  # noqa: E402
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

from norcaster_counterparty import META_KEY  # noqa: E402
from norcaster_counterparty.hooks import REDACTION_UNRECORDED, RULE_KEY, ProxyControl  # noqa: E402
from norcaster_counterparty.hooks.google_adk import (  # noqa: E402
    STATE_KEY,
    TESTED_SDK_VERSIONS,
    before_tool_callback,
    mcp_toolset,
    rule,
    status_callback,
)
from norcaster_counterparty.mcp_server import NOTICE_TOOL  # noqa: E402
from norcaster_counterparty.proxy import STATUS_KEY  # noqa: E402

ORDER = {"sku": "BRC-AX-10", "quantity": 5}


@pytest.fixture(autouse=True)
def no_google_credentials_probe(monkeypatch):
    """ADK tries Google Application Default Credentials for mTLS on every MCP connection (by default
    GOOGLE_API_USE_CLIENT_CERTIFICATE=true), which probes the GCE metadata server off this machine.
    The proxy is on 127.0.0.1: switched off, so nothing leaves localhost."""
    monkeypatch.setenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "false")


class ScriptedLlm(BaseLlm):
    """Asks for the planned tool calls, one per turn, then says it is done. Calls no model API."""

    calls: list[Any] = []

    async def generate_content_async(self, llm_request: Any, stream: bool = False):  # noqa: ANN201
        if self.calls:
            name, arguments = self.calls.pop(0)
            part = types.Part(function_call=types.FunctionCall(name=name, args=arguments))
        else:
            part = types.Part(text="done")
        yield LlmResponse(content=types.Content(role="model", parts=[part]))


def spend_limit(tool, args, tool_context):  # noqa: ANN001
    """Aurora's boundary: no order above 100 units leaves Aurora (answering the call skips the tool)."""
    if int(args.get("quantity") or 0) > 100:
        return {"error": "above Aurora's spend limit", RULE_KEY: "aurora.spend_limit"}
    return None


@rule("aurora.pii.email")
async def redact_email(tool, args, tool_context):  # noqa: ANN001
    """Aurora's boundary: a buyer's e-mail address never leaves Aurora (ADK sends the args as changed)."""
    if "buyer_email" in args:
        args["buyer_email"] = "[redacted]"
    return None


def setup(tmp_path, configs, serve, **proxy_options: Any) -> tuple[Any, Birch, str, ProxyControl]:
    aurora, birch_config = configs
    birch = Birch()
    base = start_proxy(serve, tmp_path, aurora, serve(lambda: _lowlevel_app(birch, birch_party(birch_config))), **proxy_options)
    return aurora, birch, base, ProxyControl(base, token=TOKEN)


def run_adk(ctl: ProxyControl, calls: list[tuple[str, dict[str, Any]]], *, callbacks: tuple = (spend_limit, redact_email),
            extra_tools: list[Any] | None = None, after: list[Any] | None = None) -> tuple[list[Any], dict[str, Any]]:
    """Run Aurora's ADK agent; returns the events and the session state."""

    async def go():
        toolset = mcp_toolset(ctl, "birch")
        agent = LlmAgent(name="aurora_procurement", model=ScriptedLlm(model="scripted", calls=list(calls)),
                         instruction="Order parts from Birch.", tools=[toolset, *(extra_tools or [])],
                         before_tool_callback=before_tool_callback(ctl, *callbacks),
                         after_tool_callback=[status_callback] if after is None else after)
        runner = InMemoryRunner(agent=agent, app_name="aurora")
        session = await runner.session_service.create_session(app_name="aurora", user_id="buyer")
        try:
            events = [e async for e in runner.run_async(user_id="buyer", session_id=session.id,
                                                       new_message=types.Content(role="user", parts=[types.Part(text="Order.")]))]
            state = (await runner.session_service.get_session(app_name="aurora", user_id="buyer", session_id=session.id)).state
        finally:
            await toolset.close()
            await runner.close()
        return events, dict(state)

    return asyncio.run(go())


def function_responses(events: list[Any]) -> list[dict[str, Any]]:
    return [part.function_response.response for e in events for part in (e.content.parts if e.content else [])
            if part.function_response is not None]


def test_allowed_blocked_and_redacted_calls(tmp_path, configs, serve):
    aurora, birch, base, ctl = setup(tmp_path, configs, serve)

    events, _ = run_adk(ctl, [("create_order", ORDER)])
    allowed = last_status(base)
    [response] = function_responses(events)
    assert (allowed["status"], allowed["outcome"]) == ("acknowledged", "allowed") and birch.ran == [("create_order", ORDER)]
    assert META_KEY not in json.dumps(response)  # ADK shows the model the whole result: the block is gone

    events, _ = run_adk(ctl, [("create_order", {"sku": "BRC-AX-10", "quantity": 500})])
    blocked = last_status(base)
    assert function_responses(events) == [{"error": "above Aurora's spend limit"}]  # RULE_KEY removed
    assert (blocked["outcome"], blocked["rule_id"], blocked["partner_content_check"]) == ("blocked", "aurora.spend_limit", "not_delivered")
    assert len(birch.ran) == 1 and birch.inbound[-1][0] == NOTICE_TOOL

    asked = {"sku": "BRC-AX-10", "quantity": 2, "buyer_email": "buyer@aurora.example"}
    run_adk(ctl, [("create_order", asked)])
    redacted = last_status(base)
    assert (redacted["status"], redacted["outcome"], redacted["rule_id"]) == ("acknowledged", "redacted", "aurora.pii.email")
    assert birch.ran[-1] == ("create_order", {**asked, "buyer_email": "[redacted]"})

    ids = [allowed["exchange_id"], blocked["exchange_id"], redacted["exchange_id"]]
    report = export_and_verify(aurora_party(aurora), tmp_path, ids, reveal=[ids[0], ids[2]])
    assert report["ok"] is True
    assert [exchange(report, i)[0] for i in ids] == ["acknowledged", "not_delivered", "acknowledged"]
    assert {x["exchange_id"]: x["outcome"] for x in report["exchanges"]} == dict(zip(ids, ["allowed", "blocked", "redacted"]))


def test_status_moves_from_the_result_to_session_state(tmp_path, configs, serve):
    _, _, base, ctl = setup(tmp_path, configs, serve, include_status=True)
    seen: list[Any] = []

    def yours(tool, args, tool_context, tool_response):  # noqa: ANN001
        seen.append(tool_context.state.get(STATE_KEY))  # your own after-callback still runs, and sees the status
        return None

    events, _ = run_adk(ctl, [("create_order", ORDER)], after=[status_callback, yours])
    [response] = function_responses(events)
    assert STATUS_KEY not in json.dumps(response) and META_KEY not in json.dumps(response)
    assert [s["status"] for s in seen] == ["acknowledged"]

    events, _ = run_adk(ctl, [("create_order", ORDER)], after=[])  # without it, ADK would show the model the status
    [response] = function_responses(events)
    assert STATUS_KEY in response["meta"] and META_KEY not in response["meta"]


def test_other_tools_pass_through_and_an_unrecorded_redaction_fails_closed(tmp_path, configs, serve):
    _, birch, base, ctl = setup(tmp_path, configs, serve)

    def lookup_price(sku: str, buyer_email: str = "") -> dict:
        """A local function tool, not proxied."""
        return {"sku": sku, "price": 10}

    events, _ = run_adk(ctl, [("lookup_price", {"sku": "X", "buyer_email": "buyer@aurora.example"})], extra_tools=[lookup_price])
    assert function_responses(events) == [{"sku": "X", "price": 10}]
    assert control(base, "GET", "exchanges").json()["exchanges"] == []  # nothing reported for a local tool

    unreachable = ProxyControl(ctl.url, token=TOKEN)
    unreachable_decisions = ProxyControl("http://127.0.0.1:9", token="x", timeout=2)
    unreachable.decision = unreachable_decisions.decision  # the MCP calls work, the control channel does not

    events, _ = run_adk(unreachable, [("create_order", {"sku": "X", "quantity": 1, "buyer_email": "b@aurora.example"})])
    assert function_responses(events) == [{"error": REDACTION_UNRECORDED}] and birch.ran == []


def test_the_pinned_sdk_still_has_what_the_adapter_uses():
    version = importlib.metadata.version("google-adk")
    low, high = TESTED_SDK_VERSIONS.split(",")
    as_tuple = lambda v: tuple(int(p) for p in v.split(".")[:3])  # noqa: E731
    assert as_tuple(low.lstrip(">=")) <= as_tuple(version) < as_tuple(high.lstrip("<")), (
        f"google-adk {version} is outside the tested range {TESTED_SDK_VERSIONS}")
    from google.adk.flows.llm_flows.tools import _caller
    from google.adk.tools.mcp_tool.mcp_tool import McpTool

    assert isinstance(McpTool.raw_mcp_tool, property)
    from google.adk.tools.tool_confirmation import ToolConfirmation

    assert "confirmed" in ToolConfirmation.model_fields and callable(McpTool.check_require_confirmation)
    source = inspect.getsource(_caller)
    # The callbacks get the same args dict the tool then runs with (a change in place is what is sent),
    # and the after-callbacks get the tool's result object itself.
    assert "args=function_args" in source and "_call_tool_async" in source
    assert "return cast(dict[str, Any], function_result)" in source


def test_a_person_confirms_one_call_and_rejects_another(tmp_path, configs, serve):
    """ADK's require_confirmation: the call pauses for a person; confirmed, it is receipted allowed with
    rule human_approval; rejected, it is not sent and Birch gets a notice (rule human_rejected)."""
    aurora, birch, base, ctl = setup(tmp_path, configs, serve)

    async def decide(order: dict[str, Any], confirmed: bool) -> list[Any]:
        toolset = mcp_toolset(ctl, "birch", require_confirmation=True)
        agent = LlmAgent(name="aurora_procurement", model=ScriptedLlm(model="scripted", calls=[("create_order", order)]),
                         instruction="Order parts from Birch.", tools=[toolset],
                         before_tool_callback=before_tool_callback(ctl, spend_limit, redact_email))
        runner = InMemoryRunner(agent=agent, app_name="aurora")
        session = await runner.session_service.create_session(app_name="aurora", user_id="buyer")
        try:
            first = [e async for e in runner.run_async(user_id="buyer", session_id=session.id,
                                                      new_message=types.Content(role="user", parts=[types.Part(text="Order.")]))]
            [request] = [p.function_call for e in first for p in (e.content.parts if e.content else [])
                         if p.function_call is not None and p.function_call.name == "adk_request_confirmation"]
            answer = types.Part(function_response=types.FunctionResponse(name="adk_request_confirmation", id=request.id,
                                                                         response={"confirmed": confirmed}))
            return [e async for e in runner.run_async(user_id="buyer", session_id=session.id,
                                                     new_message=types.Content(role="user", parts=[answer]))]
        finally:
            await toolset.close()
            await runner.close()

    assert birch.ran == []
    asyncio.run(decide(ORDER, True))
    approved = last_status(base)
    assert (approved["status"], approved["outcome"], approved["rule_id"]) == ("acknowledged", "allowed", "human_approval")
    events = asyncio.run(decide({"sku": "BRC-AX-10", "quantity": 7}, False))
    rejected = last_status(base)
    assert (rejected["outcome"], rejected["rule_id"], rejected["partner_content_check"]) == ("blocked", "human_rejected", "not_delivered")
    assert birch.ran == [("create_order", ORDER)] and "rejected" in json.dumps(function_responses(events))
    assert len(control(base, "GET", "exchanges").json()["exchanges"]) == 2  # the paused passes signed nothing

    ids = [approved["exchange_id"], rejected["exchange_id"]]
    report = export_and_verify(aurora_party(aurora), tmp_path, ids, reveal=[ids[0]])
    assert report["ok"] is True and [exchange(report, i)[0] for i in ids] == ["acknowledged", "not_delivered"]
