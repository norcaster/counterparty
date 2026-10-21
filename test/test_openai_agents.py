"""The OpenAI Agents SDK binding against the real SDK (the pinned version) and a real MCP server
over Streamable HTTP on 127.0.0.1, with the quickstart sandbox as the log.

No model API is called: a scripted model asks for the tool calls, and the SDK's ``Runner`` does
the rest exactly as it would with a real model (guardrails, the MCP hooks, the call). Tracing is
off, or captured in process. Nothing leaves 127.0.0.1. Two fictional companies, synthetic data:
Aurora Procurement (sending) and Birch Components (receiving).

Every case ends in an export that ``norcaster-verify`` checks offline, in Python and in Node.
"""


from __future__ import annotations

import asyncio
import dataclasses
import importlib.metadata
import inspect
import json
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

agents = pytest.importorskip("agents", reason="needs the openai-agents extra")
mcp = pytest.importorskip("mcp", reason="needs the mcp extra")

from agents import (
    Agent,
    RunConfig,
    Runner,
    ToolGuardrailFunctionOutput,
    tool_input_guardrail,
)
from agents.items import ModelResponse, ToolCallOutputItem
from agents.mcp import (
    MCPServerStreamableHttp,
    MCPToolCustomDataContext,
    MCPToolMetaContext,
)
from agents.models.interface import Model
from agents.usage import Usage
from openai.types.responses import (
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)
from two_companies import (
    AURORA_AGENT,
    BIRCH,
    BIRCH_AGENT,
    Birch,
    TamperInTransit,
    _highlevel_app,
    _lowlevel_app,
    birch_party,
    detail,
    exchange,
    export_and_verify,
)
from two_companies import configs, log_url, serve  # noqa: F401  (pytest fixtures, used by parameter name)

from norcaster_counterparty import META_KEY, Config, Counterparty, HttpLogClient
from norcaster_counterparty.mcp_server import NOTICE_TOOL
from norcaster_counterparty.openai_agents import (
    TESTED_SDK_VERSIONS,
    ExchangeStatus,
    partner_server,
)

# --- Aurora's agent ---------------------------------------------------------------------------------


class ScriptedModel(Model):
    """Asks for the given tool calls, one turn each, then says it is done. Calls no model API."""

    def __init__(self, calls: list[tuple[str, dict[str, Any]]]) -> None:
        self.calls = list(calls)
        self.turn = 0

    async def get_response(self, *args: Any, **kwargs: Any) -> ModelResponse:
        self.turn += 1
        if self.calls:
            name, arguments = self.calls.pop(0)
            item = ResponseFunctionToolCall(type="function_call", id=f"fc_{self.turn}", call_id=f"call_{self.turn}",
                                            name=name, arguments=json.dumps(arguments), status="completed")
        else:
            item = ResponseOutputMessage(id=f"msg_{self.turn}", type="message", role="assistant", status="completed",
                                         content=[ResponseOutputText(type="output_text", text="done", annotations=[])])
        return ModelResponse(output=[item], usage=Usage(), response_id=None)

    def stream_response(self, *args: Any, **kwargs: Any):
        raise NotImplementedError("the tests do not stream")


@tool_input_guardrail
def aurora_spend_limit(data):
    """Aurora's boundary: no order above 100 units leaves Aurora."""
    if int(json.loads(data.context.tool_arguments or "{}").get("quantity") or 0) > 100:
        return ToolGuardrailFunctionOutput.reject_content("Order exceeds Aurora's spend limit.",
                                                          output_info={"rule_id": "aurora.spend_limit"})
    return ToolGuardrailFunctionOutput.allow()


def aurora_redact(tool_name: str, arguments: dict[str, Any]) -> tuple[dict[str, Any], str] | None:
    """Aurora's boundary: a buyer's e-mail address never leaves Aurora."""
    if "buyer_email" in arguments:
        return {**arguments, "buyer_email": "[redacted]"}, "aurora.pii.email"
    return None


def run_agent(aurora_config: Config, url: str, calls: list[tuple[str, dict[str, Any]]], *, clock=None,
              run_config: RunConfig | None = None, **server_kwargs: Any) -> tuple[Any, list[ExchangeStatus], Counterparty]:
    party = Counterparty(aurora_config, HttpLogClient(aurora_config.log_url), clock=clock)
    statuses: list[ExchangeStatus] = []

    async def go():
        server = partner_server(url, party=party, partner_org=BIRCH, partner_agent=BIRCH_AGENT, agent_id=AURORA_AGENT,
                                tool_input_guardrails=[aurora_spend_limit], redact=aurora_redact,
                                on_exchange=statuses.append, **server_kwargs)
        async with server:
            agent = Agent(name="Aurora procurement agent", instructions="Order parts from Birch.",
                          model=ScriptedModel(calls), mcp_servers=[server])
            return await Runner.run(agent, "Order the parts.", run_config=run_config or RunConfig(tracing_disabled=True))

    return asyncio.run(go()), statuses, party


def outputs(result: Any) -> list[ToolCallOutputItem]:
    return [item for item in result.new_items if isinstance(item, ToolCallOutputItem)]


# --- the cases --------------------------------------------------------------------------------------


def test_allowed_call_is_acknowledged_and_verifies(tmp_path, configs, serve):
    aurora, birch_config = configs
    birch = Birch()
    url = serve(lambda: _lowlevel_app(birch, birch_party(birch_config)))
    result, statuses, party = run_agent(aurora, url, [("create_order", {"sku": "BRC-AX-10", "quantity": 5})])

    [item] = outputs(result)
    status = item.custom_data[META_KEY]
    assert status["status"] == "acknowledged" and status["delivered"] is True
    assert (status["outcome"], status["rule_id"]) == ("allowed", None)
    assert (status["partner_content_check"], status["partner_outcome"]) == ("matched", "allowed")
    assert "BRC-0001" in json.dumps(item.output)  # the tool ran and the model saw its result
    assert META_KEY not in json.dumps(item.output)  # the model never sees the record
    assert birch.ran == [("create_order", {"sku": "BRC-AX-10", "quantity": 5})]
    assert [s.status for s in statuses] == ["acknowledged"]

    report = export_and_verify(party, tmp_path, [status["exchange_id"]], reveal=[status["exchange_id"]])
    state, checks = exchange(report, status["exchange_id"])
    assert report["ok"] is True and state == "acknowledged"
    assert checks["content_commitment"] == "pass" and checks["receipt_signature"] == "pass"
    assert all(v != "fail" for v in checks.values())


def test_blocked_call_sends_a_notice_and_delivers_nothing(tmp_path, configs, serve):
    aurora, birch_config = configs
    birch = Birch()
    url = serve(lambda: _lowlevel_app(birch, birch_party(birch_config)))
    result, statuses, party = run_agent(aurora, url, [("create_order", {"sku": "BRC-AX-10", "quantity": 500})])

    [item] = outputs(result)
    assert "spend limit" in json.dumps(item.output)  # the guardrail's rejection, as the SDK reports it
    assert birch.ran == []  # nothing delivered, the tool never ran
    [(tool, inbound)] = birch.inbound
    assert tool == NOTICE_TOOL and inbound.content_check == "not_delivered" and inbound.delivered is False
    [status] = statuses
    assert (status.status, status.delivered, status.outcome, status.rule_id) == ("acknowledged", False, "blocked", "aurora.spend_limit")
    assert status.partner_content_check == "not_delivered"
    assert result.tool_input_guardrail_results[0].output.output_info == {"rule_id": "aurora.spend_limit"}  # unchanged

    report = export_and_verify(party, tmp_path, [status.exchange_id], reveal=[])
    state, checks = exchange(report, status.exchange_id)
    assert report["ok"] is True and state == "not_delivered"
    assert all(v != "fail" for v in checks.values())


def test_content_changed_in_transit_is_a_mismatch(tmp_path, configs, serve):
    aurora, birch_config = configs
    birch = Birch()
    url = serve(lambda: TamperInTransit(_lowlevel_app(birch, birch_party(birch_config))))
    result, _, party = run_agent(aurora, url, [("create_order", {"sku": "BRC-AX-10", "quantity": 5})])

    [item] = outputs(result)
    status = item.custom_data[META_KEY]
    assert status["status"] == "mismatch"
    assert (status["partner_content_check"], status["partner_outcome"], status["partner_rule_id"]) == (
        "mismatch", "blocked", "content_mismatch")
    assert birch.ran == []  # Birch refuses to run a call that is not what was committed to

    report = export_and_verify(party, tmp_path, [status["exchange_id"]], reveal=[status["exchange_id"]])
    state, checks = exchange(report, status["exchange_id"])
    # Birch signed that what it received does not match the commitment; the verifier shows it.
    assert state == "acknowledged_mismatch" and checks["acknowledgement"] == "pass"  # spec §11.5
    assert "content check: mismatch" in detail(report, status["exchange_id"], "acknowledgement")
    # Aurora's revealed content matches Aurora's own receipt: what Aurora sent is provable.
    assert checks["content_commitment"] == "pass" and report["ok"] is True


def test_no_acknowledgement_by_the_deadline_is_recorded(tmp_path, configs, serve):
    aurora, _ = configs
    birch = Birch()
    url = serve(lambda: _lowlevel_app(birch, None))  # Birch's server without Shared Record
    result, _, party = run_agent(aurora, url, [("create_order", {"sku": "BRC-AX-10", "quantity": 5})])

    [item] = outputs(result)
    status = item.custom_data[META_KEY]
    assert status["status"] == "missing" and birch.ran  # the tool ran, but nothing came back

    later = Counterparty(aurora, HttpLogClient(aurora.log_url),
                         clock=lambda: datetime.now(timezone.utc) + timedelta(seconds=aurora.ack_deadline_seconds + 5))

    async def record():
        try:
            return await later.record_missing_acknowledgements()
        finally:
            await later.log.aclose()

    assert asyncio.run(record()) == 1
    report = export_and_verify(party, tmp_path, [status["exchange_id"]], reveal=[status["exchange_id"]])
    state, checks = exchange(report, status["exchange_id"])
    assert state == "unacknowledged" and checks["missing_acknowledgement"] == "pass"
    assert checks.get("acknowledgement") != "pass"  # no acknowledgement in the evidence
    assert checks["content_commitment"] == "pass"


def test_redaction_commits_to_the_redacted_call_actually_sent(tmp_path, configs, serve):
    aurora, birch_config = configs
    birch = Birch()
    url = serve(lambda: _lowlevel_app(birch, birch_party(birch_config)))
    result, _, party = run_agent(aurora, url, [("create_order", {"sku": "BRC-AX-10", "quantity": 2,
                                                                  "buyer_email": "buyer@aurora.example"})])

    [item] = outputs(result)
    status = item.custom_data[META_KEY]
    assert (status["status"], status["outcome"], status["rule_id"]) == ("acknowledged", "redacted", "aurora.pii.email")
    assert status["partner_content_check"] == "matched"
    assert birch.ran == [("create_order", {"sku": "BRC-AX-10", "quantity": 2, "buyer_email": "[redacted]"})]

    report = export_and_verify(party, tmp_path, [status["exchange_id"]], reveal=[status["exchange_id"]])
    state, checks = exchange(report, status["exchange_id"])
    assert report["ok"] is True and state == "acknowledged" and checks["content_commitment"] == "pass"
    [revealed] = json.loads((tmp_path / "evidence.json").read_text())["revealed"]
    import base64

    assert b"buyer@aurora.example" not in base64.b64decode(revealed["content_b64"])


def test_partner_boundary_refusal_is_acknowledged_and_the_tool_does_not_run(tmp_path, configs, serve):
    aurora, birch_config = configs
    birch = Birch()
    url = serve(lambda: _lowlevel_app(birch, birch_party(birch_config)))
    result, _, _ = run_agent(aurora, url, [("create_order", {"sku": "BRC-AX-10", "quantity": 60})])

    [item] = outputs(result)
    status = item.custom_data[META_KEY]
    assert (status["status"], status["partner_outcome"], status["partner_rule_id"]) == ("acknowledged", "blocked", "birch.order_limit")
    assert birch.ran == []


def test_fastmcp_or_mcpserver_partner(tmp_path, configs, serve):
    """The same helper on the MCP SDK's high-level server: FastMCP (1.x) or MCPServer (2.x)."""
    aurora, birch_config = configs
    birch = Birch()
    url = serve(lambda: _highlevel_app(birch, birch_party(birch_config)))
    _, statuses, _ = run_agent(aurora, url, [("create_order", {"sku": "BRC-AX-10", "quantity": 3}),
                                                  ("create_order", {"sku": "BRC-AX-10", "quantity": 500})])
    assert [s.status for s in statuses] == ["acknowledged", "acknowledged"]
    assert [(s.delivered, s.partner_content_check) for s in statuses] == [(True, "matched"), (False, "not_delivered")]
    assert birch.ran == [("create_order", {"sku": "BRC-AX-10", "quantity": 3})]


def test_a_call_without_the_receipt_is_refused_by_both_sides(configs, serve):
    aurora, birch_config = configs
    birch = Birch()
    url = serve(lambda: _lowlevel_app(birch, birch_party(birch_config)))
    party = Counterparty(aurora, HttpLogClient(aurora.log_url))

    async def go():
        # Aurora's side: the binding never sends a call that does not carry the receipt it signed.
        server = partner_server(url, party=party, partner_org=BIRCH, partner_agent=BIRCH_AGENT, agent_id=AURORA_AGENT)
        async with server:
            assert NOTICE_TOOL not in {t.name for t in await server.list_tools()}  # the model cannot call it
            with pytest.raises(Exception, match="without the receipt"):
                await server.call_tool("create_order", {"sku": "X", "quantity": 1})
        # Birch's side: a plain MCP client without a receipt is refused, and nothing runs.
        plain = MCPServerStreamableHttp({"url": url})
        async with plain:
            result = await plain.call_tool("create_order", {"sku": "X", "quantity": 1})
        await party.log.aclose()
        return result

    result = asyncio.run(go())
    assert result.isError if hasattr(result, "isError") else result.is_error
    assert "Shared Record check failed" in result.content[0].text and birch.ran == []


def test_a_partner_tool_cannot_replace_the_receipt_with_static_meta(configs, serve):
    """The SDK lets a tool's listed ``_meta`` override the resolver's on the same key; the binding
    drops that entry, so the receipt still travels and is acknowledged."""
    aurora, birch_config = configs
    birch = Birch()
    decoy = {META_KEY: {"receipt": {"type": "receipt", "exchange_id": "decoy"}}, "other.vendor/flag": True}
    url = serve(lambda: _lowlevel_app(birch, birch_party(birch_config), static_meta=decoy))
    result, _, _ = run_agent(aurora, url, [("create_order", {"sku": "BRC-AX-10", "quantity": 4})])
    [item] = outputs(result)
    assert item.custom_data[META_KEY]["status"] == "acknowledged" and len(birch.ran) == 1
    [(_, inbound)] = birch.inbound
    assert inbound.exchange_id == item.custom_data[META_KEY]["exchange_id"] != "decoy"


def test_an_unpinned_partner_fails_closed(configs, serve):
    aurora, birch_config = configs
    birch = Birch()
    url = serve(lambda: _lowlevel_app(birch, birch_party(birch_config)))
    del aurora.pins[BIRCH]  # Aurora never pinned Birch's root: its component refuses to sign
    result, statuses, _ = run_agent(aurora, url, [("create_order", {"sku": "BRC-AX-10", "quantity": 5})])
    [status] = statuses
    assert (status.status, status.exchange_id, status.delivered) == ("refused", None, False)
    assert "no pinned root fingerprint" in status.detail
    assert birch.ran == [] and birch.inbound == []  # nothing reached Birch
    [item] = outputs(result)
    assert "error" in json.dumps(item.output).lower()  # the SDK reports a failed tool call to the model


def test_status_reaches_the_trace(configs, serve):
    from agents.tracing import TracingProcessor, set_trace_processors

    class Capture(TracingProcessor):
        def __init__(self) -> None:
            self.spans: list[Any] = []

        def on_trace_start(self, trace): ...
        def on_trace_end(self, trace): ...
        def on_span_start(self, span): ...
        def on_span_end(self, span):
            self.spans.append(span)

        def shutdown(self): ...
        def force_flush(self): ...

    capture = Capture()
    set_trace_processors([capture])  # replaces the default exporter: nothing is sent to OpenAI
    try:
        aurora, birch_config = configs
        birch = Birch()
        url = serve(lambda: _lowlevel_app(birch, birch_party(birch_config)))
        run_agent(aurora, url, [("create_order", {"sku": "BRC-AX-10", "quantity": 1})], run_config=RunConfig())
    finally:
        set_trace_processors([])
    ours = [s for s in capture.spans if getattr(s.span_data, "name", None) == "norcaster.shared_record"]
    assert [s.span_data.data["status"] for s in ours] == ["acknowledged"]
    assert "content_b64" not in json.dumps([s.span_data.data for s in ours])


# --- the SDK's hooks, as this binding depends on them ----------------------------------------------


def test_the_pinned_sdk_still_has_the_hooks_this_binding_uses():
    """Fails loudly if the SDK changes what the binding relies on. ``result_meta`` in particular is
    defined in the SDK's source (``agents/mcp/util.py``) but not described in its documentation."""
    version = importlib.metadata.version("openai-agents")
    low, high = TESTED_SDK_VERSIONS.split(",")
    as_tuple = lambda v: tuple(int(p) for p in v.split(".")[:3])
    assert as_tuple(low.lstrip(">=")) <= as_tuple(version) < as_tuple(high.lstrip("<")), (
        f"openai-agents {version} is outside the tested range {TESTED_SDK_VERSIONS}")

    custom = {f.name for f in dataclasses.fields(MCPToolCustomDataContext)}
    assert {"run_context", "tool_name", "arguments", "result_meta"} <= custom, (
        "MCPToolCustomDataContext.result_meta is gone or renamed: the acknowledgement can no longer be read")
    meta = {f.name for f in dataclasses.fields(MCPToolMetaContext)}
    assert {"run_context", "tool_name", "arguments"} <= meta
    params = inspect.signature(MCPServerStreamableHttp.__init__).parameters
    assert {"tool_meta_resolver", "custom_data_extractor", "tool_input_guardrails"} <= set(params)
    assert "meta" in inspect.signature(MCPServerStreamableHttp.call_tool).parameters

    from agents.mcp.util import MCPUtil

    source = inspect.getsource(MCPUtil)
    assert 'result_meta=cls._copy_mapping_proxy(getattr(result, "meta", None))' in source, (
        "the SDK no longer passes the MCP result's _meta to custom_data_extractor as before")
    assert "_merge_mcp_meta(resolved_meta, meta)" in source, "the SDK changed how it merges request _meta"
    from agents import RunContextWrapper
    from agents.run_state import RunState

    assert callable(getattr(RunContextWrapper, "is_tool_approved", None)), "approvals: is_tool_approved is gone"
    assert "rejection_message" in inspect.signature(RunState.reject).parameters


def test_a_person_approves_one_call_and_rejects_another(tmp_path, configs, serve):
    """The SDK's approval flow (require_approval): an approved call is receipted allowed with rule
    human_approval; a call rejected through partner.reject is not sent, and Birch gets a notice
    (rule human_rejected), as the Norcaster hub does."""
    aurora, birch_config = configs
    birch = Birch()
    url = serve(lambda: _lowlevel_app(birch, birch_party(birch_config)))
    party = Counterparty(aurora, HttpLogClient(aurora.log_url))
    statuses: list[ExchangeStatus] = []
    first, second = {"sku": "BRC-AX-10", "quantity": 5}, {"sku": "BRC-AX-10", "quantity": 7}

    async def go():
        server = partner_server(url, party=party, partner_org=BIRCH, partner_agent=BIRCH_AGENT, agent_id=AURORA_AGENT,
                                require_approval="always", on_exchange=statuses.append)
        async with server:
            agent = Agent(name="Aurora procurement agent", instructions="Order parts from Birch.",
                          model=ScriptedModel([("create_order", first), ("create_order", second)]), mcp_servers=[server])
            config = RunConfig(tracing_disabled=True)
            result = await Runner.run(agent, "Order the parts.", run_config=config)
            [first_item] = result.interruptions
            state = result.to_state()
            state.approve(first_item)  # a person approves
            result = await Runner.run(agent, state, run_config=config)
            [second_item] = result.interruptions
            state = result.to_state()
            rejected = await server.reject(state, second_item, rejection_message="Not this one.")  # a person rejects
            result = await Runner.run(agent, state, run_config=config)
            return rejected, result

    rejected, result = asyncio.run(go())
    approved = statuses[0]
    assert (approved.status, approved.outcome, approved.rule_id, approved.delivered) == ("acknowledged", "allowed", "human_approval", True)
    assert (rejected.status, rejected.outcome, rejected.rule_id, rejected.delivered) == ("acknowledged", "blocked", "human_rejected", False)
    assert rejected.partner_content_check == "not_delivered" and birch.ran == [("create_order", first)]
    assert "Not this one." in json.dumps([str(i.output) for i in outputs(result)])

    ids = [approved.exchange_id, rejected.exchange_id]
    report = export_and_verify(party, tmp_path, ids, reveal=[ids[0]])
    assert report["ok"] is True and [exchange(report, i)[0] for i in ids] == ["acknowledged", "not_delivered"]
