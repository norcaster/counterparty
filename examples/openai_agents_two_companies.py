"""Two companies, one Shared Record, no Norcaster hub: an OpenAI Agents SDK agent calls a partner's MCP tool.

Aurora Procurement and Birch Components are fictional. Neither uses Norcaster: each runs
``norcaster-counterparty`` with its own keys. Aurora's agent (OpenAI Agents SDK) orders parts
through Birch's MCP server (Streamable HTTP). For every call:

* Aurora signs and registers a receipt before the call, and it travels in the request's ``_meta``;
* Birch checks it, applies its own boundary, runs the tool, and returns its own signed, logged
  acknowledgement in the result's ``_meta``;
* a call Aurora's guardrail blocks is not delivered: Birch receives a notice, with no content.

At the end Aurora exports the evidence, and the verifier checks it offline, as a third party would.

Everything runs on 127.0.0.1: the log is the local sandbox (``norcaster-counterparty sandbox``,
NOT a SCITT transparency service). No model API is called: a scripted model stands in for the LLM,
so the example needs no API key. To use a real model, remove ``model=ScriptedModel(...)``.

    pip install "norcaster-counterparty[openai-agents]"
    python openai_agents_two_companies.py
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
import sys
import tempfile
import threading
import time
from http.server import HTTPServer
from pathlib import Path

import httpx
import uvicorn
from agents import (
    Agent,
    RunConfig,
    Runner,
    ToolGuardrailFunctionOutput,
    tool_input_guardrail,
)
from agents.items import ModelResponse, ToolCallOutputItem
from agents.models.interface import Model
from agents.usage import Usage
from norcaster_verify.shared_record.verify import verify_evidence
from openai.types.responses import (
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)

from norcaster_counterparty import (
    META_KEY,
    Config,
    Counterparty,
    HttpLogClient,
    sandbox,
)
from norcaster_counterparty.mcp_server import add_shared_record
from norcaster_counterparty.openai_agents import partner_server

try:
    from mcp.server.mcpserver import MCPServer as McpApp  # MCP Python SDK 2.x
except ImportError:
    from mcp.server.fastmcp import FastMCP as McpApp  # MCP Python SDK 1.x

AURORA, AURORA_AGENT = "org.aurora.example", "agent.procurement"
BIRCH, BIRCH_AGENT = "org.birch.example", "agent.orders"


# --- Birch Components (fictional): its MCP server, with Shared Record added -------------------------


def birch_boundary(tool_name, arguments):
    """Birch's own boundary for a delivered call."""
    if arguments.get("quantity", 0) > 50:
        return "blocked", "birch.order_limit"
    return "allowed", None


def birch_server(party):
    app = McpApp("birch-components")
    for name in ("httpx", "httpx2", "mcp"):  # the MCP SDK turns on request logging; keep the output readable
        logging.getLogger(name).setLevel(logging.WARNING)

    @app.tool()
    def create_order(sku: str, quantity: int) -> str:
        """Order parts from Birch Components (fictional). Moves no money."""
        return json.dumps({"order_id": "BRC-0001", "status": "accepted", "sku": sku, "quantity": quantity})

    def show(tool_name, inbound):
        print(f"  [Birch]  {tool_name}: receipt checked; content {inbound.content_check}; Birch's boundary: "
              f"{inbound.outcome}; acknowledgement signed and logged", flush=True)

    add_shared_record(app, party, decide=birch_boundary, on_inbound=show)  # the one Shared Record line
    return app.streamable_http_app()


# --- Aurora Procurement (fictional): an OpenAI Agents SDK agent -------------------------------------


@tool_input_guardrail
def spend_limit(data):
    """Aurora's own boundary: no order above 100 units leaves Aurora."""
    if json.loads(data.context.tool_arguments or "{}").get("quantity", 0) > 100:
        return ToolGuardrailFunctionOutput.reject_content("Above Aurora's spend limit.", output_info={"rule_id": "aurora.spend_limit"})
    return ToolGuardrailFunctionOutput.allow()


class ScriptedModel(Model):
    """Stands in for the LLM: asks for these tool calls, one per turn, then finishes."""

    def __init__(self, calls):
        self.calls, self.turn = list(calls), 0

    async def get_response(self, *args, **kwargs):
        self.turn += 1
        if self.calls:
            name, arguments = self.calls.pop(0)
            item = ResponseFunctionToolCall(type="function_call", id=f"fc_{self.turn}", call_id=f"call_{self.turn}",
                                            name=name, arguments=json.dumps(arguments), status="completed")
        else:
            item = ResponseOutputMessage(id=f"msg_{self.turn}", type="message", role="assistant", status="completed",
                                         content=[ResponseOutputText(type="output_text", text="Orders placed.", annotations=[])])
        return ModelResponse(output=[item], usage=Usage(), response_id=None)

    def stream_response(self, *args, **kwargs):
        raise NotImplementedError


async def aurora_agent(party, birch_url):
    birch = partner_server(birch_url, party=party, partner_org=BIRCH, partner_agent=BIRCH_AGENT, agent_id=AURORA_AGENT,
                           tool_input_guardrails=[spend_limit])
    async with birch:
        agent = Agent(name="Aurora procurement agent", instructions="Order the parts the user asks for from Birch.",
                      model=ScriptedModel([("create_order", {"sku": "BRC-AX-10", "quantity": 5}),
                                           ("create_order", {"sku": "BRC-AX-10", "quantity": 500})]),
                      mcp_servers=[birch])
        result = await Runner.run(agent, "Order 5 units of BRC-AX-10, then 500.", run_config=RunConfig(tracing_disabled=True))
    for item in result.new_items:
        if isinstance(item, ToolCallOutputItem):
            print(f"  [Aurora] tool output the model saw: {item.output}")
            if item.custom_data:
                print(f"  [Aurora] Shared Record (not shown to the model): {json.dumps(item.custom_data[META_KEY])}")
    for status in birch.exchanges:
        if not status.delivered:
            print(f"  [Aurora] blocked call: {json.dumps(status.as_dict())}")
    return [s.exchange_id for s in birch.exchanges]


# --- the setup: in a pilot, onboarding happens out of band ------------------------------------------


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def in_thread(start):
    ready = threading.Event()
    threading.Thread(target=start, args=(ready,), daemon=True).start()
    ready.wait(10)


def main():
    work = Path(tempfile.mkdtemp(prefix="shared-record-two-companies-"))
    print(f"State in {work}\n{sandbox.BANNER}\n")

    log_port = free_port()
    log_url = f"http://127.0.0.1:{log_port}"

    def run_log(ready):  # the sandbox's state belongs to the thread that serves it
        handler = sandbox._handler(sandbox.Sandbox(work / "sandbox"))
        handler.log_message = lambda *a: None  # quiet: one line per log request otherwise
        httpd = HTTPServer(("127.0.0.1", log_port), handler)
        ready.set()
        httpd.serve_forever()

    in_thread(run_log)

    def config(org, name, agent, agent_name):
        return Config(org_id=org, org_name=name, state_dir=work / org, log_url=log_url, log_id=sandbox.LOG_ID,
                      operator_public_key_pem=(work / "sandbox" / "log-operator.pem").read_text(),
                      agents=[{"agent_id": agent, "name": agent_name, "kind": "agent"}], witness_id=f"witness.{org}",
                      policy_content_hash="0" * 64, ack_deadline_seconds=3600)

    aurora = config(AURORA, "Aurora Procurement (fictional)", AURORA_AGENT, "Procurement agent")
    birch = config(BIRCH, "Birch Components (fictional)", BIRCH_AGENT, "Order desk agent")

    async def onboard():
        parties = [Counterparty(c, HttpLogClient(log_url)) for c in (aurora, birch)]
        # Each company pins the other's root fingerprint, exchanged at onboarding.
        aurora.pins[BIRCH], birch.pins[AURORA] = parties[1].root_fingerprint, parties[0].root_fingerprint
        for p in parties:
            httpx.post(f"{log_url}/sandbox/onboard", json={"org_id": p.config.org_id, "root_fingerprint": p.root_fingerprint,
                                                          "witness_id": p.config.witness_id,
                                                          "witness_public_key_pem": p.witness_public_key_pem}).raise_for_status()
            doc = await p.publish_key_document()
            print(f"{p.config.org_name}: key document v{doc['version']} on the log; root {p.root_fingerprint[:16]}...")
            await p.log.aclose()

    asyncio.run(onboard())

    birch_port = free_port()

    def run_birch(ready):  # Birch's records belong to the thread that serves its MCP server
        server = uvicorn.Server(uvicorn.Config(birch_server(Counterparty(birch, HttpLogClient(log_url))),
                                               host="127.0.0.1", port=birch_port, log_level="warning"))
        ready.set()
        server.run()

    in_thread(run_birch)
    time.sleep(1)
    print("\nAurora's agent calls Birch's MCP tool:")
    party = Counterparty(aurora, HttpLogClient(log_url))

    async def finish():
        try:
            ids = await aurora_agent(party, f"http://127.0.0.1:{birch_port}/mcp")
            await party.witness()  # Aurora witnesses the log; the sandbox hub is the second witness
            return ids, await party.export(ids, reveal=[ids[0]])
        finally:
            await party.log.aclose()

    _, evidence = asyncio.run(finish())
    (work / "evidence.json").write_text(json.dumps(evidence, indent=1))
    trust = httpx.get(f"{log_url}/sandbox/trust").json()
    (work / "trust.json").write_text(json.dumps(trust, indent=1))

    print("\nAurora's evidence, verified offline as a third party would:")
    report = verify_evidence(evidence, trust)
    for x in report["exchanges"]:
        failed = [c["id"] for c in x["checks"] if c["status"] == "fail"]
        print(f"  exchange {x['exchange_id'][:8]}  outcome={x['outcome']}  state={x['state']}  "
              f"failed checks: {', '.join(failed) or 'none'}")
    print(f"  result: {'no check failed' if report['ok'] else 'at least one check FAILED'}")
    print(f"\nCheck it yourself:\n  python -m norcaster_verify.shared_record verify {work / 'evidence.json'} --trust {work / 'trust.json'}")
    print("\nThe record shows what each company signed and what the log recorded; it does not decide who is right.")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
