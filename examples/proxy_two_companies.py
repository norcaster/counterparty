"""Two companies, one Shared Record, through the local MCP proxy: a LangGraph agent calls a partner's MCP tool.

Aurora Procurement and Birch Components are fictional. Neither uses Norcaster: each runs
``norcaster-counterparty`` with its own keys. Aurora's agent framework (LangGraph, through
``langchain-mcp-adapters``) cannot add a receipt to an MCP request itself, so Aurora runs the local
proxy (``norcaster-counterparty proxy serve``) and points its agent at it. For every call:

* the proxy signs and registers a receipt and forwards the call to Birch with it;
* Birch checks it, applies its own boundary, runs the tool, and returns its signed, logged
  acknowledgement; the proxy checks it and keeps it out of what the agent sees;
* a call one of Aurora's interceptors blocks is not delivered: Birch receives a notice;
* a call one of Aurora's interceptors redacts is receipted as ``redacted``, with that rule.

At the end Aurora exports the evidence, and the verifier checks it offline, as a third party would.

Everything runs on 127.0.0.1: the log is the local sandbox (``norcaster-counterparty sandbox``,
NOT a SCITT transparency service). No model API is called: a scripted chat model stands in for
the LLM, so the example needs no API key.

    pip install "norcaster-counterparty[langgraph]" "langgraph>=1.2,<2"
    python proxy_two_companies.py
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import warnings
from http.server import HTTPServer
from pathlib import Path

import httpx
import uvicorn
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, ToolMessage
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent
from mcp.types import CallToolResult, TextContent
from norcaster_verify.shared_record.verify import verify_evidence

from norcaster_counterparty import Config, Counterparty, HttpLogClient, sandbox
from norcaster_counterparty.hooks import ProxyControl
from norcaster_counterparty.hooks.langgraph import connections, interceptors, rule
from norcaster_counterparty.mcp_server import add_shared_record

try:
    from mcp.server.mcpserver import MCPServer as McpApp  # MCP Python SDK 2.x
except ImportError:
    from mcp.server.fastmcp import FastMCP as McpApp  # MCP Python SDK 1.x

AURORA, AURORA_AGENT = "org.aurora.example", "agent.procurement"
BIRCH, BIRCH_AGENT = "org.birch.example", "agent.orders"


# --- Birch Components (fictional): its MCP server, with Shared Record added -------------------------


def birch_server(party):
    app = McpApp("birch-components")
    for name in ("httpx", "httpx2", "mcp"):  # the MCP SDK turns on request logging; keep the output readable
        logging.getLogger(name).setLevel(logging.WARNING)

    @app.tool()
    def create_order(sku: str, quantity: int, buyer_email: str = "") -> str:
        """Order parts from Birch Components (fictional). Moves no money."""
        return json.dumps({"order_id": "BRC-0001", "status": "accepted", "sku": sku, "quantity": quantity})

    def show(tool_name, inbound):
        print(f"  [Birch]  {tool_name}: receipt checked; content {inbound.content_check}; Birch's boundary: "
              f"{inbound.outcome}; acknowledgement signed and logged", flush=True)

    add_shared_record(app, party, on_inbound=show)
    return app.streamable_http_app()


# --- Aurora Procurement (fictional): a LangGraph agent and its boundary -----------------------------


@rule("aurora.spend_limit")
async def spend_limit(request, handler):
    """No order above 100 units leaves Aurora: answer the call instead of passing it on."""
    if request.args.get("quantity", 0) > 100:
        return CallToolResult(content=[TextContent(type="text", text="Above Aurora's spend limit.")], isError=True)
    return await handler(request)


@rule("aurora.pii.email")
async def redact_email(request, handler):
    """A buyer's e-mail address never leaves Aurora: pass the call on without it."""
    if request.args.get("buyer_email"):
        request = request.override(args={**request.args, "buyer_email": "[redacted]"})
    return await handler(request)


class ScriptedChatModel(GenericFakeChatModel):
    """Stands in for the LLM: asks for the planned tool calls, then finishes."""

    def bind_tools(self, tools, **kwargs):
        return self


async def aurora_agent(control):
    orders = [{"sku": "BRC-AX-10", "quantity": 5},
              {"sku": "BRC-AX-10", "quantity": 500},
              {"sku": "BRC-AX-10", "quantity": 2, "buyer_email": "buyer@aurora.example"}]
    model = ScriptedChatModel(messages=iter(
        [AIMessage(content="", tool_calls=[{"name": "create_order", "args": o, "id": f"call_{i}"}]) for i, o in enumerate(orders)]
        + [AIMessage(content="Orders placed.")]))
    client = MultiServerMCPClient(connections(control, ["birch"]),
                                  tool_interceptors=interceptors(control, spend_limit, redact_email, servers=["birch"]))
    with warnings.catch_warnings():  # LangGraph 1.x points to langchain.agents.create_agent; this one works until 2.0
        warnings.simplefilter("ignore")
        agent = create_react_agent(model, await client.get_tools())
    result = await agent.ainvoke({"messages": [("user", "Order BRC-AX-10: 5 units, then 500, then 2 for buyer@aurora.example.")]})
    for message in result["messages"]:
        if isinstance(message, ToolMessage):
            text = " ".join(b.get("text", "") for b in message.content) if isinstance(message.content, list) else message.content
            print(f"  [Aurora] tool result the model saw ({message.status}): {text}")
    statuses = await control.exchanges()
    for status in statuses:
        print(f"  [Aurora] Shared Record: {status['outcome']:<8} rule={status['rule_id']}  -> {status['status']}"
              f" (Birch: content {status['partner_content_check']})")
    return [s["exchange_id"] for s in statuses]


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
    work = Path(tempfile.mkdtemp(prefix="shared-record-proxy-"))
    print(f"State in {work}\n{sandbox.BANNER}\n")
    log_port, birch_port, proxy_port = free_port(), free_port(), free_port()
    log_url = f"http://127.0.0.1:{log_port}"

    def run_log(ready):  # the sandbox's state belongs to the thread that serves it
        handler = sandbox._handler(sandbox.Sandbox(work / "sandbox"))
        handler.log_message = lambda *a: None
        httpd = HTTPServer(("127.0.0.1", log_port), handler)
        ready.set()
        httpd.serve_forever()

    in_thread(run_log)

    def counterparty_json(org, name, agent, agent_name):
        folder = work / org
        folder.mkdir()
        path = folder / "counterparty.json"
        path.write_text(json.dumps({
            "org_id": org, "org_name": name, "state_dir": "state", "log_url": log_url, "log_id": sandbox.LOG_ID,
            "operator_public_key_file": str(work / "sandbox" / "log-operator.pem"), "witness_id": f"witness.{org}",
            "agents": [{"agent_id": agent, "name": agent_name}], "policy_content_hash": "0" * 64,
            "ack_deadline_seconds": 3600}, indent=1))
        return path

    aurora_json = counterparty_json(AURORA, "Aurora Procurement (fictional)", AURORA_AGENT, "Procurement agent")
    birch_json = counterparty_json(BIRCH, "Birch Components (fictional)", BIRCH_AGENT, "Order desk agent")

    async def onboard():
        parties = [Counterparty(Config.load(p), HttpLogClient(log_url)) for p in (aurora_json, birch_json)]
        for path, other in ((aurora_json, parties[1]), (birch_json, parties[0])):  # each pins the other's root
            raw = json.loads(path.read_text())
            raw["pins"] = {other.config.org_id: other.root_fingerprint}
            path.write_text(json.dumps(raw, indent=1))
        for p in parties:
            httpx.post(f"{log_url}/sandbox/onboard", json={"org_id": p.config.org_id, "root_fingerprint": p.root_fingerprint,
                                                          "witness_id": p.config.witness_id,
                                                          "witness_public_key_pem": p.witness_public_key_pem}).raise_for_status()
            doc = await p.publish_key_document()
            print(f"{p.config.org_name}: key document v{doc['version']} on the log; root {p.root_fingerprint[:16]}...")
            await p.log.aclose()

    asyncio.run(onboard())

    def run_birch(ready):  # Birch's records belong to the thread that serves its MCP server
        server = uvicorn.Server(uvicorn.Config(birch_server(Counterparty(Config.load(birch_json), HttpLogClient(log_url))),
                                               host="127.0.0.1", port=birch_port, log_level="warning"))
        ready.set()
        server.run()

    in_thread(run_birch)

    # Aurora's proxy: proxy.json names Birch's MCP server; the command is what you would run.
    proxy_json = work / AURORA / "proxy.json"
    proxy_json.write_text(json.dumps({"port": proxy_port, "upstreams": [{
        "name": "birch", "url": f"http://127.0.0.1:{birch_port}/mcp", "partner_org": BIRCH,
        "partner_agent": BIRCH_AGENT, "agent_id": AURORA_AGENT}]}, indent=1))
    command = [sys.executable, "-m", "norcaster_counterparty.cli", "--config", str(aurora_json), "proxy", "serve",
               "--proxy", str(proxy_json)]
    print(f"\n$ norcaster-counterparty --config {aurora_json.name} proxy serve --proxy {proxy_json.name}")
    proxy = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=dict(os.environ))
    try:
        token_file = work / AURORA / "state" / "proxy-token"
        for _ in range(150):
            if token_file.exists():
                try:
                    control = ProxyControl(f"http://127.0.0.1:{proxy_port}", token_file=token_file)
                    httpx.get(f"{control.url}/control/v1/health", headers=control.headers).raise_for_status()
                    break
                except (httpx.HTTPError, OSError):
                    pass
            time.sleep(0.1)
        else:
            raise SystemExit("the proxy did not start:\n" + proxy.stdout.read())

        print("\nAurora's LangGraph agent calls Birch's MCP tool through the proxy:")
        ids = asyncio.run(aurora_agent(control))
    finally:
        proxy.terminate()
        proxy.wait(timeout=10)

    party = Counterparty(Config.load(aurora_json), HttpLogClient(log_url))

    async def export():
        try:
            await party.witness()  # Aurora witnesses the log; the sandbox hub is the second witness
            return await party.export(ids, reveal=[ids[0], ids[2]])
        finally:
            await party.log.aclose()

    evidence = asyncio.run(export())
    (work / "evidence.json").write_text(json.dumps(evidence, indent=1))
    trust = httpx.get(f"{log_url}/sandbox/trust").json()
    (work / "trust.json").write_text(json.dumps(trust, indent=1))

    print("\nAurora's evidence, verified offline as a third party would:")
    report = verify_evidence(evidence, trust)
    for x in report["exchanges"]:
        failed = [c["id"] for c in x["checks"] if c["status"] == "fail"]
        print(f"  exchange {x['exchange_id'][:8]}  outcome={x['outcome']:<8} state={x['state']:<13} "
              f"failed checks: {', '.join(failed) or 'none'}")
    print(f"  result: {'no check failed' if report['ok'] else 'at least one check FAILED'}")
    print(f"\nCheck it yourself:\n  python -m norcaster_verify.shared_record verify {work / 'evidence.json'} --trust {work / 'trust.json'}")
    print("\nThe record shows what each company signed and what the log recorded; it does not decide who is right.")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
