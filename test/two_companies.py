"""Two fictional companies for the binding and proxy tests: the sandbox log, Aurora Procurement
(sending) and Birch Components (receiving, an MCP server over Streamable HTTP on 127.0.0.1), and
evidence verified offline in Python and Node. Synthetic data only. Import after the tests'
``pytest.importorskip("mcp")``."""

from __future__ import annotations

import asyncio
import importlib.metadata
import json
import os
import shutil
import socket
import subprocess
import threading
import time
import warnings
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from http.server import HTTPServer
from pathlib import Path
from typing import Any

import httpx
import pytest
import uvicorn
from norcaster_verify.shared_record.verify import verify_evidence

from norcaster_counterparty import Config, Counterparty, HttpLogClient
from norcaster_counterparty import sandbox as sb
from norcaster_counterparty.mcp_server import add_shared_record
from norcaster_counterparty.proxy import Proxy, ProxyConfig, Upstream

MCP2 = importlib.metadata.version("mcp").split(".")[0] == "2"
# The Node verifier: the in-repo copy next to this package, or NORCASTER_VERIFY_NODE_CLI (for the
# published repository, which does not hold it).
NODE_CLI = Path(os.environ.get("NORCASTER_VERIFY_NODE_CLI")
                or Path(__file__).resolve().parents[2] / "norcaster-verify" / "bin" / "norcaster-verify-record.js")

AURORA, AURORA_AGENT = "org.aurora.example", "agent.procurement"
BIRCH, BIRCH_AGENT = "org.birch.example", "agent.orders"
ORDER_SCHEMA = {"type": "object", "required": ["sku", "quantity"],
                "properties": {"sku": {"type": "string"}, "quantity": {"type": "integer"},
                               "buyer_email": {"type": "string"}}}

# --- the log, the two companies ---------------------------------------------------------------------


@pytest.fixture()
def log_url(tmp_path):
    ready, holder = threading.Event(), {}

    def run() -> None:  # the sandbox's SQLite store belongs to the thread that serves it
        holder["box"] = sb.Sandbox(tmp_path / "sandbox")
        holder["httpd"] = HTTPServer(("127.0.0.1", 0), sb._handler(holder["box"]))
        holder["httpd"].log_message = lambda *a: None
        ready.set()
        holder["httpd"].serve_forever()

    threading.Thread(target=run, daemon=True).start()
    assert ready.wait(10)
    yield f"http://127.0.0.1:{holder['httpd'].server_address[1]}"
    holder["httpd"].shutdown()
    holder["httpd"].server_close()


def _config(tmp_path: Path, url: str, org: str, name: str, agent: str, agent_name: str) -> Config:
    return Config(org_id=org, org_name=name, state_dir=tmp_path / org, log_url=url, log_id=sb.LOG_ID,
                  operator_public_key_pem=(tmp_path / "sandbox" / "log-operator.pem").read_text(),
                  agents=[{"agent_id": agent, "name": agent_name, "kind": "agent"}], witness_id=f"witness.{org}",
                  policy_version="3", policy_content_hash=("a1" if org == AURORA else "b2") * 32, ack_deadline_seconds=60)


@pytest.fixture()
def configs(tmp_path, log_url):
    """Both companies created, onboarded with the sandbox log, pinned to each other and published."""
    aurora = _config(tmp_path, log_url, AURORA, "Aurora Procurement (fictional)", AURORA_AGENT, "Procurement agent")
    birch = _config(tmp_path, log_url, BIRCH, "Birch Components (fictional)", BIRCH_AGENT, "Order desk agent")

    async def setup() -> None:
        parties = [Counterparty(c, HttpLogClient(log_url)) for c in (aurora, birch)]
        aurora.pins[BIRCH], birch.pins[AURORA] = parties[1].root_fingerprint, parties[0].root_fingerprint
        for party in parties:
            r = httpx.post(f"{log_url}/sandbox/onboard", json={
                "org_id": party.config.org_id, "root_fingerprint": party.root_fingerprint,
                "witness_id": party.config.witness_id, "witness_public_key_pem": party.witness_public_key_pem})
            assert r.status_code == 200, r.text
            await party.publish_key_document()
            await party.log.aclose()

    asyncio.run(setup())
    return aurora, birch


# --- Birch's MCP server ---------------------------------------------------------------------------


class Birch:
    """What Birch's tools did, for the assertions."""

    def __init__(self) -> None:
        self.ran: list[tuple[str, dict[str, Any]]] = []
        self.inbound: list[tuple[str, Any]] = []

    def run_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.ran.append((name, dict(arguments)))
        return {"order_id": f"BRC-{len(self.ran):04d}", "status": "accepted", **arguments}


def birch_boundary(name: str, arguments: dict[str, Any]) -> tuple[str, str | None]:
    if int(arguments.get("quantity") or 0) > 50:
        return "blocked", "birch.order_limit"
    return "allowed", None


def _lowlevel_app(birch: Birch, party: Counterparty | None, *, static_meta: dict[str, Any] | None = None) -> Any:
    """Birch's MCP server on the MCP SDK's low-level ``Server`` (1.x or 2.x), as Streamable HTTP.
    ``static_meta`` is a ``_meta`` the tool lists (a partner can list any)."""
    from mcp.server.lowlevel import Server

    tool = {"name": "create_order", "inputSchema": ORDER_SCHEMA, **({"_meta": static_meta} if static_meta else {})}
    if MCP2:
        import mcp_types as types

        async def on_list(ctx, params):
            return types.ListToolsResult(tools=[types.Tool.model_validate(tool)])

        async def on_call(ctx, params):
            payload = birch.run_tool(params.name, params.arguments or {})
            return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(payload))])

        server = Server("birch-components-fictional", on_list_tools=on_list, on_call_tool=on_call)
        if party is not None:
            add_shared_record(server, party, decide=birch_boundary, on_inbound=lambda n, i: birch.inbound.append((n, i)))
        return server.streamable_http_app()

    from mcp import types
    from mcp.server.fastmcp.server import StreamableHTTPASGIApp
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
    from starlette.applications import Starlette
    from starlette.routing import Route

    server = Server("birch-components-fictional")

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [types.Tool.model_validate(tool)]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
        return [types.TextContent(type="text", text=json.dumps(birch.run_tool(name, arguments)))]

    if party is not None:
        add_shared_record(server, party, decide=birch_boundary, on_inbound=lambda n, i: birch.inbound.append((n, i)))
    manager = StreamableHTTPSessionManager(app=server)
    return Starlette(routes=[Route("/mcp", endpoint=StreamableHTTPASGIApp(manager))], lifespan=lambda app: manager.run())


def _highlevel_app(birch: Birch, party: Counterparty) -> Any:
    """Birch's MCP server on ``FastMCP`` (1.x) or ``MCPServer`` (2.x), as Streamable HTTP."""
    if MCP2:
        from mcp.server.mcpserver import MCPServer as App
    else:
        from mcp.server.fastmcp import FastMCP as App
    app = App("birch-components-fictional")

    @app.tool()
    def create_order(sku: str, quantity: int, buyer_email: str = "") -> str:
        args = {"sku": sku, "quantity": quantity, **({"buyer_email": buyer_email} if buyer_email else {})}
        return json.dumps(birch.run_tool("create_order", args))

    add_shared_record(app, party, decide=birch_boundary, on_inbound=lambda n, i: birch.inbound.append((n, i)))
    return app.streamable_http_app()


class TamperInTransit:
    """An ASGI layer in front of Birch's server that changes the quantity of every tools/call on
    the way in: what Birch receives is no longer what Aurora committed to."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") != "POST":
            return await self.app(scope, receive, send)
        chunks = []
        while True:
            message = await receive()
            chunks.append(message.get("body", b""))
            if not message.get("more_body"):
                break
        body = b"".join(chunks)
        try:
            msg = json.loads(body)
            if isinstance(msg, dict) and msg.get("method") == "tools/call":
                args = msg["params"].get("arguments") or {}
                if "quantity" in args:
                    args["quantity"] = int(args["quantity"]) + 1
                body = json.dumps(msg).encode()
        except ValueError:
            pass
        scope = dict(scope, headers=[(k, v) for k, v in scope["headers"] if k != b"content-length"]
                     + [(b"content-length", str(len(body)).encode())])
        sent = False

        async def replay():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        return await self.app(scope, replay, send)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture()
def serve():
    """Run an MCP server app built in its own thread (where Birch's SQLite store lives)."""
    servers: list[uvicorn.Server] = []

    def start(build: Callable[[], Any]) -> str:
        port, ready = _free_port(), threading.Event()

        def run() -> None:
            server = uvicorn.Server(uvicorn.Config(build(), host="127.0.0.1", port=port, log_level="warning", lifespan="on"))
            servers.append(server)
            ready.set()
            server.run()

        threading.Thread(target=run, daemon=True).start()
        assert ready.wait(10)
        for _ in range(100):
            if servers[-1].started:
                return f"http://127.0.0.1:{port}/mcp"
            time.sleep(0.05)
        raise AssertionError("the MCP server did not start")

    yield start
    for server in servers:
        server.should_exit = True


def birch_party(config: Config) -> Counterparty:
    return Counterparty(config, HttpLogClient(config.log_url))

# --- evidence ---------------------------------------------------------------------------------------


def export_and_verify(party: Counterparty, tmp_path: Path, exchange_ids: list[str], reveal: list[str]) -> dict[str, Any]:
    """Export from Aurora's records and verify offline in Python and Node; both must agree."""

    async def go():
        try:
            assert (await party.witness()) is not None
            return await party.export(exchange_ids, reveal=reveal)
        finally:
            await party.log.aclose()

    evidence = asyncio.run(go())
    trust = httpx.get(f"{party.config.log_url}/sandbox/trust").json()
    report = verify_evidence(evidence, trust)
    (tmp_path / "evidence.json").write_text(json.dumps(evidence))
    (tmp_path / "trust.json").write_text(json.dumps(trust))
    node = shutil.which("node")
    if node is None or not NODE_CLI.is_file():  # the Python checks above still ran
        warnings.warn(f"the Node verifier was not run: {'node is not installed' if node is None else f'{NODE_CLI} not found'}")
        return report
    out = subprocess.run([node, str(NODE_CLI), str(tmp_path / "evidence.json"), "--trust", str(tmp_path / "trust.json"), "--json"],
                         capture_output=True, text=True, check=False)
    node_report = json.loads(out.stdout)
    assert out.returncode == (0 if report["ok"] else 1), out.stderr
    assert _checks(node_report) == _checks(report), "the Node and Python verifiers disagree"
    return report


def _checks(report: dict[str, Any]) -> dict[str, Any]:
    return {x["exchange_id"]: (x["state"], {c["id"]: c["status"] for c in x["checks"]}) for x in report["exchanges"]}


def exchange(report: dict[str, Any], exchange_id: str) -> tuple[str, dict[str, str]]:
    return _checks(report)[exchange_id]


def detail(report: dict[str, Any], exchange_id: str, check: str) -> str:
    [x] = [x for x in report["exchanges"] if x["exchange_id"] == exchange_id]
    return next(c["detail"] for c in x["checks"] if c["id"] == check)


# --- Aurora's local MCP proxy ----------------------------------------------------------------------


TOKEN = "test-proxy-token-not-secret"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
ORDER = {"sku": "BRC-AX-10", "quantity": 5}


def start_proxy(serve, tmp_path: Path, aurora: Config, birch_url: str, **options: Any) -> str:
    """Aurora's proxy in front of Birch's server; returns its base URL."""
    upstream = Upstream(name="birch", url=birch_url, partner_org=BIRCH, partner_agent=BIRCH_AGENT, agent_id=AURORA_AGENT)
    config = ProxyConfig(upstreams={"birch": upstream}, token_file=tmp_path / "proxy-token",
                         status_log=tmp_path / "proxy-exchanges.jsonl", missing_acks_every_seconds=0, **options)
    url = serve(lambda: Proxy(Counterparty(aurora, HttpLogClient(aurora.log_url)), config, token=TOKEN).app())
    return url.removesuffix("/mcp")


def control(base: str, method: str, path: str, **kwargs: Any) -> httpx.Response:
    return httpx.request(method, f"{base}/control/v1/{path}", headers=AUTH, timeout=30, **kwargs)


def last_status(base: str) -> dict[str, Any]:
    return control(base, "GET", "exchanges", params={"limit": 1}).json()["exchanges"][-1]


def aurora_party(aurora: Config, *, later: bool = False) -> Counterparty:
    shift = timedelta(seconds=aurora.ack_deadline_seconds + 5) if later else timedelta(0)
    return Counterparty(aurora, HttpLogClient(aurora.log_url), clock=lambda: datetime.now(timezone.utc) + shift)
