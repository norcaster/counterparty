"""The proxy over stdio (``norcaster-counterparty proxy stdio``), with no running daemon: the client
starts the proxy process itself, several such processes share one ``state_dir``, and Claude Code's
command hook acts on ``state_dir`` directly (``proxy hook --proxy``). Birch's MCP server and the
sandbox log run on 127.0.0.1. Synthetic data; no model API is called."""

# ruff: noqa: F811  (pytest fixtures imported from two_companies are used as parameters)
from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("mcp", reason="needs the mcp extra")

from messages_stub import MessagesStub  # noqa: E402
from two_companies import BIRCH, BIRCH_AGENT, AURORA_AGENT, Birch, _lowlevel_app, aurora_party, birch_party, exchange, export_and_verify  # noqa: E402
from two_companies import configs, log_url, serve  # noqa: E402,F401  (pytest fixtures, used by parameter name)

from norcaster_counterparty import META_KEY, Config, Store  # noqa: E402
from norcaster_counterparty.hooks.claude import run_command_hook  # noqa: E402
from norcaster_counterparty.mcp_server import NOTICE_TOOL  # noqa: E402
from norcaster_counterparty.proxy import LocalControl  # noqa: E402

PKG = Path(__file__).resolve().parents[1]
ENV = {**os.environ, "PYTHONPATH": os.pathsep.join(str(p) for p in (PKG / "src", PKG.parent / "norcaster-verify" / "src"))}
ORDER = {"sku": "BRC-AX-10", "quantity": 5}
POLICY = """
import json, sys
args = json.load(sys.stdin)["tool_input"]
if args.get("quantity", 0) > 100:
    print("above Aurora's spend limit", file=sys.stderr)
    sys.exit(2)
if "buyer_email" in args:
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow",
                      "updatedInput": {**args, "buyer_email": "[redacted]"}}, "norcaster_rule_id": "aurora.pii.email"}))
"""


def write_config(config: Config, path: Path) -> Path:
    path.write_text(json.dumps({
        "org_id": config.org_id, "org_name": config.org_name, "state_dir": str(config.state_dir), "log_url": config.log_url,
        "log_id": config.log_id, "operator_public_key_pem": config.operator_public_key_pem, "pins": config.pins,
        "agents": config.agents, "witness_id": config.witness_id, "policy_version": config.policy_version,
        "policy_content_hash": config.policy_content_hash, "ack_deadline_seconds": config.ack_deadline_seconds}))
    return path


def setup(tmp_path, configs, serve) -> tuple[Config, Birch, Path, Path]:
    aurora, birch_config = configs
    birch = Birch()
    birch_url = serve(lambda: _lowlevel_app(birch, birch_party(birch_config)))
    aurora_json = write_config(aurora, tmp_path / "aurora.json")
    proxy_json = tmp_path / "proxy.json"
    proxy_json.write_text(json.dumps({"upstreams": [{"name": "birch", "url": birch_url, "partner_org": BIRCH,
                                                     "partner_agent": BIRCH_AGENT, "agent_id": AURORA_AGENT}]}))
    return aurora, birch, aurora_json, proxy_json


def stdio_command(aurora_json: Path, proxy_json: Path) -> list[str]:
    return [sys.executable, "-m", "norcaster_counterparty.cli", "--config", str(aurora_json), "proxy", "stdio",
            "--proxy", str(proxy_json), "--upstream", "birch"]


async def calls_over_stdio(command: list[str], arguments: list[dict[str, Any]]) -> list[Any]:
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    params = StdioServerParameters(command=command[0], args=command[1:], env=ENV)
    async with stdio_client(params) as streams, ClientSession(streams[0], streams[1]) as session:
        await session.initialize()
        assert NOTICE_TOOL not in [t.name for t in (await session.list_tools()).tools]
        return [await session.call_tool("create_order", args) for args in arguments]


def statuses(aurora: Config) -> list[dict[str, Any]]:
    path = aurora.state_dir / "proxy-exchanges.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def test_a_call_over_stdio_is_acknowledged(tmp_path, configs, serve):
    aurora, birch, aurora_json, proxy_json = setup(tmp_path, configs, serve)
    [result] = asyncio.run(calls_over_stdio(stdio_command(aurora_json, proxy_json), [ORDER]))
    assert "BRC-0001" in result.content[0].text and META_KEY not in (result.meta or {})
    [status] = statuses(aurora)
    assert (status["status"], status["outcome"], status["partner_content_check"]) == ("acknowledged", "allowed", "matched")
    report = export_and_verify(aurora_party(aurora), tmp_path, [status["exchange_id"]], reveal=[status["exchange_id"]])
    assert report["ok"] is True and exchange(report, status["exchange_id"])[0] == "acknowledged"


def test_two_stdio_processes_share_one_state_dir(tmp_path, configs, serve):
    aurora, birch, aurora_json, proxy_json = setup(tmp_path, configs, serve)
    command = stdio_command(aurora_json, proxy_json)

    async def both():
        return await asyncio.gather(*(calls_over_stdio(command, [{"sku": f"BRC-{p}{i}", "quantity": 1} for i in range(3)])
                                      for p in "AB"))

    results = [r for batch in asyncio.run(both()) for r in batch]
    assert not any(getattr(r, "isError", None) or getattr(r, "is_error", None) for r in results)
    assert [s["status"] for s in statuses(aurora)] == ["acknowledged"] * 6
    store = Store(aurora.state_dir)
    sequences = [row[0] for row in store.db.execute("SELECT sequence FROM exchanges WHERE role = 'sender' ORDER BY sequence")]
    assert sequences == [1, 2, 3, 4, 5, 6] and len(birch.ran) == 6


def test_the_hook_command_acts_on_state_dir_without_a_proxy_running(tmp_path, configs, serve):
    aurora, birch, aurora_json, proxy_json = setup(tmp_path, configs, serve)
    policy = tmp_path / "policy.py"
    policy.write_text(POLICY)
    local = LocalControl(aurora_json, proxy_json)

    def hook(arguments: dict[str, Any]) -> tuple[str, str, int]:
        hook_input = {"hook_event_name": "PreToolUse", "tool_name": "mcp__birch__create_order", "tool_input": arguments,
                      "tool_use_id": "toolu_x"}
        return run_command_hook(local, [sys.executable, str(policy)], json.dumps(hook_input), servers=["birch"],
                                rule_id="aurora.spend_limit")

    _, _, code = hook({"sku": "BRC-AX-10", "quantity": 500})
    assert code == 2 and birch.inbound[-1][0] == NOTICE_TOOL and birch.ran == []  # the hook process sent the notice
    asked = {"sku": "BRC-AX-10", "quantity": 2, "buyer_email": "buyer@aurora.example"}
    stdout, _, code = hook(asked)
    sent = json.loads(stdout)["hookSpecificOutput"]["updatedInput"]
    asyncio.run(calls_over_stdio(stdio_command(aurora_json, proxy_json), [sent]))  # what Claude Code then sends
    blocked, redacted = statuses(aurora)
    assert (blocked["outcome"], blocked["rule_id"], blocked["delivered"]) == ("blocked", "aurora.spend_limit", False)
    assert (redacted["outcome"], redacted["rule_id"], redacted["status"]) == ("redacted", "aurora.pii.email", "acknowledged")
    assert birch.ran == [("create_order", sent)]

    ids = [blocked["exchange_id"], redacted["exchange_id"]]
    report = export_and_verify(aurora_party(aurora), tmp_path, ids, reveal=[ids[1]])
    assert report["ok"] is True and [exchange(report, i)[0] for i in ids] == ["not_delivered", "acknowledged"]


def test_claude_code_with_the_stdio_proxy_and_the_hook_command(tmp_path, configs, serve):
    sdk = pytest.importorskip("claude_agent_sdk", reason="needs the claude-agent-sdk extra")
    aurora, birch, aurora_json, proxy_json = setup(tmp_path, configs, serve)
    policy = tmp_path / "policy.py"
    policy.write_text(POLICY)
    hook = (f"{sys.executable} -m norcaster_counterparty.cli --config {aurora_json} proxy hook --proxy {proxy_json} "
            f"--server birch --rule-id aurora.spend_limit -- {sys.executable} {policy}")
    command = stdio_command(aurora_json, proxy_json)
    stub = MessagesStub()
    stub_url = serve(lambda: stub.app).removesuffix("/mcp")

    def run(arguments: dict[str, Any]) -> list[Any]:
        stub.plan = ("mcp__birch__create_order", arguments)
        home = tmp_path / f"claude-{len(list(tmp_path.glob('claude-*')))}"
        home.mkdir()
        env = {"ANTHROPIC_BASE_URL": stub_url, "ANTHROPIC_API_KEY": "sk-ant-test-not-a-key", "CLAUDE_CONFIG_DIR": str(home),
               "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "DISABLE_TELEMETRY": "1", "DISABLE_ERROR_REPORTING": "1",
               "DISABLE_AUTOUPDATER": "1", "ENABLE_TOOL_SEARCH": "false", "PYTHONPATH": ENV["PYTHONPATH"]}
        options = sdk.ClaudeAgentOptions(
            env=env, cwd=str(home), model="claude-sonnet-5-5", max_turns=3, allowed_tools=["mcp__birch__create_order"],
            mcp_servers={"birch": {"type": "stdio", "command": command[0], "args": command[1:], "env": {"PYTHONPATH": ENV["PYTHONPATH"]}}},
            settings=json.dumps({"hooks": {"PreToolUse": [{"matcher": "mcp__birch__.*",
                                                           "hooks": [{"type": "command", "command": hook}]}]}}))

        async def go():
            return [m async for m in sdk.query(prompt="Order the parts from Birch.", options=options)]

        return asyncio.run(go())

    run(ORDER)
    run({"sku": "BRC-AX-10", "quantity": 500})
    asked = {"sku": "BRC-AX-10", "quantity": 2, "buyer_email": "buyer@aurora.example"}
    run(asked)
    assert [(s["outcome"], s["status"]) for s in statuses(aurora)] == [
        ("allowed", "acknowledged"), ("blocked", "acknowledged"), ("redacted", "acknowledged")]
    assert birch.ran == [("create_order", ORDER), ("create_order", {**asked, "buyer_email": "[redacted]"})]
    assert {r["path"] for r in stub.requests} == {"/v1/messages"}
