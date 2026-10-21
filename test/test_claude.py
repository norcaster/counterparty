"""The Claude adapter (``norcaster_counterparty.hooks.claude``) against Aurora's local MCP proxy and
Birch's MCP server on 127.0.0.1, with the quickstart sandbox as the log. Synthetic data.

The first tests call the ``PreToolUse`` hook and the command hook directly, with the input Claude
gives them. The last ones run the real Claude Code CLI bundled with the Claude Agent SDK (pinned)
against a local stand-in for the Messages API (``messages_stub.py``): no model is called, and the
CLI's configuration directory and non-essential traffic are switched off."""

# ruff: noqa: F811  (pytest fixtures imported from two_companies are used as parameters)
from __future__ import annotations

import asyncio
import importlib.metadata
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("mcp", reason="needs the mcp extra")

from messages_stub import MessagesStub  # noqa: E402
from two_companies import (  # noqa: E402
    BIRCH,
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

from norcaster_counterparty.hooks import ProxyControl  # noqa: E402
from norcaster_counterparty.hooks.claude import (  # noqa: E402
    REDACTION_UNRECORDED,
    RULE_KEY,
    TESTED_SDK_VERSIONS,
    _ToolNames,
    mcp_servers,
    pre_tool_use,
    run_command_hook,
)
from norcaster_counterparty.mcp_server import NOTICE_TOOL  # noqa: E402
from norcaster_counterparty.proxy import open_session  # noqa: E402

PKG = Path(__file__).resolve().parents[1]
TOOL = "mcp__birch__create_order"
ORDER = {"sku": "BRC-AX-10", "quantity": 5}


def hook_input(arguments: dict[str, Any], tool_name: str = TOOL) -> dict[str, Any]:
    return {"session_id": "s", "transcript_path": "/dev/null", "cwd": "/", "hook_event_name": "PreToolUse",
            "tool_name": tool_name, "tool_input": arguments, "tool_use_id": "toolu_test"}


async def spend_limit(input_data, tool_use_id, context):  # noqa: ANN001
    """Aurora's boundary: no order above 100 units leaves Aurora."""
    if int(input_data["tool_input"].get("quantity") or 0) > 100:
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                       "permissionDecisionReason": "above Aurora's spend limit"},
                RULE_KEY: "aurora.spend_limit"}
    return {}


async def redact_email(input_data, tool_use_id, context):  # noqa: ANN001
    """Aurora's boundary: a buyer's e-mail address never leaves Aurora (rule id: this function's name)."""
    if "buyer_email" in input_data["tool_input"]:
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow",
                                       "updatedInput": {**input_data["tool_input"], "buyer_email": "[redacted]"}}}
    return {}


def setup(tmp_path, configs, serve, *, birch_ok: bool = True) -> tuple[Any, Birch, str, ProxyControl]:
    aurora, birch_config = configs
    birch = Birch()
    base = start_proxy(serve, tmp_path, aurora, serve(lambda: _lowlevel_app(birch, birch_party(birch_config) if birch_ok else None)))
    return aurora, birch, base, ProxyControl(base, token=TOKEN)


def call_through_proxy(control: ProxyControl, arguments: dict[str, Any]) -> Any:
    async def go():
        async with open_session(control.mcp_url("birch"), control.headers) as session:
            return await session.call_tool("create_order", arguments)

    return asyncio.run(go())


# --- the PreToolUse hook, called as the SDK calls it -------------------------------------------------


def test_a_deny_sends_a_notice_and_the_output_reaches_claude_unchanged(tmp_path, configs, serve):
    aurora, birch, base, ctl = setup(tmp_path, configs, serve)
    hook = pre_tool_use(ctl, spend_limit, redact_email, servers=["birch"])
    output = asyncio.run(hook(hook_input({"sku": "BRC-AX-10", "quantity": 500}), "toolu_1", None))
    assert output == {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                             "permissionDecisionReason": "above Aurora's spend limit"}}  # RULE_KEY removed
    status = last_status(base)
    assert (status["status"], status["outcome"], status["rule_id"], status["delivered"]) == (
        "acknowledged", "blocked", "aurora.spend_limit", False)
    assert birch.ran == [] and [t for t, _ in birch.inbound] == [NOTICE_TOOL]
    asyncio.run(hook(hook_input({"sku": "BRC-AX-10", "quantity": 500}), "toolu_1", None))  # the same call again
    assert len(control(base, "GET", "exchanges").json()["exchanges"]) == 1  # one notice per tool use

    report = export_and_verify(aurora_party(aurora), tmp_path, [status["exchange_id"]], reveal=[])
    assert report["ok"] is True and exchange(report, status["exchange_id"])[0] == "not_delivered"


def test_changed_arguments_are_receipted_as_redacted(tmp_path, configs, serve):
    aurora, birch, base, ctl = setup(tmp_path, configs, serve)
    seen: list[dict[str, Any]] = []

    async def note(input_data, tool_use_id, context):  # noqa: ANN001
        seen.append(dict(input_data["tool_input"]))
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "additionalContext": "checked by note"}}

    hook = pre_tool_use(ctl, redact_email, note, servers=["birch"])
    asked = {"sku": "BRC-AX-10", "quantity": 2, "buyer_email": "buyer@aurora.example"}
    output = asyncio.run(hook(hook_input(asked), "toolu_2", None))
    sent = {**asked, "buyer_email": "[redacted]"}
    assert seen == [sent]  # the next hook sees the redacted arguments
    assert output["hookSpecificOutput"] == {"hookEventName": "PreToolUse", "permissionDecision": "allow",
                                            "updatedInput": sent, "additionalContext": "checked by note"}
    call_through_proxy(ctl, sent)  # what Claude then sends through the proxy
    status = last_status(base)
    assert (status["status"], status["outcome"], status["rule_id"]) == ("acknowledged", "redacted", "redact_email")
    assert birch.ran == [("create_order", sent)]

    report = export_and_verify(aurora_party(aurora), tmp_path, [status["exchange_id"]], reveal=[status["exchange_id"]])
    assert report["ok"] is True and report["exchanges"][0]["outcome"] == "redacted"


def test_other_tools_pass_through_and_an_unrecorded_redaction_fails_closed(tmp_path, configs, serve):
    _, _, base, ctl = setup(tmp_path, configs, serve)
    hook = pre_tool_use(ctl, redact_email, servers=["birch"])
    asked = {"buyer_email": "buyer@aurora.example"}
    output = asyncio.run(hook(hook_input(asked, tool_name="mcp__other__create_order"), "toolu_3", None))
    assert output["hookSpecificOutput"]["updatedInput"] == {"buyer_email": "[redacted]"}  # not proxied: no report
    assert control(base, "GET", "exchanges").json()["exchanges"] == []

    unreachable = ProxyControl("http://127.0.0.1:9", token="x", timeout=2)
    output = asyncio.run(pre_tool_use(unreachable, redact_email, servers=["birch"])(hook_input(asked), "toolu_4", None))
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert output["hookSpecificOutput"]["permissionDecisionReason"] == REDACTION_UNRECORDED


def test_claude_tool_names_map_back_to_the_partners_names():
    class Control:
        async def tool_names(self, upstream):  # noqa: ANN001
            return ["orders.create", "create_order"]

    names = _ToolNames(Control(), {"partner_birch": "birch"})
    assert asyncio.run(names.resolve("mcp__partner_birch__orders_create")) == ("birch", "orders.create")
    assert asyncio.run(names.resolve("mcp__partner_birch__create_order")) == ("birch", "create_order")
    assert asyncio.run(names.resolve("mcp__partner__create_order")) is None
    assert mcp_servers(ProxyControl("http://127.0.0.1:8790", token="t"), {"partner.birch": "birch"}) == {
        "partner.birch": {"type": "http", "url": "http://127.0.0.1:8790/mcp/birch", "headers": {"Authorization": "Bearer t"}}}


# --- the command hook (Claude Code settings.json) ----------------------------------------------------


POLICY = """
import json, sys
data = json.load(sys.stdin)
args = data["tool_input"]
if args.get("quantity", 0) > 100:
    print("above Aurora's spend limit", file=sys.stderr)
    sys.exit(2)
if "buyer_email" in args:
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow",
                      "updatedInput": {**args, "buyer_email": "[redacted]"}}, "norcaster_rule_id": "aurora.pii.email"}))
"""


def test_command_hook_reports_exit_2_and_updated_input(tmp_path, configs, serve):
    _, birch, base, ctl = setup(tmp_path, configs, serve)
    policy = tmp_path / "policy.py"
    policy.write_text(POLICY)
    command = [sys.executable, str(policy)]

    stdout, stderr, code = run_command_hook(ctl, command, json.dumps(hook_input({"sku": "X", "quantity": 500})),
                                            servers=["birch"], rule_id="aurora.spend_limit")
    assert (stdout, stderr.strip(), code) == ("", "above Aurora's spend limit", 2)  # Claude Code gets exactly that
    assert (last_status(base)["outcome"], last_status(base)["rule_id"]) == ("blocked", "aurora.spend_limit")

    asked = {"sku": "X", "quantity": 1, "buyer_email": "buyer@aurora.example"}
    stdout, _, code = run_command_hook(ctl, command, json.dumps(hook_input(asked)), servers=["birch"])
    assert code == 0 and RULE_KEY not in json.loads(stdout)
    call_through_proxy(ctl, {**asked, "buyer_email": "[redacted]"})
    assert (last_status(base)["outcome"], last_status(base)["rule_id"]) == ("redacted", "aurora.pii.email")

    # Through the CLI, as settings.json runs it.
    env = {**os.environ, "NORCASTER_PROXY_URL": base, "NORCASTER_PROXY_TOKEN": TOKEN,
           "PYTHONPATH": os.pathsep.join(str(p) for p in (PKG / "src", PKG.parent / "norcaster-verify" / "src"))}
    done = subprocess.run([sys.executable, "-m", "norcaster_counterparty.cli", "proxy", "hook", "--server", "birch",
                           "--rule-id", "aurora.spend_limit", "--", *command],
                          input=json.dumps(hook_input({"sku": "Y", "quantity": 900})), capture_output=True, text=True, env=env)
    assert done.returncode == 2 and "spend limit" in done.stderr
    assert len([s for s in control(base, "GET", "exchanges").json()["exchanges"] if s["outcome"] == "blocked"]) == 2
    assert birch.ran == [("create_order", {**asked, "buyer_email": "[redacted]"})]


# --- the real Claude Code CLI (Claude Agent SDK) -----------------------------------------------------


def run_claude(tmp_path: Path, serve, ctl: ProxyControl, arguments: dict[str, Any], *, hooks: list[Any] | None = None,
               settings: dict[str, Any] | None = None) -> list[Any]:
    sdk = pytest.importorskip("claude_agent_sdk", reason="needs the claude-agent-sdk extra")
    from norcaster_counterparty.hooks.claude import hook_matcher

    stub = MessagesStub()
    stub.plan = (TOOL, arguments)
    stub_url = serve(lambda: stub.app).removesuffix("/mcp")
    home = tmp_path / f"claude-{len(list(tmp_path.glob('claude-*')))}"
    home.mkdir()
    env = {"ANTHROPIC_BASE_URL": stub_url, "ANTHROPIC_API_KEY": "sk-ant-test-not-a-key", "CLAUDE_CONFIG_DIR": str(home),
           "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "DISABLE_TELEMETRY": "1", "DISABLE_ERROR_REPORTING": "1",
           "DISABLE_AUTOUPDATER": "1", "ENABLE_TOOL_SEARCH": "false",
           "PYTHONPATH": os.pathsep.join(str(p) for p in (PKG / "src", PKG.parent / "norcaster-verify" / "src"))}
    options = sdk.ClaudeAgentOptions(
        env=env, cwd=str(home), model="claude-sonnet-5-5", max_turns=3, allowed_tools=[TOOL],
        mcp_servers=mcp_servers(ctl, ["birch"]),
        hooks={"PreToolUse": [hook_matcher(ctl, *hooks, servers=["birch"])]} if hooks else None,
        settings=json.dumps(settings) if settings else None)

    async def go():
        return [message async for message in sdk.query(prompt="Order the parts from Birch.", options=options)]

    messages = asyncio.run(go())
    assert {r["path"] for r in stub.requests} == {"/v1/messages"}  # the CLI asked the stand-in nothing else
    return messages


def tool_results(messages: list[Any]) -> list[Any]:
    return [b for m in messages for b in (getattr(m, "content", None) or []) if type(b).__name__ == "ToolResultBlock"]


def test_claude_code_allowed_blocked_and_redacted_calls(tmp_path, configs, serve):
    aurora, birch, base, ctl = setup(tmp_path, configs, serve)

    messages = run_claude(tmp_path, serve, ctl, ORDER, hooks=[spend_limit, redact_email])
    allowed = last_status(base)
    assert (allowed["status"], allowed["outcome"]) == ("acknowledged", "allowed") and birch.ran == [("create_order", ORDER)]
    assert "norcaster/shared-record" not in json.dumps([str(b.content) for b in tool_results(messages)])

    messages = run_claude(tmp_path, serve, ctl, {"sku": "BRC-AX-10", "quantity": 500}, hooks=[spend_limit, redact_email])
    blocked = last_status(base)
    [result] = tool_results(messages)
    assert result.is_error and "spend limit" in str(result.content)  # what the model sees for a denied call
    assert (blocked["outcome"], blocked["rule_id"], blocked["partner_content_check"]) == ("blocked", "aurora.spend_limit", "not_delivered")

    asked = {"sku": "BRC-AX-10", "quantity": 2, "buyer_email": "buyer@aurora.example"}
    run_claude(tmp_path, serve, ctl, asked, hooks=[spend_limit, redact_email])
    redacted = last_status(base)
    assert (redacted["status"], redacted["outcome"], redacted["rule_id"]) == ("acknowledged", "redacted", "redact_email")
    assert birch.ran[-1] == ("create_order", {**asked, "buyer_email": "[redacted]"}) and len(birch.ran) == 2

    ids = [allowed["exchange_id"], blocked["exchange_id"], redacted["exchange_id"]]
    report = export_and_verify(aurora_party(aurora), tmp_path, ids, reveal=[ids[0], ids[2]])
    assert report["ok"] is True
    assert [exchange(report, i)[0] for i in ids] == ["acknowledged", "not_delivered", "acknowledged"]
    assert {x["exchange_id"]: x["outcome"] for x in report["exchanges"]} == dict(zip(ids, ["allowed", "blocked", "redacted"]))


def test_claude_code_command_hook_from_settings(tmp_path, configs, serve):
    _, birch, base, ctl = setup(tmp_path, configs, serve)
    policy = tmp_path / "policy.py"
    policy.write_text(POLICY)
    token_file = tmp_path / "token"
    token_file.write_text(TOKEN)
    command = (f"{sys.executable} -m norcaster_counterparty.cli proxy hook --url {base} --token-file {token_file} "
               f"--server birch --rule-id aurora.spend_limit -- {sys.executable} {policy}")
    settings = {"hooks": {"PreToolUse": [{"matcher": "mcp__birch__.*", "hooks": [{"type": "command", "command": command}]}]}}
    messages = run_claude(tmp_path, serve, ctl, {"sku": "BRC-AX-10", "quantity": 500}, settings=settings)
    [result] = tool_results(messages)
    assert result.is_error and birch.ran == []
    status = last_status(base)
    assert (status["outcome"], status["rule_id"], status["partner_content_check"]) == ("blocked", "aurora.spend_limit", "not_delivered")


def test_the_pinned_sdk_still_has_what_the_adapter_uses():
    sdk = pytest.importorskip("claude_agent_sdk", reason="needs the claude-agent-sdk extra")
    version = importlib.metadata.version("claude-agent-sdk")
    low, high = TESTED_SDK_VERSIONS.split(",")
    as_tuple = lambda v: tuple(int(p) for p in v.split(".")[:3])  # noqa: E731
    assert as_tuple(low.lstrip(">=")) <= as_tuple(version) < as_tuple(high.lstrip("<")), (
        f"claude-agent-sdk {version} is outside the tested range {TESTED_SDK_VERSIONS}")
    from claude_agent_sdk.types import PreToolUseHookSpecificOutput

    assert {"permissionDecision", "permissionDecisionReason", "updatedInput", "additionalContext"} <= set(
        PreToolUseHookSpecificOutput.__annotations__)
    assert {"matcher", "hooks", "timeout"} <= {f for f in sdk.HookMatcher.__dataclass_fields__}
    assert {"behavior", "updated_input"} <= set(sdk.PermissionResultAllow.__dataclass_fields__)
    assert {"behavior", "message"} <= set(sdk.PermissionResultDeny.__dataclass_fields__)
    assert "tool_use_id" in sdk.ToolPermissionContext.__dataclass_fields__


# --- approvals: a person (or Claude Code itself) decides on the permission request ------------------


DECIDE = """
import json, os, sys
data = json.load(sys.stdin)
args = data["tool_input"]
if args.get("quantity", 0) > 100:
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PermissionRequest",
                      "decision": {"behavior": "deny", "message": "A person said no."}}}))
else:
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PermissionRequest", "decision": {"behavior": "allow"}}}))
"""


def permission_input(event: str, arguments: dict[str, Any]) -> str:
    return json.dumps({"hook_event_name": event, "tool_name": TOOL, "tool_input": arguments, "tool_use_id": "toolu_p",
                       "permission_mode": "default"})


def test_permission_events_from_command_hooks(tmp_path, configs, serve):
    aurora, birch, base, ctl = setup(tmp_path, configs, serve)
    decide = tmp_path / "decide.py"
    decide.write_text(DECIDE)

    # Claude Code denied the call itself (auto mode): reported with no command.
    stdout, _, code = run_command_hook(ctl, [], permission_input("PermissionDenied", {"sku": "X", "quantity": 1}), servers=["birch"])
    assert (stdout, code) == ("", 0)
    assert (last_status(base)["outcome"], last_status(base)["rule_id"]) == ("blocked", "claude.permission_denied")

    # Your command answers the permission request: deny, then allow.
    _, _, code = run_command_hook(ctl, [sys.executable, str(decide)], permission_input("PermissionRequest", {"sku": "X", "quantity": 500}),
                                  servers=["birch"])
    assert code == 0 and (last_status(base)["outcome"], last_status(base)["rule_id"]) == ("blocked", "human_rejected")
    run_command_hook(ctl, [sys.executable, str(decide)], permission_input("PermissionRequest", ORDER), servers=["birch"])
    call_through_proxy(ctl, ORDER)
    approved = last_status(base)
    assert (approved["status"], approved["outcome"], approved["rule_id"]) == ("acknowledged", "allowed", "human_approval")
    assert birch.ran == [("create_order", ORDER)] and [t for t, _ in birch.inbound].count(NOTICE_TOOL) == 2

    ids = [s["exchange_id"] for s in control(base, "GET", "exchanges").json()["exchanges"]]
    report = export_and_verify(aurora_party(aurora), tmp_path, ids, reveal=[ids[2]])
    assert report["ok"] is True and [exchange(report, i)[0] for i in ids] == ["not_delivered", "not_delivered", "acknowledged"]


def test_an_approval_yields_to_a_redaction_of_the_same_call(tmp_path, configs, serve):
    _, birch, base, ctl = setup(tmp_path, configs, serve)
    sent = {"sku": "BRC-AX-10", "quantity": 2, "buyer_email": "[redacted]"}
    asyncio.run(ctl.decision("birch", "create_order", sent, "redact_email"))  # PreToolUse redacted it first
    answer = asyncio.run(ctl.decision("birch", "create_order", sent, "human_approval", outcome="allowed"))
    assert answer["registered"] is False  # the receipt must show that the content was changed
    call_through_proxy(ctl, sent)
    assert (last_status(base)["outcome"], last_status(base)["rule_id"]) == ("redacted", "redact_email")


def test_the_agent_sdk_can_use_tool_with_the_real_cli(tmp_path, configs, serve):
    sdk = pytest.importorskip("claude_agent_sdk", reason="needs the claude-agent-sdk extra")
    from norcaster_counterparty.hooks.claude import can_use_tool

    aurora, birch, base, ctl = setup(tmp_path, configs, serve)

    async def a_person(tool_name, tool_input, context):  # noqa: ANN001
        if tool_input.get("quantity", 0) > 100:
            return sdk.PermissionResultDeny(message="Rejected by a person.")
        if "buyer_email" in tool_input:
            return sdk.PermissionResultAllow(updated_input={**tool_input, "buyer_email": "[redacted]"})
        return sdk.PermissionResultAllow()

    def run(arguments: dict[str, Any], **options: Any) -> list[Any]:
        stub = MessagesStub()
        stub.plan = (TOOL, arguments)
        stub_url = serve(lambda: stub.app).removesuffix("/mcp")
        home = tmp_path / f"claude-{len(list(tmp_path.glob('claude-*')))}"
        home.mkdir()
        env = {"ANTHROPIC_BASE_URL": stub_url, "ANTHROPIC_API_KEY": "sk-ant-test-not-a-key", "CLAUDE_CONFIG_DIR": str(home),
               "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "DISABLE_TELEMETRY": "1", "DISABLE_ERROR_REPORTING": "1",
               "DISABLE_AUTOUPDATER": "1", "ENABLE_TOOL_SEARCH": "false",
               "PYTHONPATH": os.pathsep.join(str(p) for p in (PKG / "src", PKG.parent / "norcaster-verify" / "src"))}
        opts = sdk.ClaudeAgentOptions(env=env, cwd=str(home), model="claude-sonnet-5-5", max_turns=3,
                                      mcp_servers=mcp_servers(ctl, ["birch"]), **options)

        async def prompt():
            yield {"type": "user", "message": {"role": "user", "content": "Order the parts from Birch."}}

        async def go():
            return [m async for m in sdk.query(prompt=prompt(), options=opts)]

        return asyncio.run(go())

    asking = {"permission_mode": "default", "can_use_tool": can_use_tool(ctl, a_person, servers=["birch"])}
    run(ORDER, **asking)
    approved = last_status(base)
    messages = run({"sku": "BRC-AX-10", "quantity": 500}, **asking)
    rejected = last_status(base)
    asked = {"sku": "BRC-AX-10", "quantity": 2, "buyer_email": "buyer@aurora.example"}
    run(asked, **asking)
    edited = last_status(base)
    assert (approved["status"], approved["outcome"], approved["rule_id"]) == ("acknowledged", "allowed", "human_approval")
    assert (rejected["outcome"], rejected["rule_id"], rejected["partner_content_check"]) == ("blocked", "human_rejected", "not_delivered")
    assert "Rejected by a person." in str([b.content for b in tool_results(messages)])
    assert (edited["outcome"], edited["rule_id"]) == ("redacted", "human_approval")
    assert birch.ran == [("create_order", ORDER), ("create_order", {**asked, "buyer_email": "[redacted]"})]

    # Auto mode: Claude Code denies a call it cannot evaluate, and the PermissionDenied hook reports it.
    token_file = tmp_path / "token"
    token_file.write_text(TOKEN)
    hook = (f"{sys.executable} -m norcaster_counterparty.cli proxy hook --url {base} --token-file {token_file} --server birch")
    # permission_mode="auto": from claude-agent-sdk 0.2.169 the bundled CLI fires PermissionDenied for an auto-mode
    # denial but no longer for a call left unapproved in default mode (0.2.168 fired it for both).
    run({"sku": "BRC-AX-10", "quantity": 3}, permission_mode="auto",
        settings=json.dumps({"hooks": {"PermissionDenied": [{"matcher": "mcp__birch__.*", "hooks": [{"type": "command", "command": hook}]}]}}))
    denied = last_status(base)
    assert (denied["outcome"], denied["rule_id"], denied["partner_content_check"]) == ("blocked", "claude.permission_denied", "not_delivered")
    assert len(birch.ran) == 2

    ids = [approved["exchange_id"], rejected["exchange_id"], edited["exchange_id"], denied["exchange_id"]]
    report = export_and_verify(aurora_party(aurora), tmp_path, ids, reveal=[ids[0], ids[2]])
    assert report["ok"] is True
    assert {x["exchange_id"]: x["outcome"] for x in report["exchanges"]} == dict(zip(ids, ["allowed", "blocked", "redacted", "blocked"]))
