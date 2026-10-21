"""The agent-SDK and MCP bindings are optional extras: the base package keeps one dependency."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]


def test_the_base_package_imports_neither_the_agents_sdk_nor_mcp():
    code = ("import sys, norcaster_counterparty, norcaster_counterparty.cli, norcaster_counterparty.sandbox, "
            "norcaster_counterparty.proxy, norcaster_counterparty.hooks, norcaster_counterparty.hooks.claude, norcaster_counterparty.hooks.google_adk, norcaster_counterparty.hooks.langgraph; "
            "print(sorted({m.split('.')[0] for m in sys.modules} & {'agents', 'mcp', 'mcp_types', 'openai', 'claude_agent_sdk', 'google', 'langchain_mcp_adapters', 'langgraph'}))")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True, env=dict(os.environ))
    assert out.stdout.strip() == "[]"


def test_one_base_dependency_and_pinned_extras():
    text = (PKG / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(r'^dependencies = \["norcaster-verify\[signatures\]>=[^"]+"\]$', text, re.MULTILINE)
    extras = dict(re.findall(r'^(mcp|openai-agents|claude-agent-sdk|google-adk|langgraph) = \[(.*)\]$', text, re.MULTILINE))
    assert set(extras) == {"mcp", "openai-agents", "claude-agent-sdk", "google-adk", "langgraph"}
    assert '"langchain-mcp-adapters>=0.3.2,<0.4"' in extras["langgraph"]
    assert '"google-adk[mcp]>=2.12.0,<2.13; python_version >= \'3.11\'"' in extras["google-adk"]
    assert '"claude-agent-sdk>=0.2.168,<0.3"' in extras["claude-agent-sdk"]
    assert '"openai-agents>=0.24.0,<0.25"' in extras["openai-agents"]  # the SDK versions the tests ran against
    assert all("<" in spec for spec in re.findall(r'"([^"]+)"', ", ".join(extras.values())))  # every extra has an upper bound
