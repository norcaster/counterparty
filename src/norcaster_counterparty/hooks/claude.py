"""Claude Agent SDK and Claude Code: your ``PreToolUse`` decisions on a partner's MCP tools, reported
to the local MCP proxy.

The Claude Agent SDK cannot set an MCP request's ``_meta`` (its MCP client is inside the bundled
Claude Code CLI), so the agent reaches the partner through the proxy, and this module wraps your
``PreToolUse`` hooks for the proxied servers:

* a hook that **denies** the call (``permissionDecision: "deny"``, ``decision: "block"`` or
  ``continue: false``, or exit code 2 for a command hook): the call is never sent; the proxy
  registers a ``blocked`` receipt and sends the partner a notice;
* a hook that **changes the arguments** (``updatedInput``): the proxy receipts the call as
  ``redacted`` when the changed arguments arrive. If the proxy cannot take that decision, the
  call is denied instead, so no receipt misstates your boundary;
* otherwise nothing is reported, and the proxy receipts the call as ``allowed``.

Approvals (as the Norcaster hub records them): wrap the Agent SDK's ``can_use_tool`` with
``can_use_tool(control, yours, servers=...)``. A person's deny becomes a ``blocked`` receipt with rule
``human_rejected`` and a notice; an allow becomes ``allowed`` with rule ``human_approval``. For
Claude Code, ``proxy hook`` also reports a ``PermissionRequest`` hook's decision, and Claude Code's own
denials (``PermissionDenied``, rule ``claude.permission_denied``).

The rule id is the hook's ``norcaster_rule_id`` output field when it sets one (removed before
Claude sees the output), otherwise the hook's function name (``--rule-id`` for a command hook).
Your hooks run in order; each sees the arguments the previous one returned, and the first deny
ends the chain. What Claude receives is the merged output: the strongest decision (deny, defer,
ask, allow), the final arguments, and every ``additionalContext``.

Python, with the Agent SDK::

    control = ProxyControl("http://127.0.0.1:8790", token_file="state/proxy-token")
    options = ClaudeAgentOptions(
        mcp_servers=mcp_servers(control, ["birch"]),
        hooks={"PreToolUse": [hook_matcher(control, spend_limit, redact_pii, servers=["birch"])]},
    )

Claude Code (a command hook in ``settings.json``) wraps your own command::

    norcaster-counterparty proxy hook --server birch -- python my_policy.py
"""

from __future__ import annotations

import collections
import inspect
import json
import logging
import re
import subprocess
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import HUMAN_APPROVAL, HUMAN_REJECTED, REDACTION_UNRECORDED, RULE_KEY, ProxyControl

TESTED_SDK_VERSIONS = ">=0.2.168,<0.3"
_STRENGTH = {"allow": 1, "ask": 2, "defer": 3, "deny": 4}

log = logging.getLogger("norcaster_counterparty.hooks.claude")


def _normalise(name: str) -> str:
    """How Claude names an MCP server or tool inside ``mcp__<server>__<tool>``."""
    return re.sub(r"[^a-zA-Z0-9_-]", "_", name)


def _servers(servers: Mapping[str, str] | Iterable[str]) -> dict[str, str]:
    """Claude's MCP server key -> the proxy's upstream name (the same name when given a list)."""
    pairs = dict(servers) if isinstance(servers, Mapping) else {name: name for name in servers}
    if not pairs:
        raise ValueError("name at least one proxied MCP server")
    return {_normalise(key): upstream for key, upstream in pairs.items()}


class _ToolNames:
    """``mcp__<server>__<tool>`` -> (upstream, the partner's tool name). The partner's names are
    fetched from the proxy, because Claude replaces characters outside ``[a-zA-Z0-9_-]``."""

    def __init__(self, control: ProxyControl, servers: dict[str, str]) -> None:
        self._control = control
        self._servers = servers
        self._known: dict[str, dict[str, str]] = {}

    def split(self, tool_name: str) -> tuple[str, str] | None:
        for key in sorted(self._servers, key=len, reverse=True):
            prefix = f"mcp__{key}__"
            if tool_name.startswith(prefix) and len(tool_name) > len(prefix):
                return self._servers[key], tool_name[len(prefix):]
        return None

    def _lookup(self, upstream: str, shown: str, fetch: Callable[[str], list[str]]) -> str:
        for attempt in (0, 1):
            if attempt or upstream not in self._known:
                try:
                    self._known[upstream] = {_normalise(name): name for name in fetch(upstream)}
                except Exception as exc:  # noqa: BLE001 - fall back to the name Claude shows
                    log.warning("could not list %s's tools from the proxy: %s", upstream, exc)
                    return shown
            if shown in self._known[upstream]:
                return self._known[upstream][shown]
        return shown

    async def resolve(self, tool_name: str) -> tuple[str, str] | None:
        found = self.split(tool_name)
        if found is None:
            return None
        upstream, shown = found
        if upstream not in self._known or shown not in self._known[upstream]:
            try:
                self._known[upstream] = {_normalise(n): n for n in await self._control.tool_names(upstream)}
            except Exception as exc:  # noqa: BLE001 - fall back to the name Claude shows
                log.warning("could not list %s's tools from the proxy: %s", upstream, exc)
        return upstream, self._known.get(upstream, {}).get(shown, shown)

    def resolve_sync(self, tool_name: str) -> tuple[str, str] | None:
        found = self.split(tool_name)
        if found is None:
            return None
        upstream, shown = found
        return upstream, self._lookup(upstream, shown, self._control.tool_names_sync)


@dataclass
class Verdict:
    """What a chain of ``PreToolUse`` outputs decided, and the output to give Claude."""

    output: dict[str, Any]
    blocked_by: str | None
    arguments: dict[str, Any]
    redacted_by: str | None


def _blocks(output: Mapping[str, Any]) -> bool:
    specific = output.get("hookSpecificOutput") or {}
    return specific.get("permissionDecision") == "deny" or output.get("decision") == "block" or output.get("continue") is False


def _verdict(results: list[tuple[str, dict[str, Any]]], original: dict[str, Any]) -> Verdict:
    """Merge hook outputs given in order; ``results`` holds (rule id, output without RULE_KEY)."""
    current, redacted_by, best, best_strength, notes = dict(original), None, None, 0, []
    for rule_id, output in results:
        if _blocks(output):
            return Verdict(output, rule_id, current, None)
        specific = output.get("hookSpecificOutput") or {}
        updated = specific.get("updatedInput")
        if isinstance(updated, dict) and updated != current:
            current, redacted_by = dict(updated), rule_id
        strength = _STRENGTH.get(str(specific.get("permissionDecision")), 0)
        if best is None or strength > best_strength:
            best, best_strength = output, strength
        if specific.get("additionalContext"):
            notes.append(str(specific["additionalContext"]))
    merged = dict(best or {})
    specific = dict(merged.get("hookSpecificOutput") or {})
    if current != original:
        specific["updatedInput"] = current
        if "permissionDecision" not in specific:
            specific["permissionDecision"] = "allow"  # Claude applies updatedInput with an allow
    if notes:
        specific["additionalContext"] = "\n".join(notes)
    if specific:
        merged["hookSpecificOutput"] = {"hookEventName": "PreToolUse", **specific}
    return Verdict(merged, None, current, redacted_by if current != original else None)


def _deny(reason: str) -> dict[str, Any]:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                   "permissionDecisionReason": reason}}


def _rule_of(hook: Any) -> str:
    return str(getattr(hook, "__name__", None) or type(hook).__name__)


async def _maybe(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


def pre_tool_use(control: ProxyControl, *hooks: Callable[..., Any],
                 servers: Mapping[str, str] | Iterable[str]) -> Callable[..., Any]:
    """One ``PreToolUse`` hook for the Claude Agent SDK that runs ``hooks`` and reports to the proxy."""
    names = _ToolNames(control, _servers(servers))
    noticed: collections.deque[str] = collections.deque(maxlen=1000)

    async def hook(input_data: dict[str, Any], tool_use_id: str | None, context: Any) -> dict[str, Any]:
        original = dict(input_data.get("tool_input") or {})
        current, results = dict(original), []
        for each in hooks:
            output = dict(await _maybe(each({**input_data, "tool_input": current}, tool_use_id, context)) or {})
            rule_id = str(output.pop(RULE_KEY, None) or _rule_of(each))
            results.append((rule_id, output))
            if _blocks(output):
                break
            updated = (output.get("hookSpecificOutput") or {}).get("updatedInput")
            if isinstance(updated, dict):
                current = dict(updated)
        verdict = _verdict(results, original)
        target = await names.resolve(str(input_data.get("tool_name") or ""))
        if target is None or input_data.get("hook_event_name", "PreToolUse") != "PreToolUse":
            return verdict.output
        upstream, tool = target
        if verdict.blocked_by is not None:
            key = tool_use_id or json.dumps([tool, verdict.arguments], sort_keys=True)
            if key not in noticed:
                noticed.append(key)
                try:
                    await control.notice(upstream, tool, verdict.arguments, verdict.blocked_by)
                except Exception as exc:  # noqa: BLE001 - the block stands whatever happens to the notice
                    log.warning("the notice for %s could not be sent: %s", tool, exc)
        elif verdict.redacted_by is not None:
            try:
                await control.decision(upstream, tool, verdict.arguments, verdict.redacted_by)
            except Exception as exc:  # noqa: BLE001 - fail closed: deny rather than misstate the decision
                log.warning("the redaction of %s could not be recorded: %s", tool, exc)
                return _deny(REDACTION_UNRECORDED)
        return verdict.output

    return hook


def hook_matcher(control: ProxyControl, *hooks: Callable[..., Any], servers: Mapping[str, str] | Iterable[str],
                 timeout: float | None = None) -> Any:
    """A ``HookMatcher`` for the proxied servers' tools, running ``pre_tool_use(control, *hooks)``."""
    from claude_agent_sdk import HookMatcher

    keys = sorted(_servers(servers), key=len, reverse=True)
    matcher = "^mcp__(" + "|".join(re.escape(k) for k in keys) + ")__.+"
    return HookMatcher(matcher=matcher, hooks=[pre_tool_use(control, *hooks, servers=servers)], timeout=timeout)


def mcp_servers(control: ProxyControl, servers: Mapping[str, str] | Iterable[str]) -> dict[str, dict[str, Any]]:
    """``ClaudeAgentOptions.mcp_servers`` entries that reach each partner through the proxy."""
    return {key: {"type": "http", "url": control.mcp_url(upstream), "headers": control.headers}
            for key, upstream in (dict(servers) if isinstance(servers, Mapping) else {s: s for s in servers}).items()}


# --- Claude Code command hooks ------------------------------------------------------------------


PERMISSION_DENIED = "claude.permission_denied"
"""The rule id of a call Claude Code itself denied (``PermissionDenied``: an automatic decision, such
as auto mode's), not a person."""


def _notice_sync(control: Any, upstream: str, tool: str, arguments: dict[str, Any], rule: str) -> None:
    try:
        control.notice_sync(upstream, tool, arguments, rule)
    except Exception as exc:  # noqa: BLE001 - the block stands whatever happens to the notice
        log.warning("the notice for %s could not be sent: %s", tool, exc)


def run_command_hook(control: ProxyControl, command: list[str], stdin_text: str, *,
                     servers: Mapping[str, str] | Iterable[str], rule_id: str | None = None,
                     timeout: float = 60.0) -> tuple[str, str, int]:
    """Run your command hook (if any) on the hook input, report its decision, and return its
    (stdout, stderr, exit code) for Claude Code, with ``norcaster_rule_id`` removed.

    * ``PreToolUse``: a deny (or exit code 2) sends a notice; an ``updatedInput`` registers a
      redaction (refused, and the call denied, if the proxy cannot take it).
    * ``PermissionRequest`` (your command answers Claude Code's permission request): a ``deny``
      sends a notice (rule ``human_rejected`` unless ``--rule-id``); an ``allow`` registers an
      approval (rule ``human_approval``), or a redaction when it changes the input.
    * ``PermissionDenied`` (Claude Code denied the call itself, e.g. in auto mode): a notice with rule
      ``claude.permission_denied``. No command is needed.
    """
    names = _ToolNames(control, _servers(servers))
    try:
        input_data = json.loads(stdin_text or "{}")
    except ValueError:
        input_data = {}
    if command:
        done = subprocess.run(command, input=stdin_text, capture_output=True, text=True, timeout=timeout, check=False)
        stdout, stderr, code = done.stdout, done.stderr, done.returncode
    else:
        stdout, stderr, code = "", "", 0
    event = input_data.get("hook_event_name")
    target = (names.resolve_sync(str(input_data.get("tool_name") or ""))
              if event in ("PreToolUse", "PermissionRequest", "PermissionDenied") else None)
    output: dict[str, Any] = {}
    if code == 0 and stdout.strip().startswith("{"):
        try:
            output = json.loads(stdout)
        except ValueError:
            output = {}
    if isinstance(output, dict) and RULE_KEY in output:
        rule_id = str(output.pop(RULE_KEY))
        stdout = json.dumps(output)
    if target is None:
        return stdout, stderr, code
    upstream, tool = target
    arguments = dict(input_data.get("tool_input") or {})
    named = rule_id or (Path(command[0]).name if command else None)

    if event == "PermissionDenied":
        _notice_sync(control, upstream, tool, arguments, rule_id or PERMISSION_DENIED)
        return stdout, stderr, code

    if event == "PermissionRequest":
        decision = ((output.get("hookSpecificOutput") or {}).get("decision") or {}) if isinstance(output, dict) else {}
        if code == 2 or decision.get("behavior") == "deny":
            _notice_sync(control, upstream, tool, arguments, rule_id or HUMAN_REJECTED)
        elif decision.get("behavior") == "allow":
            updated = decision.get("updatedInput")
            sent = dict(updated) if isinstance(updated, dict) else arguments
            outcome = "redacted" if sent != arguments else "allowed"
            try:
                control.decision_sync(upstream, tool, sent, rule_id or HUMAN_APPROVAL, outcome=outcome)
            except Exception as exc:  # noqa: BLE001 - fail closed for a redaction; an approval only loses its rule
                log.warning("the decision on %s could not be recorded: %s", tool, exc)
                if outcome == "redacted":
                    denied = {"hookSpecificOutput": {"hookEventName": "PermissionRequest",
                                                     "decision": {"behavior": "deny", "message": REDACTION_UNRECORDED}}}
                    return json.dumps(denied), stderr, 0
        return stdout, stderr, code

    if not command:
        return stdout, stderr, code
    if code == 2 or (isinstance(output, dict) and _blocks(output)):
        _notice_sync(control, upstream, tool, arguments, named or "pre_tool_use")
        return stdout, stderr, code
    updated = ((output.get("hookSpecificOutput") or {}).get("updatedInput") if isinstance(output, dict) else None)
    if code == 0 and isinstance(updated, dict) and updated != arguments:
        try:
            control.decision_sync(upstream, tool, updated, named or "pre_tool_use")
        except Exception as exc:  # noqa: BLE001 - fail closed: deny rather than misstate the decision
            log.warning("the redaction of %s could not be recorded: %s", tool, exc)
            return json.dumps(_deny(REDACTION_UNRECORDED)), stderr, 0
    return stdout, stderr, code


def can_use_tool(control: ProxyControl, yours: Callable[..., Any], *,
                 servers: Mapping[str, str] | Iterable[str]) -> Callable[..., Any]:
    """Wrap the Agent SDK's ``can_use_tool`` (where your app asks a person) for the proxied servers:
    a deny sends the partner a notice (rule ``human_rejected``); an allow registers an approval
    (rule ``human_approval``), or a redaction when the person changed the input. A redaction the
    proxy cannot take turns the allow into a deny."""
    names = _ToolNames(control, _servers(servers))
    noticed: collections.deque[str] = collections.deque(maxlen=1000)

    async def callback(tool_name: str, tool_input: dict[str, Any], context: Any) -> Any:
        result = await _maybe(yours(tool_name, tool_input, context))
        target = await names.resolve(tool_name)
        if target is None:
            return result
        upstream, tool = target
        behavior = getattr(result, "behavior", None)
        if behavior == "deny":
            key = getattr(context, "tool_use_id", None) or json.dumps([tool, tool_input], sort_keys=True)
            if key not in noticed:
                noticed.append(key)
                try:
                    await control.notice(upstream, tool, dict(tool_input), HUMAN_REJECTED)
                except Exception as exc:  # noqa: BLE001 - the rejection stands whatever happens to the notice
                    log.warning("the notice for %s could not be sent: %s", tool, exc)
        elif behavior == "allow":
            updated = getattr(result, "updated_input", None)
            sent = dict(updated) if isinstance(updated, dict) else dict(tool_input)
            outcome = "redacted" if sent != dict(tool_input) else "allowed"
            try:
                await control.decision(upstream, tool, sent, HUMAN_APPROVAL, outcome=outcome)
            except Exception as exc:  # noqa: BLE001 - fail closed for a redaction; an approval only loses its rule
                log.warning("the decision on %s could not be recorded: %s", tool, exc)
                if outcome == "redacted":
                    from claude_agent_sdk import PermissionResultDeny

                    return PermissionResultDeny(message=REDACTION_UNRECORDED)
        return result

    return callback


__all__ = ["PERMISSION_DENIED", "REDACTION_UNRECORDED", "RULE_KEY", "TESTED_SDK_VERSIONS", "Verdict", "can_use_tool", "hook_matcher",
           "mcp_servers", "pre_tool_use", "run_command_hook"]
