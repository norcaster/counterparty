"""The local MCP proxy, over real HTTP on 127.0.0.1: a plain MCP client (no agent SDK) calls Birch's
MCP server through Aurora's proxy, with the quickstart sandbox as the log. Two fictional companies,
synthetic data. Every case ends in evidence verified offline in Python and Node."""

# ruff: noqa: F811  (pytest fixtures imported from two_companies are used as parameters)
from __future__ import annotations

import asyncio
import json
import os
import socket
from typing import Any

import httpx
import pytest

pytest.importorskip("mcp", reason="needs the mcp extra")

from two_companies import (  # noqa: E402
    AURORA,
    AURORA_AGENT,
    AUTH,
    BIRCH,
    BIRCH_AGENT,
    ORDER,
    Birch,
    TamperInTransit,
    _lowlevel_app,
    aurora_party,
    birch_party,
    control,
    detail,
    exchange,
    export_and_verify,
    last_status,
    start_proxy,
)
from two_companies import configs, log_url, serve  # noqa: E402,F401  (pytest fixtures, used by parameter name)

from norcaster_counterparty import META_KEY, Counterparty, HttpLogClient  # noqa: E402
from norcaster_counterparty.mcp_server import NOTICE_TOOL  # noqa: E402
from norcaster_counterparty.proxy import STATUS_KEY, ProxyConfig, open_session  # noqa: E402


def call(base: str, tool: str, arguments: dict[str, Any], *, upstream: str = "birch") -> Any:
    async def go():
        async with open_session(f"{base}/mcp/{upstream}", AUTH) as session:
            return await session.call_tool(tool, arguments)

    return asyncio.run(go())


def tools(base: str) -> list[Any]:
    async def go():
        async with open_session(f"{base}/mcp/birch", AUTH) as session:
            return (await session.list_tools()).tools

    return asyncio.run(go())


def is_error(result: Any) -> bool:
    return bool(getattr(result, "is_error", None) or getattr(result, "isError", None))


# --- the cases --------------------------------------------------------------------------------------


def test_allowed_call_is_acknowledged_and_the_agent_never_sees_the_record(tmp_path, configs, serve):
    aurora, birch_config = configs
    birch = Birch()
    decoy = {META_KEY: {"receipt": {"exchange_id": "decoy"}}, "other.vendor/flag": True}
    base = start_proxy(serve, tmp_path, aurora, serve(lambda: _lowlevel_app(birch, birch_party(birch_config), static_meta=decoy)))

    listed = tools(base)
    assert [t.name for t in listed] == ["create_order"]  # the notice tool is the proxy's, not the agent's
    assert META_KEY not in (listed[0].meta or {}) and listed[0].meta == {"other.vendor/flag": True}

    result = call(base, "create_order", ORDER)
    assert not is_error(result) and "BRC-0001" in result.content[0].text
    assert META_KEY not in (result.meta or {}) and STATUS_KEY not in (result.meta or {})
    status = last_status(base)
    assert (status["status"], status["outcome"], status["partner_content_check"]) == ("acknowledged", "allowed", "matched")
    assert birch.ran == [("create_order", ORDER)]
    logged = [json.loads(line) for line in (tmp_path / "proxy-exchanges.jsonl").read_text().splitlines()]
    assert logged[-1]["exchange_id"] == status["exchange_id"] and "content_b64" not in json.dumps(logged)

    report = export_and_verify(aurora_party(aurora), tmp_path, [status["exchange_id"]], reveal=[status["exchange_id"]])
    state, checks = exchange(report, status["exchange_id"])
    assert report["ok"] is True and state == "acknowledged" and checks["content_commitment"] == "pass"


def test_a_blocked_call_becomes_a_notice_and_nothing_is_delivered(tmp_path, configs, serve):
    aurora, birch_config = configs
    birch = Birch()
    base = start_proxy(serve, tmp_path, aurora, serve(lambda: _lowlevel_app(birch, birch_party(birch_config))))

    answer = control(base, "POST", "notices", json={"upstream": "birch", "tool_name": "create_order",
                                                    "arguments": {"sku": "BRC-AX-10", "quantity": 500},
                                                    "rule_id": "aurora.spend_limit"})
    assert answer.status_code == 200, answer.text
    status = answer.json()
    assert (status["status"], status["delivered"], status["outcome"], status["rule_id"]) == (
        "acknowledged", False, "blocked", "aurora.spend_limit")
    assert birch.ran == []
    [(tool, inbound)] = birch.inbound
    assert tool == NOTICE_TOOL and inbound.content_check == "not_delivered"

    report = export_and_verify(aurora_party(aurora), tmp_path, [status["exchange_id"]], reveal=[])
    state, checks = exchange(report, status["exchange_id"])
    assert report["ok"] is True and state == "not_delivered" and all(v != "fail" for v in checks.values())


def test_a_reported_redaction_marks_the_receipt_once(tmp_path, configs, serve):
    aurora, birch_config = configs
    birch = Birch()
    base = start_proxy(serve, tmp_path, aurora, serve(lambda: _lowlevel_app(birch, birch_party(birch_config))))
    redacted = {"sku": "BRC-AX-10", "quantity": 2, "buyer_email": "[redacted]"}

    registered = control(base, "POST", "decisions", json={"upstream": "birch", "tool_name": "create_order",
                                                          "arguments": redacted, "rule_id": "aurora.pii.email"}).json()
    assert registered["registered"] is True and registered["outcome"] == "redacted"
    call(base, "create_order", redacted)
    first = last_status(base)
    call(base, "create_order", redacted)  # the decision was used: the same call again is allowed
    second = last_status(base)
    assert (first["outcome"], first["rule_id"], first["status"]) == ("redacted", "aurora.pii.email", "acknowledged")
    assert (second["outcome"], second["rule_id"]) == ("allowed", None)
    assert birch.ran == [("create_order", redacted)] * 2

    report = export_and_verify(aurora_party(aurora), tmp_path, [first["exchange_id"]], reveal=[first["exchange_id"]])
    [x] = report["exchanges"]
    assert report["ok"] is True and x["outcome"] == "redacted" and exchange(report, first["exchange_id"])[1]["content_commitment"] == "pass"


def test_content_changed_after_the_proxy_is_a_mismatch(tmp_path, configs, serve):
    aurora, birch_config = configs
    birch = Birch()
    base = start_proxy(serve, tmp_path, aurora, serve(lambda: TamperInTransit(_lowlevel_app(birch, birch_party(birch_config)))))

    result = call(base, "create_order", ORDER)
    status = last_status(base)
    assert is_error(result) and birch.ran == []  # Birch refuses what does not match the commitment
    assert (status["status"], status["partner_outcome"], status["partner_rule_id"]) == ("mismatch", "blocked", "content_mismatch")

    report = export_and_verify(aurora_party(aurora), tmp_path, [status["exchange_id"]], reveal=[status["exchange_id"]])
    state, checks = exchange(report, status["exchange_id"])
    assert state == "acknowledged_mismatch" and "content check: mismatch" in detail(report, status["exchange_id"], "acknowledgement")
    assert checks["content_commitment"] == "pass"


def test_no_acknowledgement_is_recorded_after_the_deadline(tmp_path, configs, serve):
    aurora, _ = configs
    birch = Birch()
    base = start_proxy(serve, tmp_path, aurora, serve(lambda: _lowlevel_app(birch, None)))  # Birch without Shared Record

    result = call(base, "create_order", ORDER)
    status = last_status(base)
    assert not is_error(result) and status["status"] == "missing" and birch.ran

    later = aurora_party(aurora, later=True)

    async def record():
        try:
            return await later.record_missing_acknowledgements()
        finally:
            await later.log.aclose()

    assert asyncio.run(record()) == 1
    report = export_and_verify(aurora_party(aurora), tmp_path, [status["exchange_id"]], reveal=[status["exchange_id"]])
    state, checks = exchange(report, status["exchange_id"])
    assert state == "unacknowledged" and checks["missing_acknowledgement"] == "pass"


def test_concurrent_calls_take_distinct_sequence_numbers(tmp_path, configs, serve):
    aurora, birch_config = configs
    birch = Birch()
    base = start_proxy(serve, tmp_path, aurora, serve(lambda: _lowlevel_app(birch, birch_party(birch_config))))

    async def one(i: int) -> Any:
        async with open_session(f"{base}/mcp/birch", AUTH) as session:
            return await session.call_tool("create_order", {"sku": f"BRC-{i}", "quantity": 1})

    async def many():
        return await asyncio.gather(*(one(i) for i in range(5)))

    results = asyncio.run(many())
    assert not any(is_error(r) for r in results)
    statuses = control(base, "GET", "exchanges").json()["exchanges"]
    assert [s["status"] for s in statuses] == ["acknowledged"] * 5 and len({s["exchange_id"] for s in statuses}) == 5
    assert len(birch.ran) == 5  # Birch refuses a reused sequence number, so none was reused


def test_status_in_the_result_when_asked(tmp_path, configs, serve):
    aurora, birch_config = configs
    base = start_proxy(serve, tmp_path, aurora, serve(lambda: _lowlevel_app(Birch(), birch_party(birch_config))),
                       include_status=True)
    result = call(base, "create_order", ORDER)
    assert result.meta[STATUS_KEY]["status"] == "acknowledged" and META_KEY not in result.meta


def test_fails_closed_when_the_partner_is_not_pinned_or_not_reachable(tmp_path, configs, serve):
    aurora, birch_config = configs
    birch = Birch()
    birch_url = serve(lambda: _lowlevel_app(birch, birch_party(birch_config)))
    del aurora.pins[BIRCH]
    base = start_proxy(serve, tmp_path, aurora, birch_url)
    result = call(base, "create_order", ORDER)
    status = last_status(base)
    assert is_error(result) and "nothing was sent" in result.content[0].text
    assert (status["status"], status["exchange_id"]) == ("refused", None) and birch.inbound == []

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        closed = s.getsockname()[1]
    aurora.pins[BIRCH] = Counterparty(birch_config, HttpLogClient(aurora.log_url)).root_fingerprint
    base = start_proxy(serve, tmp_path / "second", aurora, f"http://127.0.0.1:{closed}/mcp")
    result = call(base, "create_order", ORDER)
    assert is_error(result) and "did not answer" in result.content[0].text
    # MCP SDK 2.x: the receipt is registered and reported missing (a missing-acknowledgement record
    # follows after the deadline). 1.x lists tools before the call, which fails first: nothing is signed.
    statuses = control(base, "GET", "exchanges").json()["exchanges"]
    assert all(s["status"] == "missing" and "did not answer" in s["detail"] for s in statuses)


def test_token_and_control_channel_checks(tmp_path, configs, serve):
    aurora, birch_config = configs
    base = start_proxy(serve, tmp_path, aurora, serve(lambda: _lowlevel_app(Birch(), birch_party(birch_config))))
    for path in ("/mcp/birch", "/control/v1/health"):
        assert httpx.get(f"{base}{path}").status_code == 401
        assert httpx.get(f"{base}{path}", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert control(base, "GET", "health").json() == {"ok": True, "org_id": AURORA, "upstreams": ["birch"], "sessions": 0}
    bad = {"upstream": "nobody", "tool_name": "create_order", "arguments": {}}
    assert control(base, "POST", "decisions", json=bad).status_code == 404
    assert control(base, "POST", "decisions", json={**bad, "upstream": "birch", "arguments": "x"}).status_code == 422
    assert control(base, "POST", "notices", content=b"not json").status_code == 400
    result = call(base, NOTICE_TOOL, {})
    assert is_error(result) and "proxy only" in result.content[0].text


def test_proxy_config_file(tmp_path, monkeypatch):
    monkeypatch.setenv("BIRCH_TOKEN", "partner-secret")
    path = tmp_path / "proxy.json"
    body = {"port": 8799, "upstreams": [{"name": "birch", "url": "https://mcp.birch.example/mcp", "partner_org": BIRCH,
                                         "partner_agent": BIRCH_AGENT, "agent_id": AURORA_AGENT,
                                         "headers": {"X-Api-Key": "${BIRCH_TOKEN}"},
                                         "pass_headers": {"X-Partner-Authorization": "Authorization"}}]}
    path.write_text(json.dumps(body))
    config = ProxyConfig.load(path, state_dir=tmp_path / "state")
    up = config.upstreams["birch"]
    assert up.headers == {"X-Api-Key": "partner-secret"} and up.pass_headers == {"x-partner-authorization": "Authorization"}
    assert config.port == 8799 and config.host == "127.0.0.1" and config.token_file == tmp_path / "state" / "proxy-token"

    monkeypatch.delenv("BIRCH_TOKEN")
    with pytest.raises(ValueError, match="BIRCH_TOKEN is not set"):
        ProxyConfig.load(path, state_dir=tmp_path)
    body["upstreams"][0]["headers"] = {}
    body["upstreams"][0]["pass_headers"] = {"Authorization": "Authorization"}
    path.write_text(json.dumps(body))
    with pytest.raises(ValueError, match="proxy's token"):
        ProxyConfig.load(path, state_dir=tmp_path)

    from norcaster_counterparty.proxy import load_or_create_token

    token = load_or_create_token(tmp_path / "state" / "proxy-token")
    assert load_or_create_token(tmp_path / "state" / "proxy-token") == token
    assert oct(os.stat(tmp_path / "state" / "proxy-token").st_mode & 0o777) == "0o600"


def test_an_approval_a_rejection_and_a_state_dir_from_before_approvals(tmp_path, configs, serve):
    import sqlite3

    from norcaster_counterparty import Store

    aurora, birch_config = configs
    birch = Birch()
    base = start_proxy(serve, tmp_path, aurora, serve(lambda: _lowlevel_app(birch, birch_party(birch_config))))
    body = {"upstream": "birch", "tool_name": "create_order", "arguments": ORDER}

    answer = control(base, "POST", "decisions", json={**body, "outcome": "allowed"}).json()
    assert (answer["registered"], answer["outcome"]) == (True, "allowed")
    call(base, "create_order", ORDER)
    assert (last_status(base)["outcome"], last_status(base)["rule_id"]) == ("allowed", "human_approval")
    assert control(base, "POST", "decisions", json={**body, "outcome": "maybe"}).status_code == 422

    # A redaction was reported, then a person rejected the call: the notice uses the decision up.
    control(base, "POST", "decisions", json={**body, "rule_id": "aurora.pii.email"})
    control(base, "POST", "notices", json={**body, "rule_id": "human_rejected"})
    call(base, "create_order", ORDER)  # the same bytes later: nothing left to label it
    assert (last_status(base)["outcome"], last_status(base)["rule_id"]) == ("allowed", None)

    old = tmp_path / "old-state"
    old.mkdir()
    db = sqlite3.connect(old / "records.sqlite3")
    db.execute("CREATE TABLE proxy_decisions (id INTEGER PRIMARY KEY AUTOINCREMENT, upstream TEXT NOT NULL, "
               "digest TEXT NOT NULL, rule_id TEXT NOT NULL, expires_at REAL NOT NULL)")
    db.execute("INSERT INTO proxy_decisions (upstream, digest, rule_id, expires_at) VALUES ('birch', 'd', 'r', 1e12)")
    db.commit()
    db.close()
    assert Store(old).take_decision("birch", "d") == ("redacted", "r")  # the column is added, old rows read as redactions
