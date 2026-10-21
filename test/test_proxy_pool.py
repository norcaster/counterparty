"""Pooled sessions between Aurora's proxy and Birch's MCP server: reused, kept apart per user,
closed when idle and at shutdown, and retried once only when Birch's server forgot the session.
Real HTTP on 127.0.0.1, the sandbox log, synthetic data."""

# ruff: noqa: F811  (pytest fixtures imported from two_companies are used as parameters)
from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import pytest

pytest.importorskip("mcp", reason="needs the mcp extra")

from two_companies import (  # noqa: E402
    AUTH,
    AURORA_AGENT,
    BIRCH,
    BIRCH_AGENT,
    TOKEN,
    Birch,
    _lowlevel_app,
    aurora_party,
    birch_party,
    control,
    exchange,
    export_and_verify,
    last_status,
)
from two_companies import configs, log_url, serve  # noqa: E402,F401  (pytest fixtures, used by parameter name)

from norcaster_counterparty import Counterparty, HttpLogClient  # noqa: E402
from norcaster_counterparty.proxy import Proxy, ProxyConfig, Upstream, open_session  # noqa: E402

ORDER = {"sku": "BRC-AX-10", "quantity": 1}


class Watch:
    """An ASGI layer in front of Birch's server: counts MCP traffic, and can forget sessions (a
    restart: 404 for the sessions it knew) or fail the next tools/call (500)."""

    def __init__(self, app: Any) -> None:
        self.app = app
        self.counts: dict[str, int] = {}
        self.sessions_seen: set[str] = set()
        self.forgotten: set[str] = set()
        self.fail_next_call = False

    async def __call__(self, scope, receive, send):  # noqa: ANN001
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
        session_id = headers.get("mcp-session-id")
        chunks, more = [], True
        while more:
            message = await receive()
            chunks.append(message.get("body", b""))
            more = message.get("more_body", False)
        body = b"".join(chunks)
        method = scope["method"]
        if method == "POST":
            try:
                method = json.loads(body).get("method") or "response"
            except (ValueError, AttributeError):
                method = "batch"
        self.counts[method] = self.counts.get(method, 0) + 1
        if session_id in self.forgotten:
            return await self._answer(send, 404, b'{"error": "unknown session"}')
        if method == "tools/call" and self.fail_next_call:
            self.fail_next_call = False
            return await self._answer(send, 500, b'{"error": "boom"}')
        if session_id:
            self.sessions_seen.add(session_id)
        sent = False

        async def replay():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        async def record(message):  # noqa: ANN001
            if message["type"] == "http.response.start":
                for k, v in message.get("headers") or []:
                    if k.decode().lower() == "mcp-session-id":
                        self.sessions_seen.add(v.decode())
            await send(message)

        return await self.app(scope, replay, record)

    @staticmethod
    async def _answer(send, status: int, body: bytes) -> None:  # noqa: ANN001
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})


def setup(tmp_path, configs, serve, **options: Any) -> tuple[Any, Birch, Watch, str]:
    aurora, birch_config = configs
    birch = Birch()
    holder: dict[str, Watch] = {}

    def build():
        holder["watch"] = Watch(_lowlevel_app(birch, birch_party(birch_config)))
        return holder["watch"]

    birch_url = serve(build)
    upstream = Upstream(name="birch", url=birch_url, partner_org=BIRCH, partner_agent=BIRCH_AGENT, agent_id=AURORA_AGENT,
                        pass_headers={"x-partner-authorization": "Authorization"})
    config = ProxyConfig(upstreams={"birch": upstream}, token_file=tmp_path / "proxy-token",
                         status_log=tmp_path / "proxy-exchanges.jsonl", missing_acks_every_seconds=0, **options)
    base = serve(lambda: Proxy(Counterparty(aurora, HttpLogClient(aurora.log_url)), config, token=TOKEN).app()).removesuffix("/mcp")
    return aurora, birch, holder["watch"], base


def calls(base: str, n: int, *, user: str | None = None, concurrent: bool = False) -> list[Any]:
    headers = {**AUTH, **({"X-Partner-Authorization": f"Bearer {user}"} if user else {})}

    async def go():
        async with open_session(f"{base}/mcp/birch", headers) as session:
            if concurrent:
                return await asyncio.gather(*(session.call_tool("create_order", {"sku": f"C-{i}", "quantity": 1}) for i in range(n)))
            return [await session.call_tool("create_order", {"sku": f"S-{i}", "quantity": 1}) for i in range(n)]

    return asyncio.run(go())


def failed(result: Any) -> bool:
    return bool(getattr(result, "isError", None) or getattr(result, "is_error", None))


def test_one_session_serves_many_calls_and_users_are_kept_apart(tmp_path, configs, serve):
    _, birch, watch, base = setup(tmp_path, configs, serve)
    calls(base, 5)
    calls(base, 5, concurrent=True)  # concurrent calls share the session
    assert watch.counts["initialize"] == 1 and watch.counts["tools/call"] == 10 and len(birch.ran) == 10
    assert control(base, "GET", "health").json()["sessions"] == 1

    calls(base, 2, user="alice")
    calls(base, 2, user="bob")
    calls(base, 2, user="alice")
    assert watch.counts["initialize"] == 3  # one more each for alice and bob; their tokens never share a session
    statuses = control(base, "GET", "exchanges").json()["exchanges"]
    assert [s["status"] for s in statuses] == ["acknowledged"] * 16


def test_without_pooling_every_request_opens_a_session(tmp_path, configs, serve):
    _, _, watch, base = setup(tmp_path, configs, serve, session_idle_seconds=0)
    calls(base, 3)
    assert watch.counts["initialize"] >= 3  # one per request (MCP SDK 1.x also lists the tools before the first call)
    assert control(base, "GET", "health").json()["sessions"] == 0


def test_a_forgotten_session_is_retried_once_on_a_new_one(tmp_path, configs, serve):
    aurora, birch, watch, base = setup(tmp_path, configs, serve)
    calls(base, 1)
    watch.forgotten = set(watch.sessions_seen)  # Birch's server restarted: it answers 404 for the sessions it knew
    [result] = calls(base, 1)
    assert not failed(result) and len(birch.ran) == 2
    assert watch.counts["initialize"] == 2
    status = last_status(base)
    assert status["status"] == "acknowledged"
    report = export_and_verify(aurora_party(aurora), tmp_path, [status["exchange_id"]], reveal=[status["exchange_id"]])
    assert report["ok"] is True and exchange(report, status["exchange_id"])[0] == "acknowledged"


def test_any_other_failure_is_not_sent_again(tmp_path, configs, serve):
    _, birch, watch, base = setup(tmp_path, configs, serve)
    calls(base, 1)
    watch.fail_next_call = True
    [result] = calls(base, 1)
    assert failed(result) and len(birch.ran) == 1  # the failed call reached no tool, and was not repeated
    assert watch.counts["tools/call"] == 2
    assert last_status(base)["status"] == "missing"
    # The next call gets a fresh session, but Birch never accepted the lost receipt: it refuses the gap
    # (spec §5.2) and signs nothing until that receipt is delivered.
    [after] = calls(base, 1)
    assert failed(after) and "sequence gap" in after.content[0].text and "receipt 2 was never accepted" in after.content[0].text
    assert last_status(base)["status"] == "missing" and len(birch.ran) == 1 and watch.counts["initialize"] == 2


def test_idle_sessions_close_and_the_rest_close_at_shutdown(tmp_path, configs, serve):
    _, _, watch, base = setup(tmp_path, configs, serve, session_idle_seconds=1)
    calls(base, 1)
    assert control(base, "GET", "health").json()["sessions"] == 1
    for _ in range(40):
        if control(base, "GET", "health").json()["sessions"] == 0:
            break
        time.sleep(0.1)
    assert control(base, "GET", "health").json()["sessions"] == 0 and watch.counts.get("DELETE", 0) >= 1


def test_a_session_that_dies_during_a_call_fails_the_call_instead_of_hanging(tmp_path, configs, serve):
    _, birch, watch, base = setup(tmp_path, configs, serve)
    calls(base, 1)
    watch.fail_next_call = True  # a 500: MCP SDK 1.x's transport task dies with the session

    async def go():
        async with open_session(f"{base}/mcp/birch", AUTH) as session:
            return await asyncio.wait_for(session.call_tool("create_order", ORDER), timeout=30)

    result = asyncio.run(go())
    assert failed(result) and last_status(base)["status"] == "missing"


def test_shutdown_closes_every_session(tmp_path, configs):
    aurora, birch_config = configs

    async def go():
        import uvicorn

        from two_companies import _free_port

        birch = Birch()
        watch = Watch(_lowlevel_app(birch, birch_party(birch_config)))
        port = _free_port()
        server = uvicorn.Server(uvicorn.Config(watch, host="127.0.0.1", port=port, log_level="warning", lifespan="on"))
        serving = asyncio.create_task(server.serve())
        while not server.started:
            await asyncio.sleep(0.02)
        upstream = Upstream(name="birch", url=f"http://127.0.0.1:{port}/mcp", partner_org=BIRCH, partner_agent=BIRCH_AGENT,
                            agent_id=AURORA_AGENT)
        proxy = Proxy(Counterparty(aurora, HttpLogClient(aurora.log_url)),
                      ProxyConfig(upstreams={"birch": upstream}, token_file=tmp_path / "t", status_log=None), token=TOKEN)
        for user in ("a", "b", "c"):
            await proxy.call_tool(upstream, "create_order", ORDER, {})
            await proxy.call_tool(upstream, "create_order", ORDER, {"x-anything": user})  # same outgoing headers: shared
        opened = proxy.pool.size()
        await proxy.aclose()
        await proxy.party.log.aclose()
        closed = watch.counts.get("DELETE", 0)
        server.should_exit = True
        await serving
        return opened, proxy.pool.size(), closed, len(birch.ran)

    opened, left, closed, ran = asyncio.run(go())
    assert (opened, left, closed, ran) == (1, 0, 1, 6)
