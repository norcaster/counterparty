"""Local MCP proxy: Shared Record receipts for any MCP client, whatever its hooks.

Some agent SDKs cannot set an MCP request's ``_meta`` (the Claude Agent SDK, Google ADK,
LangGraph's MCP adapters). The proxy sits between the agent and the partner's MCP server:

* the agent connects to it as an ordinary MCP server (Streamable HTTP on 127.0.0.1, at
  ``/mcp/<upstream>``), with a bearer token kept in a 0600 file;
* for every ``tools/call`` it signs and registers a receipt (``Counterparty.send``), forwards the
  call to the partner over Streamable HTTP with the receipt in ``_meta["norcaster/shared-record"]``,
  checks the acknowledgement in the result's ``_meta``, and removes that block before the agent
  sees the result (so the model never pays tokens for it);
* the agent's own boundary reports what it decided over the control channel
  (``/control/v1``): a call it blocked becomes a ``blocked`` receipt and a notice through the
  partner's notice tool; a call it redacted is marked ``redacted`` with the rule id. A decision
  is keyed by the SHA-256 of exactly the bytes the commitment covers, and used once.

The proxy holds the keys; the agent's process never does. It also records missing
acknowledgements and, if asked, witnesses the log on a schedule. Tools only: resources,
prompts, sampling and elicitation are not passed through.

    norcaster-counterparty --config counterparty.json proxy serve --proxy proxy.json

Install with ``pip install "norcaster-counterparty[mcp]"`` (MCP Python SDK 1.x or 2.x).
"""

from __future__ import annotations

import asyncio
import collections
import contextlib
import dataclasses
import hashlib
import hmac
import importlib.metadata
import json
import logging
import os
import re
import secrets
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .exchange_status import ExchangeStatus, settle
from .mcp_server import NOTICE_TOOL
from .party import META_KEY, Counterparty, Inconsistent, Outbound, Refused, tool_call_content
from .store import Store, _write_secret

STATUS_KEY = "norcaster/shared-record-status"
CONTROL = "/control/v1"
LOOPBACK = ("127.0.0.1", "localhost", "::1")
MAX_DECISIONS = 10_000
DECISION_OUTCOMES = ("redacted", "allowed")
MAX_BODY = 1_000_000

log = logging.getLogger("norcaster_counterparty.proxy")

try:
    _Group = BaseExceptionGroup  # Python 3.11+
except NameError:  # Python 3.10: anyio depends on the backport
    from exceptiongroup import BaseExceptionGroup as _Group

# A failed call to the partner: anyio task groups (the MCP client's) can wrap a connection error in a
# BaseExceptionGroup, which ``except Exception`` would let through.
_CALL_FAILED = (Exception, _Group)


def _mcp2() -> bool:
    return importlib.metadata.version("mcp").split(".")[0] == "2"


def _expand(value: str) -> str:
    """``${NAME}`` from the environment, so secrets stay out of the file. A missing one is an error."""
    def one(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in os.environ:
            raise ValueError(f"environment variable {name} is not set")
        return os.environ[name]

    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", one, value)


@dataclass(frozen=True)
class Upstream:
    """A partner's MCP server, served to the agent at ``/mcp/<name>``."""

    name: str
    url: str
    partner_org: str
    partner_agent: str
    agent_id: str
    headers: dict[str, str] = field(default_factory=dict)
    pass_headers: dict[str, str] = field(default_factory=dict)
    """Incoming header (lower case) -> header sent to the partner, e.g. a per-user token."""
    notice_tool: str = NOTICE_TOOL


@dataclass(frozen=True)
class ProxyConfig:
    upstreams: dict[str, Upstream]
    token_file: Path
    status_log: Path | None = None
    host: str = "127.0.0.1"
    port: int = 8790
    include_status: bool = False
    decision_ttl_seconds: int = 60
    missing_acks_every_seconds: int = 300
    witness_every_seconds: int = 0
    session_idle_seconds: int = 300
    """Keep a session with the partner open this long without use; 0 opens one per request."""
    max_sessions_per_upstream: int = 8

    @classmethod
    def load(cls, path: str | Path, *, state_dir: Path) -> ProxyConfig:
        path = Path(path)
        raw: dict[str, Any] = json.loads(path.read_text())
        upstreams: dict[str, Upstream] = {}
        for item in raw.get("upstreams") or []:
            name = str(item["name"])
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name) or name in upstreams:
                raise ValueError(f"upstream name {name!r}: letters, digits, - and _, unique")
            pass_headers = {str(k).lower(): str(v) for k, v in (item.get("pass_headers") or {}).items()}
            if "authorization" in pass_headers:
                raise ValueError("the incoming Authorization header carries the proxy's token; pass the partner's under another name")
            upstreams[name] = Upstream(
                name=name, url=str(item["url"]), partner_org=str(item["partner_org"]),
                partner_agent=str(item["partner_agent"]), agent_id=str(item["agent_id"]),
                headers={str(k): _expand(str(v)) for k, v in (item.get("headers") or {}).items()},
                pass_headers=pass_headers, notice_tool=str(item.get("notice_tool") or NOTICE_TOOL))
        if not upstreams:
            raise ValueError("configure at least one upstream")

        def where(key: str, default: Path | None) -> Path | None:
            value = raw.get(key)
            return (path.parent / str(value)).resolve() if value else default

        return cls(
            upstreams=upstreams, token_file=where("token_file", state_dir / "proxy-token"),
            status_log=where("status_log", state_dir / "proxy-exchanges.jsonl"),
            host=str(raw.get("host") or "127.0.0.1"), port=int(raw.get("port") or 8790),
            include_status=bool(raw.get("include_status", False)),
            decision_ttl_seconds=int(raw.get("decision_ttl_seconds") or 60),
            missing_acks_every_seconds=int(raw.get("missing_acks_every_seconds", 300)),
            witness_every_seconds=int(raw.get("witness_every_seconds", 0)),
            session_idle_seconds=int(raw.get("session_idle_seconds", 300)),
            max_sessions_per_upstream=max(1, int(raw.get("max_sessions_per_upstream", 8))),
        )


def load_or_create_token(path: Path) -> str:
    """The bearer token the agent and its hooks send; created once, mode 0600."""
    if path.exists():
        return path.read_text().strip()
    token = secrets.token_urlsafe(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    _write_secret(path, token.encode())
    return token


@contextlib.asynccontextmanager
async def open_session(url: str, headers: dict[str, str] | None = None) -> AsyncIterator[Any]:
    """An initialised MCP client session over Streamable HTTP (MCP Python SDK 1.x or 2.x)."""
    from mcp import ClientSession
    from mcp.client import streamable_http
    from mcp.shared._httpx_utils import create_mcp_http_client

    connect = getattr(streamable_http, "streamable_http_client", None)
    async with contextlib.AsyncExitStack() as stack:
        if connect is not None:
            http = await stack.enter_async_context(create_mcp_http_client(headers=headers or {}))
            streams = await stack.enter_async_context(connect(url, http_client=http))
        else:  # MCP Python SDK 1.x before streamable_http_client
            streams = await stack.enter_async_context(streamable_http.streamablehttp_client(url, headers=headers or {}))
        session = await stack.enter_async_context(ClientSession(streams[0], streams[1]))
        await session.initialize()
        yield session


def _leaves(exc: BaseException) -> list[BaseException]:
    if isinstance(exc, _Group):
        return [leaf for inner in exc.exceptions for leaf in _leaves(inner)]
    return [exc]


def _session_terminated(exc: BaseException) -> bool:
    """The partner's server answered 404 for our session: it did not process the request (the MCP
    Streamable HTTP rule), so the request can go again on a new session."""
    return any("Session terminated" in str(leaf) for leaf in _leaves(exc))


def _any_failure(exc: BaseException) -> bool:
    return True


@dataclass
class _Pooled:
    """One session with a partner's server, owned by its own task (anyio closes a session in the
    task that opened it) and shared by concurrent requests (MCP multiplexes them by id)."""

    key: tuple[Any, ...]
    upstream: str
    url: str
    headers: dict[str, str]
    session: Any = None
    error: BaseException | None = None
    in_use: int = 0
    last_used: float = field(default_factory=time.monotonic)
    dead: bool = False
    retired: bool = False
    ready: asyncio.Event = field(default_factory=asyncio.Event)
    stop: asyncio.Event = field(default_factory=asyncio.Event)
    ended: asyncio.Event = field(default_factory=asyncio.Event)
    task: asyncio.Task[None] | None = None

    async def run(self, work: Callable[[Any], Awaitable[Any]]) -> Any:
        """Run ``work`` on this session, and fail it if the session ends first. A request runs in a
        task other than the session's owner, so when the transport dies (MCP SDK 1.x does on a 5xx)
        nothing else would wake it."""
        job = asyncio.ensure_future(work(self.session))
        ended = asyncio.ensure_future(self.ended.wait())
        try:
            done, _ = await asyncio.wait({job, ended}, return_when=asyncio.FIRST_COMPLETED)
        except BaseException:
            job.cancel()
            ended.cancel()
            raise
        ended.cancel()
        if job in done:
            return job.result()
        job.cancel()
        with contextlib.suppress(BaseException):
            await job
        raise UpstreamUnavailable(f"the session with {self.upstream} ended during the request")

    async def own(self) -> None:
        try:
            async with open_session(self.url, self.headers) as session:
                self.session = session
                self.ready.set()
                await self.stop.wait()
        except _CALL_FAILED as exc:
            if self.session is None:
                self.error = exc
            else:
                log.info("a session with %s ended: %s", self.upstream, type(exc).__name__)
        finally:
            self.dead = True
            self.ready.set()
            self.ended.set()


class SessionPool:
    """Sessions with the partners' servers, shared per upstream and exact outgoing headers (so
    per-user tokens never share one), closed after ``idle`` seconds without use, at most
    ``limit`` per upstream (the least recently used idle one is closed first; busy ones are not)."""

    def __init__(self, idle: float, limit: int) -> None:
        self.idle = idle
        self.limit = limit
        self._entries: dict[tuple[Any, ...], _Pooled] = {}
        self._reaper: asyncio.Task[None] | None = None

    def size(self) -> int:
        return sum(1 for e in self._entries.values() if not e.dead)

    @contextlib.asynccontextmanager
    async def session(self, upstream: str, url: str, headers: dict[str, str]) -> AsyncIterator[Any]:
        entry = await self._acquire(upstream, url, headers)
        try:
            yield entry
        except BaseException:
            self._retire(entry)  # whatever failed, the next request gets a fresh session
            raise
        finally:
            entry.in_use -= 1
            entry.last_used = time.monotonic()
            if entry.retired and entry.in_use == 0:
                await self._close(entry)

    async def _acquire(self, upstream: str, url: str, headers: dict[str, str]) -> _Pooled:
        key = (upstream, url, tuple(sorted(headers.items())))
        entry = self._entries.get(key)
        if entry is None or entry.dead or entry.retired:
            entry = _Pooled(key=key, upstream=upstream, url=url, headers=dict(headers))
            self._entries[key] = entry
            await self._make_room(upstream, keep=key)
            entry.task = asyncio.create_task(entry.own())
            if self._reaper is None:
                self._reaper = asyncio.create_task(self._reap())
        entry.in_use += 1
        try:
            await entry.ready.wait()
        except BaseException:
            entry.in_use -= 1
            raise
        if entry.dead or entry.session is None:
            entry.in_use -= 1
            self._retire(entry)
            if entry.error is not None:
                raise entry.error
            raise UpstreamUnavailable(f"the session with {upstream} closed")
        return entry

    def _retire(self, entry: _Pooled) -> None:
        entry.retired = True
        if self._entries.get(entry.key) is entry:
            del self._entries[entry.key]

    async def _close(self, entry: _Pooled) -> None:
        self._retire(entry)
        entry.stop.set()
        if entry.task is not None:
            try:
                await asyncio.wait_for(asyncio.shield(entry.task), timeout=10)
            except asyncio.TimeoutError:
                entry.task.cancel()
            except Exception:  # noqa: BLE001 - closing is best effort
                pass

    async def _make_room(self, upstream: str, *, keep: tuple[Any, ...]) -> None:
        mine = [e for e in self._entries.values() if e.upstream == upstream and e.key != keep and not e.dead]
        idle = sorted((e for e in mine if e.in_use == 0), key=lambda e: e.last_used)
        while len(mine) >= self.limit and idle:
            oldest = idle.pop(0)
            mine.remove(oldest)
            await self._close(oldest)

    async def _reap(self) -> None:
        while True:
            await asyncio.sleep(max(0.2, min(self.idle / 4, 30.0)))
            now = time.monotonic()
            for entry in list(self._entries.values()):
                if entry.dead or (entry.in_use == 0 and now - entry.last_used >= self.idle):
                    await self._close(entry)

    async def close_all(self) -> None:
        if self._reaper is not None:
            self._reaper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._reaper
            self._reaper = None
        for entry in list(self._entries.values()):
            await self._close(entry)


class Decisions:
    """Boundary decisions the agent's hooks report before the call: keyed by the SHA-256 of the
    bytes the commitment will cover, used once, forgotten after ``ttl`` seconds. Kept in
    ``state_dir``'s database, so every process sharing it (HTTP and stdio proxies, the hook
    command) sees the same decisions."""

    def __init__(self, store: Store, ttl: int) -> None:
        self._store = store
        self._ttl = ttl

    @staticmethod
    def digest(tool_name: str, arguments: dict[str, Any]) -> str:
        return hashlib.sha256(tool_call_content(tool_name, arguments)).hexdigest()

    def register(self, upstream: str, tool_name: str, arguments: dict[str, Any], rule_id: str, *,
                 outcome: str = "redacted") -> tuple[str, bool]:
        """Keep a ``redacted`` decision, or an ``allowed`` one (a person approved the call). Returns
        the digest and whether it was kept (an approval yields to a pending redaction)."""
        if outcome not in DECISION_OUTCOMES:
            raise ValueError(f"outcome: one of {', '.join(DECISION_OUTCOMES)}")
        digest = self.digest(tool_name, arguments)
        kept = self._store.add_decision(upstream, digest, rule_id, time.time() + self._ttl, limit=MAX_DECISIONS, outcome=outcome)
        return digest, kept

    def take(self, upstream: str, tool_name: str, arguments: dict[str, Any]) -> tuple[str, str] | None:
        """(outcome, rule id) for the call with these bytes, if a decision was reported."""
        return self._store.take_decision(upstream, self.digest(tool_name, arguments))


def _headers_of(request: Any) -> dict[str, str]:
    return {k.lower(): v for k, v in request.headers.items()} if request is not None else {}


class Proxy:
    """The proxy for one organisation (one ``Counterparty``) and its partners' MCP servers."""

    def __init__(self, party: Counterparty, config: ProxyConfig, *, token: str) -> None:
        self.party = party
        self.config = config
        self.decisions = Decisions(party.store, config.decision_ttl_seconds)
        self.exchanges: collections.deque[ExchangeStatus] = collections.deque(maxlen=1000)
        self._token = token
        self._lock = asyncio.Lock()  # one send at a time: each receipt takes the next sequence number
        self.pool = (SessionPool(config.session_idle_seconds, config.max_sessions_per_upstream)
                     if config.session_idle_seconds > 0 else None)
        if config.status_log is not None:
            config.status_log.parent.mkdir(parents=True, exist_ok=True)

    # --- the partner's server -----------------------------------------------------------------

    def _outgoing_headers(self, up: Upstream, incoming: Mapping[str, str]) -> dict[str, str]:
        headers = dict(up.headers)
        for name, sent_as in up.pass_headers.items():
            if name in incoming:
                headers[sent_as] = incoming[name]
        return headers

    async def _with_session(self, up: Upstream, incoming: Mapping[str, str], work: Callable[[Any], Awaitable[Any]],
                            *, retry: Callable[[BaseException], bool]) -> Any:
        """Run ``work`` on a session with the partner's server: a pooled one, or one for this request
        when pooling is off. A pooled session that fails is dropped; ``retry`` says whether the
        request may go once more on a new session."""
        headers = self._outgoing_headers(up, incoming)
        for attempt in (0, 1):
            try:
                if self.pool is None:
                    async with open_session(up.url, headers) as session:
                        return await work(session)
                async with self.pool.session(up.name, up.url, headers) as entry:
                    return await entry.run(work)
            except _CALL_FAILED as exc:
                if attempt == 0 and self.pool is not None and retry(exc):
                    log.info("retrying on a new session with %s: %s", up.name, type(exc).__name__)
                    continue
                raise
        raise AssertionError("unreachable")

    async def aclose(self) -> None:
        """Close the pooled sessions with the partners' servers."""
        if self.pool is not None:
            await self.pool.close_all()

    async def _send(self, up: Upstream, tool_name: str, arguments: dict[str, Any], *, outcome: str,
                    rule_id: str | None) -> Outbound:
        async with self._lock:
            return await self.party.send(to_org=up.partner_org, to_agent=up.partner_agent, agent_id=up.agent_id,
                                         tool_name=tool_name, arguments=arguments, outcome=outcome, rule_id=rule_id)

    async def _report(self, upstream: str, status: ExchangeStatus) -> None:
        self.exchanges.append(status)
        if self.config.status_log is not None:
            line = json.dumps({"upstream": upstream, **status.as_dict()}, sort_keys=True)
            with self.config.status_log.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    # --- what the agent calls -------------------------------------------------------------------

    async def list_tools(self, up: Upstream, incoming: Mapping[str, str]) -> list[Any]:
        """The partner's tools, without the notice tool (only the proxy calls it) and without a
        static ``_meta`` entry under our key."""
        import mcp.types as types

        async def every_page(session: Any) -> list[Any]:
            found: list[Any] = []
            cursor = None
            for _ in range(100):
                page = await (session.list_tools(params=types.PaginatedRequestParams(cursor=cursor)) if cursor
                              else session.list_tools())
                found.extend(page.tools)
                cursor = getattr(page, "next_cursor", None) or getattr(page, "nextCursor", None)
                if not cursor:
                    break
            return found

        try:
            tools = await self._with_session(up, incoming, every_page, retry=_any_failure)  # listing is idempotent
        except _CALL_FAILED as exc:
            # MCP SDK 1.x lists tools before a call it has not seen, so this also ends such a call:
            # nothing is signed or sent.
            raise UpstreamUnavailable(f"the partner's MCP server did not answer ({type(exc).__name__})") from exc
        out = []
        for tool in tools:
            if tool.name == up.notice_tool:
                continue
            meta = getattr(tool, "meta", None)
            if isinstance(meta, dict) and META_KEY in meta:
                tool = tool.model_copy(update={"meta": {k: v for k, v in meta.items() if k != META_KEY} or None})
            out.append(tool)
        return out

    async def call_tool(self, up: Upstream, tool_name: str, arguments: dict[str, Any], incoming: Mapping[str, str]) -> Any:
        """Sign, forward with the receipt, check the acknowledgement; the agent gets the result without it."""
        if tool_name == up.notice_tool:
            return _error_result("the notice tool is called by the proxy only")
        outcome, rule_id = self.decisions.take(up.name, tool_name, arguments) or ("allowed", None)
        try:
            out = await self._send(up, tool_name, arguments, outcome=outcome, rule_id=rule_id)
        except Refused as exc:
            await self._report(up.name, ExchangeStatus(None, tool_name, "refused", False, outcome, rule_id, detail=str(exc)))
            return _error_result(f"Shared Record: your component refused to sign ({exc}); nothing was sent to {up.partner_org}")
        try:
            # Only a 404 for the session is retried: the server did not process the call. Any other
            # failure might have reached the partner's tool, so it is not sent again.
            result = await self._with_session(up, incoming, lambda session: session.call_tool(tool_name, arguments, meta=out.meta),
                                              retry=_session_terminated)
        except _CALL_FAILED as exc:  # reported; after the deadline a missing-acknowledgement record follows
            await self._report(up.name, ExchangeStatus(out.exchange_id, tool_name, "missing", True, outcome, rule_id,
                                                       detail=f"the partner's server did not answer ({type(exc).__name__})"))
            return _error_result(f"the partner's MCP server did not answer ({type(exc).__name__})")
        status = await settle(self.party, out, tool_name=tool_name, outcome=outcome, rule_id=rule_id,
                              result_meta=getattr(result, "meta", None))
        await self._report(up.name, status)
        meta = {k: v for k, v in (getattr(result, "meta", None) or {}).items() if k != META_KEY}
        if self.config.include_status:
            meta[STATUS_KEY] = status.as_dict()
        return result.model_copy(update={"meta": meta or None})

    async def notice(self, up: Upstream, tool_name: str, arguments: dict[str, Any], rule_id: str,
                     incoming: Mapping[str, str]) -> ExchangeStatus:
        """The agent's boundary blocked this call: register a ``blocked`` receipt and send the notice.
        Nothing of the call is delivered. A decision already reported for these bytes (a redaction
        before a person rejected the call) is used up with it, so it cannot label a later call."""
        self.decisions.take(up.name, tool_name, arguments)
        try:
            out = await self._send(up, tool_name, arguments, outcome="blocked", rule_id=rule_id)
        except Refused as exc:
            status = ExchangeStatus(None, tool_name, "refused", False, "blocked", rule_id, detail=str(exc))
        else:
            try:
                answer = await self._with_session(up, incoming,
                                                  lambda session: session.call_tool(up.notice_tool, {}, meta=out.meta),
                                                  retry=_session_terminated)
            except _CALL_FAILED as exc:  # the notice is best effort; the block is not
                status = ExchangeStatus(out.exchange_id, tool_name, "missing", False, "blocked", rule_id,
                                        detail=f"the notice did not reach the partner ({type(exc).__name__})")
            else:
                status = await settle(self.party, out, tool_name=tool_name, outcome="blocked", rule_id=rule_id,
                                      result_meta=getattr(answer, "meta", None))
        await self._report(up.name, status)
        return status

    # --- schedules ------------------------------------------------------------------------------

    async def _jobs(self) -> None:
        intervals = {"missing-acks": self.config.missing_acks_every_seconds, "witness": self.config.witness_every_seconds}
        due = {job: time.monotonic() + every for job, every in intervals.items() if every > 0}
        while due:
            job, at = min(due.items(), key=lambda item: item[1])
            await asyncio.sleep(max(0.0, at - time.monotonic()))
            try:
                if job == "missing-acks":
                    recorded = await self.party.record_missing_acknowledgements()
                    if recorded:
                        log.info("recorded %d missing acknowledgement(s)", recorded)
                else:
                    await self.party.witness()
            except Inconsistent as exc:
                log.critical("ALERT: the log rewrote or split its history: %s", exc)  # evidence: keep the log output
            except Exception:  # noqa: BLE001 - a schedule must not stop the proxy
                log.exception("%s failed; retrying at the next interval", job)
            due[job] = time.monotonic() + intervals[job]

    # --- the HTTP app ---------------------------------------------------------------------------

    def mcp_server(self, up: Upstream) -> Any:
        """The MCP server (low-level ``Server``) the agent sees for ``up``, on any transport."""
        from mcp.server.lowlevel import Server

        name = f"norcaster-shared-record-proxy-{up.name}"
        if _mcp2():
            import mcp.types as types

            async def on_list(ctx: Any, params: Any) -> Any:
                return types.ListToolsResult(tools=await self.list_tools(up, _headers_of(ctx.request)))

            async def on_call(ctx: Any, params: Any) -> Any:
                return await self.call_tool(up, params.name, params.arguments or {}, _headers_of(ctx.request))

            return Server(name, on_list_tools=on_list, on_call_tool=on_call)

        server = Server(name)

        @server.list_tools()
        async def list_tools() -> list[Any]:
            return await self.list_tools(up, _headers_of(server.request_context.request))

        @server.call_tool(validate_input=False)
        async def call_tool(tool_name: str, arguments: dict[str, Any]) -> Any:
            return await self.call_tool(up, tool_name, arguments or {}, _headers_of(server.request_context.request))

        return server

    def app(self) -> Any:
        """The Starlette app: ``/mcp/<upstream>`` for the agent and ``/control/v1`` for its hooks."""
        from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
        from mcp.server.transport_security import TransportSecuritySettings
        from starlette.applications import Starlette
        from starlette.responses import JSONResponse
        from starlette.routing import Route

        security = None
        if self.config.host in LOOPBACK:
            security = TransportSecuritySettings(
                enable_dns_rebinding_protection=True, allowed_hosts=["127.0.0.1:*", "localhost:*", "[::1]:*"],
                allowed_origins=["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"])
        managers = {name: StreamableHTTPSessionManager(app=self.mcp_server(up), security_settings=security)
                    for name, up in self.config.upstreams.items()}

        class _Endpoint:
            def __init__(self, manager: Any) -> None:
                self.manager = manager

            async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
                await self.manager.handle_request(scope, receive, send)

        async def body(request: Any) -> tuple[Upstream, str, dict[str, Any], str | None]:
            raw = await request.body()
            if len(raw) > MAX_BODY:
                raise _Bad(413, "request too large")
            try:
                data = json.loads(raw or b"{}")
            except ValueError as exc:
                raise _Bad(400, "expected JSON") from exc
            up = self.config.upstreams.get(str(data.get("upstream") or ""))
            if up is None:
                raise _Bad(404, "unknown upstream")
            tool_name, arguments, rule_id = data.get("tool_name"), data.get("arguments"), data.get("rule_id")
            if not isinstance(tool_name, str) or not tool_name or not isinstance(arguments, dict):
                raise _Bad(422, "give tool_name (a string) and arguments (an object), as the call will be sent")
            if rule_id is not None and (not isinstance(rule_id, str) or not 0 < len(rule_id) <= 128):
                raise _Bad(422, "rule_id: a string of 1 to 128 characters")
            return up, tool_name, arguments, rule_id

        def handled(fn: Any) -> Any:
            async def endpoint(request: Any) -> Any:
                try:
                    return JSONResponse(await fn(request))
                except _Bad as exc:
                    return JSONResponse({"detail": exc.detail}, status_code=exc.status)
            return endpoint

        async def decisions(request: Any) -> dict[str, Any]:
            up, tool_name, arguments, rule_id = await body(request)
            outcome = str(json.loads(await request.body() or b"{}").get("outcome") or "redacted")
            if outcome not in DECISION_OUTCOMES:
                raise _Bad(422, f"outcome: one of {', '.join(DECISION_OUTCOMES)}")
            try:
                digest, kept = self.decisions.register(up.name, tool_name, arguments,
                                                       rule_id or ("redacted" if outcome == "redacted" else "human_approval"),
                                                       outcome=outcome)
            except ValueError as exc:
                raise _Bad(429, str(exc)) from exc
            return {"registered": kept, "outcome": outcome, "content_sha256": digest,
                    "expires_in": self.config.decision_ttl_seconds}

        async def notices(request: Any) -> dict[str, Any]:
            up, tool_name, arguments, rule_id = await body(request)
            status = await self.notice(up, tool_name, arguments, rule_id or "blocked", _headers_of(request))
            return {"upstream": up.name, **status.as_dict()}

        async def exchanges(request: Any) -> dict[str, Any]:
            try:
                limit = max(1, min(1000, int(request.query_params.get("limit") or 50)))
            except ValueError as exc:
                raise _Bad(422, "limit: an integer") from exc
            return {"exchanges": [s.as_dict() for s in list(self.exchanges)[-limit:]]}

        async def tool_names(request: Any) -> dict[str, Any]:
            up = self.config.upstreams.get(request.path_params["upstream"])
            if up is None:
                raise _Bad(404, "unknown upstream")
            try:
                listed = await self.list_tools(up, _headers_of(request))
            except UpstreamUnavailable as exc:
                raise _Bad(502, str(exc)) from exc
            return {"upstream": up.name, "tools": [t.name for t in listed]}

        async def health(request: Any) -> dict[str, Any]:
            return {"ok": True, "org_id": self.party.config.org_id, "upstreams": sorted(self.config.upstreams),
                    "sessions": self.pool.size() if self.pool is not None else 0}

        @contextlib.asynccontextmanager
        async def lifespan(app: Any) -> AsyncIterator[None]:
            async with contextlib.AsyncExitStack() as stack:
                for manager in managers.values():
                    await stack.enter_async_context(manager.run())
                jobs = asyncio.create_task(self._jobs())
                try:
                    yield
                finally:
                    jobs.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await jobs
                    await self.aclose()

        routes = [Route(f"/mcp/{name}", endpoint=_Endpoint(manager)) for name, manager in managers.items()]
        routes += [Route(f"{CONTROL}/decisions", handled(decisions), methods=["POST"]),
                   Route(f"{CONTROL}/notices", handled(notices), methods=["POST"]),
                   Route(f"{CONTROL}/exchanges", handled(exchanges), methods=["GET"]),
                   Route(f"{CONTROL}/tools/{{upstream}}", handled(tool_names), methods=["GET"]),
                   Route(f"{CONTROL}/health", handled(health), methods=["GET"])]
        return _RequireToken(Starlette(routes=routes, lifespan=lifespan), self._token)


class UpstreamUnavailable(RuntimeError):
    """The partner's MCP server could not be reached."""


class _Bad(Exception):
    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status, self.detail = status, detail


class _RequireToken:
    """Every HTTP request needs ``Authorization: Bearer <token>``: the MCP endpoints sign receipts
    in your organisation's name, so nothing else on the machine may call them."""

    def __init__(self, app: Any, token: str) -> None:
        self.app = app
        self._expected = f"Bearer {token}".encode()

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            given = dict(scope.get("headers") or []).get(b"authorization", b"")
            if not hmac.compare_digest(given, self._expected):
                body = b'{"detail": "missing or wrong bearer token (see the proxy\'s token_file)"}'
                await send({"type": "http.response.start", "status": 401,
                            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
                await send({"type": "http.response.body", "body": body})
                return
        await self.app(scope, receive, send)


def _error_result(text: str) -> Any:
    import mcp.types as types

    return types.CallToolResult.model_validate({"content": [{"type": "text", "text": text}], "isError": True})


def serve(config_path: Path, proxy_config_path: Path) -> None:
    """Run the proxy until interrupted (``norcaster-counterparty proxy serve``)."""
    import uvicorn

    from .config import Config
    from .log_client import HttpLogClient

    config = Config.load(config_path)
    proxy_config = ProxyConfig.load(proxy_config_path, state_dir=config.state_dir)
    party = Counterparty(config, HttpLogClient(config.log_url))
    token = load_or_create_token(proxy_config.token_file)
    proxy = Proxy(party, proxy_config, token=token)
    base = f"http://{proxy_config.host}:{proxy_config.port}"
    print(f"Shared Record proxy for {config.org_id} on {base} (token in {proxy_config.token_file})")
    for name, up in proxy_config.upstreams.items():
        print(f"  {base}/mcp/{name}  ->  {up.url}  (partner {up.partner_org}, your agent {up.agent_id})")
    if proxy_config.host not in LOOPBACK:
        print(f"WARNING: listening on {proxy_config.host}, not loopback: anything that reaches it with the token "
              "can have receipts signed in your organisation's name")
    print("Ctrl-C stops it.", flush=True)
    uvicorn.run(proxy.app(), host=proxy_config.host, port=proxy_config.port, log_level="warning")


def serve_stdio(config_path: Path, proxy_config_path: Path, upstream: str) -> None:
    """Serve one upstream over stdio (``norcaster-counterparty proxy stdio``): the agent starts this
    process itself, so there is no port and no token. Several such processes, and a ``proxy serve``,
    may share one ``state_dir``: sends are serialised by the component's cross-process lock and
    decisions are kept in its database. The schedules do not run here; run ``missing-acks`` (and
    ``witness``) from cron or a ``proxy serve``. Nothing but MCP is written to stdout."""
    import sys

    from mcp.server.stdio import stdio_server

    from .config import Config
    from .log_client import HttpLogClient

    config = Config.load(config_path)
    proxy_config = ProxyConfig.load(proxy_config_path, state_dir=config.state_dir)
    up = proxy_config.upstreams.get(upstream)
    if up is None:
        raise ValueError(f"no upstream {upstream!r} in {proxy_config_path} (have: {', '.join(sorted(proxy_config.upstreams))})")
    party = Counterparty(config, HttpLogClient(config.log_url))
    proxy = Proxy(party, proxy_config, token="")
    server = proxy.mcp_server(up)
    print(f"Shared Record proxy (stdio) for {config.org_id}: {up.name} -> {up.url}", file=sys.stderr, flush=True)

    async def main() -> None:
        try:
            async with stdio_server() as (read, write):
                await server.run(read, write, server.create_initialization_options())
        finally:
            await proxy.aclose()
            await party.log.aclose()

    asyncio.run(main())


class LocalControl:
    """The control channel without a running proxy: a hook command acts on ``state_dir`` itself.
    Notices are signed and sent from this process (the lock keeps the sequence right); decisions go
    to the database the proxies read. Same calls as ``hooks.ProxyControl``'s sync ones."""

    def __init__(self, config_path: Path, proxy_config_path: Path) -> None:
        from .config import Config

        self._config = Config.load(config_path)
        # One request per hook process: nothing to pool.
        self._proxy_config = dataclasses.replace(ProxyConfig.load(proxy_config_path, state_dir=self._config.state_dir),
                                                 session_idle_seconds=0)

    def _run(self, work: Any) -> Any:
        from .log_client import HttpLogClient

        async def go() -> Any:
            proxy = Proxy(Counterparty(self._config, HttpLogClient(self._config.log_url)), self._proxy_config, token="")
            try:
                return await work(proxy)
            finally:
                await proxy.party.log.aclose()

        return asyncio.run(go())

    def _upstream(self, proxy: Proxy, name: str) -> Upstream:
        up = proxy.config.upstreams.get(name)
        if up is None:
            raise ValueError(f"no upstream {name!r} in the proxy configuration")
        return up

    def notice_sync(self, upstream: str, tool_name: str, arguments: dict[str, Any], rule_id: str) -> dict[str, Any]:
        async def work(proxy: Proxy) -> dict[str, Any]:
            return (await proxy.notice(self._upstream(proxy, upstream), tool_name, arguments, rule_id, {})).as_dict()
        return self._run(work)

    def decision_sync(self, upstream: str, tool_name: str, arguments: dict[str, Any], rule_id: str, *,
                      outcome: str = "redacted") -> dict[str, Any]:
        async def work(proxy: Proxy) -> dict[str, Any]:
            self._upstream(proxy, upstream)
            digest, kept = proxy.decisions.register(upstream, tool_name, arguments, rule_id, outcome=outcome)
            return {"registered": kept, "outcome": outcome, "content_sha256": digest}
        return self._run(work)

    def tool_names_sync(self, upstream: str) -> list[str]:
        async def work(proxy: Proxy) -> list[str]:
            return [t.name for t in await proxy.list_tools(self._upstream(proxy, upstream), {})]
        return self._run(work)
