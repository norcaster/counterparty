"""A local sandbox to try the component: a log stand-in and a fictional hub, on your machine.

THIS IS NOT A SCITT TRANSPARENCY SERVICE, and nothing here is a real company. It is a stand-in
for the quickstart (QUICKSTART.md): one operator key on this machine, entries kept in a JSON
file, and a small registration policy (key documents only from onboarded organisations, every
other statement signed by a key in its issuer's logged key document). It speaks the same public
log interface as a real Shared Record log (``/v1/shared-record/log``), so the component talks to
it exactly as it would to a pilot log.

The fictional hub, **Alpha Test Lender (synthetic)**, is the hub of the v0 demo. It is itself a
:class:`~norcaster_counterparty.Counterparty` with its own keys, so every receipt it sends is a
real one. Its witness cosigns each checkpoint the sandbox makes; in a pilot the hub's witness
checks consistency itself, but here operator and hub are the same process. You are the second
witness, so a checkpoint is witnessed only after you cosign it.

Nothing is sent anywhere: the server listens on 127.0.0.1 unless you pass another ``--host``.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from cryptography.hazmat.primitives import serialization
from norcaster_verify.shared_record import cose, es256, merkle, objects
from norcaster_verify.shared_record.canonical import CanonicalError, format_timestamp, parse_timestamp

from .config import Config
from .party import META_KEY, Counterparty, Refused
from .store import _pem, _write_secret

LOG_ID = "log.sandbox.localhost"
HUB_ORG = "org-alpha.example"
HUB_NAME = "Alpha Test Lender (synthetic)"
HUB_AGENT = "alpha-credit-agent"
HUB_AGENT_NAME = "Credit decision agent (synthetic)"
HUB_WITNESS = "witness.alpha.example"
DEFAULT_PORT = 8765
LOG_PREFIX = "/v1/shared-record/log"
BANNER = "NOT a SCITT transparency service: a local sandbox with a fictional hub, for trying the component."


class SandboxRefused(ValueError):
    """The sandbox's registration policy refused a statement (HTTP 422)."""


def _now_stamp() -> str:
    return format_timestamp(datetime.now(timezone.utc).replace(microsecond=0))


def _private_key(path: Path) -> Any:
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    key = es256.generate_private_key()
    _write_secret(path, _pem(key))
    return key


@dataclass
class SandboxLog:
    """An append-only RFC 9162 tree of Signed Statements with RFC 9942 receipts (the verifier
    package's code), checkpoints and witness cosignatures, kept in ``dir/log.json``."""

    dir: Path
    quorum: int = 2
    entries: list[dict[str, Any]] = field(default_factory=list)
    checkpoints: list[dict[str, Any]] = field(default_factory=list)
    pins: dict[str, str] = field(default_factory=dict)
    witnesses: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.dir = Path(self.dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)
        self.operator = _private_key(self.dir / "keys" / "operator.key")
        self.operator_pem = es256.public_key_pem(self.operator)
        (self.dir / "log-operator.pem").write_text(self.operator_pem)
        state = self.dir / "log.json"
        if state.exists():
            raw = json.loads(state.read_text())
            self.entries, self.checkpoints = raw["entries"], raw["checkpoints"]
            self.pins, self.witnesses = raw["pins"], raw["witnesses"]

    def _save(self) -> None:
        tmp = self.dir / "log.json.tmp"
        tmp.write_text(json.dumps({"log_id": LOG_ID, "entries": self.entries, "checkpoints": self.checkpoints,
                                   "pins": self.pins, "witnesses": self.witnesses}, indent=1))
        os.replace(tmp, self.dir / "log.json")

    def _leaves(self, size: int | None = None) -> list[bytes]:
        return [merkle.leaf_hash(bytes.fromhex(e["statement"])) for e in self.entries[:size]]

    # --- registration policy -----------------------------------------------------------------------

    def _identity(self, issuer: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        """The issuer's latest logged key document and any open root rotation after it."""
        doc = rotation = None
        for e in self.entries:
            obj = e.get("object")
            if e["issuer"] != issuer or not obj:
                continue
            if obj.get("type") == "key-document":
                doc, rotation = obj, None
            elif obj.get("type") == "root-rotation":
                rotation = obj
        return doc, rotation

    def _check(self, statement: bytes, obj: dict[str, Any] | None) -> tuple[str, dict[str, Any] | None]:
        try:
            info = cose.read_statement(statement)
        except cose.COSEError as exc:
            raise SandboxRefused(f"not a Shared Record Signed Statement: {exc}") from exc
        if obj is not None and obj.get("type") in ("key-document", "root-rotation"):
            try:
                same = info.payload == objects.statement_preimage_digest(obj)
            except CanonicalError as exc:
                raise SandboxRefused(f"unreadable object: {exc}") from exc
            if not same or obj.get("org_id") != info.issuer or objects.shape_problems(obj):
                raise SandboxRefused("the statement is not for this object and issuer")
            last, rotation = self._identity(info.issuer)
            if obj["type"] == "root-rotation":
                if last is None or rotation is not None or obj.get("previous") != objects.digest_hex(last):
                    raise SandboxRefused("a rotation must follow the issuer's latest key document, one at a time")
                signer = last["root_public_key_pem"]
            else:
                root = obj.get("root_public_key_pem")
                if last is None:
                    pin = self.pins.get(info.issuer)
                    if pin is None:
                        raise SandboxRefused(f"unknown issuer {info.issuer}: onboard with the sandbox hub first "
                                             "(norcaster-counterparty sandbox onboard)")
                    if not isinstance(root, str) or es256.fingerprint(root) != pin:
                        raise SandboxRefused(f"{info.issuer}'s key document is not under its pinned root")
                elif obj.get("version") != last.get("version", 0) + 1 or obj.get("previous") != objects.digest_hex(last):
                    raise SandboxRefused("key-document versions must chain")
                elif root != last.get("root_public_key_pem") and (rotation is None or rotation.get("new_root_public_key_pem") != root):
                    raise SandboxRefused("the root changed without a rotation signed by the previous root")
                if (obj.get("version") or 0) == 1 and obj.get("previous") is not None:
                    raise SandboxRefused("version 1 has no previous version")
                earlier = [e["object"] for e in self.key_documents(info.issuer) if e["object"].get("type") == "key-document"]
                problems = objects.key_document_problems(earlier, obj)  # one key per key id; revocations stay (spec §6.5)
                if problems:
                    raise SandboxRefused("; ".join(problems))
                signer = root
            if not isinstance(signer, str) or not objects.verify_signature(obj, signer):
                raise SandboxRefused("the object is not signed by the right root")
            if not cose.verify_statement(es256.load_public_key(signer), statement):
                raise SandboxRefused("the statement is not signed by the right root")
            return info.issuer, obj
        doc, _ = self._identity(info.issuer)
        expires = parse_timestamp((doc or {}).get("expires_at"))
        if doc is not None and (expires is None or expires < datetime.now(timezone.utc)):
            raise SandboxRefused(f"{info.issuer}'s key document v{doc.get('version')} has expired; publish a new version first")
        key = next((k for k in (doc or {}).get("signing_keys") or [] if k.get("key_id") == info.kid and not k.get("revoked_at")), None)
        if key is None or not cose.verify_statement(es256.load_public_key(key["public_key_pem"]), statement):
            raise SandboxRefused(f"not signed by a current key in {info.issuer}'s logged key document")
        return info.issuer, None

    # --- the public log interface ------------------------------------------------------------------

    def register(self, statement: bytes, obj: dict[str, Any] | None = None) -> dict[str, Any]:
        for e in self.entries:
            if e["statement"] == statement.hex():
                return {"leaf_index": e["leaf_index"], "receipt": e["receipt"], "existing": True}
        issuer, kept = self._check(statement, obj)
        index = len(self.entries)
        leaves = self._leaves() + [merkle.leaf_hash(statement)]
        receipt = cose.make_inclusion_receipt(
            self.operator, log_id=LOG_ID, kid=es256.key_id(self.operator_pem), tree_size=index + 1, leaf_index=index,
            path=merkle.inclusion_path(index, leaves), root=merkle.tree_hash(leaves), issued_at=int(time.time()))
        self.entries.append({"leaf_index": index, "issuer": issuer, "statement": statement.hex(), "receipt": receipt.hex(),
                             "object": kept, "registered_at": _now_stamp()})
        self._save()
        return {"leaf_index": index, "receipt": receipt.hex(), "existing": False}

    def key_documents(self, issuer: str) -> list[dict[str, Any]]:
        return [e for e in self.entries if e["issuer"] == issuer and e.get("object")]

    def checkpoint(self, hub_witness: Any) -> None:
        """A new checkpoint when the tree grew, cosigned at once by the hub's witness."""
        size = len(self.entries)
        if size == 0 or (self.checkpoints and self.checkpoints[-1]["checkpoint"]["tree_size"] == size):
            return
        cp = objects.sign(objects.checkpoint(log_id=LOG_ID, tree_size=size, root=merkle.tree_hash(self._leaves()).hex(),
                                             issued_at=_now_stamp()), self.operator)
        cosig = objects.sign(objects.cosignature(log_id=LOG_ID, checkpoint_digest=objects.digest_hex(cp), witness_id=HUB_WITNESS,
                                                 cosigned_at=_now_stamp()), hub_witness)
        self.checkpoints.append({"checkpoint": cp, "cosignatures": [cosig]})
        self._save()

    def _valid_cosigners(self, item: dict[str, Any]) -> set[str]:
        return {c["witness_id"] for c in item["cosignatures"]
                if c.get("witness_id") in self.witnesses and objects.verify_signature(c, self.witnesses[c["witness_id"]])}

    def latest_checkpoint(self, *, witnessed: bool = False) -> dict[str, Any] | None:
        for item in reversed(self.checkpoints):
            if not witnessed or len(self._valid_cosigners(item)) >= self.quorum:
                return item
        return None

    def consistency(self, old: int, new: int) -> list[str]:
        if not 0 < old <= new <= len(self.entries):
            raise SandboxRefused("bad tree sizes")
        return [] if old == new else [p.hex() for p in merkle.consistency_path(old, self._leaves(new))]

    def cosign(self, cosignature: dict[str, Any]) -> dict[str, Any]:
        wid = cosignature.get("witness_id")
        if wid not in self.witnesses or not objects.verify_signature(cosignature, self.witnesses[wid]):
            raise SandboxRefused("unknown witness or bad signature")
        for item in self.checkpoints:
            if objects.digest_hex(item["checkpoint"]) == cosignature.get("checkpoint"):
                if wid not in {c["witness_id"] for c in item["cosignatures"]}:
                    item["cosignatures"].append(cosignature)
                    self._save()
                return {"witnessed": len(self._valid_cosigners(item)) >= self.quorum}
        raise SandboxRefused("unknown checkpoint")


class _InProcessLog:
    """The hub's log client: the same calls as ``HttpLogClient``, without HTTP."""

    def __init__(self, log: SandboxLog) -> None:
        self._log = log

    async def register(self, statement: bytes, obj: dict[str, Any] | None = None) -> dict[str, Any]:
        return self._log.register(statement, obj)

    async def key_documents(self, issuer: str) -> list[dict[str, Any]]:
        return self._log.key_documents(issuer)

    async def latest_checkpoint(self, *, witnessed: bool = False) -> dict[str, Any] | None:
        return self._log.latest_checkpoint(witnessed=witnessed)

    async def consistency(self, old_size: int, new_size: int) -> list[str]:
        return self._log.consistency(old_size, new_size)

    async def cosign(self, cosignature: dict[str, Any]) -> dict[str, Any]:
        return self._log.cosign(cosignature)


class Sandbox:
    """The log stand-in, the fictional hub and the calls the hub has queued for each organisation."""

    def __init__(self, directory: Path) -> None:
        self.dir = Path(directory)
        self.log = SandboxLog(self.dir)
        config = Config(org_id=HUB_ORG, org_name=HUB_NAME, state_dir=self.dir / "hub", log_url="in-process", log_id=LOG_ID,
                        operator_public_key_pem=self.log.operator_pem, pins=dict(self.log.pins),
                        agents=[{"agent_id": HUB_AGENT, "name": HUB_AGENT_NAME, "kind": "agent"}], witness_id=HUB_WITNESS,
                        policy_version="1", policy_content_hash="4d1f8a" + "0" * 58, ack_deadline_seconds=3600)
        self.hub = Counterparty(config, _InProcessLog(self.log))
        self.calls: list[dict[str, Any]] = []
        self.log.pins.setdefault(HUB_ORG, self.hub.root_fingerprint)
        self.log.witnesses.setdefault(HUB_WITNESS, self.hub.witness_public_key_pem)
        if not self.log.key_documents(HUB_ORG):
            asyncio.run(self.hub.publish_key_document())
        self.log.checkpoint(self.hub.store.witness_key())

    def hub_details(self) -> dict[str, Any]:
        return {"note": BANNER, "log_id": LOG_ID, "log_operator_public_key_pem": self.log.operator_pem,
                "hub_org_id": HUB_ORG, "hub_name": HUB_NAME, "hub_agent_id": HUB_AGENT,
                "root_fingerprint": self.hub.root_fingerprint, "witness_id": HUB_WITNESS,
                "witness_public_key_pem": self.hub.witness_public_key_pem, "quorum": self.log.quorum}

    def onboard(self, details: dict[str, Any]) -> dict[str, Any]:
        """What ``norcaster-counterparty init`` prints: the hub pins your root and accepts your witness."""
        org, fp = str(details.get("org_id") or ""), str(details.get("root_fingerprint") or "")
        wid, wpem = details.get("witness_id"), details.get("witness_public_key_pem")
        if not org or len(fp) != 64 or org == HUB_ORG:
            raise SandboxRefused("give the org_id and root_fingerprint that init printed")
        if self.log.pins.get(org, fp) != fp:
            raise SandboxRefused(f"{org} is already onboarded with another root")
        self.log.pins[org] = fp
        self.hub.config.pins[org] = fp
        if wid and wpem:
            es256.load_public_key(str(wpem))
            self.log.witnesses[str(wid)] = str(wpem)
        self.log._save()
        return {"onboarded": org, "pinned_root_fingerprint": fp, "witness_accepted": bool(wid and wpem)}

    def send_call(self, body: dict[str, Any]) -> dict[str, Any]:
        to_org, to_agent = str(body.get("to_org") or ""), str(body.get("to_agent") or "")
        tool, arguments = str(body.get("tool_name") or "create_order"), body.get("arguments")
        if not isinstance(arguments, dict):
            arguments = {"sku": "SKU-0021", "quantity": 1, "customer_ref": "QS-0001"}
        outcome = "blocked" if body.get("blocked") else "allowed"
        try:
            out = asyncio.run(self.hub.send(to_org=to_org, to_agent=to_agent, agent_id=HUB_AGENT, tool_name=tool, arguments=arguments,
                                            outcome=outcome, rule_id="sandbox.blocked_tool" if outcome == "blocked" else None))
        except Refused as exc:
            raise SandboxRefused(str(exc)) from exc
        self.log.checkpoint(self.hub.store.witness_key())
        # A blocked call is never delivered: the receiver gets a notice, with no arguments.
        self.calls.append({"exchange_id": out.exchange_id, "to_org": to_org, "tool_name": tool if out.delivered else "norcaster_shared_record_notice",
                           "arguments": arguments if out.delivered else {}, "meta": out.meta, "status": "queued"})
        return {"exchange_id": out.exchange_id, "delivered": out.delivered, "queued_for": to_org}

    def next_call(self, to_org: str) -> dict[str, Any] | None:
        for call in self.calls:
            if call["to_org"] == to_org and call["status"] == "queued":
                call["status"] = "delivered"
                return {k: call[k] for k in ("exchange_id", "tool_name", "arguments", "meta")}
        return None

    def result(self, exchange_id: str, body: dict[str, Any]) -> dict[str, Any]:
        status = asyncio.run(self.hub.accept_acknowledgement(exchange_id, body.get("meta")))
        self.log.checkpoint(self.hub.store.witness_key())
        return {"exchange_id": exchange_id, "hub_status": status}

    def trust(self) -> dict[str, Any]:
        """A trust file for the quickstart's last step. In a real dispute the third party builds its
        own from what each party pinned; it does not take it from the log operator."""
        return {"log": {"log_id": LOG_ID, "operator_public_key_pem": self.log.operator_pem, "quorum": self.log.quorum,
                        "witnesses": dict(self.log.witnesses)},
                "orgs": {org: {"root_fingerprint": fp} for org, fp in sorted(self.log.pins.items())}}


def _handler(sandbox: Sandbox) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "norcaster-counterparty-sandbox"

        def log_message(self, fmt: str, *args: Any) -> None:  # one short line per request
            print(f"  {self.command} {urlparse(self.path).path} -> {args[1] if len(args) > 1 else ''}", flush=True)

        def _send(self, status: int, body: Any) -> None:
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length") or 0)
            if length > 1_000_000:
                raise SandboxRefused("request too large")
            raw = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(raw, dict):
                raise SandboxRefused("expected a JSON object")
            return raw

        def _route(self, method: str) -> tuple[int, Any]:
            url = urlparse(self.path)
            path, query = url.path.rstrip("/"), {k: v[-1] for k, v in parse_qs(url.query).items()}
            log = sandbox.log
            if path.startswith(LOG_PREFIX):
                sub = path[len(LOG_PREFIX):]
                if method == "POST" and sub == "/entries":
                    body = self._body()
                    obj = body.get("object")
                    return 200, log.register(bytes.fromhex(str(body.get("statement") or "")), obj if isinstance(obj, dict) else None)
                if method == "GET" and sub.startswith("/key-documents/"):
                    return 200, {"entries": log.key_documents(unquote(sub[len("/key-documents/"):]))}
                if method == "GET" and sub == "/checkpoints/latest":
                    sandbox.log.checkpoint(sandbox.hub.store.witness_key())
                    item = log.latest_checkpoint(witnessed=query.get("witnessed") == "true")
                    return (200, item) if item else (404, {"detail": "no checkpoint yet"})
                if method == "GET" and sub == "/consistency":
                    return 200, {"path": log.consistency(int(query.get("old", 0)), int(query.get("new", 0)))}
                if method == "POST" and sub == "/cosignatures":
                    return 200, log.cosign(self._body())
                if method == "GET" and sub == "":
                    return 200, {"log_id": LOG_ID, "tree_size": len(log.entries), "note": BANNER}
            if method == "GET" and path == "/sandbox/hub":
                return 200, sandbox.hub_details()
            if method == "GET" and path == "/sandbox/trust":
                return 200, sandbox.trust()
            if method == "POST" and path == "/sandbox/onboard":
                return 200, sandbox.onboard(self._body())
            if method == "POST" and path == "/sandbox/calls":
                return 200, sandbox.send_call(self._body())
            if method == "GET" and path == "/sandbox/calls/next":
                call = sandbox.next_call(str(query.get("to") or ""))
                return (200, call) if call else (404, {"detail": "no call queued for you; run: norcaster-counterparty sandbox send-call"})
            if method == "POST" and path.startswith("/sandbox/calls/") and path.endswith("/result"):
                return 200, sandbox.result(path.split("/")[3], self._body())
            return 404, {"detail": "not found"}

        def _handle(self, method: str) -> None:
            try:
                status, body = self._route(method)
            except (SandboxRefused, ValueError, KeyError, TypeError) as exc:
                status, body = 422, {"detail": str(exc)}
            self._send(status, body)

        def do_GET(self) -> None:  # noqa: N802
            self._handle("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._handle("POST")

    return Handler


def serve(directory: Path, *, host: str = "127.0.0.1", port: int = DEFAULT_PORT) -> None:
    sandbox = Sandbox(directory)
    server = HTTPServer((host, port), _handler(sandbox))
    hub = sandbox.hub_details()
    print(BANNER)
    print(f"Sandbox log and hub on http://{host}:{port}  (state in {Path(directory).resolve()})")
    print(f"  log id:            {LOG_ID}")
    print(f"  log operator key:  {Path(directory) / 'log-operator.pem'}")
    print(f"  hub:               {HUB_NAME}  ({HUB_ORG}, agent {HUB_AGENT})")
    print(f"  hub root fingerprint (pin it): {hub['root_fingerprint']}")
    print("Ctrl-C stops it; the state stays in the directory.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
