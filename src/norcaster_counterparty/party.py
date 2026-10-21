"""One organisation's side of Shared Record, run in its own environment (spec §6–§12).

The keys are generated here and never leave ``state_dir``: a root that signs key documents,
a signing key that signs receipts and acknowledgements, and a witness key. A partner is
trusted only through the root fingerprint pinned at onboarding (``Config.pins``) and the log
only through its pinned operator key: every key document, receipt and checkpoint read from
the log is checked before it is used.

Integration is two calls around a tool call:

* receiving (an MCP server): ``inbound = await party.receive(meta_block, tool_name=…,
  arguments=…)``; run the tool when ``inbound.run_tool`` is true, and return
  ``inbound.meta`` as the result's ``_meta`` either way;
* sending (an MCP client): ``out = await party.send(…)``; send ``out.meta`` as the
  request's ``_meta`` (a blocked call is not sent: ``out.meta`` is then the notice), and
  pass the result's ``_meta`` to ``accept_acknowledgement``.

The records show what each side signed and what the log recorded; they do not decide who is right.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import json
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from norcaster_verify.shared_record import cose, es256, merkle, objects
from norcaster_verify.shared_record.canonical import CanonicalError, format_timestamp, parse_timestamp
from norcaster_verify.shared_record.verify import EVIDENCE_FORMAT, HONESTY_BOUNDARY

from .config import Config
from .log_client import LogClient, LogError
from .store import LockTimeout, Store

META_KEY = "norcaster/shared-record"
MEDIA_TYPE = "application/json"
SKEW = timedelta(minutes=5)  # key and agent validity starts a little in the past, for clock skew with the log

Decide = Callable[[str, dict[str, Any]], tuple[str, "str | None"]]


class Refused(Exception):
    """A check failed; nothing was signed, registered or stored."""


class Inconsistent(RuntimeError):
    """The log shows a history that does not extend what this witness cosigned (keep the output)."""


def tool_call_content(tool_name: str, arguments: dict[str, Any]) -> bytes:
    """The bytes a commitment covers: the tool call as sent, compact sorted UTF-8 JSON."""
    return json.dumps({"name": tool_name, "arguments": arguments}, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


@dataclass(frozen=True)
class Inbound:
    exchange_id: str
    delivered: bool
    content_check: str
    outcome: str
    rule_id: str | None
    meta: dict[str, Any]

    @property
    def run_tool(self) -> bool:
        return self.content_check == "matched" and self.outcome != "blocked"


@dataclass(frozen=True)
class Outbound:
    exchange_id: str
    delivered: bool
    meta: dict[str, Any]


def _key_in(doc: dict[str, Any] | None, key_id: str | None, at: datetime) -> str | None:
    for entry in (doc or {}).get("signing_keys") or []:
        if not isinstance(entry, dict) or entry.get("key_id") != key_id:
            continue
        start, end = parse_timestamp(entry.get("not_before")), parse_timestamp(entry.get("not_after"))
        if start is None or end is None or not start <= at <= end:
            return None
        revoked = entry.get("revoked_at")
        if revoked is not None and (parse_timestamp(revoked) is None or parse_timestamp(revoked) <= at):
            return None
        return entry.get("public_key_pem")
    return None


def _agent_in(doc: dict[str, Any] | None, agent_id: str | None, at: datetime) -> bool:
    for entry in (doc or {}).get("agents") or []:
        if not isinstance(entry, dict) or entry.get("agent_id") != agent_id:
            continue
        registered, retired = parse_timestamp(entry.get("registered_at")), entry.get("retired_at")
        if registered is None or registered > at:
            return False
        return retired is None or (parse_timestamp(retired) is not None and parse_timestamp(retired) > at)
    return False


class Counterparty:
    def __init__(self, config: Config, log: LogClient, *, store: Store | None = None,
                 clock: Callable[[], datetime] | None = None, lock_timeout: float = 60.0) -> None:
        self.config = config
        self.log = log
        self.store = store or Store(config.state_dir)
        self.lock_timeout = lock_timeout
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._operator = es256.load_public_key(config.operator_public_key_pem)

    @contextlib.asynccontextmanager
    async def _exclusive(self, kind: str, org: str) -> AsyncIterator[None]:
        """One send to (or receive from) ``org`` at a time, across every process sharing ``state_dir``:
        each receipt takes the next sequence number and chains to the previous one, and a receipt is
        checked against those already accepted."""
        try:
            lock = self.store.lock(f"{kind}:{org}", timeout=self.lock_timeout)
            await lock.__aenter__()
        except LockTimeout as exc:
            raise Refused(str(exc)) from exc
        try:
            yield
        finally:
            await lock.__aexit__(None, None, None)

    # --- identity --------------------------------------------------------------------------------

    def now(self) -> datetime:
        return self._clock().astimezone(timezone.utc).replace(microsecond=0)

    def _stamp(self, moment: datetime | None = None) -> str:
        return format_timestamp(moment or self.now())

    @property
    def root_public_key_pem(self) -> str:
        return es256.public_key_pem(self.store.root_key())

    @property
    def root_fingerprint(self) -> str:
        """Give this to each partner at onboarding; they pin it."""
        return es256.fingerprint(self.root_public_key_pem)

    @property
    def witness_public_key_pem(self) -> str:
        """Give this to the log operator so it accepts this organisation's cosignatures."""
        return es256.public_key_pem(self.store.witness_key())

    # --- the log ---------------------------------------------------------------------------------

    def _included(self, statement: bytes, log_receipt: bytes) -> dict[str, int]:
        result = cose.verify_inclusion_receipt(log_receipt, statement, self._operator)
        if not result.ok or result.log_id != self.config.log_id:
            raise Refused(f"not registered on the pinned log: {result.reason if not result.ok else 'another log'}")
        return {"leaf_index": int(result.leaf_index), "tree_size": int(result.tree_size)}

    async def _register(self, signed: dict[str, Any], key: Any, *, obj: dict[str, Any] | None = None) -> dict[str, Any]:
        statement = cose.make_statement(key, issuer=self.config.org_id, kid=objects.signature_key_id(signed),
                                        preimage_digest=objects.statement_preimage_digest(signed))
        try:
            answer = await self.log.register(statement, obj)
        except LogError as exc:
            raise Refused(str(exc)) from exc
        return {"statement": statement.hex(), "receipt": answer["receipt"],
                **self._included(statement, bytes.fromhex(answer["receipt"]))}

    def _logged(self, obj: dict[str, Any], statement_hex: Any, receipt_hex: Any, *, issuer: str, key_pem: str) -> dict[str, Any]:
        """Check that a partner's object was registered by its issuer under ``key_pem``."""
        try:
            statement, receipt = bytes.fromhex(str(statement_hex)), bytes.fromhex(str(receipt_hex))
            info = cose.read_statement(statement)
            same = info.payload == objects.statement_preimage_digest(obj)
        except (ValueError, cose.COSEError, CanonicalError) as exc:
            raise Refused(f"unreadable log material: {exc}") from exc
        if not same or info.issuer != issuer or info.kid != objects.signature_key_id(obj):
            raise Refused("the Signed Statement is not for this object and signer")
        if not cose.verify_statement(es256.load_public_key(key_pem), statement):
            raise Refused("the Signed Statement does not verify")
        return {"statement": statement.hex(), "receipt": receipt.hex(), **self._included(statement, receipt)}

    async def key_documents(self, issuer: str) -> list[dict[str, Any]]:
        """``issuer``'s logged key-document versions, checked as the verifier does (spec §11.2):
        versions chain; a root change needs a rotation signed by the previous root, logged before
        the new version; the pinned fingerprint is one of the chain's roots."""
        pin = self.root_fingerprint if issuer == self.config.org_id else self.config.pins.get(issuer)
        if not pin:
            raise Refused(f"no pinned root fingerprint for {issuer}")
        try:
            entries = await self.log.key_documents(issuer)
        except LogError as exc:
            raise Refused(str(exc)) from exc
        docs: list[dict[str, Any]] = []
        roots: set[str] = set()
        rotation: dict[str, Any] | None = None
        for entry in entries:
            obj = entry.get("object")
            if not isinstance(obj, dict):
                raise Refused(f"{issuer}'s log entry {entry.get('leaf_index')} has no object")
            last = docs[-1]["object"] if docs else None
            if obj.get("type") == "root-rotation":
                old_root = (last or {}).get("root_public_key_pem")
                if (last is None or rotation is not None or objects.shape_problems(obj) or obj.get("org_id") != issuer
                        or obj.get("previous") != objects.digest_hex(last) or not isinstance(old_root, str)
                        or not objects.verify_signature(obj, old_root)):
                    raise Refused(f"{issuer}'s root rotation at log entry {entry.get('leaf_index')} is not signed by the previous root")
                self._logged(obj, entry.get("statement"), entry.get("receipt"), issuer=issuer, key_pem=old_root)
                rotation = obj
                continue
            position = len(docs) + 1
            root_pem = obj.get("root_public_key_pem")
            problem = None
            if objects.shape_problems(obj) or obj.get("org_id") != issuer or not isinstance(root_pem, str):
                problem = "malformed"
            elif obj.get("version") != position or obj.get("previous") != (objects.digest_hex(last) if last else None):
                problem = "versions do not chain"
            elif last is not None and root_pem != last.get("root_public_key_pem") and (
                    rotation is None or rotation.get("new_root_public_key_pem") != root_pem):
                problem = "the root changed without a rotation signed by the previous root"
            elif rotation is not None and root_pem != rotation.get("new_root_public_key_pem"):
                problem = "a root rotation is open but this version is not under the new root"
            elif not objects.verify_signature(obj, root_pem):
                problem = "not signed by its root"
            else:  # one key per key id across versions, revocations stay: resolved as the verifier does (spec §6.5)
                problem = "; ".join(objects.key_document_problems([d["object"] for d in docs], obj)) or None
            if problem:
                raise Refused(f"{issuer}'s key document v{position}: {problem}")
            entry_material = self._logged(obj, entry.get("statement"), entry.get("receipt"), issuer=issuer, key_pem=root_pem)
            docs.append({"object": obj, **entry_material})
            roots.add(es256.fingerprint(root_pem))
            rotation = None
        if rotation is not None:  # an open rotation, checked above: its new root belongs to the chain
            roots.add(es256.fingerprint(rotation["new_root_public_key_pem"]))
        if docs and pin not in roots:
            raise Refused(f"no version of {issuer}'s key document is under the pinned root")
        return docs

    async def _identity_entries(self, issuer: str) -> list[dict[str, Any]]:
        """Key documents and root rotations, for an export (checked by ``key_documents`` first)."""
        await self.key_documents(issuer)
        entries = await self.log.key_documents(issuer)
        out = []
        for entry in entries:
            obj = entry["object"]
            signer = obj["root_public_key_pem"] if obj.get("type") == "key-document" else None
            if signer is None:  # a rotation: signed by the root of the version before it
                signer = next(e["object"]["root_public_key_pem"] for e in reversed(out) if e["object"].get("type") == "key-document")
            out.append({"object": obj, **self._logged(obj, entry["statement"], entry["receipt"], issuer=issuer, key_pem=signer)})
        return out

    async def _latest_doc(self, issuer: str) -> dict[str, Any]:
        docs = await self.key_documents(issuer)
        if not docs:
            raise Refused(f"{issuer} has no key document on the log")
        return docs[-1]["object"]

    # --- own key documents -----------------------------------------------------------------------

    async def publish_key_document(self, *, rotate: bool = False, revoke_current: bool = False) -> dict[str, Any]:
        """Register the next version: the current signing key (a new one with ``rotate``), keys
        revoked so far, and the configured agents. Signed by the root, which never leaves here."""
        existing = await self.key_documents(self.config.org_id)
        now = self.now()
        current = self.store.current_signing_key()
        if revoke_current and current is not None:
            self.store.revoke_signing_key(current["key_id"], self._stamp(now))
            current = None
        if rotate or current is None:
            self.store.new_signing_key(not_before=self._stamp(now - SKEW),
                                       not_after=self._stamp(now + timedelta(days=self.config.signing_key_days)))
            current = self.store.current_signing_key()
        keys = [objects.signing_key_entry(current["public_key_pem"], not_before=current["not_before"], not_after=current["not_after"])]
        keys += [objects.signing_key_entry(r["public_key_pem"], not_before=r["not_before"], not_after=r["not_after"],
                                           revoked_at=r["revoked_at"]) for r in self.store.revoked_signing_keys()]
        agents = []
        for agent in self.config.agents:
            registered = self.store.get(f"agent:{agent['agent_id']}")
            if registered is None:
                registered = self._stamp(now - SKEW)
                self.store.put(f"agent:{agent['agent_id']}", registered)
            agents.append(objects.agent_entry(agent["agent_id"], name=agent["name"], kind=agent.get("kind", "agent"),
                                              registered_at=registered))
        last = existing[-1]["object"] if existing else None
        body = objects.key_document(
            org_id=self.config.org_id, org_name=self.config.org_name, version=len(existing) + 1,
            previous=objects.digest_hex(last) if last else None, issued_at=self._stamp(now),
            expires_at=self._stamp(now + timedelta(days=self.config.signing_key_days)),
            root_public_key_pem=self.root_public_key_pem, signing_keys=keys, agents=agents,
        )
        root = self.store.root_key()
        signed = objects.sign(body, root)
        await self._register(signed, root, obj=signed)
        return signed

    async def rotate_root(self) -> dict[str, Any]:
        """Move to a new root (spec §6.4): the current root signs a rotation naming it, then the
        next key-document version is signed by the new root. Safe to run again after a failure."""
        docs = await self.key_documents(self.config.org_id)
        if not docs:
            raise Refused("publish a key document first")
        entries = await self.log.key_documents(self.config.org_id)
        open_rotation = entries[-1]["object"] if entries and entries[-1]["object"].get("type") == "root-rotation" else None
        next_root = self.store.next_root_key()
        next_pem = es256.public_key_pem(next_root)
        if open_rotation is None:
            old_root = self.store.root_key()
            rotation = objects.sign(objects.root_rotation(
                org_id=self.config.org_id, previous=objects.digest_hex(docs[-1]["object"]),
                new_root_public_key_pem=next_pem, rotated_at=self._stamp()), old_root)
            await self._register(rotation, old_root, obj=rotation)
        elif open_rotation.get("new_root_public_key_pem") != next_pem:
            raise Refused("a rotation to a different root is open on the log; finish it with the root it names")
        self.store.promote_next_root()  # registered: from here on the new root is this organisation's root
        return await self.publish_key_document()

    async def _ready_signer(self, agent_id: str | None) -> tuple[Any, str]:
        current = self.store.current_signing_key()
        if current is None:
            raise Refused("publish a key document first")
        doc = await self._latest_doc(self.config.org_id)
        now = self.now()
        if _key_in(doc, current["key_id"], now) is None:
            raise Refused(f"signing key {current['key_id']} is not valid in your latest key document; publish a new version")
        if agent_id is not None and not _agent_in(doc, agent_id, now):
            raise Refused(f"agent {agent_id} is not listed in your key document; add it to the config and publish a new version")
        return self.store.signing_key(current["key_id"]), current["key_id"]

    def _decision(self, outcome: str, rule_id: str | None) -> dict[str, Any]:
        return objects.boundary_decision(outcome, rule_id=rule_id, policy_version=self.config.policy_version,
                                         policy_content_hash=self.config.policy_content_hash)

    # --- receiving -------------------------------------------------------------------------------

    async def receive(self, block: dict[str, Any] | None, *, tool_name: str, arguments: dict[str, Any] | None,
                      decide: Decide | None = None) -> Inbound:
        """Check an inbound receipt, apply ``decide`` (your own boundary; default: allow), and sign,
        register and keep an acknowledgement. Raises ``Refused`` when the receipt does not check out."""
        receipt = (block or {}).get("receipt")
        sender = (receipt.get("sender") or {}) if isinstance(receipt, dict) else {}
        async with self._exclusive("receive", str(sender.get("org_id") or "")):
            return await self._receive_unlocked(block, tool_name=tool_name, arguments=arguments, decide=decide)

    async def _receive_unlocked(self, block: dict[str, Any] | None, *, tool_name: str, arguments: dict[str, Any] | None,
                                decide: Decide | None = None) -> Inbound:
        receipt = (block or {}).get("receipt")
        if not isinstance(receipt, dict) or receipt.get("type") != "receipt" or objects.shape_problems(receipt):
            raise Refused("no well-formed receipt in the Shared Record block")
        sender, receiver = receipt.get("sender") or {}, receipt.get("receiver") or {}
        sender_org, exchange_id = str(sender.get("org_id") or ""), str(receipt.get("exchange_id") or "")
        if receiver.get("org_id") != self.config.org_id:
            raise Refused("this receipt is addressed to another organisation")
        existing = self.store.exchange("receiver", exchange_id)
        if existing is not None:
            return self._inbound(existing)
        if sender.get("key_id") != objects.signature_key_id(receipt):
            raise Refused("the receipt names a different sender key than the one that signed it")
        created = parse_timestamp(receipt.get("created_at"))
        if created is None:
            raise Refused("the receipt has no valid creation time")
        now = self.now()
        if abs(created - now) > timedelta(seconds=self.config.max_clock_skew_seconds):
            raise Refused(f"the receipt's created_at {receipt.get('created_at')} is more than {self.config.max_clock_skew_seconds} "
                          f"seconds from this receiver's clock ({self._stamp(now)})")
        deadline = parse_timestamp(receipt.get("ack_deadline"))
        if deadline is None or deadline < created:
            raise Refused("the receipt's ack_deadline is before its created_at")
        sender_doc = await self._latest_doc(sender_org)
        expires = parse_timestamp(sender_doc.get("expires_at"))
        if expires is None or created > expires:
            raise Refused(f"{sender_org}'s key document v{sender_doc.get('version')} expired at {sender_doc.get('expires_at')}")
        key_pem = _key_in(sender_doc, sender.get("key_id"), created)
        if key_pem is None or not objects.verify_signature(receipt, key_pem):
            raise Refused(f"not signed by a valid key in {sender_org}'s key document")
        if not _agent_in(sender_doc, sender.get("agent_id"), created):
            raise Refused("the sending agent is not listed in the sender's key document")
        receipt_entry = self._logged(receipt, block.get("statement"), block.get("log_receipt"), issuer=sender_org, key_pem=key_pem)
        sequence = receipt.get("sequence")
        if not isinstance(sequence, int) or self.store.db.execute(
            "SELECT 1 FROM exchanges WHERE role = 'receiver' AND counterparty = ? AND sequence = ?", (sender_org, sequence)
        ).fetchone():
            raise Refused("this sender already used that sequence number with you (possible replay)")
        # The pair's chain (spec §5.2): the next number, linked to the last receipt accepted from this sender.
        last = self.store.last_sequence("receiver", sender_org)
        expected = int(last["sequence"]) + 1 if last is not None else 1
        if sequence != expected:
            missing = f"receipt {expected} was" if sequence - 1 == expected else f"receipts {expected}..{sequence - 1} were"
            raise Refused(f"sequence gap: the last receipt accepted from {sender_org} is number {expected - 1} and this one is "
                          f"{sequence}; {missing} never accepted here and must be delivered first")
        if receipt.get("previous_receipt") != (objects.digest_hex(json.loads(last["receipt"])) if last is not None else None):
            raise Refused(f"previous_receipt does not name the last receipt accepted from {sender_org} (a fork of the pair's chain)")

        delivered = receipt.get("delivered") is True
        content = salt = None
        if delivered:
            try:
                content = base64.b64decode(str(block.get("content_b64") or ""), validate=True)
                salt = bytes.fromhex(str(block.get("salt_hex") or ""))
            except (binascii.Error, ValueError):
                content = salt = None
            matched = (content is not None and salt is not None
                       and objects.content_commitment(salt, content) == (receipt.get("content") or {}).get("commitment")
                       and content == tool_call_content(tool_name, arguments or {}))
            check = "matched" if matched else "mismatch"
        else:
            check = "not_delivered"
        if check == "matched":
            outcome, rule = (decide or (lambda _n, _a: ("allowed", None)))(tool_name, arguments or {})
        elif check == "mismatch":
            outcome, rule = "blocked", "content_mismatch"
        else:
            outcome, rule = "allowed", None  # the notice was accepted; nothing was delivered to decide on

        key, key_id = await self._ready_signer(str(receiver.get("agent_id") or ""))
        ack = objects.sign(objects.acknowledgement(
            exchange_id=exchange_id, receipt_digest=objects.digest_hex(receipt),
            receiver={"org_id": self.config.org_id, "agent_id": str(receiver.get("agent_id")), "key_id": key_id},
            content_check=check, decision=self._decision(outcome, rule), acknowledged_at=self._stamp(now),
        ), key)
        ack_entry = await self._register(ack, key)
        self.store.add_exchange(
            role="receiver", exchange_id=exchange_id, counterparty=sender_org, sequence=sequence, delivered=int(delivered),
            receipt=receipt, receipt_entry=receipt_entry, ack=ack, ack_entry=ack_entry, content=content, salt=salt,
            ack_deadline=str(receipt.get("ack_deadline") or ""), retain_until=self._stamp(now + timedelta(days=self.config.retention_days)),
            created_at=self._stamp(now),
        )
        return self._inbound(self.store.exchange("receiver", exchange_id))

    def _inbound(self, row: Any) -> Inbound:
        ack, entry = json.loads(row["ack"]), json.loads(row["ack_entry"])
        decision = ack.get("boundary_decision") or {}
        return Inbound(
            exchange_id=row["exchange_id"], delivered=bool(row["delivered"]), content_check=ack.get("content_check"),
            outcome=decision.get("outcome"), rule_id=decision.get("rule_id"),
            meta={META_KEY: {"acknowledgement": ack, "statement": entry["statement"], "log_receipt": entry["receipt"]}},
        )

    # --- sending ---------------------------------------------------------------------------------

    async def send(self, *, to_org: str, to_agent: str, agent_id: str, tool_name: str, arguments: dict[str, Any],
                   outcome: str = "allowed", rule_id: str | None = None) -> Outbound:
        """Sign and register a receipt for a call to ``to_org``'s agent. ``outcome`` is your own
        boundary's decision; for ``blocked`` do not send the call, send ``meta`` as a notice."""
        async with self._exclusive("send", to_org):
            return await self._send_unlocked(to_org=to_org, to_agent=to_agent, agent_id=agent_id, tool_name=tool_name,
                                             arguments=arguments, outcome=outcome, rule_id=rule_id)

    async def _send_unlocked(self, *, to_org: str, to_agent: str, agent_id: str, tool_name: str, arguments: dict[str, Any],
                             outcome: str, rule_id: str | None) -> Outbound:
        await self._latest_doc(to_org)  # the partner must be pinned and on the log
        key, key_id = await self._ready_signer(agent_id)
        delivered = outcome != "blocked"
        content = tool_call_content(tool_name, arguments)
        salt = objects.new_salt()
        now = self.now()
        last = self.store.last_sequence("sender", to_org)
        deadline = now + timedelta(seconds=self.config.ack_deadline_seconds)
        receipt = objects.sign(objects.receipt(
            exchange_id=uuid.uuid4().hex, sequence=(last["sequence"] + 1) if last else 1,
            previous_receipt=objects.digest_hex(json.loads(last["receipt"])) if last else None,
            sender={"org_id": self.config.org_id, "agent_id": agent_id, "key_id": key_id},
            receiver={"org_id": to_org, "agent_id": to_agent},
            commitment=objects.content_commitment(salt, content), media_type=MEDIA_TYPE,
            decision=self._decision(outcome, rule_id), delivered=delivered,
            created_at=self._stamp(now), ack_deadline=self._stamp(deadline),
        ), key)
        entry = await self._register(receipt, key)
        self.store.add_exchange(
            role="sender", exchange_id=receipt["exchange_id"], counterparty=to_org, sequence=receipt["sequence"],
            delivered=int(delivered), receipt=receipt, receipt_entry=entry, content=content, salt=salt,
            ack_deadline=receipt["ack_deadline"], retain_until=self._stamp(now + timedelta(days=self.config.retention_days)),
            created_at=self._stamp(now),
        )
        block: dict[str, Any] = {"receipt": receipt, "statement": entry["statement"], "log_receipt": entry["receipt"],
                                 "log_id": self.config.log_id}
        if delivered:
            block.update(content_b64=base64.b64encode(content).decode("ascii"), salt_hex=salt.hex())
        return Outbound(receipt["exchange_id"], delivered, {META_KEY: block})

    async def accept_acknowledgement(self, exchange_id: str, result_meta: dict[str, Any] | None) -> str:
        """Check and keep the partner's acknowledgement from a result's ``_meta``. Returns a status."""
        row = self.store.exchange("sender", exchange_id)
        if row is None:
            return "unknown exchange"
        if row["ack"] is not None:
            return "already acknowledged"
        block = (result_meta or {}).get(META_KEY)
        ack = block.get("acknowledgement") if isinstance(block, dict) else None
        if not isinstance(ack, dict):
            return "none"
        receipt = json.loads(row["receipt"])
        receiver = ack.get("receiver") or {}
        if (ack.get("type") != "acknowledgement" or objects.shape_problems(ack) or ack.get("exchange_id") != exchange_id
                or ack.get("receipt") != objects.digest_hex(receipt) or receiver.get("org_id") != row["counterparty"]
                or receiver.get("agent_id") != (receipt.get("receiver") or {}).get("agent_id")):
            return "invalid: does not match the receipt"
        try:
            doc = await self._latest_doc(row["counterparty"])
            at = parse_timestamp(ack.get("acknowledged_at")) or self.now()
            key_pem = _key_in(doc, objects.signature_key_id(ack), at)
            if key_pem is None or not objects.verify_signature(ack, key_pem):
                return "invalid: not signed by a valid key in the partner's key document"
            entry = self._logged(ack, block.get("statement"), block.get("log_receipt"), issuer=row["counterparty"], key_pem=key_pem)
        except Refused as exc:
            return f"invalid: {exc}"
        self.store.update_exchange(row["id"], ack=ack, ack_entry=entry)
        return "acknowledged"

    async def record_missing_acknowledgements(self) -> int:
        """Sign and register a missing-acknowledgement record for each delivered receipt past its deadline."""
        now = self.now()
        recorded = 0
        for row in self.store.overdue(self._stamp(now)):
            key, key_id = await self._ready_signer(None)
            record = objects.sign(objects.missing_acknowledgement(
                exchange_id=row["exchange_id"], receipt_digest=objects.digest_hex(json.loads(row["receipt"])),
                recorded_by={"org_id": self.config.org_id, "key_id": key_id}, ack_deadline=row["ack_deadline"],
                recorded_at=self._stamp(now),
            ), key)
            entry = await self._register(record, key)
            self.store.update_exchange(row["id"], missing=json.dumps(record), missing_entry=json.dumps(entry))
            recorded += 1
        return recorded

    # --- witnessing ------------------------------------------------------------------------------

    async def witness(self) -> dict[str, Any] | None:
        """Cosign the log's latest checkpoint if it extends the last one this witness cosigned.
        Raises ``Inconsistent`` (keep the message: it is evidence) when it does not."""
        if not self.config.witness_id:
            raise Refused("set witness_id in the config")
        item = await self.log.latest_checkpoint()
        if not item:
            return None
        cp = item.get("checkpoint") or {}
        if (cp.get("type") != "checkpoint" or objects.shape_problems(cp) or cp.get("log_id") != self.config.log_id
                or not objects.verify_signature(cp, self.config.operator_public_key_pem)):
            raise Refused("the latest checkpoint is not signed by the pinned log operator key")
        size, root = int(cp["tree_size"]), bytes.fromhex(cp["root"])
        state = self.store.get("witness_state")
        if state:
            old_size, old_root = int(state["tree_size"]), bytes.fromhex(state["root"])
            if size < old_size:
                raise Inconsistent(f"the log now reports tree size {size}, smaller than {old_size} which this witness cosigned")
            if size == old_size:
                if root != old_root:
                    raise Inconsistent(f"tree size {size} now has a different root than the one this witness cosigned")
                return None
            path = [bytes.fromhex(p) for p in await self.log.consistency(old_size, size)]
            if not merkle.verify_consistency(old_size, size, old_root, root, path):
                raise Inconsistent(f"checkpoint {size} is not consistent with checkpoint {old_size} this witness cosigned")
        cosignature = objects.sign(objects.cosignature(
            log_id=self.config.log_id, checkpoint_digest=objects.digest_hex(cp), witness_id=self.config.witness_id,
            cosigned_at=self._stamp(),
        ), self.store.witness_key())
        answer = await self.log.cosign(cosignature)
        self.store.put("witness_state", {"tree_size": size, "root": root.hex()})
        return answer

    # --- export and retention --------------------------------------------------------------------

    async def export(self, exchange_ids: list[str], *, reveal: list[str] = ()) -> dict[str, Any]:
        """Evidence (spec §10, §12) for a third party, who verifies it with its own trust configuration."""
        if not set(reveal) <= set(exchange_ids):
            raise Refused("you can only reveal exchanges that are in the export")
        rows = self.store.exchanges(list(exchange_ids))
        missing = sorted(set(exchange_ids) - {r["exchange_id"] for r in rows})
        if missing:
            raise Refused(f"not in your records (or past retention): {', '.join(missing)}")
        item = await self.log.latest_checkpoint(witnessed=True)
        if not item:
            raise Refused("the log has no witnessed checkpoint yet")
        target = int(item["checkpoint"]["tree_size"])

        async def with_proof(obj: dict[str, Any], material: dict[str, Any]) -> dict[str, Any]:
            entry = {"object": obj, "statement": material["statement"], "receipt": material["receipt"]}
            size = int(material["tree_size"])
            if size <= target:
                entry["consistency_to_checkpoint"] = {
                    "tree_size": target, "path": [] if size == target else await self.log.consistency(size, target)}
            return entry

        entries: list[dict[str, Any]] = []
        orgs = {self.config.org_id}
        revealed = []
        for row in rows:
            orgs.add(row["counterparty"])
            for obj_col, entry_col in (("receipt", "receipt_entry"), ("ack", "ack_entry"), ("missing", "missing_entry")):
                if row[obj_col] and row[entry_col]:
                    entries.append(await with_proof(json.loads(row[obj_col]), json.loads(row[entry_col])))
            if row["exchange_id"] in reveal:
                if row["content"] is None or row["salt"] is None:
                    raise Refused(f"the content of {row['exchange_id']} is not held (not delivered to you)")
                revealed.append({"exchange_id": row["exchange_id"], "content_b64": base64.b64encode(row["content"]).decode("ascii"),
                                 "salt_hex": bytes(row["salt"]).hex()})
        for org in sorted(orgs):
            for identity in await self._identity_entries(org):
                entries.append(await with_proof(identity["object"], identity))
        return {
            "format": EVIDENCE_FORMAT,
            "entries": entries,
            "checkpoints": [{"checkpoint": item["checkpoint"], "cosignatures": item.get("cosignatures") or []}],
            "revealed": revealed,
            "produced_by": {"exporter": "norcaster-counterparty", "exported_at": self._stamp(),
                            "exporting_org_id": self.config.org_id},
            "honesty_boundary": HONESTY_BOUNDARY,
        }

    def purge_expired(self) -> int:
        """Delete records past their retention date (the log keeps its hashes)."""
        return self.store.purge(self._stamp())
