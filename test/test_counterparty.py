"""Two counterparties exchange tool calls through an in-memory log; synthetic data only.

The log stand-in here applies no registration policy (the Norcaster log does); every check
the component makes on what it reads from the log is exercised: pinned roots, pinned
operator key, inclusion receipts, witnessed checkpoints and consistency.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from norcaster_verify.shared_record import cose, es256, merkle, objects
from norcaster_verify.shared_record.canonical import format_timestamp
from norcaster_verify.shared_record.verify import verify_evidence

from norcaster_counterparty import META_KEY, Config, Counterparty, Inconsistent, Refused

LOG_ID = "log.test.example"


class MemoryLog:
    def __init__(self, clock=None) -> None:
        self.clock = clock  # registration time (the log receipt's iat) follows the parties' test clock
        self.operator = es256.generate_private_key()
        self.operator_pem = es256.public_key_pem(self.operator)
        self.entries: list[dict] = []
        self.checkpoints: list[dict] = []
        self.witnesses: dict[str, str] = {}
        self.quorum = 2

    def _leaves(self, size: int | None = None) -> list[bytes]:
        return [merkle.leaf_hash(bytes.fromhex(e["statement"])) for e in self.entries[:size]]

    async def register(self, statement: bytes, obj=None):
        for i, e in enumerate(self.entries):
            if e["statement"] == statement.hex():
                return {"leaf_index": i, "receipt": e["receipt"], "existing": True}
        info = cose.read_statement(statement)
        index = len(self.entries)
        leaves = self._leaves() + [merkle.leaf_hash(statement)]
        receipt = cose.make_inclusion_receipt(self.operator, log_id=LOG_ID, kid=es256.key_id(self.operator_pem),
                                              tree_size=index + 1, leaf_index=index, path=merkle.inclusion_path(index, leaves),
                                              root=merkle.tree_hash(leaves),
                                              issued_at=int(self.clock().timestamp()) if self.clock else 1_790_000_000)
        self.entries.append({"issuer": info.issuer, "statement": statement.hex(), "receipt": receipt.hex(),
                             "object": obj if obj and obj.get("type") in ("key-document", "root-rotation") else None,
                             "leaf_index": index})
        return {"leaf_index": index, "receipt": receipt.hex(), "existing": False}

    async def key_documents(self, issuer: str):
        return [e for e in self.entries if e["issuer"] == issuer and e["object"]]

    def publish_checkpoint(self) -> dict:
        cp = objects.sign(objects.checkpoint(log_id=LOG_ID, tree_size=len(self.entries), root=merkle.tree_hash(self._leaves()).hex(),
                                             issued_at="2026-10-06T12:00:00Z"), self.operator)
        self.checkpoints.append({"checkpoint": cp, "cosignatures": []})
        return cp

    async def latest_checkpoint(self, *, witnessed: bool = False):
        for item in reversed(self.checkpoints):
            ok = {c["witness_id"] for c in item["cosignatures"]
                  if c["witness_id"] in self.witnesses and objects.verify_signature(c, self.witnesses[c["witness_id"]])}
            if not witnessed or len(ok) >= self.quorum:
                return item
        return None

    async def consistency(self, old: int, new: int):
        return [p.hex() for p in merkle.consistency_path(old, self._leaves(new))] if old != new else []

    async def cosign(self, cosignature: dict):
        for item in self.checkpoints:
            if objects.digest_hex(item["checkpoint"]) == cosignature["checkpoint"]:
                item["cosignatures"].append(cosignature)
                return {"witnessed": len(item["cosignatures"]) >= self.quorum}
        raise AssertionError("unknown checkpoint")


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 10, 6, 9, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now


def _party(tmp_path: Path, log: MemoryLog, clock: Clock, org: str, agent: str, pins: dict) -> Counterparty:
    config = Config(org_id=org, org_name=f"{org} (synthetic)", state_dir=tmp_path / org, log_url="http://log.invalid",
                    log_id=LOG_ID, operator_public_key_pem=log.operator_pem, pins=pins,
                    agents=[{"agent_id": agent, "name": f"{agent} (synthetic)", "kind": "agent"}],
                    witness_id=f"witness.{org}", policy_version="4", policy_content_hash="ab" * 32, ack_deadline_seconds=3600)
    return Counterparty(config, log, clock=clock)


def _pair(tmp_path: Path):
    clock = Clock()
    log = MemoryLog(clock)
    a = _party(tmp_path, log, clock, "org.a.example", "agent.a", {})
    b = _party(tmp_path, log, clock, "org.b.example", "agent.b", {})
    a.config.pins["org.b.example"] = b.root_fingerprint  # onboarding: each pins the other's root
    b.config.pins["org.a.example"] = a.root_fingerprint
    log.witnesses = {a.config.witness_id: a.witness_public_key_pem, b.config.witness_id: b.witness_public_key_pem}
    return log, clock, a, b


def test_keys_are_local_and_private(tmp_path):
    _, _, a, _ = _pair(tmp_path)
    key_file = tmp_path / "org.a.example" / "keys" / "root.key"
    assert key_file.exists() and b"PRIVATE KEY" in key_file.read_bytes()
    if os.name != "nt":  # Windows has no POSIX modes (chmod sets only read-only): the README says to use NTFS permissions
        assert (key_file.stat().st_mode & 0o777) == 0o600
    assert len(a.root_fingerprint) == 64


def test_a_full_exchange_both_ways_witnessed_and_exported(tmp_path):
    async def run():
        log, clock, a, b = _pair(tmp_path)
        await a.publish_key_document()
        await b.publish_key_document()

        # A -> B, delivered and acknowledged.
        out = await a.send(to_org="org.b.example", to_agent="agent.b", agent_id="agent.a", tool_name="lookup",
                           arguments={"case": "synthetic-1", "amount": 10})
        inbound = await b.receive(out.meta[META_KEY], tool_name="lookup", arguments={"case": "synthetic-1", "amount": 10})
        assert inbound.content_check == "matched" and inbound.run_tool
        assert await a.accept_acknowledgement(out.exchange_id, inbound.meta) == "acknowledged"
        # A retried delivery returns the same acknowledgement.
        again = await b.receive(out.meta[META_KEY], tool_name="lookup", arguments={"case": "synthetic-1", "amount": 10})
        assert again.meta == inbound.meta

        # A -> B blocked by A's boundary: a notice, no content.
        notice = await a.send(to_org="org.b.example", to_agent="agent.b", agent_id="agent.a", tool_name="lookup",
                              arguments={"note": "id 19800101-0000 (synthetic)"}, outcome="blocked", rule_id="pii.national_id")
        assert "content_b64" not in notice.meta[META_KEY] and not notice.delivered
        n_in = await b.receive(notice.meta[META_KEY], tool_name="norcaster_shared_record_notice", arguments={})
        assert n_in.content_check == "not_delivered" and not n_in.run_tool
        assert await a.accept_acknowledgement(notice.exchange_id, n_in.meta) == "acknowledged"

        # B's own boundary blocks an inbound call; content tampered in transit is a mismatch.
        refused = await a.send(to_org="org.b.example", to_agent="agent.b", agent_id="agent.a", tool_name="transfer", arguments={"x": 1})
        r_in = await b.receive(refused.meta[META_KEY], tool_name="transfer", arguments={"x": 1}, decide=lambda n, args: ("blocked", "b.rule.7"))
        assert r_in.outcome == "blocked" and r_in.rule_id == "b.rule.7" and not r_in.run_tool
        assert await a.accept_acknowledgement(refused.exchange_id, r_in.meta) == "acknowledged"
        tampered = await a.send(to_org="org.b.example", to_agent="agent.b", agent_id="agent.a", tool_name="transfer", arguments={"x": 2})
        t_in = await b.receive(tampered.meta[META_KEY], tool_name="transfer", arguments={"x": 999})
        assert t_in.content_check == "mismatch" and t_in.outcome == "blocked"
        assert await a.accept_acknowledgement(tampered.exchange_id, t_in.meta) == "acknowledged"

        # B -> A, never acknowledged: B records it after the deadline.
        silent = await b.send(to_org="org.a.example", to_agent="agent.a", agent_id="agent.b", tool_name="status", arguments={})
        clock.now += timedelta(hours=2)
        assert await b.record_missing_acknowledgements() == 1
        assert await b.record_missing_acknowledgements() == 0

        # Witnesses cosign; a third party verifies each side's export with its own trust config.
        log.publish_checkpoint()
        assert (await a.witness()) is not None and (await b.witness())["witnessed"] is True
        assert await a.witness() is None  # nothing new
        trust = {"orgs": {"org.a.example": {"root_fingerprint": a.root_fingerprint},
                          "org.b.example": {"root_fingerprint": b.root_fingerprint}},
                 "log": {"log_id": LOG_ID, "operator_public_key_pem": log.operator_pem, "witnesses": log.witnesses, "quorum": 2}}
        ids = [out.exchange_id, notice.exchange_id, refused.exchange_id]
        report = verify_evidence(await a.export(ids, reveal=[out.exchange_id]), trust)
        assert report["ok"], report
        states = {x["exchange_id"]: x["state"] for x in report["exchanges"]}
        # refused: Birch's own boundary blocked the call it acknowledged (spec §11.5, acknowledged_blocked)
        assert states == {out.exchange_id: "acknowledged", notice.exchange_id: "not_delivered", refused.exchange_id: "acknowledged_blocked"}
        b_report = verify_evidence(await b.export([silent.exchange_id, tampered.exchange_id]), trust)
        assert b_report["ok"], b_report
        assert {x["exchange_id"]: x["state"] for x in b_report["exchanges"]}[silent.exchange_id] == "unacknowledged"

        # A rewritten log is caught by the witness.
        log.entries[0]["statement"] = log.entries[1]["statement"]
        log.publish_checkpoint()
        with pytest.raises(Inconsistent):
            await a.witness()

    asyncio.run(run())


def test_partners_are_trusted_only_through_pinned_roots_and_the_pinned_log(tmp_path):
    async def run():
        log, clock, a, b = _pair(tmp_path)
        await a.publish_key_document()
        await b.publish_key_document()
        out = await a.send(to_org="org.b.example", to_agent="agent.b", agent_id="agent.a", tool_name="t", arguments={})

        b.config.pins["org.a.example"] = "00" * 32  # wrong pin
        with pytest.raises(Refused, match="pinned root"):
            await b.receive(out.meta[META_KEY], tool_name="t", arguments={})
        b.config.pins["org.a.example"] = a.root_fingerprint

        forged = json.loads(json.dumps(out.meta[META_KEY]))
        forged["receipt"]["sequence"] = 99  # breaks A's signature
        with pytest.raises(Refused, match="not signed"):
            await b.receive(forged, tool_name="t", arguments={})

        other_log = es256.generate_private_key()  # a receipt from a log B does not pin
        statement = bytes.fromhex(out.meta[META_KEY]["statement"])
        bogus = cose.make_inclusion_receipt(other_log, log_id=LOG_ID, kid="x", tree_size=1, leaf_index=0, path=[],
                                            root=merkle.leaf_hash(statement), issued_at=1)
        with pytest.raises(Refused, match="pinned log"):
            await b.receive({**out.meta[META_KEY], "log_receipt": bogus.hex()}, tool_name="t", arguments={})

        inbound = await b.receive(out.meta[META_KEY], tool_name="t", arguments={})
        replay = objects.sign({**objects.body_of(out.meta[META_KEY]["receipt"]), "exchange_id": "e" * 32},
                              a.store.signing_key(a.store.current_signing_key()["key_id"]))
        st = cose.make_statement(a.store.signing_key(a.store.current_signing_key()["key_id"]), issuer="org.a.example",
                                 kid=objects.signature_key_id(replay), preimage_digest=objects.statement_preimage_digest(replay))
        reg = await log.register(st)
        with pytest.raises(Refused, match="sequence"):
            await b.receive({**out.meta[META_KEY], "receipt": replay, "statement": st.hex(), "log_receipt": reg["receipt"]},
                            tool_name="t", arguments={})
        assert inbound.run_tool

        # An unlisted agent cannot send; a rotated key needs a new key-document version first.
        with pytest.raises(Refused, match="not listed"):
            await a.send(to_org="org.b.example", to_agent="agent.b", agent_id="agent.unknown", tool_name="t", arguments={})
        a.store.new_signing_key(not_before=format_timestamp(clock.now - timedelta(minutes=5)),
                                not_after=format_timestamp(clock.now + timedelta(days=30)))
        with pytest.raises(Refused, match="publish a new version"):
            await a.send(to_org="org.b.example", to_agent="agent.b", agent_id="agent.a", tool_name="t", arguments={})
        doc = await a.publish_key_document()
        assert doc["version"] == 2
        assert (await a.send(to_org="org.b.example", to_agent="agent.b", agent_id="agent.a", tool_name="t", arguments={})).delivered

    asyncio.run(run())


def test_root_rotation_keeps_existing_pins_working(tmp_path):
    async def run():
        log, clock, a, b = _pair(tmp_path)
        await a.publish_key_document()
        await b.publish_key_document()
        old_fingerprint = a.root_fingerprint
        before = await a.send(to_org="org.b.example", to_agent="agent.b", agent_id="agent.a", tool_name="t", arguments={"n": 1})
        await a.accept_acknowledgement(before.exchange_id, (await b.receive(before.meta[META_KEY], tool_name="t", arguments={"n": 1})).meta)

        doc = await a.rotate_root()
        assert doc["version"] == 2 and a.root_fingerprint != old_fingerprint
        assert (tmp_path / "org.a.example" / "keys" / f"root-{old_fingerprint[:16]}.key").exists()  # the old root is archived
        assert b.config.pins["org.a.example"] == old_fingerprint  # B pinned A's old root and keeps working
        after = await a.send(to_org="org.b.example", to_agent="agent.b", agent_id="agent.a", tool_name="t", arguments={"n": 2})
        inbound = await b.receive(after.meta[META_KEY], tool_name="t", arguments={"n": 2})
        assert inbound.run_tool and await a.accept_acknowledgement(after.exchange_id, inbound.meta) == "acknowledged"

        log.publish_checkpoint()
        await a.witness()
        await b.witness()
        evidence = await b.export([before.exchange_id, after.exchange_id])
        assert sum(1 for e in evidence["entries"] if e["object"]["type"] == "root-rotation") == 1
        for pin in (old_fingerprint, a.root_fingerprint):  # partners onboarded before or after the rotation
            trust = {"orgs": {"org.a.example": {"root_fingerprint": pin}, "org.b.example": {"root_fingerprint": b.root_fingerprint}},
                     "log": {"log_id": LOG_ID, "operator_public_key_pem": log.operator_pem, "witnesses": log.witnesses, "quorum": 2}}
            report = verify_evidence(evidence, trust)
            assert report["ok"], report

        # Someone with a key of their own cannot rotate A's identity: B refuses A's chain.
        thief = es256.generate_private_key()
        thief_pem = es256.public_key_pem(thief)
        last = (await b.key_documents("org.a.example"))[-1]["object"]
        forged = objects.sign(objects.root_rotation(org_id="org.a.example", previous=objects.digest_hex(last),
                                                    new_root_public_key_pem=thief_pem, rotated_at="2026-10-06T10:00:00Z"), thief)
        await log.register(cose.make_statement(thief, issuer="org.a.example", kid=es256.key_id(thief_pem),
                                               preimage_digest=objects.statement_preimage_digest(forged)), forged)
        with pytest.raises(Refused, match="previous root"):
            await b.key_documents("org.a.example")

    asyncio.run(run())


def test_cli_init_prints_what_partners_and_the_log_operator_need(tmp_path, capsys):
    from norcaster_counterparty.cli import main

    log = MemoryLog()
    (tmp_path / "operator.pem").write_text(log.operator_pem)
    (tmp_path / "counterparty.json").write_text(json.dumps({
        "org_id": "org.c.example", "log_url": "http://log.invalid", "log_id": LOG_ID,
        "operator_public_key_file": "operator.pem", "witness_id": "witness.c", "state_dir": "state",
        "agents": [{"agent_id": "agent.c", "name": "agent c (synthetic)"}],
    }))
    assert main(["--config", str(tmp_path / "counterparty.json"), "init"]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert len(printed["root_fingerprint"]) == 64 and printed["witness_public_key_pem"].startswith("-----BEGIN PUBLIC KEY-----")


def test_receive_refuses_clock_skew_bad_deadlines_gaps_and_forks(tmp_path):
    """Pre-review Q14 and F-07: the receiver refuses (and signs nothing) when created_at is far from its
    clock, when ack_deadline is before created_at, when a sequence number is skipped, and when
    previous_receipt does not name the last receipt it accepted from that sender."""
    async def run():
        log, clock, a, b = _pair(tmp_path)
        await a.publish_key_document()
        await b.publish_key_document()
        key = a.store.signing_key(a.store.current_signing_key()["key_id"])
        first = (await a.send(to_org="org.b.example", to_agent="agent.b", agent_id="agent.a", tool_name="t", arguments={})).meta[META_KEY]

        async def deliver(**changes):
            receipt = objects.sign({**objects.body_of(first["receipt"]), **changes}, key)
            statement = cose.make_statement(key, issuer="org.a.example", kid=objects.signature_key_id(receipt),
                                            preimage_digest=objects.statement_preimage_digest(receipt))
            registered = await log.register(statement)
            return await b.receive({**first, "receipt": receipt, "statement": statement.hex(), "log_receipt": registered["receipt"]},
                                   tool_name="t", arguments={})

        with pytest.raises(Refused, match="more than 300 seconds from this receiver's clock"):
            await deliver(created_at=format_timestamp(clock.now - timedelta(minutes=10)))
        with pytest.raises(Refused, match="ack_deadline is before its created_at"):
            await deliver(ack_deadline=format_timestamp(clock.now - timedelta(seconds=1)))
        second = {"exchange_id": "f" * 32, "sequence": 2, "previous_receipt": objects.digest_hex(first["receipt"])}
        with pytest.raises(Refused, match="sequence gap: .* receipt 1 was never accepted here"):
            await deliver(**second)
        assert (await b.receive(first, tool_name="t", arguments={})).run_tool
        with pytest.raises(Refused, match="fork of the pair's chain"):
            await deliver(**{**second, "previous_receipt": "ab" * 32})
        assert (await deliver(**second)).run_tool  # the next receipt, chained: accepted

    asyncio.run(run())


def test_a_partner_key_document_whose_key_id_names_another_key_is_refused(tmp_path):
    """Pre-review F-03: a version listing the sender's key id with another public key makes the chain
    invalid for the receiver as for the verifier, so the two never resolve a key id differently."""
    async def run():
        log, _, a, b = _pair(tmp_path)
        v1 = await a.publish_key_document()
        await b.publish_key_document()
        out = await a.send(to_org="org.b.example", to_agent="agent.b", agent_id="agent.a", tool_name="t", arguments={})
        entry = v1["signing_keys"][0]
        planted = {**entry, "public_key_pem": es256.public_key_pem(es256.generate_private_key())}
        body = {**objects.body_of(v1), "version": 2, "previous": objects.digest_hex(v1), "signing_keys": [entry, planted]}
        v2 = objects.sign(body, a.store.root_key())
        statement = cose.make_statement(a.store.root_key(), issuer="org.a.example", kid=objects.signature_key_id(v2),
                                        preimage_digest=objects.statement_preimage_digest(v2))
        await log.register(statement, v2)  # this in-memory log applies no registration policy; the Norcaster log refuses it
        with pytest.raises(Refused, match="key document v2: .*(listed twice|not the key id of its public key)"):
            await b.receive(out.meta[META_KEY], tool_name="t", arguments={})

    asyncio.run(run())
