"""The quickstart sandbox over real HTTP on 127.0.0.1: onboarding, its registration policy, an
acknowledged call, a blocked call's notice, witnessing, and an export that verifies. Synthetic data."""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import threading
from http.server import HTTPServer
from pathlib import Path

import httpx
import pytest
from norcaster_verify.shared_record import es256, objects
from norcaster_verify.shared_record.verify import verify_evidence

from norcaster_counterparty import META_KEY, Config, Counterparty, HttpLogClient
from norcaster_counterparty import sandbox as sb

ORG, AGENT = "org.quickstart.example", "agent.orders"
PKG = Path(__file__).resolve().parents[1]


@pytest.fixture()
def server(tmp_path):
    # The sandbox's SQLite store belongs to the thread that serves it, as in ``serve``.
    ready, holder = threading.Event(), {}

    def run() -> None:
        holder["box"] = sb.Sandbox(tmp_path / "sandbox")
        holder["httpd"] = HTTPServer(("127.0.0.1", 0), sb._handler(holder["box"]))
        holder["httpd"].log_message = lambda *a: None
        ready.set()
        holder["httpd"].serve_forever()

    threading.Thread(target=run, daemon=True).start()
    assert ready.wait(10)
    yield holder["box"], f"http://127.0.0.1:{holder['httpd'].server_address[1]}"
    holder["httpd"].shutdown()
    holder["httpd"].server_close()


def _party(tmp_path: Path, url: str, box: sb.Sandbox) -> Counterparty:
    config = Config(org_id=ORG, org_name="Quickstart Co (synthetic)", state_dir=tmp_path / "state", log_url=url, log_id=sb.LOG_ID,
                    operator_public_key_pem=(tmp_path / "sandbox" / "log-operator.pem").read_text(),
                    pins={sb.HUB_ORG: box.hub.root_fingerprint}, agents=[{"agent_id": AGENT, "name": "Order agent", "kind": "agent"}],
                    witness_id="witness.quickstart.example", policy_content_hash="00" * 32)
    return Counterparty(config, HttpLogClient(url))


def test_quickstart_flow_ends_in_an_export_that_verifies(tmp_path, server):
    box, url = server

    async def run():
        party = _party(tmp_path, url, box)
        try:
            # Not onboarded yet: the sandbox's registration policy refuses the key document.
            with pytest.raises(Exception, match="onboard with the sandbox hub first"):
                await party.publish_key_document()
            onboard = httpx.post(f"{url}/sandbox/onboard", json={"org_id": ORG, "root_fingerprint": party.root_fingerprint,
                                                                 "witness_id": party.config.witness_id,
                                                                 "witness_public_key_pem": party.witness_public_key_pem})
            assert onboard.status_code == 200, onboard.text
            await party.publish_key_document()

            ids = []
            for blocked in (False, True):
                sent = httpx.post(f"{url}/sandbox/calls", json={"to_org": ORG, "to_agent": AGENT, "blocked": blocked}).json()
                call = httpx.get(f"{url}/sandbox/calls/next", params={"to": ORG}).json()
                assert call["exchange_id"] == sent["exchange_id"]
                assert ("content_b64" in call["meta"][META_KEY]) is not blocked  # a notice carries no content or salt
                inbound = await party.receive(call["meta"][META_KEY], tool_name=call["tool_name"], arguments=call["arguments"])
                assert inbound.content_check == ("not_delivered" if blocked else "matched")
                assert inbound.run_tool is not blocked
                answer = httpx.post(f"{url}/sandbox/calls/{inbound.exchange_id}/result", json={"meta": inbound.meta}).json()
                assert answer["hub_status"] == "acknowledged"
                ids.append(inbound.exchange_id)
            assert httpx.get(f"{url}/sandbox/calls/next", params={"to": ORG}).status_code == 404

            assert (await party.witness())["witnessed"] is True
            evidence = await party.export(ids, reveal=[ids[0]])
        finally:
            await party.log.aclose()
        trust = httpx.get(f"{url}/sandbox/trust").json()
        report = verify_evidence(evidence, trust)
        assert report["ok"] is True, json.dumps(report, indent=1)
        states = {x["exchange_id"]: x["state"] for x in report["exchanges"]}
        assert states == {ids[0]: "acknowledged", ids[1]: "not_delivered"}  # the notice, acknowledged
        # Tamper with the revealed content: the commitment no longer matches.
        evidence["revealed"][0]["content_b64"] = evidence["revealed"][0]["content_b64"][:-4] + "AAAA"
        failed = {c["id"] for x in verify_evidence(evidence, trust)["exchanges"] for c in x["checks"] if c["status"] == "fail"}
        assert failed == {"content_commitment"}

    asyncio.run(run())


def test_registration_policy_refuses_a_stranger_and_a_wrong_root(tmp_path, server):
    box, url = server
    stranger = es256.generate_private_key()
    body = objects.key_document(org_id=ORG, org_name="x", version=1, previous=None, issued_at="2026-10-17T09:00:00Z",
                                expires_at="2027-10-17T09:00:00Z", root_public_key_pem=es256.public_key_pem(stranger),
                                signing_keys=[], agents=[])
    doc = objects.sign(body, stranger)
    from norcaster_verify.shared_record import cose

    statement = cose.make_statement(stranger, issuer=ORG, kid=objects.signature_key_id(doc),
                                    preimage_digest=objects.statement_preimage_digest(doc))
    r = httpx.post(f"{url}/v1/shared-record/log/entries", json={"statement": statement.hex(), "object": doc})
    assert r.status_code == 422 and "onboard" in r.json()["detail"]
    httpx.post(f"{url}/sandbox/onboard", json={"org_id": ORG, "root_fingerprint": "ab" * 32})
    r = httpx.post(f"{url}/v1/shared-record/log/entries", json={"statement": statement.hex(), "object": doc})
    assert r.status_code == 422 and "pinned root" in r.json()["detail"]
    assert len(box.log.entries) == 1  # only the hub's own key document


def test_state_survives_a_restart(tmp_path):
    first = sb.Sandbox(tmp_path / "sandbox")
    again = sb.Sandbox(tmp_path / "sandbox")
    assert again.hub.root_fingerprint == first.hub.root_fingerprint
    assert len(again.log.entries) == 1 and again.log.operator_pem == first.log.operator_pem


def test_quickstart_uses_the_example_script_verbatim():
    quickstart = (PKG / "QUICKSTART.md").read_text(encoding="utf-8")
    script = (PKG / "examples" / "receive_one_call.py").read_text(encoding="utf-8")
    start = quickstart.index("cat > receive_one_call.py <<'EOF'\n") + len("cat > receive_one_call.py <<'EOF'\n")
    assert quickstart[start:quickstart.index("\nEOF\n", start) + 1] == script


def test_cli_needs_a_config_except_for_the_sandbox():
    out = subprocess.run([sys.executable, "-m", "norcaster_counterparty.cli", "witness"], capture_output=True, text=True, check=False)
    assert out.returncode == 2 and "--config is required" in out.stderr


def test_sandbox_policy_refuses_planted_key_ids_and_expired_key_documents(tmp_path):
    """Pre-review F-03 and F-09: the sandbox refuses what verifiers reject."""
    from norcaster_verify.shared_record import cose

    log = sb.SandboxLog(tmp_path / "log")
    root, leaf = es256.generate_private_key(), es256.generate_private_key()
    root_pem, leaf_pem = es256.public_key_pem(root), es256.public_key_pem(leaf)
    log.pins[ORG] = es256.fingerprint(root_pem)
    entry = objects.signing_key_entry(leaf_pem, not_before="2026-01-01T00:00:00Z", not_after="2099-01-01T00:00:00Z")

    def register(keys: list[dict], *, expires: str = "2099-01-01T00:00:00Z") -> dict:
        doc = objects.sign(objects.key_document(org_id=ORG, org_name="Quickstart Co (synthetic)", version=1, previous=None,
                                                issued_at="2026-10-01T00:00:00Z", expires_at=expires, root_public_key_pem=root_pem,
                                                signing_keys=keys, agents=[]), root)
        return log.register(cose.make_statement(root, issuer=ORG, kid=es256.key_id(root_pem),
                                                preimage_digest=objects.statement_preimage_digest(doc)), doc)

    with pytest.raises(sb.SandboxRefused, match="not the key id of its public key"):
        register([{**entry, "public_key_pem": es256.public_key_pem(es256.generate_private_key())}])
    with pytest.raises(sb.SandboxRefused, match="listed twice"):
        register([entry, entry])
    register([entry], expires="2026-10-02T00:00:00Z")  # already expired
    with pytest.raises(sb.SandboxRefused, match="has expired"):
        log.register(cose.make_statement(leaf, issuer=ORG, kid=entry["key_id"], preimage_digest=b"\x01" * 32))
