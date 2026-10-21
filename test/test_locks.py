"""Several processes sharing one ``state_dir``: the cross-process lock around sending and receiving.

Real processes, the quickstart sandbox as the log on 127.0.0.1, synthetic data. Without the lock,
two processes sending to one partner could take the same sequence number (the loser failing after
its receipt was already registered), and two processes receiving one receipt could both register
an acknowledgement. Needs nothing beyond the base package."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import threading
import time
from http.server import HTTPServer
from pathlib import Path

import httpx
import pytest
from norcaster_verify.shared_record import objects

from norcaster_counterparty import Config, Counterparty, HttpLogClient, META_KEY, Store
from norcaster_counterparty import sandbox as sb
from norcaster_counterparty.store import LockTimeout

PKG = Path(__file__).resolve().parents[1]
ENV = {**os.environ, "PYTHONPATH": os.pathsep.join(str(p) for p in (PKG / "src", PKG.parent / "norcaster-verify" / "src"))}
AURORA, BIRCH = "org.aurora.example", "org.birch.example"


def spawn(script: str, *args: str) -> subprocess.Popen:
    return subprocess.Popen([sys.executable, "-c", script, *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=ENV)


def finish(procs: list[subprocess.Popen]) -> list[str]:
    outs = []
    for proc in procs:
        out, err = proc.communicate(timeout=120)
        assert proc.returncode == 0, err
        outs.append(out.strip())
    return outs


# --- the lock ---------------------------------------------------------------------------------------

HOLD = """
import asyncio, os, sys, time
from pathlib import Path
from norcaster_counterparty.store import Store
store, log, go = Store(Path(sys.argv[1])), Path(sys.argv[2]), Path(sys.argv[3])
while not go.exists():
    time.sleep(0.005)
async def main():
    async with store.lock("send:org.birch.example"):
        with log.open("a") as fh:
            fh.write(f"start {os.getpid()}\\n")
        await asyncio.sleep(0.15)
        with log.open("a") as fh:
            fh.write(f"end {os.getpid()}\\n")
asyncio.run(main())
"""


def test_the_lock_excludes_other_processes_and_times_out(tmp_path):
    state, log, go = tmp_path / "state", tmp_path / "order.log", tmp_path / "go"
    Store(state)
    procs = [spawn(HOLD, str(state), str(log), str(go)) for _ in range(4)]
    time.sleep(0.5)
    go.touch()
    finish(procs)
    lines = log.read_text().split()
    pairs = [(lines[i], lines[i + 1], lines[i + 2], lines[i + 3]) for i in range(0, len(lines), 4)]
    assert len(pairs) == 4 and all(a == "start" and c == "end" and b == d for a, b, c, d in pairs)  # never interleaved

    held = tmp_path / "held.log"
    holder = spawn(HOLD.replace("asyncio.sleep(0.15)", "asyncio.sleep(3)"), str(state), str(held), str(go))
    for _ in range(300):  # until the holder has the lock (process start-up can be slow on a busy machine)
        if held.exists() and "start" in held.read_text():
            break
        time.sleep(0.02)

    async def wait_briefly():
        async with Store(state).lock("send:org.birch.example", timeout=0.3):
            pass

    with pytest.raises(LockTimeout):
        asyncio.run(wait_briefly())
    finish([holder])


def test_the_lock_excludes_tasks_in_one_process(tmp_path):
    store, order = Store(tmp_path / "state"), []

    async def one(i: int) -> None:
        async with store.lock("send:x"):
            order.append(("start", i))
            await asyncio.sleep(0.02)
            order.append(("end", i))

    async def both():
        await asyncio.gather(one(1), one(2))

    asyncio.run(both())
    assert [kind for kind, _ in order] == ["start", "end", "start", "end"]


# --- two companies, several processes each ----------------------------------------------------------


@pytest.fixture()
def companies(tmp_path):
    """The sandbox log on a thread; Aurora and Birch as config files (each pinning the other), published."""
    ready, holder = threading.Event(), {}

    def run() -> None:
        holder["box"] = sb.Sandbox(tmp_path / "sandbox")
        handler = sb._handler(holder["box"])
        handler.log_message = lambda *a: None
        holder["httpd"] = HTTPServer(("127.0.0.1", 0), handler)
        ready.set()
        holder["httpd"].serve_forever()

    threading.Thread(target=run, daemon=True).start()
    assert ready.wait(10)
    url = f"http://127.0.0.1:{holder['httpd'].server_address[1]}"
    paths = {}
    for org, agent in ((AURORA, "agent.procurement"), (BIRCH, "agent.orders")):
        paths[org] = tmp_path / org / "counterparty.json"
        paths[org].parent.mkdir()
        paths[org].write_text(json.dumps({
            "org_id": org, "org_name": f"{org} (fictional)", "state_dir": "state", "log_url": url, "log_id": sb.LOG_ID,
            "operator_public_key_file": str(tmp_path / "sandbox" / "log-operator.pem"), "witness_id": f"witness.{org}",
            "agents": [{"agent_id": agent, "name": agent}], "policy_content_hash": "0" * 64, "ack_deadline_seconds": 3600}))

    async def publish():
        parties = {org: Counterparty(Config.load(p), HttpLogClient(url)) for org, p in paths.items()}
        for org, other in ((AURORA, BIRCH), (BIRCH, AURORA)):
            raw = json.loads(paths[org].read_text())
            raw["pins"] = {other: parties[other].root_fingerprint}
            paths[org].write_text(json.dumps(raw))
        for party in parties.values():
            httpx.post(f"{url}/sandbox/onboard", json={"org_id": party.config.org_id, "root_fingerprint": party.root_fingerprint,
                                                      "witness_id": party.config.witness_id,
                                                      "witness_public_key_pem": party.witness_public_key_pem}).raise_for_status()
            await party.publish_key_document()
            await party.log.aclose()

    asyncio.run(publish())
    yield {"url": url, "paths": paths, "box": holder["box"]}
    holder["httpd"].shutdown()
    holder["httpd"].server_close()


SEND = """
import asyncio, json, sys, time
from pathlib import Path
from norcaster_counterparty import Config, Counterparty, HttpLogClient
config, go, n = Config.load(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
party = Counterparty(config, HttpLogClient(config.log_url))
while not go.exists():
    time.sleep(0.005)
async def main():
    try:
        out = await party.send(to_org="org.birch.example", to_agent="agent.orders", agent_id="agent.procurement",
                               tool_name="create_order", arguments={"sku": f"BRC-{n}", "quantity": 1})
        print(out.meta["norcaster/shared-record"]["receipt"]["sequence"])
    finally:
        await party.log.aclose()
asyncio.run(main())
"""


def test_concurrent_sends_from_several_processes_take_distinct_chained_sequences(tmp_path, companies):
    go = tmp_path / "go-send"
    procs = [spawn(SEND, str(companies["paths"][AURORA]), str(go), str(i)) for i in range(6)]
    time.sleep(1.0)
    go.touch()
    sequences = sorted(int(out) for out in finish(procs))
    assert sequences == [1, 2, 3, 4, 5, 6]

    store = Store(Config.load(companies["paths"][AURORA]).state_dir)
    rows = list(store.db.execute("SELECT sequence, receipt FROM exchanges WHERE role = 'sender' ORDER BY sequence"))
    receipts = [json.loads(r["receipt"]) for r in rows]
    assert [r["sequence"] for r in receipts] == sequences
    assert receipts[0]["previous_receipt"] is None
    assert all(receipts[i]["previous_receipt"] == objects.digest_hex(receipts[i - 1]) for i in range(1, 6))  # one chain
    registered = [e for e in companies["box"].log.entries if e["issuer"] == AURORA and not e.get("object")]
    assert len(registered) == 6  # no stray receipt on the log


RECEIVE = """
import asyncio, json, sys, time
from pathlib import Path
from norcaster_counterparty import Config, Counterparty, HttpLogClient
config, block, go = Config.load(sys.argv[1]), json.loads(Path(sys.argv[2]).read_text()), Path(sys.argv[3])
party = Counterparty(config, HttpLogClient(config.log_url))
while not go.exists():
    time.sleep(0.005)
async def main():
    try:
        inbound = await party.receive(block, tool_name="create_order", arguments={"sku": "BRC-1", "quantity": 1})
        ack = inbound.meta["norcaster/shared-record"]["acknowledgement"]
        print(json.dumps([inbound.exchange_id, inbound.content_check, ack["signature"]["value"]]))
    finally:
        await party.log.aclose()
asyncio.run(main())
"""


def test_one_receipt_received_by_several_processes_is_acknowledged_once(tmp_path, companies):
    async def send_one():
        party = Counterparty(Config.load(companies["paths"][AURORA]), HttpLogClient(companies["url"]))
        try:
            return await party.send(to_org=BIRCH, to_agent="agent.orders", agent_id="agent.procurement",
                                    tool_name="create_order", arguments={"sku": "BRC-1", "quantity": 1})
        finally:
            await party.log.aclose()

    out = asyncio.run(send_one())
    block = tmp_path / "block.json"
    block.write_text(json.dumps(out.meta[META_KEY]))
    go = tmp_path / "go-receive"
    procs = [spawn(RECEIVE, str(companies["paths"][BIRCH]), str(block), str(go)) for _ in range(4)]
    time.sleep(1.0)
    go.touch()
    answers = {out for out in finish(procs)}
    assert len(answers) == 1  # every process returned the same, single acknowledgement
    exchange_id, check, _ = json.loads(answers.pop())
    assert (exchange_id, check) == (out.exchange_id, "matched")
    store = Store(Config.load(companies["paths"][BIRCH]).state_dir)
    assert store.db.execute("SELECT COUNT(*) FROM exchanges WHERE role = 'receiver'").fetchone()[0] == 1
    acks = [e for e in companies["box"].log.entries if e["issuer"] == BIRCH and not e.get("object")]
    assert len(acks) == 1  # registered once
