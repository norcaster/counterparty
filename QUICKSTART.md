# Quickstart: your first acknowledged receipt

From an empty directory to a receipt your partner signed, your own signed acknowledgement, a witnessed log and an evidence file a third party verifies offline. About 15 minutes. You need Python 3.10 or later and two terminals. You don't need a Norcaster account.

You work against a **local sandbox**: a log stand-in and a fictional hub, **Alpha Test Lender (synthetic)**, both on 127.0.0.1. The sandbox is **not a SCITT transparency service**, and no real company is involved. In a pilot you point the same configuration at the pilot log and pin your real partner's root; nothing else changes.

## 1. Install

```bash
mkdir shared-record-quickstart && cd shared-record-quickstart
python3 -m venv .venv && . .venv/bin/activate
pip install norcaster-counterparty
```

## 2. Start the sandbox (terminal 1)

```bash
cd shared-record-quickstart && . .venv/bin/activate
norcaster-counterparty sandbox serve
```

It prints the log id, the path of the log operator's public key (`sandbox/log-operator.pem`), and the hub's organisation id and **root fingerprint**. Leave it running. The other steps run in terminal 2, in the same directory.

## 3. Configure your organisation (terminal 2)

Pin the hub's root fingerprint. In a pilot you get it from your partner at onboarding; here you read it from the sandbox:

```bash
cd shared-record-quickstart && . .venv/bin/activate
HUB_FP=$(curl -s http://127.0.0.1:8765/sandbox/hub | python -c "import json, sys; print(json.load(sys.stdin)['root_fingerprint'])")
cat > counterparty.json <<EOF
{
  "org_id": "org.yourcompany.example",
  "org_name": "Your Company (synthetic)",
  "state_dir": "state",
  "log_url": "http://127.0.0.1:8765",
  "log_id": "log.sandbox.localhost",
  "operator_public_key_file": "sandbox/log-operator.pem",
  "witness_id": "witness.yourcompany.example",
  "pins": {"org-alpha.example": "$HUB_FP"},
  "agents": [{"agent_id": "agent.orders", "name": "Order agent"}],
  "policy_version": "1",
  "policy_content_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "ack_deadline_seconds": 3600
}
EOF
```

`policy_content_hash` names your boundary policy in every acknowledgement you sign: use the SHA-256 of your real policy in a pilot.

## 4. Create your keys and give the hub your root fingerprint

```bash
norcaster-counterparty --config counterparty.json init > onboarding.json
cat onboarding.json
norcaster-counterparty sandbox onboard onboarding.json
```

`init` creates your root, signing and witness keys in `state/keys/` (mode 0600). They are never sent anywhere. It prints your `root_fingerprint`, which your partner pins, and your witness key, which the log operator accepts. `sandbox onboard` hands both over; in a pilot you send them to your partner and the log operator out of band.

## 5. Publish your key document

```bash
norcaster-counterparty --config counterparty.json publish-key-document
```

Expected: `registered key document v1 (1 signing key(s), 1 agent(s))`. The log now holds your organisation name, your signing public key and your agent's name, under the root the hub pinned. Key documents are public by design.

## 6. Receive one call and acknowledge it

Ask the hub to send your agent a tool call:

```bash
norcaster-counterparty sandbox send-call --to org.yourcompany.example --agent agent.orders
```

The script below shows what your MCP server does with an inbound call. It checks the receipt against the hub's logged key document and the pinned log, recomputes the content commitment, applies your own boundary (`decide`), runs the tool, and returns your signed, logged acknowledgement:

```bash
cat > receive_one_call.py <<'EOF'
"""Receive one tool call from the sandbox hub, check its receipt, run the tool, acknowledge.

In production these lines sit in your MCP server's tools/call handler: the receipt arrives in
the request's _meta and the acknowledgement goes back in the result's _meta. Here the sandbox
hands over the call and takes the result over plain HTTP.
"""

import asyncio
import json

import httpx

from norcaster_counterparty import META_KEY, Config, Counterparty, HttpLogClient

SANDBOX = "http://127.0.0.1:8765"


def run_tool(name, arguments):
    """Your tool. Here: accept the order."""
    return {"order_id": "ORD-0001", "status": "accepted", "tool": name, **arguments}


def decide(name, arguments):
    """Your own boundary: allowed, redacted or blocked, and a rule id."""
    return ("allowed", None)


async def main():
    config = Config.load("counterparty.json")
    log = HttpLogClient(config.log_url)
    party = Counterparty(config, log)
    try:
        call = httpx.get(f"{SANDBOX}/sandbox/calls/next", params={"to": config.org_id})
        if call.status_code == 404:
            raise SystemExit(call.json()["detail"])
        call = call.json()
        inbound = await party.receive(call["meta"][META_KEY], tool_name=call["tool_name"],
                                      arguments=call["arguments"], decide=decide)
        result = run_tool(call["tool_name"], call["arguments"]) if inbound.run_tool else None
        # Return inbound.meta as the result's _meta, whether or not the tool ran.
        answer = httpx.post(f"{SANDBOX}/sandbox/calls/{inbound.exchange_id}/result",
                            json={"result": result, "meta": inbound.meta}).json()
        print(json.dumps({"exchange_id": inbound.exchange_id, "content_check": inbound.content_check,
                          "your_decision": inbound.outcome, "tool_ran": inbound.run_tool,
                          "hub_status": answer["hub_status"]}, indent=2))
        with open("exchange-id.txt", "w") as fh:
            fh.write(inbound.exchange_id)
    finally:
        await log.aclose()


asyncio.run(main())
EOF
python receive_one_call.py
```

Expected: `"content_check": "matched"`, `"tool_ran": true` and `"hub_status": "acknowledged"`. The hub checked your acknowledgement against your logged key document. That is your first acknowledged receipt.

If the call does not check out (a key the hub never published, a log you did not pin, a reused sequence number), `receive` raises `Refused`, and nothing is signed or stored.

## 7. Witness the log

```bash
norcaster-counterparty --config counterparty.json witness
```

Expected: `cosigned; witnessed: True`. You cosign a checkpoint only if it extends the last one you cosigned. The sandbox hub cosigned it too, so the quorum of two is met. In a pilot you run this on a schedule. Exit code 2 means the log rewrote or split its history: keep the output.

## 8. Export the evidence and verify it as a third party would

Export the exchange and reveal its content:

```bash
norcaster-counterparty --config counterparty.json export --exchange $(cat exchange-id.txt) --reveal $(cat exchange-id.txt) --out evidence.json
```

Verify it offline. Here the sandbox prints the trust file. In a real dispute the third party builds its own from the root fingerprints each party pinned and the log and witness keys it trusts; it never takes them from the log operator.

```bash
norcaster-counterparty sandbox trust > trust.json
python -m norcaster_verify.shared_record verify evidence.json --trust trust.json
```

Expected: `state=acknowledged`, the `content_commitment` check `PASS`, and `Result: no check failed`. Then change one byte of the revealed content and verify again:

```bash
python -c "import json; e = json.load(open('evidence.json')); r = e['revealed'][0]; r['content_b64'] = r['content_b64'][:-4] + 'AAAA'; json.dump(e, open('tampered.json', 'w'))"
python -m norcaster_verify.shared_record verify tampered.json --trust trust.json
```

Expected: `[FAIL] content_commitment` and exit code 1.

## Use it with the OpenAI Agents SDK

Two companies that both run this component can keep a Shared Record of their agents' calls without a Norcaster hub. Try it with two fictional companies: Aurora Procurement's agent (OpenAI Agents SDK) orders parts through Birch Components' MCP server. Everything runs on 127.0.0.1 against the sandbox, and no model API is called. A scripted model stands in for the LLM, so you need no API key. The example is in this repository's `examples/` directory; it starts its own sandbox on free ports, in a new temporary directory, so the one from step 2 can keep running:

```bash
pip install "norcaster-counterparty[openai-agents]"
python examples/openai_agents_two_companies.py
```

Expected: Birch checks one receipt (`content matched`) and one notice (`content not_delivered`). Aurora prints `"status": "acknowledged"` for both: one call delivered and one its guardrail blocked. The verifier then reports `Result: no check failed`.

The wiring, in your own code:

```python
# Sending: your agent. Every call to the partner's MCP tools carries a receipt.
from norcaster_counterparty.openai_agents import partner_server

partner = partner_server("https://mcp.partner.example/mcp", party=party, partner_org="org.partner.example",
                         partner_agent="agent.orders", agent_id="agent.procurement",
                         tool_input_guardrails=[your_guardrail])  # a guardrail that does not allow the call sends a notice
agent = Agent(name="Procurement agent", mcp_servers=[partner])
# After a run: item.custom_data["norcaster/shared-record"]["status"] on each tool output item.
```

```python
# Receiving: the partner's existing MCP server (MCP Python SDK 1.x or 2.x), one line.
from norcaster_counterparty.mcp_server import add_shared_record

add_shared_record(server, party, decide=your_boundary)
```

This covers MCP tools over Streamable HTTP only. Function tools and handoffs carry no MCP `_meta`, so they get no receipt. See [README.md](README.md#use-it-with-the-openai-agents-sdk) for the decision fields and the limits.

## Any agent framework: the local proxy

The Claude Agent SDK, Google ADK and LangGraph's MCP adapters cannot add a receipt to an MCP request themselves. Run the proxy next to your agents instead: it holds your keys, and your agent connects to it in place of the partner's MCP server.

The second example runs this with the same two fictional companies, using LangGraph. Aurora runs `norcaster-counterparty proxy serve`, its LangGraph agent calls Birch's tool through it, and two of Aurora's interceptors block one order and redact another. It needs no API key, because a scripted chat model stands in for the LLM:

```bash
pip install "norcaster-counterparty[langgraph]" "langgraph>=1.2,<2"
python examples/proxy_two_companies.py
```

Expected: the three statuses below, and then `Result: no check failed`.

| Call | Status |
|---|---|
| the allowed call | `allowed -> acknowledged` |
| the blocked call (Birch got only a notice) | `blocked rule=aurora.spend_limit -> acknowledged` |
| the redacted call (Birch got `"[redacted]"`) | `redacted rule=aurora.pii.email -> acknowledged` |

For your own agents:

1. **Describe each partner in `proxy.json`.** Give the partner's MCP URL, its organisation id and receiving agent, and your agent id.
2. **Start the proxy:** `norcaster-counterparty --config counterparty.json proxy serve --proxy proxy.json`.
3. **Point your agent at `http://127.0.0.1:8790/mcp/<partner>`.** Send `Authorization: Bearer <token>`, with the token from `state/proxy-token`.
4. **Wrap your boundary with the adapter for your framework,** so the proxy learns what your boundary blocked or redacted:

| Framework | Adapter | Extra |
|---|---|---|
| Claude Agent SDK | `hooks.claude.hook_matcher` | `[claude-agent-sdk]` |
| Claude Code | `norcaster-counterparty proxy hook -- <your command>` | none |
| Google ADK | `hooks.google_adk.before_tool_callback` | `[google-adk]` |
| LangGraph | `hooks.langgraph.interceptors` | `[langgraph]` |

The details are in [README.md](README.md#any-mcp-client-the-local-proxy).

## Next

- **A blocked call.** Run `norcaster-counterparty sandbox send-call --to org.yourcompany.example --agent agent.orders --blocked`, then `python receive_one_call.py` again. You get a notice with no content, `"content_check": "not_delivered"`, and the tool does not run.
- **Sending calls yourself, rotating keys, missing acknowledgements, retention:** see [README.md](README.md).
- **Your real partner:** replace `log_url`, `log_id`, `operator_public_key_file` and `pins` with what you receive at onboarding. Then run `init` once in a fresh `state_dir`, because the sandbox keys stay in the sandbox.

The record shows what each company signed and what the log recorded; it does not decide who is right.
