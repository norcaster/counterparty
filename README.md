# norcaster-counterparty

The self-hosted side of a **Shared Record** for a company whose partner uses Norcaster. No Norcaster account is needed. When your agents and your partner's agents exchange tool calls, each side keeps a tamper-evident record of:

- what was sent;
- what each side's boundary decided;
- whether the other side acknowledged it.

Either side, or a third party it chooses, can check that record offline with [`norcaster-verify`](https://github.com/norcaster/verify). The record shows what each company signed and what the log recorded; it does not decide who is right.

Protocol: [`shared-record-v0.md`](https://github.com/norcaster/verify/blob/main/spec/shared-record-v0.md) (draft, in development, designed on the IETF SCITT architecture, RFC 9943).

**Status:** Shared Record is in development · pilot pairs by application. A pilot version is built and in testing. It is not in production or available to customers.

**Start here:** [QUICKSTART.md](QUICKSTART.md) takes you from an empty directory to a first acknowledged receipt against a local sandbox (`norcaster-counterparty sandbox`, a log stand-in and a fictional hub; not a SCITT transparency service) in about 15 minutes.

## What stays with you

- **Keys, generated locally:** a root key (it signs your key documents), a signing key (it signs your receipts and acknowledgements) and a witness key. They live in `state_dir/keys/` with mode 0600 and are never sent anywhere. On Windows, file modes do not apply: put `state_dir` where only the account that runs the component can read it (NTFS permissions), for example under that account's profile.
- **Records, in `state_dir/records.sqlite3`:** your receipts, acknowledgements and missing-acknowledgement records, plus the content and salt of each exchange, until your retention date. A party can only prove what it sent if it keeps it. Protect `state_dir` like any other system of record.
- **What reaches the shared log:** salted hashes, your organisation id, your key ids and times, and your key documents. Key documents are public by design: they list your organisation name, signing public keys and agent names. Message content never reaches the log.

## What you trust

- **Your partner:** only through the root fingerprint you pin at onboarding (`pins`). Every one of your partner's key documents read from the log must be under that root and chain version to version.
- **The log:** only through its operator key, which you pin (`operator_public_key_pem`). Every receipt must prove inclusion under that key.
- **The log's history:** you witness the log. You cosign a checkpoint only if it extends the last one you cosigned, so a rewrite or split view is caught (`witness`, exit code 2).

## Setup with a real partner

```json
{
  "org_id": "org.yourcompany.example",
  "org_name": "Your Company",
  "state_dir": "state",
  "log_url": "https://api.norcaster.example",
  "log_id": "log.shared-record.norcaster",
  "operator_public_key_file": "log-operator.pem",
  "witness_id": "witness.yourcompany.example",
  "pins": {"<your partner's organisation id>": "<their root fingerprint>"},
  "agents": [{"agent_id": "agent.settlement", "name": "Settlement agent"}],
  "policy_version": "1",
  "policy_content_hash": "<sha256 of your boundary policy>",
  "ack_deadline_seconds": 86400,
  "retention_days": 2555,
  "max_clock_skew_seconds": 300
}
```

`max_clock_skew_seconds` (default 300): a received receipt whose `created_at` is further than this from your clock is refused. Keep your clock synchronised (NTP).

```bash
pip install norcaster-counterparty
```

```bash
norcaster-counterparty --config counterparty.json init
```

`init` prints two things to hand over:

- give `root_fingerprint` to your partner, who pins it;
- give `witness_id` and `witness_public_key_pem` to the log operator.

Then publish your first key document, which needs the log operator to have pinned your root:

```bash
norcaster-counterparty --config counterparty.json publish-key-document
```

## In your MCP server and client

```python
from norcaster_counterparty import META_KEY, Config, Counterparty, HttpLogClient

config = Config.load("counterparty.json")
party = Counterparty(config, HttpLogClient(config.log_url))

# Receiving a call (your MCP server): check the receipt, decide, acknowledge.
inbound = await party.receive(request_meta[META_KEY], tool_name=name, arguments=arguments,
                              decide=lambda name, args: ("allowed", None))  # your boundary: allowed | redacted | blocked
result = run_tool(name, arguments) if inbound.run_tool else refusal
# Return inbound.meta as the result's _meta, whether or not the tool ran.

# Sending a call (your MCP client): sign and register first.
out = await party.send(to_org=partner, to_agent=partner_agent, agent_id="agent.settlement",
                       tool_name=name, arguments=arguments, outcome="allowed")
# Send out.meta as the request's _meta. For outcome="blocked", send no call: deliver out.meta as a notice.
status = await party.accept_acknowledgement(out.exchange_id, result_meta)
```

`receive` raises `Refused` when a receipt does not check out, for example:

- it is not signed by a key in the sender's logged key document under the pinned root;
- it was not registered on the pinned log;
- it reuses a sequence number.

Nothing is signed or stored in that case.

## Use it with the OpenAI Agents SDK

Two companies that both run this component can keep a Shared Record of their agents' calls without a Norcaster hub. Install the extra:

```bash
pip install "norcaster-counterparty[openai-agents]"
```

It is tested with `openai-agents` 0.24.0 and pinned to `>=0.24.0,<0.25`. A partner that only receives calls needs `pip install "norcaster-counterparty[mcp]"` (MCP Python SDK `>=1.22.0,<3`). [`examples/openai_agents_two_companies.py`](examples/openai_agents_two_companies.py) runs both sides end to end against the local sandbox, without a model API.

**Sending: your agent.** `partner_server` returns an `MCPServerStreamableHttp` for the partner's MCP server:

```python
from agents import Agent, Runner
from norcaster_counterparty import Config, Counterparty, HttpLogClient
from norcaster_counterparty.openai_agents import partner_server

config = Config.load("counterparty.json")
party = Counterparty(config, HttpLogClient(config.log_url))
partner = partner_server("https://mcp.partner.example/mcp", party=party, partner_org="org.partner.example",
                         partner_agent="agent.orders", agent_id="agent.procurement",
                         tool_input_guardrails=[spend_limit], redact=redact_pii, on_exchange=print)
async with partner:
    result = await Runner.run(Agent(name="Procurement agent", mcp_servers=[partner]), "Order 5 units of BRC-AX-10.")
```

For every call to one of the partner's tools:

1. **Before the call**, through the SDK's `tool_meta_resolver`, `Counterparty.send` signs and registers a receipt. The exchange block goes in the request's `_meta["norcaster/shared-record"]`.
2. **After it**, through the SDK's `custom_data_extractor`, the partner's acknowledgement is read from the result's `_meta` and checked.
3. **The status** goes to four places:
   - the tool output item: `item.custom_data["norcaster/shared-record"]`, which the model never sees;
   - a trace span named `norcaster.shared_record`, holding ids, decisions and the status, never content;
   - `partner.exchanges`;
   - `on_exchange`.

| `status` | Meaning |
|---|---|
| `acknowledged` | The partner signed and logged an acknowledgement, and its content check is `matched`, or `not_delivered` for a notice. The partner's own decision is in `partner_outcome` and `partner_rule_id`. |
| `mismatch` | The partner acknowledged, but what it received does not match your commitment. The partner refuses to run the tool. |
| `missing` | No acknowledgement came back. Run `missing-acks` on a schedule: after the deadline it registers a missing-acknowledgement record. |
| `invalid` | An acknowledgement came back but does not check out against the partner's logged key. |
| `refused` | Your component refused to sign, for example because the partner is not pinned or your agent is not in your key document. Nothing was sent. |

**Your boundary and the receipt's decision fields.** The receipt names your boundary's decision:

| What your boundary did | `outcome` | `rule_id` |
|---|---|---|
| Every tool input guardrail allows, and `redact` changes nothing or is not set | `allowed` | none |
| Every guardrail allows, and `redact` changes the arguments | `redacted` | the rule `redact` returns, or `"redacted"` |
| The first guardrail that does not allow the call returns `reject_content` or `raise_exception` | `blocked` | `output_info["rule_id"]` when it is a string, otherwise the guardrail's name |

- **`policy_version` and `policy_content_hash`** come from your `counterparty.json`, as in every receipt the component signs.
- **A blocked call is never delivered.** The receipt says `delivered: false` and goes to the partner as a notice through its notice tool. The guardrail's own result stands, whatever happens to the notice.
- **Redaction.** The SDK's guardrails can allow or refuse a call but cannot change its arguments. Redaction is therefore the binding's `redact(tool_name, arguments)` hook, which returns `(arguments_to_send, rule_id)` or None. The commitment covers the redacted call, and the binding sends exactly the arguments it committed to.

**Receiving: the partner's MCP server.** One line on an existing server, after its tools are registered. It works with the MCP Python SDK 1.x (low-level `Server`, `FastMCP`) and 2.x (low-level `Server`, `MCPServer`):

```python
from norcaster_counterparty.mcp_server import add_shared_record

add_shared_record(server, party, decide=lambda name, args: ("allowed", None))  # your boundary: allowed | redacted | blocked
```

The helper:

- checks the receipt;
- applies `decide`;
- runs your tool only when both allow it;
- returns the signed acknowledgement in the result's `_meta`;
- serves the notice tool (`norcaster_shared_record_notice`).

A call without a receipt is refused. Pass `require_receipt=False` to serve clients outside the pair as before, with nothing signed for those calls.

**Limits.**

- **What is covered.** MCP tools over Streamable HTTP. Function tools and handoffs carry no MCP `_meta`, so they get no receipt; handoffs between two companies' agents are the A2A binding's job. SSE and stdio servers are not covered.
- **An undocumented hook.** The acknowledgement is read through the SDK's `MCPToolCustomDataContext.result_meta`, which the SDK's source defines but its documentation does not describe. That is why the extra pins the SDK's minor version, and why a test fails if the hook changes.
- **Approvals.** With `require_approval`, a call a person approves (`state.approve`) is receipted `allowed` with rule `human_approval`. Reject with `await partner.reject(state, item, rejection_message=...)` instead of `state.reject`: the call is not sent, a `blocked` receipt with rule `human_rejected` is registered, and the partner gets a notice. The SDK reports a rejection to no hook, so `state.reject` alone leaves no record.
- **Static `_meta` from the partner.** A partner tool that lists a static `_meta` entry under `norcaster/shared-record` would take the receipt's place. The binding drops that entry from the tool list, and it never sends a call without the receipt it signed.

## Any MCP client: the local proxy

Some agent SDKs cannot add a receipt to an MCP request themselves, for example the Claude Agent SDK, Google ADK and LangGraph's MCP adapters. For those, run the proxy next to your agents. It holds your keys, so your agents' processes never see them. Install the extra:

```bash
pip install "norcaster-counterparty[mcp]"
```

Describe your partners' MCP servers in `proxy.json`:

```json
{
  "port": 8790,
  "upstreams": [
    {"name": "birch", "url": "https://mcp.birch.example/mcp", "partner_org": "org.birch.example",
     "partner_agent": "agent.orders", "agent_id": "agent.procurement",
     "headers": {"X-Api-Key": "${BIRCH_API_KEY}"},
     "pass_headers": {"X-Partner-Authorization": "Authorization"}}
  ]
}
```

Then start it:

```bash
norcaster-counterparty --config counterparty.json proxy serve --proxy proxy.json
```

Point your agent at `http://127.0.0.1:8790/mcp/birch` instead of the partner's URL, with the header `Authorization: Bearer <token>`. The token is in `state_dir/proxy-token`, mode 0600, created on first start.

For every tool call, the proxy:

1. signs and registers a receipt;
2. forwards the call with the receipt in `_meta`;
3. checks the partner's acknowledgement;
4. removes the acknowledgement from the result, so the model never sees it.

Your agent's own boundary reports its decisions over the control channel on the same port, with the same token:

| Call | When | Effect |
|---|---|---|
| `POST /control/v1/notices` `{"upstream", "tool_name", "arguments", "rule_id"}` | your boundary blocked the call | a `blocked` receipt, sent to the partner as a notice; nothing of the call is delivered |
| `POST /control/v1/decisions` `{"upstream", "tool_name", "arguments", "rule_id", "outcome"}` | your boundary redacted the call (`outcome: "redacted"`, the default), or a person approved it (`"allowed"`, rule `human_approval`); send the arguments as they will be sent | the next call with exactly those arguments is receipted with that outcome and rule (used once, kept 60 s). An approval yields to a pending redaction of the same call, and a notice uses up any decision for its call |
| `GET /control/v1/exchanges?limit=50` | any time | recent statuses: `acknowledged`, `mismatch`, `missing`, `invalid`, `refused` (also appended to `state_dir/proxy-exchanges.jsonl`) |

Ready-made adapters for the Claude Agent SDK and Claude Code, Google ADK and LangGraph follow. For other frameworks, call these endpoints from your own hooks. [`examples/proxy_two_companies.py`](examples/proxy_two_companies.py) runs the proxy command with a LangGraph agent end to end against the local sandbox, without a model API.

### Claude Agent SDK and Claude Code

`norcaster_counterparty.hooks.claude` wraps your `PreToolUse` hooks for the proxied servers and reports what they decided. For the Agent SDK, install `pip install "norcaster-counterparty[claude-agent-sdk]"` (tested with 0.2.168, pinned `<0.3`):

```python
from claude_agent_sdk import ClaudeAgentOptions
from norcaster_counterparty.hooks import ProxyControl
from norcaster_counterparty.hooks.claude import hook_matcher, mcp_servers

control = ProxyControl("http://127.0.0.1:8790", token_file="state/proxy-token")
options = ClaudeAgentOptions(
    mcp_servers=mcp_servers(control, ["birch"]),  # mcp__birch__* goes through the proxy
    hooks={"PreToolUse": [hook_matcher(control, spend_limit, redact_pii, servers=["birch"])]},
)
```

Your hooks run in order. Each sees the arguments the previous one returned, and the first deny ends the chain.

| Your hooks | The receipt |
|---|---|
| a deny (`permissionDecision: "deny"`, `decision: "block"` or `continue: false`) | `blocked`, sent to the partner as a notice; the model sees your reason as an error result |
| `updatedInput` that changes the arguments | `redacted` when the changed call reaches the proxy. If the proxy cannot take the decision, the call is denied instead, so no receipt misstates your boundary |
| neither | `allowed` |

The rule id is the hook's `norcaster_rule_id` output field, which is removed before Claude sees the output, or else the hook's function name.

**Approvals.** Where a person decides on Claude's permission request, the receipt records it, as the Norcaster hub does:

| Where the decision is made | Deny | Allow |
|---|---|---|
| The Agent SDK's `can_use_tool`, wrapped with `hooks.claude.can_use_tool(control, yours, servers=[...])` | `blocked`, rule `human_rejected`, notice to the partner | `allowed`, rule `human_approval`; `redacted` with that rule if the person changed the input |
| A `PermissionRequest` command hook, wrapped with `proxy hook -- <your command>` | `blocked`, rule `human_rejected` (or `--rule-id`) | `allowed`, rule `human_approval` (or `--rule-id`) |
| Claude Code itself (`PermissionDenied`, e.g. auto mode), `proxy hook` with no command | `blocked`, rule `claude.permission_denied` | n/a |

**Claude Code.** Wrap your existing command hook in `settings.json`. `proxy hook` runs your command with the same input, reports its decision (exit code 2, or the JSON output as above), and passes its output and exit code through unchanged. It needs only the base package:

```json
{"hooks": {"PreToolUse": [{"matcher": "mcp__birch__.*", "hooks": [{"type": "command",
  "command": "norcaster-counterparty proxy hook --server birch --rule-id aurora.spend_limit -- python my_policy.py"}]}]}}
```

It reads `NORCASTER_PROXY_URL` and `NORCASTER_PROXY_TOKEN_FILE`, or takes `--url` and `--token-file`.

**Limits.**

- **A person at Claude Code's interactive permission prompt is reported to no hook.** A rejection there leaves no receipt, and an approval is receipted `allowed` without the approval rule. Decide permissions in a `PermissionRequest` hook, or with `can_use_tool` in the Agent SDK, to have them recorded.
- The adapter matches Claude's `mcp__<server>__<tool>` names back to the partner's tool names through the proxy. Claude replaces characters outside `[a-zA-Z0-9_-]` in those names.

**Settings.** All are optional:

- `host` and `port`: default `127.0.0.1:8790`. Listening beyond loopback is allowed, with a warning.
- `include_status`: adds a compact status to the result's `_meta`.
- `missing_acks_every_seconds`: default 300.
- `witness_every_seconds`: default 0, which is off.
- `decision_ttl_seconds`: default 60.
- `session_idle_seconds`: default 300. Sessions with a partner's server are kept open and shared, one per upstream and exact set of outgoing headers, so different users' tokens never share a session. A session unused this long is closed; 0 opens one per request.
- `max_sessions_per_upstream`: default 8. When the cap is reached, the least recently used idle session is closed; busy ones are never closed.
- `token_file`, `status_log`.

Header values can name environment variables (`${NAME}`), so secrets stay out of the file. The incoming `Authorization` header carries the proxy's token. A per-user token for the partner therefore arrives under another name (`pass_headers`) and is renamed on the way out.

**Retries.** If the partner's server has forgotten a pooled session (for example after a restart), it answers 404, which MCP defines as "not processed". The call then goes once more on a new session, with the same receipt, so the partner acknowledges it once. Any other failure is reported `missing` and is never sent again, because it might already have reached the partner's tool.

**Limits.**

- Only tools pass through: no resources, prompts, sampling or elicitation.
- `state_dir` must be on a local disk: file locks are not reliable on network filesystems.

### Over stdio, with no daemon

`norcaster-counterparty --config counterparty.json proxy stdio --proxy proxy.json --upstream birch` serves one partner's MCP server over stdio, so your agent or client starts the proxy itself, with no port and no token. For example, in Claude Code:

```bash
claude mcp add birch -- norcaster-counterparty --config /path/counterparty.json proxy stdio --proxy /path/proxy.json --upstream birch
```

Several stdio proxies, a `proxy serve` and the commands below may all run on one `state_dir` at once:

- **Sequence numbers:** every send to, and every receive from, a partner takes a lock in `state_dir/locks/` that holds across processes, so sequence numbers stay unique and chained.
- **Decisions:** the proxy's redaction decisions are kept in the database, where every process sees them.
- **Schedules:** a stdio proxy runs neither the missing-acknowledgement nor the witness schedule. Run `missing-acks` and `witness` from cron, or keep a `proxy serve` running.

For Claude Code's command hook, `proxy hook` then needs no running proxy either. Give it the top-level `--config` and `--proxy`, and it records decisions in the database and signs and sends notices itself:

```json
{"hooks": {"PreToolUse": [{"matcher": "mcp__birch__.*", "hooks": [{"type": "command",
  "command": "norcaster-counterparty --config /path/counterparty.json proxy hook --proxy /path/proxy.json --server birch -- python my_policy.py"}]}]}}
```

The Python adapters (Claude Agent SDK, Google ADK, LangGraph) still use a running `proxy serve` through `ProxyControl`, so that keys stay out of the agent's process.

### Google ADK

`norcaster_counterparty.hooks.google_adk` wraps your agent's `before_tool_callback`s for the proxied tools. Install `pip install "norcaster-counterparty[google-adk]"` (Python 3.11 or later; tested with ADK 2.12.0, pinned `<2.13`):

```python
from google.adk.agents import LlmAgent
from norcaster_counterparty.hooks import ProxyControl
from norcaster_counterparty.hooks.google_adk import before_tool_callback, mcp_toolset, rule, status_callback

control = ProxyControl("http://127.0.0.1:8790", token_file="state/proxy-token")
agent = LlmAgent(
    name="procurement", model="gemini-...",
    tools=[mcp_toolset(control, "birch")],  # the partner's tools, through the proxy
    before_tool_callback=before_tool_callback(control, spend_limit, redact_pii),
    after_tool_callback=[status_callback],
)
```

| Your callbacks | The receipt |
|---|---|
| a callback returns a dict, so ADK skips the tool | `blocked`, sent to the partner as a notice; the model sees your dict |
| a callback changes `args` in place, so ADK sends them changed | `redacted`. If the proxy cannot take the decision, the call is answered with an error instead |
| neither | `allowed` |

The rule id is the dict's `norcaster_rule_id`, removed before the model sees it. Otherwise it is the callback's `@rule("...")`, or else its function name.

**Approvals.** With `mcp_toolset(control, "birch", require_confirmation=True)`, ADK holds the call for a person. Nothing is signed while it waits.

- **Confirmed:** the receipt says `allowed`, with rule `human_approval`.
- **Rejected:** nothing is sent, and the partner gets a notice with rule `human_rejected`.

ADK hands the model the whole MCP result, `_meta` included. The proxy always removes its acknowledgement. With the proxy's `include_status` on, `status_callback` also moves the status out of the result and into `tool_context.state["temp:norcaster_shared_record"]`. Put it first: it returns None, so your own after-callbacks still run.

**Limits.**

- **Plugins:** blocks made by ADK plugins (`BasePlugin.before_tool_callback`) run before the agent's callbacks and are not seen. Put boundary decisions for proxied tools on the agent.
- **Credential lookups:** by default (`GOOGLE_API_USE_CLIENT_CERTIFICATE=true`), ADK looks up Google Application Default Credentials for mTLS on every MCP connection, the proxy's included. On a machine without Google credentials, that probes the cloud metadata server. Set `GOOGLE_API_USE_CLIENT_CERTIFICATE=false` if your agent does not need mTLS to Google; the setting is process-wide.

### LangGraph

`norcaster_counterparty.hooks.langgraph` wraps your `langchain-mcp-adapters` tool interceptors for the proxied servers. Install `pip install "norcaster-counterparty[langgraph]"` (tested with langchain-mcp-adapters 0.3.2 and LangGraph 1.2; the adapters need the MCP Python SDK 1.x):

```python
from langchain_mcp_adapters.client import MultiServerMCPClient
from norcaster_counterparty.hooks import ProxyControl
from norcaster_counterparty.hooks.langgraph import connections, interceptors

control = ProxyControl("http://127.0.0.1:8790", token_file="state/proxy-token")
client = MultiServerMCPClient(connections(control, ["birch"]),
                              tool_interceptors=interceptors(control, spend_limit, redact_pii, servers=["birch"]))
tools = await client.get_tools()  # give them to your LangGraph agent as usual
```

| Your interceptors | The receipt |
|---|---|
| an interceptor answers without calling the next handler (a `CallToolResult` or `ToolMessage`) | `blocked`, sent to the partner as a notice |
| an interceptor passes the call on with other arguments (`request.override(args=...)`) | `redacted`. If the proxy cannot take the decision, the call is answered with an error instead |
| neither | `allowed` |

Your interceptors keep their order, the first being outermost. The rule id is the interceptor's `@rule("...")`, or else its name.

**Approvals.** Give your approval interceptor (for example one built on LangGraph's `interrupt()`) the rule `@rule(HUMAN_REJECTED)` for its rejecting branch, and call `approved()` once the person has approved. The receipt then says `allowed`, with rule `human_approval`.

## Operating

Run these on a schedule:

```bash
norcaster-counterparty --config counterparty.json witness
```

```bash
norcaster-counterparty --config counterparty.json missing-acks
```

```bash
norcaster-counterparty --config counterparty.json purge
```

- `witness` cosigns the log's latest checkpoint if it extends the last one you cosigned. Exit code 2 means the log rewrote or split its history; keep the output.
- `missing-acks` records missing acknowledgements past their deadline.
- `purge` deletes records past retention.

Signing keys:

```bash
norcaster-counterparty --config counterparty.json publish-key-document --rotate
```

```bash
norcaster-counterparty --config counterparty.json publish-key-document --revoke-current
```

- `--rotate` starts a new signing key and publishes it.
- `--revoke-current` publishes the current key as revoked and starts a new one.

To move to a new root, for example on a key-management schedule:

```bash
norcaster-counterparty --config counterparty.json rotate-root
```

Your current root signs a rotation naming the new one, and the new root signs the next key document. The old root is archived in `state_dir/keys/`. Partners who pinned the old root keep working; give the new fingerprint to new partners.

For a dispute, export chosen exchanges and reveal the ones you choose:

```bash
norcaster-counterparty --config counterparty.json export --exchange <id> --reveal <id> --out evidence.json
```

The third party verifies the export with its own trust configuration:

```bash
norcaster-verify-record evidence.json --trust trust.json
```

## Limits

- **One log operator:** the pilot log is operated by Norcaster and witnessed by the two companies. The operator can refuse service. It cannot rewrite or split the history without a witness noticing, unless it colludes with one of you.
- **Lost root:** a lost or compromised root cannot sign its own rotation. If that happens, re-onboard with your partners under a new root, out of band. Keep the root key backed up.
- **Partner's signatures:** if your partner runs on Norcaster's hosted runtime, its signing key is held by Norcaster for its validity period. A key document under the partner's own root controls which keys are published, not each signature.

## Container image

`ghcr.io/norcaster/counterparty` runs the same command line (Red Hat UBI 9, non-root uid 10001 in group 0, hash-pinned dependencies). Mount your configuration and state:

```bash
docker run --rm -v "$PWD:/work" -w /work ghcr.io/norcaster/counterparty:0.1.0 --config counterparty.json witness
```

**The local MCP proxy in the image.** The image includes the MCP Python SDK (exactly pinned, with hashes), so `proxy serve` and `proxy stdio` run from it. The proxy listens on port 8790. Mount a `state_dir` that the container's user (uid 10001, or an arbitrary uid in group 0) can write: the token file and the status log go there, and the root filesystem can stay read-only.

- **As a sidecar** (for example in the same Kubernetes pod as your agent): keep the default `127.0.0.1` in `proxy.json`. The agent reaches `http://127.0.0.1:8790/mcp/<partner>` over the pod's shared network, nothing outside the pod can, and DNS-rebinding protection stays on.

  ```yaml
  - name: shared-record-proxy
    image: ghcr.io/norcaster/counterparty@sha256:<digest>
    args: ["--config", "counterparty.json", "proxy", "serve", "--proxy", "proxy.json"]
    workingDir: /work
    volumeMounts: [{name: shared-record-state, mountPath: /work}, {name: tmp, mountPath: /tmp}]  # tmp: an emptyDir
    securityContext: {readOnlyRootFilesystem: true, runAsNonRoot: true}
    readinessProbe: {tcpSocket: {port: 8790}}
  ```

- **As its own container** (for example with Docker Compose): set `"host": "0.0.0.0"` in `proxy.json` and publish the port only where your agent runs. The proxy warns that it listens beyond loopback, and the bearer token is then the only thing between other hosts and your organisation's signature:

  ```bash
  docker run -d -v "$PWD:/work" -p 127.0.0.1:8790:8790 --read-only --tmpfs /tmp ghcr.io/norcaster/counterparty:<version> --config counterparty.json proxy serve --proxy proxy.json
  ```

Check health with a TCP probe on 8790. Every HTTP endpoint, `/control/v1/health` included, needs the token.

Each release image is signed with Norcaster's **release key** (`cosign.pub` in this repository; a key used for nothing else). It carries an SBOM and build provenance. Check it before you run it:

```bash
cosign verify --key cosign.pub ghcr.io/norcaster/counterparty@sha256:<digest>
```

Each signature and the SBOM attestation are also recorded in the public Sigstore transparency log (Rekor), and `cosign verify` checks that entry too. A release built with the upload turned off says so in its notes; verify it with `--insecure-ignore-tlog=true`, and the key alone still checks the signature.

## Source and releases

This repository is a published snapshot of `packages/norcaster-counterparty` in Norcaster's main repository, which is the source of truth. Releases are cut from version tags (`v0.1.0`). `release.yml` publishes to PyPI with trusted publishing, then builds, signs and attests the image. The version in `pyproject.toml`, `__init__.py` and the top entry of `CHANGELOG.md` must equal the tag.

Security reports: security@norcaster.com.

Licence: Apache-2.0.
