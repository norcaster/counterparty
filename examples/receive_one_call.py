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
