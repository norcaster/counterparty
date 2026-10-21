"""``norcaster-counterparty``: keys, key documents, witnessing, missing acknowledgements, export."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .config import Config
from .log_client import HttpLogClient, LogError
from .party import Counterparty, Inconsistent, Refused


def _sandbox(args: argparse.Namespace) -> int:
    """The local sandbox (``sandbox.py``): ``serve`` runs it; the other commands talk to it."""
    import httpx

    from . import sandbox

    if args.sandbox_command == "serve":
        sandbox.serve(args.dir, host=args.host, port=args.port)
        return 0
    url = args.url.rstrip("/")
    try:
        if args.sandbox_command == "onboard":
            resp = httpx.post(f"{url}/sandbox/onboard", json=json.loads(Path(args.file).read_text()))
        elif args.sandbox_command == "send-call":
            resp = httpx.post(f"{url}/sandbox/calls", json={
                "to_org": args.to, "to_agent": args.agent, "tool_name": args.tool, "blocked": args.blocked,
                "arguments": json.loads(args.arguments) if args.arguments else None})
        else:  # trust
            resp = httpx.get(f"{url}/sandbox/trust")
    except httpx.HTTPError as exc:
        print(f"error: the sandbox at {url} is not reachable ({type(exc).__name__}); start it with: "
              "norcaster-counterparty sandbox serve", file=sys.stderr)
        return 1
    if resp.status_code >= 400:
        print(f"error: {resp.json().get('detail')}", file=sys.stderr)
        return 1
    print(json.dumps(resp.json(), indent=2))
    return 0


def _proxy_hook(args: argparse.Namespace) -> int:
    """``proxy hook``: Claude Code runs this as the command hook; it runs yours."""
    import os

    from .hooks import DEFAULT_URL, ProxyControl
    from .hooks.claude import run_command_hook

    # Your hook command after --; none for PermissionDenied, which only needs reporting.
    command = list(args.hook_command[1:]) if args.hook_command[:1] == ["--"] else list(args.hook_command)
    servers = dict(item.split("=", 1) if "=" in item else (item, item) for item in args.server)
    if args.proxy is not None:  # no running proxy: act on state_dir directly
        from .proxy import LocalControl

        if args.config is None:
            print("error: --proxy needs the top-level --config (your counterparty.json)", file=sys.stderr)
            return 1
        try:
            control = LocalControl(args.config, args.proxy)
        except (ValueError, KeyError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        stdout, stderr, code = run_command_hook(control, command, sys.stdin.read(), servers=servers, rule_id=args.rule_id)
        sys.stdout.write(stdout)
        sys.stderr.write(stderr)
        return code
    try:
        control = ProxyControl(args.url or os.environ.get("NORCASTER_PROXY_URL") or DEFAULT_URL,
                               token=None if args.token_file else os.environ.get("NORCASTER_PROXY_TOKEN"),
                               token_file=args.token_file or os.environ.get("NORCASTER_PROXY_TOKEN_FILE"))
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    stdout, stderr, code = run_command_hook(control, command, sys.stdin.read(), servers=servers, rule_id=args.rule_id)
    sys.stdout.write(stdout)
    sys.stderr.write(stderr)
    return code


async def _run(args: argparse.Namespace) -> int:
    config = Config.load(args.config)
    log = HttpLogClient(config.log_url)
    party = Counterparty(config, log)
    try:
        if args.command == "init":
            print(json.dumps({"org_id": config.org_id, "root_fingerprint": party.root_fingerprint,
                              "witness_id": config.witness_id, "witness_public_key_pem": party.witness_public_key_pem}, indent=2))
        elif args.command == "publish-key-document":
            doc = await party.publish_key_document(rotate=args.rotate, revoke_current=args.revoke_current)
            print(f"registered key document v{doc['version']} ({len(doc['signing_keys'])} signing key(s), {len(doc['agents'])} agent(s))")
        elif args.command == "rotate-root":
            doc = await party.rotate_root()
            print(f"rotated to root {party.root_fingerprint}; key document v{doc['version']} registered. "
                  "Give partners the new fingerprint for new onboardings; existing pins keep working.")
        elif args.command == "witness":
            answer = await party.witness()
            print("nothing new to cosign" if answer is None else f"cosigned; witnessed: {answer.get('witnessed')}")
        elif args.command == "missing-acks":
            print(f"recorded {await party.record_missing_acknowledgements()} missing acknowledgement(s)")
        elif args.command == "export":
            evidence = await party.export(args.exchange, reveal=args.reveal or [])
            Path(args.out).write_text(json.dumps(evidence, indent=2))
            print(f"wrote {args.out}; verify with: norcaster-verify-record {args.out} --trust trust.json")
        elif args.command == "purge":
            print(f"removed {party.purge_expired()} record(s) past retention")
        return 0
    except Inconsistent as exc:
        print(f"ALERT: {exc}", file=sys.stderr)
        return 2
    except (Refused, LogError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        await log.aclose()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="norcaster-counterparty", description=__doc__)
    ap.add_argument("--config", type=Path, help="counterparty.json (every command except sandbox)")
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="create the root, witness and state; print what partners and the log operator need")
    pub = sub.add_parser("publish-key-document", help="register the next key-document version")
    pub.add_argument("--rotate", action="store_true", help="start a new signing key")
    pub.add_argument("--revoke-current", action="store_true", help="revoke the current signing key (and start a new one)")
    sub.add_parser("rotate-root", help="move to a new root: the old root signs the rotation, the new root the next version")
    sub.add_parser("witness", help="cosign the latest checkpoint if it extends the last one cosigned")
    sub.add_parser("missing-acks", help="record missing acknowledgements past their deadline")
    exp = sub.add_parser("export", help="evidence for chosen exchanges")
    exp.add_argument("--exchange", action="append", required=True)
    exp.add_argument("--reveal", action="append")
    exp.add_argument("--out", required=True)
    sub.add_parser("purge", help="delete records past retention")
    sb = sub.add_parser("sandbox", help="a local log and fictional hub to try the component (NOT a SCITT transparency service)")
    sbs = sb.add_subparsers(dest="sandbox_command", required=True)
    serve = sbs.add_parser("serve", help="run the sandbox log and hub")
    serve.add_argument("--dir", type=Path, default=Path("sandbox"), help="where the sandbox keeps its keys and log")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    for name, text in (("onboard", "give the hub what init printed (it pins your root and accepts your witness)"),
                       ("send-call", "ask the hub to send you one tool call"), ("trust", "print a trust file for verification")):
        cmd = sbs.add_parser(name, help=text)
        cmd.add_argument("--url", default="http://127.0.0.1:8765")
        if name == "onboard":
            cmd.add_argument("file", type=Path, help="the JSON that init printed")
        if name == "send-call":
            cmd.add_argument("--to", required=True, help="your org_id")
            cmd.add_argument("--agent", required=True, help="your agent_id that receives the call")
            cmd.add_argument("--tool", default="create_order")
            cmd.add_argument("--arguments", help='JSON, default {"sku": "SKU-0021", "quantity": 1, "customer_ref": "QS-0001"}')
            cmd.add_argument("--blocked", action="store_true", help="the hub's boundary blocks it: you get a notice")
    px = sub.add_parser("proxy", help="a local MCP proxy: receipts for any MCP client (needs the mcp extra)")
    pxs = px.add_subparsers(dest="proxy_command", required=True)
    pserve = pxs.add_parser("serve", help="serve the partners' MCP servers at /mcp/<upstream>, with the control channel")
    pserve.add_argument("--proxy", type=Path, required=True, help="proxy.json: upstreams, port, schedules")
    pstdio = pxs.add_parser("stdio", help="serve one partner's MCP server over stdio (your agent starts this process)")
    pstdio.add_argument("--proxy", type=Path, required=True, help="proxy.json: the upstreams")
    pstdio.add_argument("--upstream", required=True, help="which upstream in proxy.json to serve")
    phook = pxs.add_parser("hook", help="Claude Code PreToolUse command hook: run your hook command and report its "
                                        "decision to the proxy (stdin and stdout as Claude Code expects)")
    phook.add_argument("--url", help="the proxy (default: NORCASTER_PROXY_URL or http://127.0.0.1:8790)")
    phook.add_argument("--token-file", help="the proxy's token file (default: NORCASTER_PROXY_TOKEN[_FILE])")
    phook.add_argument("--server", action="append", required=True,
                       help="a proxied MCP server as Claude names it, NAME or NAME=UPSTREAM (repeatable)")
    phook.add_argument("--rule-id", help="rule id for this hook's decisions (default: the command's name)")
    phook.add_argument("--proxy", type=Path, help="proxy.json: act on state_dir directly, with no running proxy "
                                                  "(needs the top-level --config)")
    phook.add_argument("hook_command", nargs=argparse.REMAINDER, help="-- your hook command and its arguments")
    args = ap.parse_args(argv)
    if args.command == "sandbox":
        return _sandbox(args)
    if args.command == "proxy" and args.proxy_command == "hook":
        return _proxy_hook(args)
    if args.config is None:
        ap.error("--config is required")
    if args.command == "proxy":
        from .proxy import serve, serve_stdio

        try:
            if args.proxy_command == "stdio":
                serve_stdio(args.config, args.proxy, args.upstream)
            else:
                serve(args.config, args.proxy)
        except ImportError as exc:
            print(f"error: the proxy needs the mcp extra: pip install \"norcaster-counterparty[mcp]\" ({exc})", file=sys.stderr)
            return 1
        except (ValueError, KeyError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        return 0
    return asyncio.run(_run(args))


if __name__ == "__main__":
    sys.exit(main())
