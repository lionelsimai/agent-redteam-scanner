"""Command-line interface."""
from __future__ import annotations

import argparse
import sys

from agent_redteam_scanner.adapters import CommandAgent, load_module_agent
from agent_redteam_scanner.agents import BaseAgent, get_agent
from agent_redteam_scanner.config import Config
from agent_redteam_scanner.errors import ScannerError
from agent_redteam_scanner.payloads import HELD_OUT_PAYLOADS, PAYLOADS, list_payloads
from agent_redteam_scanner.report import to_json, to_markdown
from agent_redteam_scanner.scanner import scan

_SUITES = {"core": PAYLOADS, "held-out": HELD_OUT_PAYLOADS, "all": PAYLOADS + HELD_OUT_PAYLOADS}


def _resolve_agent(args: argparse.Namespace, config: Config) -> tuple[BaseAgent, tuple[str, ...]]:
    """Build the target agent and the canary-secret tuple for the scan."""
    canary = (config.canary_secret,) if config.canary_secret else ()
    if args.agent_command:
        return CommandAgent(args.agent_command), canary
    if args.agent_module:
        return load_module_agent(args.agent_module), canary
    # Bundled mocks hold the configured demo secret — plant it as canary.
    return get_agent(args.target), (config.demo_secret,)


def main(argv: list[str] | None = None) -> int:
    """Entry point."""
    parser = argparse.ArgumentParser(prog="agent-redteam", description="Red-team your own agents.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    list_p = sub.add_parser("list-payloads", help="List payloads")
    list_p.add_argument("--suite", choices=list(_SUITES), default="core")
    scan_p = sub.add_parser("scan", help="Scan a mock target or your own agent")
    scan_p.add_argument("--target", choices=["vulnerable", "hardened"], default="vulnerable",
                        help="Bundled mock target (ignored with --agent-*)")
    scan_p.add_argument("--agent-command", default=None,
                        help="Your agent as a subprocess speaking the line protocol "
                             "(one prompt line in, one response line out)")
    scan_p.add_argument("--agent-module", default=None,
                        help="Your agent as 'path/to/module.py:ClassName' or "
                             "'package.module:ClassName'")
    scan_p.add_argument("--suite", choices=list(_SUITES), default="core",
                        help="core (18), held-out (12, unseen by the mock defences) or all")
    scan_p.add_argument("--max-payloads", type=int, default=None,
                        help="Cap payloads run (default: REDTEAM_MAX_PAYLOADS or all)")
    scan_p.add_argument("--format", choices=["markdown", "json"], default="markdown")
    args = parser.parse_args(argv)
    config = Config.from_env()
    try:
        if args.cmd == "list-payloads":
            for p in list_payloads(held_out=args.suite == "held-out"):
                print(f"{p.id:6} {p.category:20} {p.severity:9} {p.name}")
            return 0
        agent, canary = _resolve_agent(args, config)
        try:
            limit = args.max_payloads if args.max_payloads is not None else config.max_payloads
            report = scan(agent, _SUITES[args.suite], max_payloads=limit, known_secrets=canary)
        finally:
            if isinstance(agent, CommandAgent):
                agent.close()
        print(to_json(report) if args.format == "json" else to_markdown(report))
        return 0
    except ScannerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
