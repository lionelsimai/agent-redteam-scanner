"""Command-line interface."""
from __future__ import annotations

import argparse
import sys

from agent_redteam_scanner.agents import get_agent
from agent_redteam_scanner.errors import ScannerError
from agent_redteam_scanner.payloads import list_payloads
from agent_redteam_scanner.report import to_json, to_markdown
from agent_redteam_scanner.scanner import scan


def main(argv: list[str] | None = None) -> int:
    """Entry point."""
    parser = argparse.ArgumentParser(prog="agent-redteam", description="Red-team your own agents.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list-payloads", help="List payloads")
    scan_p = sub.add_parser("scan", help="Scan a mock target")
    scan_p.add_argument("--target", choices=["vulnerable", "hardened"], default="vulnerable")
    scan_p.add_argument("--format", choices=["markdown", "json"], default="markdown")
    args = parser.parse_args(argv)
    try:
        if args.cmd == "list-payloads":
            for p in list_payloads():
                print(f"{p.id:6} {p.category:20} {p.severity:9} {p.name}")
            return 0
        report = scan(get_agent(args.target))
        print(to_json(report) if args.format == "json" else to_markdown(report))
        return 0
    except ScannerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
