"""Markdown + JSON report generation."""
from __future__ import annotations

import json
from dataclasses import asdict

from agent_redteam_scanner.scanner import ScanReport


def to_json(report: ScanReport) -> str:
    """Serialise a report to JSON."""
    return json.dumps({"target": report.target, "total": report.total, "score": report.score,
                       "critical": report.critical_count, "by_category": report.by_category(),
                       "findings": [asdict(f) | {"category": str(f.category), "severity": str(f.severity)}
                                    for f in report.findings]}, indent=2)


def to_markdown(report: ScanReport) -> str:
    """Render a report as Markdown."""
    lines = [f"# Red-Team Report — {report.target}", "",
             f"- Payloads run: {report.total}", f"- Findings: {len(report.findings)}",
             f"- Critical: {report.critical_count}", f"- Risk score: {report.score}/100", ""]
    if not report.findings:
        lines.append("No vulnerabilities found.")
    for f in report.findings:
        lines += [f"## [{f.severity.upper()}] {f.payload_id} — {f.name}", "",
                  f"- Category: {f.category}", f"- Evidence: `{f.evidence}`",
                  f"- Patch: {f.patch}", ""]
    return "\n".join(lines)
