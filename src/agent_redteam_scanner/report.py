"""Markdown + JSON report generation.

Evidence is redacted again at render time (the scanner already
redacts before storing) so a report can never persist a leaked
secret, even if a finding was constructed by hand.
"""
from __future__ import annotations

import json
from dataclasses import asdict

from agent_redteam_scanner.scanner import ScanReport, redact_text


def to_json(report: ScanReport) -> str:
    """Serialise a report to JSON (evidence redacted)."""
    findings = []
    for f in report.findings:
        item = asdict(f) | {"category": str(f.category), "severity": str(f.severity),
                            "evidence": redact_text(f.evidence)}
        findings.append(item)
    return json.dumps({"target": report.target, "total": report.total, "score": report.score,
                       "critical": report.critical_count, "by_category": report.by_category(),
                       "findings": findings}, indent=2)


def to_markdown(report: ScanReport) -> str:
    """Render a report as Markdown (evidence redacted)."""
    lines = [f"# Red-Team Report — {report.target}", "",
             f"- Payloads run: {report.total}", f"- Findings: {len(report.findings)}",
             f"- Critical: {report.critical_count}", f"- Risk score: {report.score}/100", ""]
    if not report.findings:
        lines.append("No vulnerabilities found.")
    for f in report.findings:
        lines += [f"## [{f.severity.upper()}] {f.payload_id} — {f.name}", "",
                  f"- Category: {f.category}", f"- Evidence: `{redact_text(f.evidence)}`",
                  f"- Patch: {f.patch}"]
        if f.reasons:
            lines.append(f"- Detection: {', '.join(f.reasons)}")
        lines.append("")
    return "\n".join(lines)
