"""Report generation + end-to-end demo tests."""
import json

from agent_redteam_scanner.agents import VulnerableAgent
from agent_redteam_scanner.cli import main
from agent_redteam_scanner.report import to_json, to_markdown
from agent_redteam_scanner.scanner import scan


def test_markdown_report_has_findings_and_patches() -> None:
    md = to_markdown(scan(VulnerableAgent()))
    assert "Red-Team Report" in md and "Patch:" in md


def test_json_report_valid() -> None:
    data = json.loads(to_json(scan(VulnerableAgent())))
    assert data["findings"] and data["score"] > 0


def test_e2e_cli_scan(capsys) -> None:  # type: ignore[no-untyped-def]
    assert main(["scan", "--target", "vulnerable"]) == 0
    out = capsys.readouterr().out
    assert "Findings:" in out


def test_e2e_cli_list_and_hardened(capsys) -> None:  # type: ignore[no-untyped-def]
    assert main(["list-payloads"]) == 0
    assert "PI-01" in capsys.readouterr().out
    assert main(["scan", "--target", "hardened", "--format", "json"]) == 0
    assert '"critical": 0' in capsys.readouterr().out
