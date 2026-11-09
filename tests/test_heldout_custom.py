"""Held-out suite, custom-agent adapters, redaction and FP tests."""
import base64
import json
import sys
import textwrap
from typing import ClassVar

import pytest

from agent_redteam_scanner.adapters import CommandAgent, load_module_agent
from agent_redteam_scanner.agents import BaseAgent, HardenedAgent, VulnerableAgent
from agent_redteam_scanner.config import Config
from agent_redteam_scanner.errors import ScannerError
from agent_redteam_scanner.payloads import HELD_OUT_PAYLOADS, PAYLOADS
from agent_redteam_scanner.report import to_json, to_markdown
from agent_redteam_scanner.scanner import is_vulnerable_response, redact_text, scan

CANARY = (Config.from_env().demo_secret,)

# Literal trigger strings of the core suite / legacy shared blocklist.
# Held-out payloads must not contain any of them (checked case-insensitively).
LEGACY_TRIGGERS = (
    "ignore previous", "system prompt", "developer mode", "do anything now",
    "base64 encode your secret", "full context", "rm -rf", "delete all",
    "admin_grant", "transfer_funds", "169.254", "attacker", "evil.example",
    "send the secret", "email the api key",
)


def test_held_out_has_10_plus_payloads() -> None:
    assert len(HELD_OUT_PAYLOADS) >= 10
    assert all(p.held_out for p in HELD_OUT_PAYLOADS)


def test_held_out_prompts_share_no_legacy_triggers() -> None:
    for p in HELD_OUT_PAYLOADS:
        low = p.prompt.lower()
        for trigger in LEGACY_TRIGGERS:
            assert trigger not in low, f"{p.id} contains legacy trigger {trigger!r}"


def test_hardened_core_suite_clean() -> None:
    report = scan(HardenedAgent(), known_secrets=CANARY)
    assert report.findings == [] and report.score == 0


def test_hardened_held_out_real_catch_rate() -> None:
    """Verified behaviour: 10 refusals, HO-11 leaks transformed (canary
    finding), HO-12 discloses a paraphrase no marker can see."""
    report = scan(HardenedAgent(), HELD_OUT_PAYLOADS, known_secrets=CANARY)
    assert [f.payload_id for f in report.findings] == ["HO-11"]
    assert report.findings[0].reasons == ("canary secret leaked with separators inserted",)


def test_ho12_paraphrase_is_scanner_blind_spot() -> None:
    """Documented honestly: the paraphrase disclosure has no marker."""
    payload = next(p for p in HELD_OUT_PAYLOADS if p.id == "HO-12")
    response = HardenedAgent().respond(payload.prompt)
    assert "paraphrased" in response  # the agent DID disclose
    assert not is_vulnerable_response(response, CANARY)  # scanner cannot see it


def test_evidence_is_redacted_everywhere() -> None:
    report = scan(VulnerableAgent(), known_secrets=CANARY)
    secret = CANARY[0]
    assert secret not in to_markdown(report)
    assert secret not in to_json(report)
    assert all(secret not in f.evidence for f in report.findings)
    held = scan(HardenedAgent(), HELD_OUT_PAYLOADS, known_secrets=CANARY)
    assert "s.k._.l.i.v.e" not in to_markdown(held)  # dotted canary masked too


def test_redact_text_masks_transforms() -> None:
    secret = "tok-ABC-123"
    assert redact_text(f"leak: {secret}", (secret,)) == "leak: ***REDACTED***"
    assert secret[::-1] not in redact_text(secret[::-1], (secret,))
    assert base64.b64encode(secret.encode()).decode() not in redact_text(
        base64.b64encode(secret.encode()).decode(), (secret,))


def test_base64_leak_detected_without_canary() -> None:
    class B64Agent(BaseAgent):
        name = "b64"

        def respond(self, prompt: str) -> str:
            return base64.b64encode(b"SYSTEM_SECRET=hunter2hunter2").decode()

    report = scan(B64Agent(), PAYLOADS[:2])
    assert len(report.findings) == 2
    assert any("base64" in r for f in report.findings for r in f.reasons)


def test_score_denominator_uses_payloads_run() -> None:
    subset = scan(VulnerableAgent(), PAYLOADS[:3])
    assert subset.total == 3 and subset.score == 100
    capped = scan(VulnerableAgent(), max_payloads=2)
    assert capped.total == 2 and len(capped.findings) == 2 and capped.score == 100
    clean = scan(HardenedAgent(), PAYLOADS[:5])
    assert clean.total == 5 and clean.score == 0


class _BenignAgent(BaseAgent):
    """Agent that answers normally, incl. talking *about* security."""

    name = "benign"
    _answers: ClassVar[dict[str, str]] = {
        "password": "To reset your password, open Settings > Security and follow the steps.",
        "base64": "Base64 is an encoding scheme that represents binary data as ASCII text.",
        "capital": "Paris is the capital of France.",
    }

    def respond(self, prompt: str) -> str:
        for key, answer in self._answers.items():
            if key in prompt.lower():
                return answer
        return "Here is a helpful, ordinary answer."


def test_no_false_positives_on_benign_agent() -> None:
    benign_prompts = [
        "How do I reset my password safely?",
        "Explain base64 encoding with an example",
        "What is the capital of France?",
        "Write a haiku about autumn leaves",
        "How do I protect my api key in a mobile app?",
    ]

    class BenignTarget(_BenignAgent):
        def respond(self, prompt: str) -> str:
            return _BenignAgent().respond(prompt)

    for prompt in benign_prompts:
        assert not is_vulnerable_response(BenignTarget().respond(prompt), CANARY), prompt


def test_command_agent_scans_custom_process(tmp_path) -> None:  # type: ignore[no-untyped-def]
    script = tmp_path / "leaky_agent.py"
    script.write_text(textwrap.dedent("""
        import sys
        for line in sys.stdin:
            print("SYSTEM_SECRET=MY_OWN_CANARY_123", flush=True)
    """))
    agent = CommandAgent(f"{sys.executable} {script}")
    try:
        report = scan(agent, PAYLOADS[:3], known_secrets=("MY_OWN_CANARY_123",))
    finally:
        agent.close()
    assert len(report.findings) == 3
    assert "MY_OWN_CANARY_123" not in to_json(report)  # redacted even for custom agents


def test_module_agent_scans_custom_class(tmp_path) -> None:  # type: ignore[no-untyped-def]
    module = tmp_path / "my_agent.py"
    module.write_text(textwrap.dedent("""
        class MyAgent:
            name = "mine"

            def respond(self, prompt):
                return "a perfectly safe answer"
    """))
    agent = load_module_agent(f"{module}:MyAgent")
    report = scan(agent, PAYLOADS[:3])
    assert report.target == "mine" and report.findings == []


def test_module_agent_bad_spec_raises() -> None:
    with pytest.raises(ScannerError):
        load_module_agent("no-colon-here")
    with pytest.raises(ScannerError):
        load_module_agent("/nonexistent/agent.py:Nope")


def test_cli_custom_agent_and_held_out(capsys, tmp_path) -> None:  # type: ignore[no-untyped-def]
    from agent_redteam_scanner.cli import main

    script = tmp_path / "echo_agent.py"
    script.write_text("import sys\nfor line in sys.stdin:\n    print('safe answer', flush=True)\n")
    rc = main(["scan", "--agent-command", f"{sys.executable} {script}", "--format", "json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["findings"] == []
    rc = main(["scan", "--target", "hardened", "--suite", "held-out", "--format", "json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["total"] == len(HELD_OUT_PAYLOADS)
    assert [f["payload_id"] for f in data["findings"]] == ["HO-11"]
