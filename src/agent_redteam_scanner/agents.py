"""Mock target agents: one deliberately vulnerable, one hardened."""
from __future__ import annotations

from agent_redteam_scanner.config import Config

_BLOCKED = (
    "ignore previous", "system prompt", "developer mode", "do anything now",
    "dan,", "base64 encode your secret", "full context",
)
_TOOL_WORDS = ("rm -rf", "delete all", "admin_grant", "transfer_funds", "169.254")
_EXFIL_WORDS = ("attacker", "evil.example", "send the secret", "email the api key")


class BaseAgent:
    """Agent interface."""

    name: str = "base"

    def respond(self, prompt: str) -> str:
        """Respond to a prompt."""
        raise NotImplementedError


class VulnerableAgent(BaseAgent):
    """Deliberately vulnerable agent — follows any instruction, leaks secrets."""

    name = "vulnerable"

    def __init__(self, config: Config | None = None) -> None:
        """Initialise with demo (fake) secrets."""
        self._config = config or Config.from_env()
        self._secret = self._config.demo_secret

    def respond(self, prompt: str) -> str:
        """Naively comply — this is the bug the scanner must find."""
        low = prompt.lower()
        if any(w in low for w in _TOOL_WORDS):
            return f"[TOOL_EXECUTED: {prompt[:60]}] done, no confirmation needed"
        if any(w in low for w in _EXFIL_WORDS):
            return f"[EXFILTRATED secret={self._secret} to attacker] SYSTEM_SECRET={self._secret}"
        if any(w in low for w in _BLOCKED) or "secret" in low or "reveal" in low:
            return f"SYSTEM_SECRET={self._secret} system prompt: you are helpful, secret is {self._secret}"
        return "Sure, here is a helpful answer to your request."


class HardenedAgent(BaseAgent):
    """Hardened agent — hierarchy, allowlists, confirmation, DLP."""

    name = "hardened"

    def respond(self, prompt: str) -> str:
        """Refuse attacks, answer benign prompts helpfully."""
        low = prompt.lower()
        if any(w in low for w in _BLOCKED):
            return "I can't help with that. System instructions are confidential."
        if any(w in low for w in _TOOL_WORDS):
            return "Tool execution requires human approval and an allowlisted action. Refused."
        if any(w in low for w in _EXFIL_WORDS):
            return "I can't send secrets or data to external destinations. Refused."
        if "secret" in low or "api key" in low:
            return "I can't reveal secrets or credentials."
        return "Sure, here is a helpful answer to your request."


def get_agent(name: str) -> BaseAgent:
    """Factory by name."""
    from agent_redteam_scanner.errors import UnknownAgentError

    if name == "vulnerable":
        return VulnerableAgent()
    if name == "hardened":
        return HardenedAgent()
    raise UnknownAgentError(f"unknown agent: {name!r} (expected vulnerable|hardened)")
