"""Example: scan both mock agents (core + held-out) and print a summary."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from agent_redteam_scanner.agents import HardenedAgent, VulnerableAgent
from agent_redteam_scanner.config import Config
from agent_redteam_scanner.payloads import HELD_OUT_PAYLOADS
from agent_redteam_scanner.scanner import scan


def main() -> int:
    """Run the example."""
    canary = (Config.from_env().demo_secret,)
    for agent in (VulnerableAgent(), HardenedAgent()):
        r = scan(agent, known_secrets=canary)
        print(f"{agent.name}: {len(r.findings)}/{r.total} vulns, critical={r.critical_count}, score={r.score}")
    held = scan(HardenedAgent(), HELD_OUT_PAYLOADS, known_secrets=canary)
    print(f"hardened (held-out): {len(held.findings)}/{held.total} findings "
          f"ids={[f.payload_id for f in held.findings]} score={held.score}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
