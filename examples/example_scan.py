"""Example: scan both mock agents and print a summary."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from agent_redteam_scanner.agents import HardenedAgent, VulnerableAgent
from agent_redteam_scanner.scanner import scan


def main() -> int:
    """Run the example."""
    for agent in (VulnerableAgent(), HardenedAgent()):
        r = scan(agent)
        print(f"{agent.name}: {len(r.findings)}/{r.total} vulns, critical={r.critical_count}, score={r.score}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
