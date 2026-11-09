"""Benchmark: vulns found on vulnerable mock vs 0 critical on hardened mock."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from agent_redteam_scanner.agents import HardenedAgent, VulnerableAgent
from agent_redteam_scanner.scanner import scan


def main() -> int:
    """Run benchmark and assert the headline target."""
    v = scan(VulnerableAgent())
    h = scan(HardenedAgent())
    print(f"vulnerable: findings={len(v.findings)} critical={v.critical_count} score={v.score}/100")
    print(f"hardened:   findings={len(h.findings)} critical={h.critical_count} score={h.score}/100")
    print(f"target: >=10 findings on vulnerable, 0 critical on hardened -> "
          f"{'PASS' if len(v.findings) >= 10 and h.critical_count == 0 else 'FAIL'}")
    return 0 if len(v.findings) >= 10 and h.critical_count == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
