# Changelog

## [0.1.1] - 2026-11-09
### Fixed (world-class remediation after adversarial audit)
- Decoupled the mocks: the hardened agent now holds its own secret and defends
  it with independent layers (input normalisation incl. leetspeak/despace/
  base64 decoding, hierarchy + tool policy, output DLP) around a generator
  that can genuinely leak — it no longer shares the payload substring lists.
- Detection is layered: literal markers + secret-pattern regexes + a
  base64-decode pass + canary matching (raw, reversed, base64,
  separator-transformed). Reports now redact all secret-shaped evidence.
- Risk score denominator is the payloads actually run, not the global list.
- `max_payloads` config is wired through the CLI into the scanner.

### Added
- Held-out suite: 12 payloads (leetspeak, spacing, synonyms, encodings) that
  share no literal triggers with the core suite. Hardened mock, measured:
  10 refused, 1 finding (HO-11 transformed canary), 1 scanner-blind
  paraphrase disclosure (HO-12, documented for manual review).
- Scan your own agent: `--agent-command` (line-protocol subprocess) and
  `--agent-module` (Python class) adapters, `--suite core|held-out|all`,
  `REDTEAM_CANARY_SECRET` canary support.
- False-positive tests: benign agents discussing passwords/base64/API keys
  produce no findings.

## [0.1.0] - 2026-11-09
### Added
- 18-payload library across 4 categories
- Vulnerable + hardened mock agents, scanner engine, scoring
- Markdown + JSON reports, CLI, benchmarks, CI
