# Changelog

## Unreleased

### Changed

- Separated CLI presentation from a typed scan service, with dedicated
  filesystem, rule-pack, engine, terminal, and result modules. Documented module
  ownership and contribution paths. Existing CLI behavior, output contracts,
  detections, and the `scanner.main` compatibility entry point are preserved.
- Terminal findings now lead with severity and file location, followed by the
  reason and highlighted evidence. A severity-count summary supports triage;
  full rule IDs, confidence, trigger prerequisites, and evidence limits remain
  visible.
- Text wraps to the terminal width, up to 120 columns, or 100 columns when
  redirected. `--width` selects a reproducible width from 40 to 240 columns.
  Color remains optional, with the same labels and details in plain output.
- Incomplete scans retain prominent errors and follow-up guidance. Empty
  selections use a warning color, and every text result shows its exit code.
  Detection behavior, JSON/Markdown output, and exit-code meanings are unchanged.
- Refreshed the GIF/MP4 demonstration and recording guide for the updated
  terminal layout, with complete report pages and verified scan exit statuses.

## 0.2.0 - 2026-11-05

Version 0.2.0 centers the developer workflow of reviewing an unfamiliar
repository before trusting, installing, or running it.

### Added

- Common static-review warnings for supported Git/VS Code and package trigger
  contexts, obfuscation, and suspicious constructs.
- The Web3Market same-file entry signature derived from report TP-2026-018,
  with explicit confidence and coverage limits.
- Finding categories, confidence, trigger prerequisites, source-report
  references, bounded byte evidence, scanned-file hashes, and stable finding IDs.
- A versioned JSON contract, Markdown output, coverage information, and
  packaged rule/configuration resources.
- An installed `reposcan` command and `--version`.
- Inert detection cases and documentation of the pre-execution review boundary.
- MIT licensing for project-owned code, original rules, tests, and documentation.
- A pipx quick start with YARA support and a manual virtual-environment fallback.
- A Linux `install.sh` convenience installer that verifies the installed scanner
  before exposing its command and reports existing-installation conflicts.
- Installation and maintenance guidance, including migration from earlier
  previews and removal instructions.

### Changed

- Canonical verdicts now use `review-needed` or `high-risk` instead of
  `suspicious` or `malicious-likely`. Exit `2` requires a critical,
  high-confidence canonical finding; severity alone is insufficient.
- Common `REVIEW_*` findings can accompany both canonical and Lite matches.
  Lite remains explicit, retains `HEUR_*` matches, and never emits the canonical
  `high-risk` verdict.
- Lite descriptions distinguish co-occurring constructs from proved data flow
  or successful execution.
- Source-checkout rules and defaults now live under `src/reposcan/`; legacy
  Python and Bash scan entry points continue to delegate to the implementation.
- The Python distribution name is `threatprophet-reposcan`. The `reposcan`
  command and Python import remain unchanged. Use a fresh environment when
  migrating from a preview installed under the old distribution name.

### Reliability

- Bounded Lite matching and the whitespace near-match path.
- Metadata handling for valid compact and tagged YARA rules.
- Rule sources are captured once, so metadata, reported hashes, and compilation
  use the same bytes; errors retain the original trusted rule paths.
- Matching per-file namespaces across the two canonical adapters preserve
  consistent global-rule scope.
- Runtime YARA warnings make results incomplete. Recognized CLI compiler
  performance warnings remain permissible.
- Installed-distribution and evidence/output verification, retaining the
  existing safe-file and race-condition regression cases.
- Fresh pipx installation checks with native YARA, benign and inert positive
  scans, and removal, alongside the dependency-free wheel check.
- Installer conflict and failure handling tests.

## 0.1.0 development baseline

Established explicit YARA engine selection, separate Lite heuristics,
deterministic output, structured incomplete-scan errors, resource accounting,
safe filesystem handling, and automated verification.
