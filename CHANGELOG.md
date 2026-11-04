# Changelog

## 0.2.0 candidate, unreleased

This candidate centers the developer workflow of reviewing an unfamiliar
repository before trusting, installing, or running it. License selection
remains a release blocker.

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

## 0.1.0 development baseline

Established explicit YARA engine selection, separate Lite heuristics,
deterministic output, structured incomplete-scan errors, resource accounting,
safe filesystem handling, and automated verification.
