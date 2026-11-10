# Changelog

## Unreleased

### Changed

- Refreshed the checked-in quick-run launcher to the published RepoScan 0.4.0
  wheel and its verified SHA-256, and updated the source-launcher instructions.
- Updated the pinned checkout and Python setup actions to releases that declare
  Node 24, retaining the existing CI matrix and release qualification gates.
- Refreshed the GIF, MP4 and poster for the RepoScan 0.4.0 download-and-scan
  flow, current terminal colors and summary at the end. Added tools and
  contributor instructions to capture real output and reproduce the media.

## 0.4.0 - 2026-11-09

RepoScan 0.4.0 adds a quick-run shell launcher for a first scan without an
existing Python installation, native macOS qualification, and a terminal
summary that follows the findings and coverage details.

### Added

- A portable `reposcan-run.sh` quick-run entry point that prepares a private
  pinned uv/CPython/YARA environment and scans with a verified release wheel.
  It supports cached offline operation, preserves scanner results and exit
  codes, and leaves permanent installations and the scanned project separate.
- Native macOS 15 qualification jobs for Apple Silicon and Intel, retaining
  Linux/Python 3.10 and 3.12 coverage. All four native CI jobs passed for the
  merged changes. Publication also requires checks of the exact release
  launcher and wheel on Linux and both Mac architectures.
- Launcher verification from empty runtime state, with benign/review/high-risk
  inputs, ignored project configuration and tool overrides, intact inputs,
  offline reuse, and rejection of corrupted cached artifacts.
- Release-generated launchers bound to the exact wheel version and SHA-256.
  The release workflow verifies that artifact on Linux and both Mac
  architectures before creating its draft, and includes the launcher in
  uploaded checksums.

### Changed

- Terminal reports end with the verdict, finding and severity counts, scanned
  file totals, and completion status after the findings and coverage details.
  Target and engine context remain at the top; follow-up guidance and the
  actual exit code follow the summary.
- The README leads with running a first scan; permanent installation remains
  available for regular use.
- Installer and installation gates accept Darwin for native qualification.
  Test harnesses account for platform descriptor paths and short Unix-socket
  path limits without changing the scanner's target-read policy.

### Compatibility

- Detection rules, review checks, verdicts and exit-code meanings are unchanged.
- JSON schema 1.0 and the Markdown report format are preserved; the reported
  tool version is now 0.4.0.
- The scanner retains Python 3.10+ support. The quick-run launcher manages its
  own pinned CPython 3.12 runtime and YARA dependency.
- Use the `reposcan-run.sh` release asset to run this release. The checked-in
  source launcher remains pinned to the published 0.3.1 wheel during release
  preparation and is refreshed separately after publication.

## 0.3.1 - 2026-11-05

RepoScan 0.3.1 makes findings easier to interpret and the codebase easier to
maintain and extend. It includes the terminal improvements and architecture
refactor developed since 0.2.0.

The earlier `v0.3.0` tag was created while the package still identified itself
as 0.2.0. Release preparation stopped at version validation, and no release
assets were published for that tag. Version 0.3.1 aligns the tag, package
metadata, runtime version, and changelog while preserving the existing tag.

### Added

- `--width` selects a reproducible text width from 40 to 240 columns.
- An architecture guide documents module responsibilities, the scan lifecycle,
  contribution paths, and the security and correctness properties to preserve.
- Focused service tests cover explicit arguments, structured failures,
  API/CLI consistency, independent repeated scans, and engine-loading failures.
- A maintainer release guide documents version preparation, local validation
  before pushing a tag, verified draft assets, and publication.

### Changed

- Terminal findings now lead with severity and file location, followed by the
  reason and highlighted evidence. A severity-count summary supports triage;
  full rule IDs, confidence, trigger prerequisites, and evidence limits remain
  visible.
- Text wraps to the terminal width, up to 120 columns, or 100 columns when
  redirected. Color remains optional, with the same labels and details in
  plain output.
- Incomplete scans retain prominent errors and follow-up guidance. Empty
  selections use a warning color, and every text result shows its exit code.
- Separated CLI presentation from a typed `scan(ScanOptions) -> ScanResult`
  service, with dedicated filesystem, rule-pack, engine, terminal, and result
  modules. The scanner module is reduced from 1,642 to 223 lines.
- Refreshed the GIF/MP4 demonstration and recording guide for the updated
  terminal layout, using public inert fixtures. Existing media remains labeled
  as a pre-release capture; reproduction commands now use 0.3.1.
- Updated installation instructions, contributor examples, and example reports
  for the release version.

### Compatibility

- Detection rules, common static-review checks, verdict rules, and exit-code
  meanings are preserved. This release does not add detection coverage.
- JSON schema 1.0 and the Markdown report contract are preserved. The reported
  tool version changes to 0.3.1. Integrations should consume JSON rather than
  parsing the redesigned terminal text layout.
- Installed, module, and source-checkout command-line entry points remain
  available, including the `scanner.main` compatibility delegate. Internal
  helpers formerly imported from `scanner.py` now live in their owning modules;
  the typed service is an internal development interface.
- Linux remains the supported platform with Python 3.10 or later and a
  compatible YARA installation for canonical scanning.

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
