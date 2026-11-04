# Security reporting

RepoScan processes untrusted repository content. Reports of unintended code
execution, filesystem-boundary escapes, unbounded resource use, or exposure of
source secrets are relevant scanner security issues.

## Reporting route

Use the repository's private vulnerability-reporting option if it is available.
If it is not, use a contact method the maintainer publishes on the
[ThreatProphet GitHub profile](https://github.com/ThreatProphet). If no private
route is listed, a public issue may request one without disclosing exploit
details, private source, or sensitive evidence. This document does not assert
that private GitHub reporting is enabled.

Include the scanner version, platform, engine and version, effective command,
expected and observed behavior, and a minimal inert reproducer when possible.
Do not attach credentials, personal identifiers, private repositories, or live
payloads to a public issue. Do not execute a suspicious project to prepare a
report.

Detection misses and excessive warnings can be reported as ordinary issues
with sanitized examples. Distinguish a useful review warning from a claim that
the tool incorrectly classified malware.

## Current support scope

This is an unreleased development candidate. Verification focuses on the
current development code and the Linux support boundary described in the
[design note](docs/design.md). No long-term support or response-time commitment
is stated.

A no-findings result is limited to the configured scope and supplied bytes.
It is not authorization to trust or execute the target project.
