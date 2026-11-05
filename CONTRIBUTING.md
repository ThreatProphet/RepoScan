# Contributing to RepoScan

RepoScan helps developers inspect unfamiliar code before enabling its triggers
or running project commands. Contributions should improve useful warnings,
their explanation, or the reliability of the scan boundary.

You can help without writing a detector. A confusing finding, a benign
counterexample, a clearer explanation, or an independent investigation can
all lead to a useful improvement.

## Choose a starting point

| What you noticed | Where to start |
| --- | --- |
| A crash, installation problem, or incorrect output | [Report a scanner bug](https://github.com/ThreatProphet/RepoScan/issues/new?template=bug_report.yml) with the command and observed behavior. |
| A suspicious mechanism that is not covered | [Suggest a detection](https://github.com/ThreatProphet/RepoScan/issues/new?template=detection_gap.yml) using a public report or a short description of what is visible before execution. |
| A warning that overstates the evidence or is not useful | [Review a warning](https://github.com/ThreatProphet/RepoScan/issues/new?template=false_positive.yml) with its exact rule ID and the legitimate behavior it matched. |
| An unclear instruction, finding explanation, or example | Submit a focused documentation pull request. Describe where a reader gets stuck and show the clearer wording. |
| A missing test or close benign comparison | Add an inert case and exact expectations. [Detection-quality tests](tests/test_detection_quality.py) and [common-review tests](tests/test_review.py) show the current conventions. |

Small corrections can go straight to a pull request. For a new detector or a
change to verdicts, an issue helps establish the intended warning before
substantial implementation. A public report or mechanism description is enough
to start; a private repository or raw specimen is not required.

The initial report-derived rules come from ThreatProphet investigations of
developer-task attacks. Research from other publishers is welcome. Link the
original evidence and explain how it applies to inspecting a repository before
execution. External research does not need a ThreatProphet report number.

For vulnerabilities in the scanner itself, follow [SECURITY.md](SECURITY.md).

## Propose a detection

Describe the mechanism and input stage before choosing a predicate:

1. Identify the source report or independently documented evidence.
2. State what is visible in the repository before execution.
3. Define the minimum combination that warrants a warning.
4. Distinguish observed syntax, inferred relationships, and unresolved behavior.
5. Choose severity and confidence separately.
6. Document supported forms and known detection limits.

Use a stable, descriptive rule ID. Keep report identifiers and available primary
source URLs in metadata. Do not name an actor in a verdict merely because its
reported tooling uses a similar mechanism.

Canonical rules live in `src/reposcan/rules/`. Common static checks live in
`src/reposcan/review.py`; Lite remains a separate explicit heuristic matcher.
Preserve source labels and do not claim parity between different detector types.

## Fixtures and expectations

Every new family needs a small positive fixture and close benign comparisons.
Use exact expected rule IDs, not only an assertion that some finding exists.
Include supported quote/whitespace variants and at least one documented
boundary case.

Fixtures are data. Use reserved destinations such as `example.invalid`, remove
credentials and personal identifiers, and avoid a working acquisition or
execution chain. Do not execute JavaScript, shell, PowerShell, hooks, package
scripts, or build commands from a fixture. Preserve executable bits deliberately
only when the test needs to inspect metadata, never to run the content.

A benign example can legitimately produce a review warning. Test its
classification and explanation: dynamic evaluation, obfuscation, or an unusual
hook need not be silently ignored, but they must not receive an unsupported
claim of maliciousness, remote input, or successful execution.

Keep original, decoded, and reconstructed representations distinct. A match on
a readable analysis derivative must not be advertised as a match on the
delivered bytes. Private specimens should not be added to this repository merely
to make a public regression test.

## Verify changes

For documentation and template changes, check formatting, links, and YAML
syntax where applicable. Use the checks below for scanner, detection, and
packaging changes, recording which checks apply to your change.

From the trusted RepoScan checkout:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --editable '.[dev,yara]'
.venv/bin/python -m pytest
.venv/bin/python -m ruff check src tools tests
.venv/bin/python -m compileall -q src tools
shellcheck tools/scan_task.sh
yara -w src/reposcan/rules/*.yar /dev/null
.venv/bin/python -m build
.venv/bin/python tools/verify_wheel.py dist/reposcan-0.2.0-py3-none-any.whl
```

The YARA CLI and ShellCheck are separate verification dependencies. Record
skipped or unavailable checks accurately. Changes to engine behavior should be
checked across both canonical adapters when available. A package change should
also pass `tools/verify_wheel.py`. The gate installs the specified wheel without
dependencies or network access into a temporary fresh environment, then runs
the installed scanner outside the source checkout. It checks packaged
resources, benign and inert positive inputs, and unavailable-engine behavior.

Preserve filesystem, race, budget, and incomplete-scan tests. New parsers and
decoders must have bounds on input, work, and output. Avoid evaluating source
or following target-supplied paths outside the established read policy.

## Pull requests

Explain the developer-facing problem, the resulting warning or behavior, and
the evidence used to verify it. Include any changed verdicts, output-schema
implications, and remaining limits. Update the detection guide and changelog
when behavior changes. Example outputs should be generated by the implemented
CLI against the documented inert fixture.

For scanner vulnerabilities, follow [SECURITY.md](SECURITY.md). No license has
yet been selected; contribution and distribution terms must be resolved with
the project owner before a public packaged release.
