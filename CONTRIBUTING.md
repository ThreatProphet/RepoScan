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

## Work on the code

Start with the [architecture guide](docs/architecture.md) for module ownership,
the scan lifecycle, and a change-to-test map. The service boundary is
`scan(ScanOptions) -> ScanResult`; CLI parsing and output rendering are separate.
Keep new operations in the module that owns their responsibility and test that
boundary directly.

When refactoring, preserve the established result and filesystem contracts.
Move existing assertions with their owning modules, and retain the race,
resource-budget, incomplete-scan, and adapter-parity coverage. Compare output
against the original implementation using the same fixtures and engine
versions. CLI entry points and the versioned JSON schema are compatibility
surfaces; importing former internal helpers from `scanner.py` is not a stable
extension mechanism.

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
`src/reposcan/review.py`; Lite patterns live in `src/reposcan/engines/lite.py`
and remain a separate explicit heuristic matcher.
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
shellcheck install.sh tools/scan_task.sh reposcan-run.sh
yara -w src/reposcan/rules/*.yar /dev/null
.venv/bin/python -m build
.venv/bin/python tools/verify_wheel.py dist/threatprophet_reposcan-0.4.0-py3-none-any.whl
.venv/bin/python tools/verify_install.py dist/threatprophet_reposcan-0.4.0-py3-none-any.whl
.venv/bin/python tools/prepare_launcher.py dist/threatprophet_reposcan-0.4.0-py3-none-any.whl \
  --output dist/reposcan-run.sh
.venv/bin/python tools/verify_launcher.py --launcher dist/reposcan-run.sh \
  --wheel dist/threatprophet_reposcan-0.4.0-py3-none-any.whl
```

The YARA CLI and ShellCheck are separate verification dependencies. Pipx is
included in the `dev` extra for installation verification. Record skipped or
unavailable checks accurately. Changes to engine behavior should be checked
across both canonical adapters when available.

Package changes should pass the installation and launcher gates:

- `tools/verify_wheel.py` installs the exact wheel without dependencies or
  network access into a fresh environment and runs outside the source checkout.
  It checks distribution identity and licensing, packaged resources, benign
  and inert positive inputs, and unavailable-engine behavior.
- `tools/verify_install.py` installs the exact wheel with its YARA extra using
  an isolated pipx environment. It checks installed origin, a benign scan, the
  inert Web3Market case with `yara-python`, and removal. Dependencies are
  resolved over the network unless `--wheelhouse /absolute/path/to/wheels`
  supplies the required artifacts for an offline run.
- `tools/prepare_launcher.py` binds a release launcher to the exact built
  wheel version and SHA-256. `tools/verify_launcher.py` exercises it with empty
  private uv/Python/YARA state. Supplying `--wheel` seeds only that exact wheel
  into the normal verified cache because an unpublished release URL does not
  exist yet. It does not skip the launcher's checksum or runtime checks.
  Benign, review and high-risk scans verify exits `0`, `1` and `2`; offline
  reuse, usage errors, target integrity, ignored project settings and corrupt
  cached artifacts are also checked. First-time runtime preparation needs the
  network, even when the scanner wheel is supplied locally.

For a change to the source launcher's published download path or pins, also run:

```bash
.venv/bin/python tools/verify_launcher.py
```

This downloads the source launcher's actual pinned public wheel into fresh
state. It complements exact candidate-wheel checks. Neither command uses an
existing system Python to satisfy the launcher's runtime, and positive
fixtures are never executed.

CI runs the existing suites and installation gates on Ubuntu/Python 3.10 and
3.12 plus native macOS 15 Apple Silicon and Intel/Python 3.12. All four native
jobs passed for the merged quick-run changes. Each release must additionally
qualify its exact uploaded launcher and wheel on Linux and both Mac platforms.
Record the actual platform and any skips in a pull request; a Linux run does
not establish Mac support. Keep target filesystem and timeout protections
intact when fixing a platform-specific harness assumption.

### Update launcher runtime pins

Keep runtime updates separate from detection changes. `reposcan-run.sh`
declares the uv version, platform archive hashes, exact CPython version and
build date, YARA version, and scanner wheel pins. Obtain uv archive hashes
from the matching [official uv release](https://github.com/astral-sh/uv/releases),
and confirm the Python version/build/platform combination in that uv tag's
`crates/uv-python-managed/download-metadata.json`. Confirm prebuilt native
YARA wheels for every advertised platform. Do not replace these with mutable
`latest` references or enable source builds to make a qualification job pass.

Use `tools/prepare_launcher.py` for scanner-wheel version/hash changes. Run the
source launcher against its published artifacts and the generated launcher
against the candidate wheel, then require the native matrix. The launcher
unit tests use only temporary test copies with inert artifacts; production
has no URL or hash override that bypasses artifact verification.

Changes to the convenience installer also need a fresh `install.sh` run with
temporary `--prefix` and `--bin-dir` directories. Verify that engine checks
finish before the command is exposed and that collisions fail without
overwriting existing files. The installer scans a benign temporary file;
test fixtures remain data.

Preserve filesystem, race, budget, and incomplete-scan tests. New parsers and
decoders must have bounds on input, work, and output. Avoid evaluating source
or following target-supplied paths outside the established read policy.

Maintainers preparing a version should follow the [release guide](docs/releases.md)
for version updates, verification, tagging, and draft publication.

## Pull requests

Explain the developer-facing problem, the resulting warning or behavior, and
the evidence used to verify it. Include any changed verdicts, output-schema
implications, and remaining limits. Update the detection guide and changelog
when behavior changes. Example outputs should be generated by the implemented
CLI against the documented inert fixture.

For scanner vulnerabilities, follow [SECURITY.md](SECURITY.md).

## License and source material

Project-owned code, original rules, tests, and documentation use the
[MIT license](LICENSE). Contributions are accepted under those terms. Submit
work you have the right to contribute, and identify the origin and license of
any reused material. Preserve required third-party copyright, license, and
attribution notices. A link to an investigation supplies research provenance;
it does not change that publisher's licensing terms.
