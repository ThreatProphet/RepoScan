# RepoScan

**Inspect an unfamiliar repository before you trust, install, or run it.**

RepoScan helps developers find suspicious execution triggers, concealed code,
and patterns observed in malicious developer projects. It combines YARA rules
derived from [ThreatProphet investigations](https://threatprophet.com/) with
static review checks for Git and VS Code configuration, obfuscation, and risky
code constructs.

Findings identify what to inspect and why. A review warning does not require a
complete execution chain, and a scan with no findings does not establish that a
project is safe.

**Development status:** version 0.2.0 candidate. A license has not yet been
selected; that decision remains a release blocker.

## Install and scan

Use Python 3.10 or later on Linux. These installation commands apply to a trusted
RepoScan checkout containing this version:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install '.[yara]'
.venv/bin/reposcan --version
.venv/bin/reposcan /path/to/unfamiliar-project
```

The scanner reads the target as data. It does not install its dependencies, run
its setup commands, invoke its Git hooks, execute decoded source, or fetch
payloads. Run it before enabling workspace tasks or following the project's
installation and startup instructions.

Save a report outside the target directory:

```bash
.venv/bin/reposcan /path/to/unfamiliar-project --format markdown > review.md
.venv/bin/reposcan /path/to/unfamiliar-project --format json > review.json
```

`--json` remains an alias for JSON output. Source-checkout entry points remain
available as `.venv/bin/python tools/scan_task.py` and `tools/scan_task.sh`, with
the same arguments. The Bash wrapper uses `python3` from `PATH`; activate the
RepoScan environment before using it. Use `.venv/bin/reposcan --help` for the
full CLI reference.

## What it looks for

| Category | Examples | Interpretation |
| --- | --- | --- |
| Execution triggers | Folder-open tasks, supplied Git hooks and configuration, package lifecycle commands | A developer action may activate this command or referenced file. |
| Obfuscation | Character-code arrays, decoder tables, encoded commands, off-screen code | Concealed content deserves inspection, even when its behavior is unresolved. |
| Suspicious behavior | Download-and-execute patterns, dynamic evaluation, hidden processes, credential collection patterns | The construct or combination creates a reason to pause before proceeding. |
| Report patterns | Tested mechanisms from previous ThreatProphet investigations, including Web3Market | The source resembles a documented technique; this is not actor attribution. |

See the [detection guide](docs/detections.md) for coverage and limits.

## Read a finding

Each finding includes its rule, category, severity, confidence, relative file
path, available byte evidence locations, a SHA-256 of the scanned file bytes,
and a stable finding identifier. Trigger checks explain the relevant action and
prerequisites. Report-derived rules retain report identifiers and available
source references. Reports identify source locations without copying source
snippets or decoded content.

**Severity** expresses potential impact or review urgency. **Confidence**
expresses the strength of the matched evidence. A high-impact operation can
still have uncertain purpose. Quoted documentation, an intentional updater, or
an obfuscated dependency can warrant a warning without establishing malware.

| Exit code | Meaning |
| --- | --- |
| `0` | No findings in the configured scan scope |
| `1` | Review warnings, or explicit Lite heuristic findings |
| `2` | A critical, high-confidence canonical pattern; verdict `high-risk` |
| `64` | Invalid arguments, target, or configuration |
| `69` | Requested canonical YARA engine unavailable |
| `70` | Operational failure or incomplete scan |

Exit codes `0`–`2` apply only to complete scans. Inspect `complete`, `status`, and
`errors` in machine-readable output; an operational failure is not a clean
result. Completeness describes the scan operation, not complete understanding
of the code. `REVIEW_Analysis_Limit` and `REVIEW_Configuration_Unparsed` flag
unresolved analysis even when the scan finishes. The strongest verdict is a
reason to pause and inspect, not proof of successful execution or compromise.

## Engines and scope

The default `auto` mode selects `yara-python`, then the `yara` CLI. If neither is
available, it exits with `69`; it does not silently fall back to heuristics.

```bash
.venv/bin/reposcan /path/to/project --engine yara-python
.venv/bin/reposcan /path/to/project --engine yara-cli
.venv/bin/reposcan /path/to/project --engine lite
```

Bundled canonical rules use `TP_DevelTask_*` IDs. Explicit Lite matches use `HEUR_*`
IDs and the `heuristic-findings` verdict. Common static review findings use
`REVIEW_*` IDs in every engine. Lite never emits canonical YARA findings or the
canonical `high-risk` verdict. `--lite` and `--strict-yara` remain compatibility
options.

The default policy skips dependency/build directories, symlinks, special files,
and oversized files. It preserves inspection of supplied `.git/hooks` and
`.git/config`. A complete scan means the eligible set was processed; the result
also reports coverage and policy skips. See [design and scope](docs/design.md)
for resource bounds, platform support, and the limits of static review.

## Reproduce the Web3Market example

From this checkout, scan the reduced, inert fixture as data:

```bash
.venv/bin/reposcan tests/fixtures/web3market-entry --engine yara-python --format markdown
```

A finding exit code is expected. Do not run the fixture content. The
[case study](docs/web3market.md) explains how the published report became a
detector, what the signature establishes, and what remains unresolved.

Captured example outputs: [Markdown](examples/web3market.md),
[JSON](examples/web3market.json), and [text](examples/web3market.txt).

## Develop and contribute

```bash
.venv/bin/python -m pip install --editable '.[dev,yara]'
.venv/bin/python -m pytest
.venv/bin/python -m ruff check src tools tests
```

Full adapter verification also requires the YARA CLI; Bash linting requires
ShellCheck. Missing dependencies are reported as skipped or not run, never as
successful verification. CI configuration describes the intended verification
matrix; a workflow file alone is not evidence of a successful run.

See [contribution guidance](CONTRIBUTING.md), [security reporting](SECURITY.md),
and the [changelog](CHANGELOG.md). No open-source license has been selected;
license selection and distribution terms remain a project-owner decision.
