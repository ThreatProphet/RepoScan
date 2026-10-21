# RepoScan

RepoScan is a YARA-based triage tool for suspicious developer assignments, interview tasks, and untrusted codebases.

The rules are derived from ThreatProphet incident reporting on malicious developer-task lures. The reports are not stored in this repository; use the public archive at [threatprophet.com](https://threatprophet.com/) for the source writeups and context behind the `TP-2026-*` references in the rule metadata.

The rules focus on repeated behavior rather than fragile one-off IOCs:

- VS Code `runOn: folderOpen` task abuse with pipe-to-shell commands
- npm lifecycle hooks that launch hidden server-side execution chains
- remote payload fetch plus `new Function`, `Function.constructor`, or `eval`
- known `AUTH_API` / full `process.env` exfiltration patterns
- generalized base64-encoded URL hiding in `.env`, JSON, or JavaScript config
- downloaded remote content piped or passed directly to shells/interpreters
- local `.git/hooks` fetching remote scripts from delivered tasks
- browser, wallet, clipboard, and Socket.IO collection primitives
- horizontal whitespace used to push loader code off-screen
- hidden or encoded PowerShell

## Quick Start

```bash
python3 tools/scan_task.py /path/to/project-or-dev-task
```

Exit codes:

- `0`: no findings
- `1`: suspicious or review-needed findings
- `2`: critical findings, malicious likely
- `64`: invalid target or configuration
- `69`: requested canonical YARA engine is unavailable
- `70`: operational failure or incomplete scan

Finding exit codes (`0`-`2`) are emitted only for complete scans. An unreadable
file, resource-limit breach, rule compilation error, or engine failure is an
operational failure; it is never reported as a clean verdict.

JSON output:

```bash
python3 tools/scan_task.py /path/to/project-or-dev-task --json
```

Color output is automatic in interactive terminals. Override it when needed:

```bash
python3 tools/scan_task.py /path/to/project-or-dev-task --color always
python3 tools/scan_task.py /path/to/project-or-dev-task --color never
```

## Bash compatibility wrapper

The Bash entry point preserves the established invocation style while delegating
all discovery, engine, output, and error handling to the Python scanner:

```bash
tools/scan_task.sh /path/to/project-or-dev-task
```

It accepts the same options as the Python scanner and propagates its standard
output, standard error, and exit code unchanged:

```bash
tools/scan_task.sh --color always /path/to/project-or-dev-task
tools/scan_task.sh --color never /path/to/project-or-dev-task
```

The wrapper does not interpret target names or implement a second scanner.

## YARA Engine

Canonical YARA is the default. In `auto` mode the scanner uses engines in this
order:

1. `yara-python`, if installed
2. `yara` CLI, if installed

If neither is available, the scan fails with exit code `69`. Canonical engine or
rule failures do not trigger heuristic matching. Select an engine explicitly
when reproducibility requires it:

```bash
python3 tools/scan_task.py /path/to/project --engine yara-python
python3 tools/scan_task.py /path/to/project --engine yara-cli
```

`--strict-yara` remains as a deprecated compatibility option for canonical-only
behavior.

### Explicit heuristic mode

The lite matcher is available only by explicit opt-in:

```bash
python3 tools/scan_task.py /path/to/project --engine lite
# compatibility alias
python3 tools/scan_task.py /path/to/project --lite
```

Lite mode is a heuristic triage mode, not a YARA implementation. Its findings
use `HEUR_*` identifiers and the `heuristic-findings` verdict; it never emits
canonical `TP_DevelTask_*` rule identifiers or a `malicious-likely` verdict.

Install one of:

```bash
python3 -m pip install yara-python
# or install the yara command-line package with your OS package manager
```

## Rules

The main rule file is:

```text
rules/developer_task_malware.yar
```

Rule metadata keeps the relevant ThreatProphet report IDs, such as `TP-2026-001` and `TP-2026-011`, so you can map detections back to the public analysis.

The scanner (and therefore its Bash wrapper) reads shared ignore patterns from:

```text
config/scan_ignore.txt
```

Override it when needed:

```bash
python3 tools/scan_task.py /path/to/project --ignore-config config/scan_ignore.txt
tools/scan_task.sh --ignore-config config/scan_ignore.txt /path/to/project
```

These are triage rules. Treat matches as prompts for review, containment, or sandboxing. A clean result does not prove a task is safe, especially if the project uses unusual build tooling, generated code, encrypted blobs, or remote dependencies.

## Discovery and scan completeness

RepoScan admits regular files using filesystem metadata without following
symlinks. Symlinks, FIFOs, sockets, device nodes, and unsupported filesystem
entries are skipped and accounted for. Directory traversal and JSON lists are
sorted for deterministic output. Ignore patterns match normalized paths relative
to the scan root.

Resource use is bounded with positive-value options:

```bash
python3 tools/scan_task.py /path/to/project \
  --max-size 2097152 \
  --max-files 10000 \
  --max-entries 100000 \
  --max-total-bytes 268435456 \
  --timeout 30
```

JSON output includes `complete`, `status`, `errors`, and `stats`. Policy skips
such as ignored, special, symlink, and oversized entries are accounted for but
do not make a scan incomplete. Discovery, read, engine, timeout, and resource
limit failures do.

## Platform support

Linux is the baseline supported and CI-tested platform. Safe scanning depends
on POSIX descriptor-relative filesystem operations, including no-follow and
directory-only opens.

macOS support is conditional on native verification of those filesystem
primitives and the complete test suite. Native Windows is unsupported; use a
supported Linux environment instead.

## Verify Locally

```bash
python3 -m pip install --editable '.[dev,yara]'
pytest
ruff check tools tests
python3 -m compileall -q tools tests
shellcheck tools/scan_task.sh
yara -w rules/developer_task_malware.yar /dev/null
```

The test fixtures under `tests/fixtures/`, including
`malicious-githook/pre-commit.fixture`, are inert scanner inputs. Verification
reads them as data and must never execute JavaScript, shell, PowerShell, Git
hooks, npm scripts, or build instructions from a fixture.

The automated suite distinguishes unavailable YARA and shell-lint dependencies
as skipped or not run; absence is not a successful verification result. CI
installs both canonical YARA engines and ShellCheck before running the full
suite.

## Licensing

No open-source license has been selected. Choosing and adding a license remains
a project-owner decision and is a release blocker.
