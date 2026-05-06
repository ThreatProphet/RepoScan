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

JSON output:

```bash
python3 tools/scan_task.py /path/to/project-or-dev-task --json
```

## Minimal Bash Scanner

If you want fewer runtime dependencies and already have the `yara` CLI installed:

```bash
tools/scan_task.sh /path/to/project-or-dev-task
```

The Bash scanner runs the `.yar` rules directly. It does not include the Python fallback matcher, JSON output, severity sorting, or rich descriptions.

## YARA Engine

The scanner uses engines in this order:

1. `yara-python`, if installed
2. `yara` CLI, if installed
3. built-in lite fallback patterns, so the script remains usable immediately

For strict real-YARA mode:

```bash
python3 tools/scan_task.py /path/to/project --strict-yara
```

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

Both scanners read shared ignore patterns from:

```text
config/scan_ignore.txt
```

Override it when needed:

```bash
python3 tools/scan_task.py /path/to/project --ignore-config config/scan_ignore.txt
tools/scan_task.sh --ignore-config config/scan_ignore.txt /path/to/project
```

These are triage rules. Treat matches as prompts for review, containment, or sandboxing. A clean result does not prove a task is safe, especially if the project uses unusual build tooling, generated code, encrypted blobs, or remote dependencies.

## Verify Locally

```bash
python3 tools/scan_task.py tests/fixtures/malicious-vscode
python3 tools/scan_task.py tests/fixtures/malicious-githook
python3 tools/scan_task.py tests/fixtures/suspicious-env
python3 tools/scan_task.py tests/fixtures/suspicious-pipe
python3 tools/scan_task.py tests/fixtures/benign
```
