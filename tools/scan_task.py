#!/usr/bin/env python3
"""Scan developer-task repositories with ThreatProphet-derived YARA rules."""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RULES = ROOT / "rules"
DEFAULT_IGNORE_CONFIG = ROOT / "config" / "scan_ignore.txt"
SEVERITY_SCORE = {"critical": 90, "high": 70, "medium": 40, "low": 10}


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    path: str
    source: str
    description: str = ""


@dataclass(frozen=True)
class LiteRule:
    name: str
    severity: str
    description: str
    patterns: tuple[re.Pattern[bytes], ...]
    minimum: int

    def match(self, data: bytes) -> bool:
        return sum(1 for pattern in self.patterns if pattern.search(data)) >= self.minimum


def rx(pattern: bytes) -> re.Pattern[bytes]:
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


LITE_RULES = (
    LiteRule(
        "TP_DevelTask_VSCode_FolderOpen_PipeToShell",
        "critical",
        "VS Code task auto-executes a cross-platform pipe-to-shell command",
        (
            rx(br'"runOn"\s*:\s*"folderOpen"'),
            rx(br'(curl|wget|Invoke-WebRequest|iwr)[^\r\n]{0,240}\|[ \t]*(bash|sh|cmd|powershell)'),
            rx(br'(/api/settings/|\.vercel\.app|"presentation"|"silent")'),
        ),
        2,
    ),
    LiteRule(
        "TP_DevelTask_VSCode_FolderOpen_Suspicious_AutoTask",
        "high",
        "VS Code folderOpen task runs suspicious install, shell, or network command",
        (
            rx(br'"runOn"\s*:\s*"folderOpen"'),
            rx(br'(npm[ \t]+(install|i)|bash|sh|cmd\.exe|powershell|pwsh|curl|wget|Invoke-WebRequest|iwr|https?://|\.vercel\.app|/api/settings/)'),
        ),
        2,
    ),
    LiteRule(
        "TP_DevelTask_NPM_Lifecycle_Server_Execution",
        "high",
        "npm lifecycle or common scripts launch a local server-side execution chain",
        (
            rx(br'"scripts"'),
            rx(br'"(prepare|preinstall|postinstall)"'),
            rx(br'node[ \t]+server/server\.js'),
            rx(br'react-scripts|node[ \t]+server/server\.js[ \t]*\|'),
        ),
        3,
    ),
    LiteRule(
        "TP_DevelTask_NPM_Lifecycle_Suspicious_Command",
        "high",
        "npm lifecycle hook runs suspicious shell, network, or inline execution command",
        (
            rx(br'"scripts"'),
            rx(br'"(prepare|preinstall|install|postinstall|prepack|postpack)"[ \t]*:[ \t]*"[^"\r\n]{0,260}(curl|wget|Invoke-WebRequest|iwr|bash|sh|cmd|powershell|pwsh|node[ \t]+-e|eval|base64|atob|Buffer\.from)'),
        ),
        2,
    ),
    LiteRule(
        "TP_DevelTask_Node_Remote_Fetch_Dynamic_Execute",
        "critical",
        "Node.js fetches remote staged content and executes it dynamically",
        (
            rx(br'(new[ \t]+Function|Function\.constructor|eval[ \t]*\()'),
            rx(br'["\']require["\']'),
            rx(br'(axios\.|fetch[ \t]*\(|response\.data|res\.data|\.cookie|atob[ \t]*\(|process\.env)'),
        ),
        3,
    ),
    LiteRule(
        "TP_DevelTask_ENV_Exfil_AUTH_API",
        "critical",
        "Known AUTH_API-style base64 C2 config and full process.env POST exfiltration",
        (
            rx(br'AUTH_API'),
            rx(br'(atob[ \t]*\([^)]*AUTH_API|aHR0cHM6Ly9[a-zA-Z0-9+/=]{12,})'),
            rx(br'process\.env'),
            rx(br'(\.\.\.process\.env|axios\.post|x-app-request|ip-check)'),
        ),
        4,
    ),
    LiteRule(
        "TP_DevelTask_ENV_Base64_URL_Hidden_Config",
        "high",
        "Base64-encoded URL hidden in dotenv or config variable",
        (
            rx(br'((^|[\r\n])[ \t]*(REACT_APP_|NEXT_PUBLIC_|VITE_|NUXT_|PUBLIC_|SERVER_|API_|APP_|AUTH_|CONFIG_|BACKEND_|FRONTEND_|DATABASE_|JWT_|SESSION_|TOKEN_|SECRET_)?[A-Z0-9_]{4,64}[ \t]*=[ \t]*["\']?(aHR0cHM6Ly9|aHR0cDovL)[A-Za-z0-9+/=_-]{10,}|(const|let|var)[ \t]+[A-Za-z0-9_$]{4,64}[ \t]*=[ \t]*["\'](aHR0cHM6Ly9|aHR0cDovL)[A-Za-z0-9+/=_-]{10,}["\']|"[A-Za-z0-9_$-]{4,64}"[ \t]*:[ \t]*"(aHR0cHM6Ly9|aHR0cDovL)[A-Za-z0-9+/=_-]{10,}")'),
        ),
        1,
    ),
    LiteRule(
        "TP_DevelTask_Remote_Content_Piped_To_Shell",
        "high",
        "Remote content is downloaded and piped or passed directly to a shell/interpreter",
        (
            rx(br'(curl|wget|Invoke-WebRequest|iwr)[^\r\n;]{0,260}\|[ \t]*(bash|sh|zsh|cmd|powershell|pwsh|node|python|python3|ruby|perl|iex|Invoke-Expression)'),
            rx(br'(Invoke-RestMethod|irm|iwr|Invoke-WebRequest)[^\r\n;]{0,260}\|[ \t]*(iex|Invoke-Expression)'),
            rx(br'(bash|sh|zsh|cmd|powershell|pwsh)[ \t]+(-c[ \t]+)?<\([ \t]*(curl|wget)[^\r\n)]{0,260}\)'),
            rx(br'(https?://|hxxps?://|\.vercel\.app|short\.gy|jsonkeeper\.com|npoint\.io|/api/settings/)'),
        ),
        2,
    ),
    LiteRule(
        "TP_DevelTask_GitHook_Remote_Pipe",
        "critical",
        "Local Git hook fetches and executes remote commands",
        (
            rx(br'#!/bin/sh'),
            rx(br'OSTYPE'),
            rx(br'(curl -s|wget -qO-)'),
            rx(br'\|[ \t]*(sh|bash|cmd)'),
            rx(br'(short\.gy|> /dev/null 2>&1 &|pre-commit)'),
        ),
        4,
    ),
    LiteRule(
        "TP_DevelTask_GitHook_Suspicious_Command",
        "high",
        "Git hook contains suspicious remote, hidden, or shell execution command",
        (
            rx(br'^#![^\r\n]*(sh|bash|zsh|node|python|python3)'),
            rx(br'(pre-(commit|push|merge|rebase)|post-(commit|checkout|merge)|commit-msg)'),
            rx(br'(curl|wget|Invoke-WebRequest|iwr|Invoke-RestMethod|irm)[^\r\n]{0,220}(https?://|hxxps?://|short\.gy|\.vercel\.app|/task/)'),
            rx(br'\|[ \t]*(sh|bash|zsh|cmd|powershell|pwsh|node|python|python3)'),
            rx(br'(> /dev/null 2>&1 &|WindowStyle Hidden|nohup|Start-Process)'),
        ),
        4,
    ),
    LiteRule(
        "TP_DevelTask_Browser_Wallet_Harvester",
        "high",
        "Browser credential and wallet-extension collection strings",
        (
            rx(br'Login Data'),
            rx(br'Web Data'),
            rx(br'Local Extension Settings'),
            rx(br'leveldb'),
            rx(br'(nkbihfbeogaeaoehlefnkodbefgpgknn|aeachknmefphepccionboohckonoeemg|BraveSoftware|wallet)'),
        ),
        3,
    ),
    LiteRule(
        "TP_DevelTask_Sensitive_File_Collection_Patterns",
        "high",
        "Code searches for wallet, seed, private-key, env, or credential files",
        (
            rx(br'(seed( phrase)?|mnemonic|recovery phrase|private[_-]?key|BEGIN (RSA|OPENSSH|EC|PRIVATE) KEY|\.env|\.ssh|\.aws/credentials|wallet|metamask|phantom|keystore|ledger|trezor)'),
            rx(br'(readdirSync|walkSync|recursive|find[ \t]+.*-type[ \t]+f|os\.homedir|process\.env\.HOME)'),
            rx(br'(upload|axios\.post|fetch[ \t]*\(|form-data|FormData)'),
        ),
        3,
    ),
    LiteRule(
        "TP_DevelTask_Clipboard_C2_Control",
        "high",
        "Clipboard collection paired with command-control primitives",
        (
            rx(br'(clipboardy|Clipboard|pbpaste|xclip -selection clipboard -o|xsel --clipboard --output)'),
            rx(br'(socket\.io-client|processControl|whour|child_process\.exec|/api/notify)'),
        ),
        2,
    ),
    LiteRule(
        "TP_DevelTask_Horizontal_Whitespace_Loader",
        "medium",
        "Long horizontal whitespace hides a staged loader off-screen",
        (
            rx(br'[ \t]{120,}(fetch|axios|get|new[ \t]+Function|curl|wget)'),
            rx(br'(cookie|jsonkeeper\.com|npoint\.io|\.vercel\.app)'),
        ),
        2,
    ),
    LiteRule(
        "TP_DevelTask_PowerShell_Hidden_Encoded",
        "high",
        "Hidden or encoded PowerShell in a developer task codebase",
        (
            rx(br'powershell'),
            rx(br'(EncodedCommand|WindowStyle Hidden|NoProfile|Get-Clipboard|System\.Security\.Cryptography\.ProtectedData)'),
        ),
        2,
    ),
)


def load_ignore_patterns(path: Path) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    patterns = []
    for line in lines:
        line = line.strip()
        if line and not line.startswith("#"):
            patterns.append(line)
    return patterns


def ignored(path: Path, root: Path, patterns: list[str]) -> bool:
    rel = path.relative_to(root).as_posix()
    for pattern in patterns:
        if pattern.endswith("/**") and fnmatch.fnmatch(rel, pattern[:-3]):
            return True
        if fnmatch.fnmatch(rel, pattern):
            return True
    return False


def iter_files(root: Path, max_size: int, ignore_patterns: list[str]) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        kept = []
        for dirname in dirnames:
            child = current / dirname
            if not ignored(child, root, ignore_patterns):
                kept.append(dirname)
        dirnames[:] = kept

        for filename in filenames:
            path = current / filename
            try:
                if path.stat().st_size <= max_size:
                    yield path
            except OSError:
                continue


def load_yara_python(rule_dir: Path):
    try:
        import yara  # type: ignore
    except ImportError:
        return None

    rule_files = sorted(rule_dir.glob("*.yar"))
    if not rule_files:
        return None
    return yara.compile(filepaths={path.stem: str(path) for path in rule_files})


def load_rule_metadata(rule_dir: Path) -> dict[str, dict[str, str]]:
    metadata: dict[str, dict[str, str]] = {}
    rule_re = re.compile(r"\brule\s+([A-Za-z0-9_]+)\s*\{(?P<body>.*?)\n\}", re.DOTALL)
    meta_re = re.compile(r"\b(severity|description)\s*=\s*\"([^\"]*)\"")
    for path in rule_dir.glob("*.yar"):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for match in rule_re.finditer(text):
            body = match.group("body")
            metadata[match.group(1)] = {key: value for key, value in meta_re.findall(body)}
    return metadata


def scan_with_yara_python(compiled, files: Iterable[Path], target: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in files:
        try:
            matches = compiled.match(str(path))
        except Exception as exc:
            print(f"warning: failed to scan {path}: {exc}", file=sys.stderr)
            continue
        for match in matches:
            meta = getattr(match, "meta", {}) or {}
            severity = str(meta.get("severity", "medium")).lower()
            findings.append(
                Finding(
                    rule=match.rule,
                    severity=severity,
                    path=str(path.relative_to(target)),
                    source="yara-python",
                    description=str(meta.get("description", "")),
                )
            )
    return findings


def scan_with_yara_cli(rule_dir: Path, files: Iterable[Path], target: Path) -> list[Finding] | None:
    yara_bin = shutil.which("yara")
    if not yara_bin:
        return None
    rule_files = sorted(str(path) for path in rule_dir.glob("*.yar"))
    if not rule_files:
        return None
    metadata = load_rule_metadata(rule_dir)
    findings: list[Finding] = []
    for file_path in files:
        cmd = [yara_bin, "-w", *rule_files, str(file_path)]
        proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if proc.returncode not in (0, 1):
            print(proc.stderr.strip(), file=sys.stderr)
            return None
        for line in proc.stdout.splitlines():
            parts = line.split(maxsplit=1)
            if len(parts) != 2:
                continue
            rule, path = parts
            meta = metadata.get(rule, {})
            findings.append(
                Finding(
                    rule=rule,
                    severity=meta.get("severity", "medium").lower(),
                    path=str(Path(path).resolve().relative_to(target.resolve())),
                    source="yara-cli",
                    description=meta.get("description", ""),
                )
            )
    return findings


def scan_with_lite(files: Iterable[Path], target: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in files:
        try:
            data = path.read_bytes()
        except OSError:
            continue
        for rule in LITE_RULES:
            if rule.match(data):
                findings.append(
                    Finding(
                        rule=rule.name,
                        severity=rule.severity,
                        path=str(path.relative_to(target)),
                        source="lite-fallback",
                        description=rule.description,
                    )
                )
    return findings


def summarize(findings: list[Finding]) -> tuple[str, int]:
    if any(f.severity == "critical" for f in findings):
        return "malicious-likely", 2
    if any(f.severity == "high" for f in findings):
        return "suspicious", 1
    if findings:
        return "review-needed", 1
    return "no-findings", 0


def print_text(findings: list[Finding], verdict: str, exit_code: int) -> None:
    print(f"Verdict: {verdict}")
    print(f"Findings: {len(findings)}")
    if not findings:
        print("No matching developer-task malware patterns were found.")
        return

    ordered = sorted(findings, key=lambda f: (-SEVERITY_SCORE.get(f.severity, 0), f.path, f.rule))
    for finding in ordered:
        desc = f" - {finding.description}" if finding.description else ""
        print(f"[{finding.severity.upper()}] {finding.rule} in {finding.path} ({finding.source}){desc}")
    print(f"Exit code: {exit_code}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan a developer task or project for malicious patterns.")
    parser.add_argument("target", type=Path, help="Path to the project/dev-task to scan")
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES, help="Directory containing .yar files")
    parser.add_argument("--ignore-config", type=Path, default=DEFAULT_IGNORE_CONFIG, help="Shared ignore pattern file")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    parser.add_argument("--max-size", type=int, default=2 * 1024 * 1024, help="Maximum file size to scan")
    parser.add_argument("--strict-yara", action="store_true", help="Fail if neither yara-python nor yara CLI is available")
    args = parser.parse_args()

    target = args.target.resolve()
    if not target.exists():
        print(f"error: target does not exist: {target}", file=sys.stderr)
        return 64

    ignore_patterns = load_ignore_patterns(args.ignore_config)
    files = list(iter_files(target, args.max_size, ignore_patterns))
    compiled = load_yara_python(args.rules)
    if compiled:
        findings = scan_with_yara_python(compiled, files, target)
        engine = "yara-python"
    else:
        cli_findings = scan_with_yara_cli(args.rules, files, target)
        if cli_findings is not None:
            findings = cli_findings
            engine = "yara-cli"
        elif args.strict_yara:
            print("error: install yara-python or the yara CLI to use --strict-yara", file=sys.stderr)
            return 69
        else:
            findings = scan_with_lite(files, target)
            engine = "lite-fallback"

    verdict, exit_code = summarize(findings)
    payload = {
        "target": str(target),
        "engine": engine,
        "verdict": verdict,
        "findings": [finding.__dict__ for finding in findings],
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        if engine == "lite-fallback":
            print("Engine: lite-fallback (install yara-python or yara CLI for real YARA matching)")
        else:
            print(f"Engine: {engine}")
        print_text(findings, verdict, exit_code)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
