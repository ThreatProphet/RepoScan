"""Explicit Lite heuristics and their bounded matching adapter."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Iterable

from reposcan.engine_support import bounded_matching
from reposcan.engines.common import append_read_error, contextualize
from reposcan.filesystem import ReadBudget, read_regular_file
from reposcan.models import EngineResult, Finding, ScanError, ScannableFile, ScanStats, evidence_at
from reposcan.review import review_bytes
from reposcan.settings import DEFAULT_TIMEOUT


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
        "HEUR_DevelTask_VSCode_FolderOpen_PipeToShell",
        "critical",
        "VS Code task-related strings coexist with remote pipe-to-shell constructs",
        (
            rx(br'"runOn"\s*:\s*"folderOpen"'),
            rx(br'(curl|wget|Invoke-WebRequest|iwr)[^\r\n]{0,240}\|[ \t]*(bash|sh|cmd|powershell)'),
            rx(br'(/api/settings/|\.vercel\.app|"presentation"|"silent")'),
        ),
        2,
    ),
    LiteRule(
        "HEUR_DevelTask_VSCode_FolderOpen_Suspicious_AutoTask",
        "high",
        "VS Code folder-open configuration contains install, shell, or network constructs",
        (
            rx(br'"runOn"\s*:\s*"folderOpen"'),
            rx(br'(npm[ \t]+(install|i)|bash|sh|cmd\.exe|powershell|pwsh|curl|wget|Invoke-WebRequest|iwr|https?://|\.vercel\.app|/api/settings/)'),
        ),
        2,
    ),
    LiteRule(
        "HEUR_DevelTask_NPM_Lifecycle_Server_Execution",
        "high",
        "Package lifecycle keys and a server-launch command coexist; inspect the declared script",
        (
            rx(br'"scripts"'),
            rx(br'"(prepare|preinstall|postinstall)"'),
            rx(br'node[ \t]+server/server\.js'),
            rx(br'react-scripts|node[ \t]+server/server\.js[ \t]*\|'),
        ),
        3,
    ),
    LiteRule(
        "HEUR_DevelTask_NPM_Lifecycle_Suspicious_Command",
        "high",
        "Package lifecycle text contains shell, network, or inline-execution constructs",
        (
            rx(br'"scripts"'),
            rx(br'"(prepare|preinstall|install|postinstall|prepack|postpack)"[ \t]*:[ \t]*"[^"\r\n]{0,260}(curl|wget|Invoke-WebRequest|iwr|bash|sh|cmd|powershell|pwsh|node[ \t]+-e|eval|base64|atob|Buffer\.from)'),
        ),
        2,
    ),
    LiteRule(
        "HEUR_DevelTask_Node_Remote_Fetch_Dynamic_Execute",
        "critical",
        "Dynamic evaluation and input-related strings occur together; inspect the input source",
        (
            rx(br'(new[ \t]+Function|Function\.constructor|eval[ \t]*\()'),
            rx(br'["\']require["\']'),
            rx(br'(axios\.|fetch[ \t]*\(|response\.data|res\.data|\.cookie|atob[ \t]*\(|process\.env)'),
        ),
        3,
    ),
    LiteRule(
        "HEUR_DevelTask_ENV_Exfil_AUTH_API",
        "critical",
        "AUTH_API-style configuration and process.env upload-related constructs coexist",
        (
            rx(br'AUTH_API'),
            rx(br'(atob[ \t]*\([^)]*AUTH_API|aHR0cHM6Ly9[a-zA-Z0-9+/=]{12,})'),
            rx(br'process\.env'),
            rx(br'(\.\.\.process\.env|axios\.post|x-app-request|ip-check)'),
        ),
        4,
    ),
    LiteRule(
        "HEUR_DevelTask_ENV_Base64_URL_Hidden_Config",
        "high",
        "Base64-encoded URL hidden in dotenv or config variable",
        (
            rx(br'((^|[\r\n])[ \t]*(REACT_APP_|NEXT_PUBLIC_|VITE_|NUXT_|PUBLIC_|SERVER_|API_|APP_|AUTH_|CONFIG_|BACKEND_|FRONTEND_|DATABASE_|JWT_|SESSION_|TOKEN_|SECRET_)?[A-Z0-9_]{4,64}[ \t]*=[ \t]*["\']?(aHR0cHM6Ly9|aHR0cDovL)[A-Za-z0-9+/=_-]{10,}|(const|let|var)[ \t]+[A-Za-z0-9_$]{4,64}[ \t]*=[ \t]*["\'](aHR0cHM6Ly9|aHR0cDovL)[A-Za-z0-9+/=_-]{10,}["\']|"[A-Za-z0-9_$-]{4,64}"[ \t]*:[ \t]*"(aHR0cHM6Ly9|aHR0cDovL)[A-Za-z0-9+/=_-]{10,}")'),
        ),
        1,
    ),
    LiteRule(
        "HEUR_DevelTask_Remote_Content_Piped_To_Shell",
        "high",
        "A remote-content pipe-to-interpreter or related execution pattern appears in source",
        (
            rx(br'(curl|wget|Invoke-WebRequest|iwr)[^\r\n;]{0,260}\|[ \t]*(bash|sh|zsh|cmd|powershell|pwsh|node|python|python3|ruby|perl|iex|Invoke-Expression)'),
            rx(br'(Invoke-RestMethod|irm|iwr|Invoke-WebRequest)[^\r\n;]{0,260}\|[ \t]*(iex|Invoke-Expression)'),
            rx(br'(bash|sh|zsh|cmd|powershell|pwsh)[ \t]+(-c[ \t]+)?<\([ \t]*(curl|wget)[^\r\n)]{0,260}\)'),
            rx(br'(https?://|hxxps?://|\.vercel\.app|short\.gy|jsonkeeper\.com|npoint\.io|/api/settings/)'),
        ),
        2,
    ),
    LiteRule(
        "HEUR_DevelTask_GitHook_Remote_Pipe",
        "critical",
        "Git-hook-style source combines OS branching with remote pipe-to-shell commands",
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
        "HEUR_DevelTask_GitHook_Suspicious_Command",
        "high",
        "Git-hook-related text contains remote, hidden, or shell-execution constructs",
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
        "HEUR_DevelTask_Browser_Wallet_Harvester",
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
        "HEUR_DevelTask_Sensitive_File_Collection_Patterns",
        "high",
        "Sensitive-file names, traversal, and upload-related constructs coexist",
        (
            rx(br'(seed( phrase)?|mnemonic|recovery phrase|private[_-]?key|BEGIN (RSA|OPENSSH|EC|PRIVATE) KEY|\.env|\.ssh|\.aws/credentials|wallet|metamask|phantom|keystore|ledger|trezor)'),
            rx(br'(readdirSync|walkSync|recursive|find[ \t]{1,32}[^\r\n]{0,512}-type[ \t]{1,32}f|os\.homedir|process\.env\.HOME)'),
            rx(br'(upload|axios\.post|fetch[ \t]*\(|form-data|FormData)'),
        ),
        3,
    ),
    LiteRule(
        "HEUR_DevelTask_Clipboard_C2_Control",
        "high",
        "Clipboard access and command-control-related constructs coexist",
        (
            rx(br'(clipboardy|Clipboard|pbpaste|xclip -selection clipboard -o|xsel --clipboard --output)'),
            rx(br'(socket\.io-client|processControl|whour|child_process\.exec|/api/notify)'),
        ),
        2,
    ),
    LiteRule(
        "HEUR_DevelTask_Horizontal_Whitespace_Loader",
        "medium",
        "A long horizontal whitespace gap precedes execution-related text",
        (
            rx(br'[ \t]{120}(fetch|axios|get|new[ \t]{1,32}Function|curl|wget)'),
            rx(br'(cookie|jsonkeeper\.com|npoint\.io|\.vercel\.app)'),
        ),
        2,
    ),
    LiteRule(
        "HEUR_DevelTask_PowerShell_Hidden_Encoded",
        "high",
        "Hidden or encoded PowerShell in a developer task codebase",
        (
            rx(br'powershell'),
            rx(br'(EncodedCommand|WindowStyle Hidden|NoProfile|Get-Clipboard|System\.Security\.Cryptography\.ProtectedData)'),
        ),
        2,
    ),
)


def scan_with_lite(
    files: Iterable[ScannableFile],
    max_size: int,
    max_total_bytes: int,
    stats: ScanStats,
    timeout: int = DEFAULT_TIMEOUT,
) -> EngineResult:
    result = EngineResult()
    budget = ReadBudget(max_total_bytes)
    for candidate in files:
        try:
            data = read_regular_file(candidate, max_size, budget, stats)
        except OSError as exc:
            if append_read_error(result, exc, candidate, stats):
                break
            continue
        digest = hashlib.sha256(data).hexdigest()
        file_findings: list[Finding] = []
        try:
            with bounded_matching(timeout):
                for rule in LITE_RULES:
                    matches = [(index, pattern.search(data)) for index, pattern in enumerate(rule.patterns)]
                    observed = [(index, match) for index, match in matches if match is not None]
                    if len(observed) >= rule.minimum:
                        evidence = tuple(evidence_at(
                            data, f"pattern-{index + 1}", match.start(), match.end() - match.start()
                        ) for index, match in observed)
                        file_findings.append(Finding(
                            rule.name, rule.severity, candidate.display_path, "heuristic-lite", rule.description,
                            confidence="medium", evidence=evidence,
                        ))
                file_findings.extend(review_bytes(data, candidate.display_path))
            stats.files_scanned += 1
        except Exception as exc:
            result.errors.append(ScanError("file-scan", str(exc), str(candidate.path)))
        result.findings.extend(contextualize(f, data, digest) for f in file_findings)
    return result
