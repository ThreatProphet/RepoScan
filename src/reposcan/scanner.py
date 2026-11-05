#!/usr/bin/env python3
"""Inspect unfamiliar repositories without executing their code or tooling."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import selectors
import shutil
import stat
import subprocess
import sys
import tempfile
import unicodedata
from contextlib import ExitStack
from dataclasses import asdict, dataclass, field, replace
from importlib.resources import files as package_files
from pathlib import Path
from time import monotonic
from typing import Any, Callable, Iterable, Sequence

from reposcan import __version__
from reposcan.engine_support import (
    MAX_RULE_FILE_BYTES,
    MAX_RULE_FILES,
    MAX_RULE_PACK_BYTES,
    bounded_matching,
    load_rule_metadata,
)
from reposcan.models import Evidence, Finding, evidence_at
from reposcan.reporting import render_markdown
from reposcan.review import review_bytes

ROOT = Path(str(package_files("reposcan")))
DEFAULT_RULES = ROOT / "rules"
DEFAULT_IGNORE_CONFIG = ROOT / "config" / "scan_ignore.txt"
SEVERITY_SCORE = {"critical": 90, "high": 70, "medium": 40, "low": 10}
SEVERITY_LABEL = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
}
DEFAULT_MAX_SIZE = 2 * 1024 * 1024
DEFAULT_MAX_FILES = 10_000
DEFAULT_MAX_TOTAL_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_ENTRIES = 100_000
DEFAULT_TIMEOUT = 30
EXIT_USAGE = 64
EXIT_ENGINE_UNAVAILABLE = 69
EXIT_OPERATIONAL_FAILURE = 70
MAX_EVIDENCE = 32
MAX_SKIP_DETAILS = 128
SCHEMA_VERSION = "1.0"
MAX_ENGINE_OUTPUT = 8 * 1024 * 1024


class Colors:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled
        self.reset = "\033[0m" if enabled else ""
        self.bold = "\033[1m" if enabled else ""
        self.dim = "\033[2m" if enabled else ""
        self.red = "\033[31m" if enabled else ""
        self.yellow = "\033[33m" if enabled else ""
        self.blue = "\033[34m" if enabled else ""
        self.cyan = "\033[36m" if enabled else ""
        self.magenta = "\033[35m" if enabled else ""
        self.green = "\033[32m" if enabled else ""
        self.gray = "\033[90m" if enabled else ""

    def wrap(self, text: str, color: str) -> str:
        return f"{color}{text}{self.reset}" if self.enabled else text


def color_enabled(mode: str) -> bool:
    if mode == "always":
        return True
    if mode == "never":
        return False
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


@dataclass(frozen=True)
class ScanError:
    code: str
    message: str
    path: str | None = None


@dataclass
class ScanStats:
    entries_seen: int = 0
    directories_visited: int = 0
    regular_files: int = 0
    files_selected: int = 0
    files_scanned: int = 0
    selected_bytes: int = 0
    ignored: int = 0
    skipped_symlinks: int = 0
    skipped_special: int = 0
    skipped_oversize: int = 0
    skipped_resource_limit: int = 0
    skip_details: list[dict[str, str]] = field(default_factory=list)
    skip_details_truncated: bool = False

    def note_skip(self, path: str, reason: str) -> None:
        if len(self.skip_details) < MAX_SKIP_DETAILS:
            self.skip_details.append({"path": path, "reason": reason})
        else:
            self.skip_details_truncated = True


@dataclass
class Discovery:
    files: list["ScannableFile"] = field(default_factory=list)
    errors: list[ScanError] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)


@dataclass
class EngineResult:
    findings: list[Finding] = field(default_factory=list)
    errors: list[ScanError] = field(default_factory=list)


@dataclass(frozen=True)
class ScannableFile:
    path: Path
    display_path: str
    device: int
    inode: int


@dataclass
class ReadBudget:
    maximum: int
    consumed: int = 0

    @property
    def remaining(self) -> int:
        return self.maximum - self.consumed

    def charge(self, amount: int) -> None:
        if amount > self.remaining:
            raise ResourceLimitError(
                f"maximum total selected bytes exceeded ({self.maximum})"
            )
        self.consumed += amount


class ResourceLimitError(OSError):
    """A configured scan resource bound was reached."""


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


def load_ignore_patterns(path: Path, data: bytes | None = None) -> list[str]:
    """Load path globs, failing closed when the requested config is unusable."""
    lines = (path.read_bytes() if data is None else data).decode("utf-8").splitlines()
    return [line for raw in lines if (line := raw.strip()) and not line.startswith("#")]


def ignored_relative(relative_path: Path, patterns: Sequence[str]) -> bool:
    """Match normalized POSIX paths; ``dir/**`` also excludes ``dir`` itself."""
    candidate = relative_path.as_posix()
    for raw_pattern in patterns:
        pattern = raw_pattern.replace("\\", "/")
        if pattern.startswith("/"):
            pattern = pattern[1:]
        if pattern.endswith("/**"):
            directory_pattern = pattern[:-3].rstrip("/")
            if fnmatch.fnmatchcase(candidate, directory_pattern):
                return True
        if pattern.endswith("/"):
            directory_pattern = pattern.rstrip("/")
            if fnmatch.fnmatchcase(candidate, directory_pattern):
                return True
            pattern = f"{directory_pattern}/**"
        if fnmatch.fnmatchcase(candidate, pattern):
            return True
    return False


def _resource_error(message: str, path: Path) -> ScanError:
    return ScanError("resource-limit", message, str(path))


def _open_flags(*, directory: bool) -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise OSError("this platform cannot safely disable symbolic-link traversal")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    if directory:
        if not hasattr(os, "O_DIRECTORY"):
            raise OSError("this platform cannot safely open directory descriptors")
        flags |= os.O_DIRECTORY
    return flags


def open_path_without_symlinks(path: Path, *, directory: bool) -> int:
    """Open an absolute path one anchored, non-symlink component at a time."""
    if not path.is_absolute():
        raise OSError("safe path opening requires an absolute path")
    components = path.parts[1:]
    current = os.open(path.anchor, _open_flags(directory=True))
    try:
        if not components:
            if not directory:
                raise OSError("the filesystem root is not a regular file")
            return current
        for index, component in enumerate(components):
            final = index == len(components) - 1
            next_descriptor = os.open(
                component,
                _open_flags(directory=directory if final else True),
                dir_fd=current,
            )
            os.close(current)
            current = next_descriptor
        return current
    except BaseException:
        os.close(current)
        raise


def verify_identity(file_stat: os.stat_result, device: int, inode: int) -> None:
    if (file_stat.st_dev, file_stat.st_ino) != (device, inode):
        raise OSError("entry identity changed after discovery")


def discover_files(
    target: Path,
    target_stat: os.stat_result,
    max_size: int,
    max_files: int,
    max_total_bytes: int,
    max_entries: int,
    ignore_patterns: Sequence[str],
) -> Discovery:
    """Discover regular files via anchored directory descriptors."""
    result = Discovery()

    def admit(path: Path, relative: Path, file_stat: os.stat_result) -> bool:
        result.stats.regular_files += 1
        if file_stat.st_size > max_size:
            result.stats.skipped_oversize += 1
            result.stats.note_skip(relative.as_posix(), "oversize")
            return True
        if result.stats.files_selected >= max_files:
            result.stats.skipped_resource_limit += 1
            result.stats.note_skip(relative.as_posix(), "file-limit")
            result.errors.append(
                _resource_error(f"maximum file count exceeded ({max_files})", path)
            )
            return False
        result.files.append(
            ScannableFile(
                path=path,
                display_path=target.name if path == target else relative.as_posix(),
                device=file_stat.st_dev,
                inode=file_stat.st_ino,
            )
        )
        result.stats.files_selected += 1
        return True

    if stat.S_ISREG(target_stat.st_mode):
        result.stats.entries_seen = 1
        try:
            descriptor = open_path_without_symlinks(target, directory=False)
            try:
                current_stat = os.fstat(descriptor)
                if not stat.S_ISREG(current_stat.st_mode):
                    raise OSError("target is no longer a regular file")
                verify_identity(current_stat, target_stat.st_dev, target_stat.st_ino)
            finally:
                os.close(descriptor)
        except OSError as exc:
            result.errors.append(ScanError("file-admission", str(exc), str(target)))
            return result
        admit(target, Path(target.name), current_stat)
        return result

    pending: list[tuple[Path, Path, int, int]] = [
        (target, Path("."), target_stat.st_dev, target_stat.st_ino)
    ]
    while pending:
        directory, relative_directory, expected_device, expected_inode = pending.pop()
        result.stats.directories_visited += 1
        directory_descriptor: int | None = None
        child_directories: list[tuple[Path, Path, int, int]] = []
        try:
            directory_descriptor = open_path_without_symlinks(directory, directory=True)
            directory_stat = os.fstat(directory_descriptor)
            verify_identity(directory_stat, expected_device, expected_inode)
            entries: list[os.DirEntry[str]] = []
            remaining_entries = max_entries - result.stats.entries_seen
            with os.scandir(directory_descriptor) as iterator:
                for entry in iterator:
                    entries.append(entry)
                    if len(entries) > remaining_entries:
                        result.stats.entries_seen = max_entries + 1
                        result.stats.skipped_resource_limit += 1
                        result.errors.append(
                            _resource_error(
                                f"maximum filesystem entry count exceeded ({max_entries})",
                                directory,
                            )
                        )
                        return result
            result.stats.entries_seen += len(entries)
            for entry in sorted(entries, key=lambda item: os.fsencode(item.name)):
                path = directory / entry.name
                relative = (
                    Path(entry.name)
                    if relative_directory == Path(".")
                    else relative_directory / entry.name
                )
                if ignored_relative(relative, ignore_patterns):
                    result.stats.ignored += 1
                    result.stats.note_skip(relative.as_posix(), "ignore-policy (directory may be pruned)")
                    continue
                try:
                    entry_stat = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    result.errors.append(ScanError("entry-stat", str(exc), str(path)))
                    continue
                mode = entry_stat.st_mode
                if stat.S_ISLNK(mode):
                    result.stats.skipped_symlinks += 1
                    result.stats.note_skip(relative.as_posix(), "symlink")
                elif stat.S_ISDIR(mode):
                    child_directories.append(
                        (path, relative, entry_stat.st_dev, entry_stat.st_ino)
                    )
                elif stat.S_ISREG(mode):
                    if not admit(path, relative, entry_stat):
                        return result
                else:
                    result.stats.skipped_special += 1
                    result.stats.note_skip(relative.as_posix(), "special-file")
        except OSError as exc:
            result.errors.append(ScanError("directory-read", str(exc), str(directory)))
            continue
        finally:
            if directory_descriptor is not None:
                os.close(directory_descriptor)
        pending.extend(reversed(child_directories))
    return result


def regular_rule_files(rule_dir: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted(rule_dir.glob("*.yar"), key=lambda item: os.fsencode(item.name)):
        try:
            mode = path.lstat().st_mode
        except OSError as exc:
            raise OSError(f"cannot inspect YARA rule entry {path}: {exc}") from exc
        if not stat.S_ISREG(mode):
            raise OSError(f"YARA rule entry must be a regular file: {path}")
        files.append(path.absolute())
    return files


def import_yara() -> Any | None:
    try:
        import yara  # type: ignore
    except ModuleNotFoundError as exc:
        if exc.name == "yara":
            return None
        raise
    return yara


def read_regular_file(
    candidate: ScannableFile,
    max_size: int,
    budget: ReadBudget,
    stats: ScanStats,
) -> bytes:
    """Read the discovered inode without following any pathname symlink."""
    descriptor = open_path_without_symlinks(candidate.path, directory=False)
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise OSError("entry is no longer a regular file")
        verify_identity(file_stat, candidate.device, candidate.inode)
        chunks: list[bytes] = []
        available_total = budget.remaining
        allowed = min(max_size, available_total)
        remaining = allowed + 1
        file_bytes = 0
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
            file_bytes += len(chunk)
            chargeable = min(len(chunk), budget.remaining)
            budget.charge(chargeable)
            stats.selected_bytes = budget.consumed
            if chargeable < len(chunk):
                raise ResourceLimitError(
                    f"maximum total selected bytes exceeded ({budget.maximum})"
                )
            if file_bytes > max_size:
                raise OSError(f"file grew beyond maximum size ({max_size})")
        data = b"".join(chunks)
        return data
    finally:
        os.close(descriptor)


def append_read_error(
    result: EngineResult,
    error: OSError,
    candidate: ScannableFile,
    stats: ScanStats,
) -> bool:
    code = "file-read"
    resource_limit = isinstance(error, ResourceLimitError)
    if resource_limit:
        code = "resource-limit"
        stats.skipped_resource_limit += 1
    result.errors.append(ScanError(code, str(error), str(candidate.path)))
    return resource_limit


def contextualize(finding: Finding, data: bytes, digest: str) -> Finding:
    """Preserve a warning while keeping quoted documentation below a strong verdict."""
    confidence = finding.confidence
    prerequisites = finding.prerequisites
    if Path(finding.path).suffix.lower() in {".md", ".rst", ".adoc"}:
        confidence = "low"
        prerequisites = (*prerequisites, "Matched in documentation; executable use is not established.")
    evidence = finding.evidence[:MAX_EVIDENCE]
    identity = json.dumps([finding.rule, finding.path, digest, [asdict(item) for item in evidence]],
                          ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return replace(
        finding, confidence=confidence, prerequisites=prerequisites, sha256=digest, evidence=evidence,
        evidence_truncated=finding.evidence_truncated or len(finding.evidence) > MAX_EVIDENCE,
        finding_id=hashlib.sha256(identity.encode("ascii")).hexdigest(),
    )


def rule_finding(
    rule: str,
    meta: dict[str, Any],
    candidate: ScannableFile,
    source: str,
    evidence: Sequence[Evidence],
    truncated: bool = False,
) -> Finding:
    severity = str(meta.get("severity", "")).lower()
    confidence = str(meta.get("confidence", "medium")).lower()
    category = str(meta.get("category", "report-pattern")).lower()
    if severity not in SEVERITY_SCORE:
        raise ValueError(f"rule {rule} has missing or invalid severity metadata")
    if confidence not in {"low", "medium", "high"}:
        raise ValueError(f"rule {rule} has invalid confidence metadata")
    if category not in {"trigger", "obfuscation", "behavior", "report-pattern"}:
        raise ValueError(f"rule {rule} has invalid category metadata")
    reports = tuple(sorted(set(re.findall(r"TP-\d{4}-\d{3}", str(meta.get("reports", ""))))))
    reference = str(meta.get("reference", ""))
    references = (reference,) if reference.startswith(("https://", "http://")) else ()
    return Finding(
        rule, severity, candidate.display_path, source, str(meta.get("description", "")),
        category=category, confidence=confidence,
        trigger=str(meta.get("trigger", "")),
        prerequisites=(str(meta["prerequisites"]),) if meta.get("prerequisites") else (),
        reports=reports, references=references,
        evidence=tuple(sorted(evidence, key=lambda item: (item.offset, item.identifier, item.length))),
        evidence_truncated=truncated,
    )


def python_match_evidence(match: Any, data: bytes) -> tuple[list[Evidence], bool]:
    evidence: list[Evidence] = []
    for string in match.strings:
        for instance in string.instances:
            if len(evidence) == MAX_EVIDENCE:
                return evidence, True
            evidence.append(evidence_at(data, string.identifier, instance.offset, instance.matched_length))
    return evidence, False


def reject_yara_runtime_warning(warning_type: int, message: object) -> None:
    """A runtime match limit must not be reported as a complete scan."""
    raise RuntimeError("YARA runtime warning: match results may be incomplete")


def scan_with_yara_python(
    compiled: Any,
    files: Iterable[ScannableFile],
    max_size: int,
    max_total_bytes: int,
    timeout: int,
    stats: ScanStats,
    metadata: dict[str, dict[str, Any]] | None = None,
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
        runtime_warning = False

        def warning_callback(warning_type: int, message: object) -> None:
            nonlocal runtime_warning
            runtime_warning = True
            reject_yara_runtime_warning(warning_type, message)

        try:
            with bounded_matching(timeout):
                matches = compiled.match(
                    data=data, timeout=timeout, console_callback=lambda message: None,
                    warnings_callback=warning_callback,
                )
                if runtime_warning:
                    raise RuntimeError("YARA runtime warning: match results may be incomplete")
                for match in matches:
                    meta = metadata[match.rule] if metadata is not None else match.meta
                    evidence, truncated = python_match_evidence(match, data)
                    file_findings.append(rule_finding(
                        match.rule, meta, candidate, "yara-python", evidence, truncated
                    ))
                file_findings.extend(review_bytes(data, candidate.display_path))
            stats.files_scanned += 1
        except Exception as exc:
            result.errors.append(ScanError("file-scan", str(exc), str(candidate.path)))
        result.findings.extend(contextualize(f, data, digest) for f in file_findings)
    return result


def run_yara_cli(command: Sequence[str], timeout: int) -> subprocess.CompletedProcess[str]:
    """Capture bounded engine output; matched strings never go directly to the terminal."""
    deadline = monotonic() + timeout
    output = {"stdout": bytearray(), "stderr": bytearray()}
    size = 0
    with subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
        assert process.stdout is not None and process.stderr is not None
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            try:
                while selector.get_map():
                    remaining = deadline - monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(command, timeout)
                    for key, _ in selector.select(remaining):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        size += len(chunk)
                        if size > MAX_ENGINE_OUTPUT:
                            raise OSError(f"YARA CLI output exceeded {MAX_ENGINE_OUTPUT} bytes")
                        output[key.data].extend(chunk)
                process.wait(timeout=max(0.001, deadline - monotonic()))
            except BaseException:
                process.kill()
                process.wait()
                raise
    return subprocess.CompletedProcess(
        command, process.returncode,
        output["stdout"].decode("utf-8"), output["stderr"].decode("utf-8"),
    )


def yara_cli_exception_message(
    error: OSError | UnicodeError | subprocess.TimeoutExpired,
    timeout: int,
) -> str:
    if isinstance(error, subprocess.TimeoutExpired):
        return f"YARA CLI timed out after {timeout} seconds"
    return str(error)


def has_yara_runtime_diagnostic(stderr: str) -> bool:
    """Allow compiler performance warnings; reject other diagnostics conservatively."""
    compiler_warning = re.compile(
        r'^(?:warning: rule "[A-Za-z_][A-Za-z0-9_]*" in .+\(\d+\): |.+\(\d+\): warning: )'
    )
    return any(line.strip() and not compiler_warning.match(line.strip()) for line in stderr.splitlines())


def validate_yara_cli(yara_bin: str, rule_files: Sequence[Path], timeout: int) -> ScanError | None:
    try:
        process = run_yara_cli(
            [yara_bin, "-q", *(f"rule_{index:04d}:{path}" for index, path in enumerate(rule_files)), os.devnull],
            timeout,
        )
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as exc:
        return ScanError("rules-compile", yara_cli_exception_message(exc, timeout))
    if process.returncode != 0:
        detail = process.stderr.strip() or f"yara exited with status {process.returncode}"
        return ScanError("rules-compile", detail)
    if has_yara_runtime_diagnostic(process.stderr):
        return ScanError("rules-compile", "YARA CLI reported a runtime diagnostic during rule validation")
    return None


def scan_with_yara_cli(
    yara_bin: str,
    rule_files: Sequence[Path],
    files: Iterable[ScannableFile],
    max_size: int,
    max_total_bytes: int,
    timeout: int,
    stats: ScanStats,
    metadata: dict[str, dict[str, Any]] | None = None,
) -> EngineResult:
    metadata = load_rule_metadata(rule_files) if metadata is None else metadata
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
                with tempfile.NamedTemporaryFile(prefix="reposcan-", suffix=".scan") as safe_copy:
                    safe_copy.write(data)
                    safe_copy.flush()
                    process = run_yara_cli(
                        [yara_bin, "-q", "-s", "-L",
                         *(f"rule_{index:04d}:{path}" for index, path in enumerate(rule_files)), safe_copy.name],
                        timeout,
                    )
                if process.returncode != 0:
                    raise OSError(process.stderr.strip().replace(safe_copy.name, "[captured file]")
                                  or f"yara exited with status {process.returncode}")
                if has_yara_runtime_diagnostic(process.stderr):
                    raise OSError("YARA CLI reported a runtime diagnostic; match results may be incomplete")
                rule = ""
                evidence: list[Evidence] = []
                truncated = False
                for line in process.stdout.splitlines():
                    location = re.match(r"^0x([0-9a-fA-F]+):(\d+):(\$[A-Za-z0-9_]*):", line)
                    if location:
                        if not rule:
                            raise ValueError("YARA CLI emitted a match without a rule identifier")
                        if len(evidence) < MAX_EVIDENCE:
                            offset, length = int(location[1], 16), int(location[2])
                            if offset < 0 or length < 0 or offset + length > len(data):
                                raise ValueError("YARA CLI emitted an invalid match location")
                            evidence.append(evidence_at(data, location[3], offset, length))
                        else:
                            truncated = True
                        continue
                    identifier = line.split(maxsplit=1)[0] if line.split() else ""
                    if not identifier:
                        continue
                    if identifier not in metadata:
                        raise ValueError("YARA CLI emitted an unrecognized result line")
                    if rule:
                        file_findings.append(rule_finding(
                            rule, metadata[rule], candidate, "yara-cli", evidence, truncated
                        ))
                    rule, evidence, truncated = identifier, [], False
                if rule:
                    file_findings.append(rule_finding(
                        rule, metadata[rule], candidate, "yara-cli", evidence, truncated
                    ))
                file_findings.extend(review_bytes(data, candidate.display_path))
            stats.files_scanned += 1
        except Exception as exc:
            result.errors.append(
                ScanError(
                    "file-scan",
                    yara_cli_exception_message(exc, timeout),
                    str(candidate.path),
                )
            )
        result.findings.extend(contextualize(f, data, digest) for f in file_findings)
    return result


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


def summarize(findings: list[Finding], engine: str) -> tuple[str, int]:
    if engine == "lite":
        return ("heuristic-findings", 1) if findings else ("no-findings", 0)
    if any(f.severity == "critical" and f.confidence == "high" and f.source in {"yara-python", "yara-cli"}
           for f in findings):
        return "high-risk", 2
    if findings:
        return "review-needed", 1
    return "no-findings", 0


def severity_color(severity: str, colors: Colors) -> str:
    return {
        "critical": colors.magenta,
        "high": colors.red,
        "medium": colors.yellow,
        "low": colors.blue,
    }.get(severity, colors.gray)


def verdict_color(verdict: str, colors: Colors) -> str:
    return {
        "high-risk": colors.red,
        "suspicious": colors.yellow,
        "review-needed": colors.yellow,
        "heuristic-findings": colors.yellow,
        "scan-incomplete": colors.red,
        "scan-failed": colors.red,
        "not-scanned": colors.red,
        "no-findings": colors.green,
    }.get(verdict, colors.gray)


def safe_terminal_text(value: object) -> str:
    return "".join(character if character.isprintable() else ascii(character)[1:-1] for character in str(value))


def terminal_columns(text: str) -> int:
    """Measure printable text before styling, including wide and combining characters."""
    return sum(
        0 if unicodedata.category(character) in {"Mn", "Me"}
        else 2 if unicodedata.east_asian_width(character) in {"W", "F"}
        else 1
        for character in text
    )


def wrap_terminal_text(text: str, width: int, *, preserve_spaces: bool = False) -> list[str]:
    """Wrap escaped prose at words, or preserve every character in path fields."""
    lines: list[str] = []
    current = ""
    pending_space = ""
    for token in [text] if preserve_spaces else re.findall(r" +|[^ ]+", text):
        if token.isspace() and not preserve_spaces:
            pending_space += token
            continue
        separator = pending_space if current else ""
        pending_space = ""
        if terminal_columns(current + separator + token) <= width:
            current += separator + token
            continue
        if current:
            lines.append(current)
            current = ""
        used = 0
        for character in token:
            size = terminal_columns(character)
            if current and used + size > width:
                lines.append(current)
                current = ""
                used = 0
            current += character
            used += size
    if current or not lines:
        lines.append(current)
    return lines


def print_text(
    findings: list[Finding],
    errors: list[ScanError],
    verdict: str,
    exit_code: int,
    engine: str,
    target: Path,
    complete: bool,
    status: str,
    stats: ScanStats,
    colors: Colors,
    width: int | None = None,
) -> None:
    if width is None:
        width = min(shutil.get_terminal_size(fallback=(100, 24)).columns, 120) if sys.stdout.isatty() else 100
    width = max(20, width)

    def line(value: object = "", style: str = "", highlight: Callable[[str], str] | None = None) -> None:
        for part in wrap_terminal_text(safe_terminal_text(value), width):
            print(highlight(part) if highlight else colors.wrap(part, style))

    def field(
        label: str, value: object, style: str = "", *, indent: int = 2,
        highlight: Callable[[str], str] | None = None, preserve_spaces: bool = False,
    ) -> None:
        prefix = " " * indent + f"{label + ':':<10}"
        parts = wrap_terminal_text(safe_terminal_text(value), width - len(prefix), preserve_spaces=preserve_spaces)
        for index, part in enumerate(parts):
            lead = colors.wrap(prefix, colors.bold) if index == 0 else " " * len(prefix)
            rendered = highlight(part) if highlight else colors.wrap(part, style)
            print(lead + rendered)

    def priority(text: str) -> str:
        return re.sub(
            r"\[(CRITICAL|HIGH|MEDIUM|LOW)(?: \d+)?\]",
            lambda match: colors.wrap(match.group(), colors.bold + severity_color(match[1].lower(), colors)),
            text,
        )

    def match_location(text: str) -> str:
        text = re.sub(
            r"\bline \d+\b", lambda match: colors.wrap(match.group(), colors.bold + colors.cyan), text,
        )
        return re.sub(
            r"\$[A-Za-z_][A-Za-z0-9_]*", lambda match: colors.wrap(match.group(), colors.magenta), text,
        )

    line(f"RepoScan {__version__}", colors.bold)
    line("Review before trusting, installing, or running.")
    line()
    verdict_style = colors.yellow if complete and stats.files_scanned == 0 else verdict_color(verdict, colors)
    field("Verdict", verdict, colors.bold + verdict_style, indent=0)
    finding_files = len({finding.path for finding in findings})
    file_label = "file" if finding_files == 1 else "files"
    field("Findings", f"{len(findings)} across {finding_files} {file_label}", indent=0)
    if findings:
        counts = {severity: sum(f.severity == severity for f in findings) for severity in SEVERITY_LABEL}
        levels = [f"[{SEVERITY_LABEL[severity]} {count}]" for severity, count in counts.items() if count]
        other = len(findings) - sum(counts.values())
        if other:
            levels.append(f"[OTHER {other}]")
        field("Severity", "  ".join(levels), indent=0, highlight=priority)
    field("Scanned", f"{stats.files_scanned}/{stats.files_selected} selected files", indent=0)
    field("Status", f"{status} | scope complete: {'yes' if complete else 'no'}",
          "" if complete else colors.bold + colors.red, indent=0)
    field("Target", target, colors.cyan, indent=0, preserve_spaces=True)
    display_engine = "lite (heuristic-only; not YARA)" if engine == "lite" else engine
    field("Engine", display_engine, indent=0)

    if errors:
        line()
        line("SCAN ERRORS", colors.bold + colors.red)
        for error in errors:
            field("Error", f"{error.code}: {error.message}", colors.red)
            if error.path:
                field("Location", error.path, colors.cyan, preserve_spaces=True)

    for index, finding in enumerate(findings, start=1):
        line()
        label = SEVERITY_LABEL.get(finding.severity, finding.severity.upper())
        line(f"[{label}]  Finding {index}/{len(findings)}", highlight=priority)
        first_line = min((evidence.line for evidence in finding.evidence), default=None)
        location = f"{finding.path}:{first_line}" if first_line is not None else finding.path
        field("Location", location, colors.bold + colors.cyan, preserve_spaces=True)
        if finding.description:
            field("Why", finding.description)
        if finding.trigger:
            field("Trigger", finding.trigger)
        for prerequisite in finding.prerequisites:
            field("Prereq", prerequisite)
        for evidence in finding.evidence[:4]:
            field("Match", f"line {evidence.line} | byte {evidence.offset} | "
                  f"{evidence.length} bytes | {evidence.identifier}", highlight=match_location)
        if len(finding.evidence) > 4:
            remaining = len(finding.evidence) - 4
            location_label = "location" if remaining == 1 else "locations"
            field("More", f"{remaining} more recorded {location_label} in JSON/Markdown.")
        if finding.evidence_truncated:
            field("Limit", "Evidence collection was capped; further matches may be omitted.")
        field("Review", f"{finding.category} | confidence: {finding.confidence}")
        field("Rule", finding.rule)
        field("Source", finding.source)
        if finding.reports:
            field("Report", ", ".join(finding.reports), colors.blue)

    if not findings and complete:
        line()
        if stats.files_scanned == 0:
            line("No file content was scanned. Review the selection and skip policy before proceeding.",
                 colors.bold + colors.yellow)
        elif engine == "lite":
            line("No heuristic patterns were found; this was not a YARA scan.", colors.green)
        else:
            line("No matching review patterns were found in the inspected scope.", colors.green)

    line()
    line("COVERAGE", colors.bold)
    skipped = (f"{stats.ignored} ignored entries, {stats.skipped_oversize} oversized, "
               f"{stats.skipped_symlinks} symlinks, {stats.skipped_special} special files")
    if stats.skipped_resource_limit:
        skipped += f", {stats.skipped_resource_limit} resource-limited"
    field("Skipped", skipped)
    field("Scope", "Completeness applies to the selected policy; no findings is not a safety guarantee.")
    line()
    if not complete:
        field("Next", "Resolve the reported scan errors and rescan; this result is incomplete.",
              colors.bold + colors.red, indent=0)
    elif findings:
        field("Next", "Review the flagged files and their execution context before running the project.", indent=0)
    line(f"Exit code: {exit_code}", colors.bold)


class RepoScanArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")


def positive_integer(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def text_width(value: str) -> int:
    number = positive_integer(value)
    if not 40 <= number <= 240:
        raise argparse.ArgumentTypeError("must be between 40 and 240 columns")
    return number


def ordered_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda finding: (
            -SEVERITY_SCORE.get(finding.severity, 0),
            finding.path,
            finding.rule,
            finding.source,
        ),
    )


def ordered_errors(errors: Iterable[ScanError]) -> list[ScanError]:
    return sorted(errors, key=lambda error: (error.path or "", error.code, error.message))


def snapshot_rule_files(rule_files: Sequence[Path], stack: ExitStack) -> tuple[list[Path], dict[str, str]]:
    """Capture bounded trusted rule bytes once for metadata, identity, and both engines."""
    if len(rule_files) > MAX_RULE_FILES:
        raise ValueError(f"rule pack exceeds {MAX_RULE_FILES} files")
    directory = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="reposcan-rules-")))
    snapshots: list[Path] = []
    display_paths: dict[str, str] = {}
    total = 0
    for original in rule_files:
        with original.open("rb") as stream:
            data = stream.read(min(MAX_RULE_FILE_BYTES, MAX_RULE_PACK_BYTES - total) + 1)
        if len(data) > MAX_RULE_FILE_BYTES or total + len(data) > MAX_RULE_PACK_BYTES:
            raise ValueError(f"rule source exceeds configured size limits: {original}")
        total += len(data)
        captured = directory / original.name
        captured.write_bytes(data)
        snapshots.append(captured)
        display_paths[str(captured)] = str(original)
    return snapshots, display_paths


def emit_result(
    args: argparse.Namespace,
    target: Path,
    engine: str,
    findings: Iterable[Finding],
    errors: Iterable[ScanError],
    stats: ScanStats,
    status: str,
    verdict: str,
    exit_code: int,
) -> int:
    sorted_findings = ordered_findings(findings)
    normalized_errors = []
    for error in errors:
        message, path = error.message, error.path
        for captured, original in getattr(args, "rule_display_paths", {}).items():
            message = message.replace(captured, original)
            if path is not None:
                path = path.replace(captured, original)
        normalized_errors.append(replace(error, message=message, path=path))
    sorted_errors = ordered_errors(normalized_errors)
    complete = status == "complete"
    stats_payload = asdict(stats)
    skipped = stats_payload.pop("skip_details")
    skipped_truncated = stats_payload.pop("skip_details_truncated")
    payload = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "RepoScan", "version": __version__},
        "target": str(target),
        "engine": engine,
        "engine_version": getattr(args, "engine_version", ""),
        "rule_pack": getattr(args, "rule_pack", {"sha256": "", "files": []}),
        "policy": {
            "max_size": args.max_size,
            "max_files": args.max_files,
            "max_total_bytes": args.max_total_bytes,
            "max_entries": args.max_entries,
            "timeout": args.timeout,
            "ignore_config_sha256": getattr(args, "ignore_config_sha256", ""),
        },
        "coverage": {
            "scope": "Configured eligible files only; ignored entries may include pruned directories.",
            "skipped": sorted(skipped, key=lambda item: (item["path"], item["reason"])),
            "skipped_truncated": skipped_truncated,
        },
        "complete": complete,
        "status": status,
        "verdict": verdict,
        "findings": [asdict(finding) for finding in sorted_findings],
        "errors": [asdict(error) for error in sorted_errors],
        "stats": stats_payload,
    }
    output_format = "json" if args.json else args.format
    if output_format == "json":
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif output_format == "markdown":
        print(render_markdown(payload), end="")
    else:
        print_text(
            sorted_findings,
            sorted_errors,
            verdict,
            exit_code,
            engine,
            target,
            complete,
            status,
            stats,
            Colors(color_enabled(args.color)),
            getattr(args, "width", None),
        )
    return exit_code


def fail(
    args: argparse.Namespace,
    target: Path,
    engine: str,
    code: str,
    message: str,
    exit_code: int,
    path: Path | None = None,
    stats: ScanStats | None = None,
) -> int:
    return emit_result(
        args,
        target,
        engine,
        [],
        [ScanError(code, message, str(path) if path is not None else None)],
        stats or ScanStats(),
        "failed",
        "not-scanned",
        exit_code,
    )


def run_scan(stack: ExitStack) -> int:
    parser = RepoScanArgumentParser(
        prog="reposcan",
        description="Review unfamiliar repositories before trusting, installing, or running their code.",
    )
    parser.add_argument("target", type=Path, help="Path to the project/dev-task to scan")
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES, help="Directory containing .yar files")
    parser.add_argument("--ignore-config", type=Path, default=DEFAULT_IGNORE_CONFIG, help="Shared ignore pattern file")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    parser.add_argument("--format", choices=("text", "json", "markdown"), default="text", help="Output format")
    parser.add_argument("--version", action="version", version=f"RepoScan {__version__}")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto", help="Colorize text output")
    parser.add_argument(
        "--width", type=text_width,
        help="Text width in columns (40-240); default: terminal width up to 120, or 100 when redirected",
    )
    parser.add_argument("--max-size", type=positive_integer, default=DEFAULT_MAX_SIZE, help="Maximum bytes per file")
    parser.add_argument("--max-files", type=positive_integer, default=DEFAULT_MAX_FILES, help="Maximum selected files")
    parser.add_argument(
        "--max-total-bytes",
        type=positive_integer,
        default=DEFAULT_MAX_TOTAL_BYTES,
        help="Maximum total bytes selected",
    )
    parser.add_argument(
        "--max-entries",
        type=positive_integer,
        default=DEFAULT_MAX_ENTRIES,
        help="Maximum filesystem entries visited",
    )
    parser.add_argument("--timeout", type=positive_integer, default=DEFAULT_TIMEOUT,
                        help="Per-file matching timeout, including static review (POSIX main thread)")
    parser.add_argument(
        "--engine",
        choices=("auto", "yara-python", "yara-cli", "lite"),
        default="auto",
        help="Scanning engine; lite is heuristic-only and must be selected explicitly",
    )
    parser.add_argument("--lite", action="store_true", help="Compatibility alias for --engine lite")
    parser.add_argument(
        "--strict-yara",
        action="store_true",
        help="Compatibility option; canonical YARA is now the default",
    )
    args = parser.parse_args()

    target = Path(os.path.abspath(os.fspath(args.target)))
    requested_engine = args.engine
    if args.json and args.format not in {"text", "json"}:
        return fail(args, target, requested_engine, "usage", "--json conflicts with --format markdown", EXIT_USAGE)
    if args.lite:
        if requested_engine not in ("auto", "lite"):
            return fail(
                args,
                target,
                requested_engine,
                "usage",
                "--lite cannot be combined with a different --engine",
                EXIT_USAGE,
            )
        requested_engine = "lite"
    if args.strict_yara and requested_engine == "lite":
        return fail(
            args,
            target,
            requested_engine,
            "usage",
            "--strict-yara cannot be combined with lite mode",
            EXIT_USAGE,
        )

    try:
        target_stat = target.lstat()
    except OSError as exc:
        return fail(args, target, requested_engine, "target", str(exc), EXIT_USAGE, target)
    if stat.S_ISLNK(target_stat.st_mode):
        return fail(
            args,
            target,
            requested_engine,
            "target-type",
            "symlink targets are not followed",
            EXIT_USAGE,
            target,
        )
    if not (stat.S_ISREG(target_stat.st_mode) or stat.S_ISDIR(target_stat.st_mode)):
        return fail(
            args,
            target,
            requested_engine,
            "target-type",
            "target must be a regular file or directory",
            EXIT_USAGE,
            target,
        )

    ignore_config = Path(os.path.abspath(os.fspath(args.ignore_config)))
    try:
        ignore_stat = ignore_config.lstat()
        if not stat.S_ISREG(ignore_stat.st_mode):
            raise OSError("ignore config must be a regular file")
        ignore_bytes = ignore_config.read_bytes()
        ignore_patterns = load_ignore_patterns(ignore_config, ignore_bytes)
        args.ignore_config_sha256 = hashlib.sha256(ignore_bytes).hexdigest()
    except (OSError, UnicodeError) as exc:
        return fail(
            args,
            target,
            requested_engine,
            "ignore-config",
            str(exc),
            EXIT_USAGE,
            ignore_config,
        )

    rule_files: list[Path] = []
    if requested_engine != "lite":
        rule_dir = Path(os.path.abspath(os.fspath(args.rules)))
        try:
            rule_dir_stat = rule_dir.lstat()
        except OSError as exc:
            return fail(
                args,
                target,
                requested_engine,
                "rules-config",
                str(exc),
                EXIT_USAGE,
                rule_dir,
            )
        if not stat.S_ISDIR(rule_dir_stat.st_mode):
            return fail(
                args,
                target,
                requested_engine,
                "rules-config",
                "rules path must be a directory",
                EXIT_USAGE,
                rule_dir,
            )
        try:
            rule_files = regular_rule_files(rule_dir)
        except OSError as exc:
            return fail(
                args,
                target,
                requested_engine,
                "rules-config",
                str(exc),
                EXIT_USAGE,
                rule_dir,
            )
        if not rule_files:
            return fail(
                args,
                target,
                requested_engine,
                "rules-config",
                "rules directory contains no regular .yar files",
                EXIT_USAGE,
                rule_dir,
            )

    metadata: dict[str, dict[str, Any]] = {}
    if requested_engine != "lite":
        try:
            rule_files, args.rule_display_paths = snapshot_rule_files(rule_files, stack)
            metadata = load_rule_metadata(rule_files)
            pack_hash = hashlib.sha256()
            members = []
            for path in rule_files:
                rule_hash = hashlib.sha256(path.read_bytes()).hexdigest()
                name_bytes = path.name.encode("utf-8")
                pack_hash.update(len(name_bytes).to_bytes(4, "big") + name_bytes + rule_hash.encode("ascii"))
                members.append({"name": path.name, "sha256": rule_hash})
            args.rule_pack = {"sha256": pack_hash.hexdigest(), "files": members}
        except (OSError, UnicodeError, ValueError) as exc:
            return fail(args, target, requested_engine, "rules-metadata", str(exc), EXIT_OPERATIONAL_FAILURE)

    discovery = discover_files(
        target,
        target_stat,
        args.max_size,
        args.max_files,
        args.max_total_bytes,
        args.max_entries,
        ignore_patterns,
    )
    yara_module: Any | None = None
    yara_bin: str | None = None
    engine = requested_engine
    if requested_engine in ("auto", "yara-python"):
        try:
            yara_module = import_yara()
        except Exception as exc:
            return fail(
                args,
                target,
                "yara-python",
                "engine-load",
                str(exc),
                EXIT_OPERATIONAL_FAILURE,
                stats=discovery.stats,
            )
        if yara_module is not None:
            engine = "yara-python"
            args.engine_version = str(getattr(yara_module, "__version__", "unknown"))
        elif requested_engine == "yara-python":
            return fail(
                args,
                target,
                "yara-python",
                "engine-unavailable",
                "yara-python is not installed",
                EXIT_ENGINE_UNAVAILABLE,
                stats=discovery.stats,
            )
    if engine == "auto":
        yara_bin = shutil.which("yara")
        if yara_bin:
            engine = "yara-cli"
        else:
            return fail(
                args,
                target,
                "auto",
                "engine-unavailable",
                "install yara-python or the yara CLI, or explicitly select --engine lite",
                EXIT_ENGINE_UNAVAILABLE,
                stats=discovery.stats,
            )
    elif engine == "yara-cli":
        yara_bin = shutil.which("yara")
        if not yara_bin:
            return fail(
                args,
                target,
                engine,
                "engine-unavailable",
                "yara CLI is not installed",
                EXIT_ENGINE_UNAVAILABLE,
                stats=discovery.stats,
            )

    if engine == "yara-python":
        assert yara_module is not None
        try:
            compiled = yara_module.compile(
                filepaths={f"rule_{index:04d}": str(path) for index, path in enumerate(rule_files)},
                includes=False,
            )
        except Exception as exc:
            return fail(
                args,
                target,
                engine,
                "rules-compile",
                str(exc),
                EXIT_OPERATIONAL_FAILURE,
                stats=discovery.stats,
            )
        engine_result = scan_with_yara_python(
            compiled,
            discovery.files,
            args.max_size,
            args.max_total_bytes,
            args.timeout,
            discovery.stats,
            metadata=metadata,
        )
    elif engine == "yara-cli":
        assert yara_bin is not None
        try:
            version = run_yara_cli([yara_bin, "--version"], args.timeout)
            args.engine_version = version.stdout.strip() if version.returncode == 0 else "unknown"
        except (OSError, UnicodeError, subprocess.TimeoutExpired):
            args.engine_version = "unknown"
        validation_error = validate_yara_cli(yara_bin, rule_files, args.timeout)
        if validation_error is not None:
            return fail(
                args,
                target,
                engine,
                validation_error.code,
                validation_error.message,
                EXIT_OPERATIONAL_FAILURE,
                stats=discovery.stats,
            )
        try:
            engine_result = scan_with_yara_cli(
                yara_bin,
                rule_files,
                discovery.files,
                args.max_size,
                args.max_total_bytes,
                args.timeout,
                discovery.stats,
                metadata=metadata,
            )
        except (OSError, UnicodeError, ValueError) as exc:
            return fail(
                args,
                target,
                engine,
                "rules-metadata",
                str(exc),
                EXIT_OPERATIONAL_FAILURE,
                stats=discovery.stats,
            )
    else:
        args.engine_version = __version__
        engine_result = scan_with_lite(
            discovery.files,
            args.max_size,
            args.max_total_bytes,
            discovery.stats,
            timeout=args.timeout,
        )

    errors = [*discovery.errors, *engine_result.errors]
    verdict, detection_exit = summarize(engine_result.findings, engine)
    if errors:
        if not engine_result.findings:
            verdict = "scan-incomplete"
        return emit_result(
            args,
            target,
            engine,
            engine_result.findings,
            errors,
            discovery.stats,
            "partial",
            verdict,
            EXIT_OPERATIONAL_FAILURE,
        )
    return emit_result(
        args,
        target,
        engine,
        engine_result.findings,
        [],
        discovery.stats,
        "complete",
        verdict,
        detection_exit,
    )


def main() -> int:
    with ExitStack() as stack:
        return run_scan(stack)


if __name__ == "__main__":
    raise SystemExit(main())
