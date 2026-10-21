#!/usr/bin/env python3
"""Scan developer-task repositories with ThreatProphet-derived YARA rules."""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

ROOT = Path(__file__).resolve().parents[1]
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


class Colors:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled
        self.reset = "\033[0m" if enabled else ""
        self.bold = "\033[1m" if enabled else ""
        self.dim = "\033[2m" if enabled else ""
        self.red = "\033[31m" if enabled else ""
        self.yellow = "\033[33m" if enabled else ""
        self.blue = "\033[34m" if enabled else ""
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
class Finding:
    rule: str
    severity: str
    path: str
    source: str
    description: str = ""


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
        "VS Code task auto-executes a cross-platform pipe-to-shell command",
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
        "VS Code folderOpen task runs suspicious install, shell, or network command",
        (
            rx(br'"runOn"\s*:\s*"folderOpen"'),
            rx(br'(npm[ \t]+(install|i)|bash|sh|cmd\.exe|powershell|pwsh|curl|wget|Invoke-WebRequest|iwr|https?://|\.vercel\.app|/api/settings/)'),
        ),
        2,
    ),
    LiteRule(
        "HEUR_DevelTask_NPM_Lifecycle_Server_Execution",
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
        "HEUR_DevelTask_NPM_Lifecycle_Suspicious_Command",
        "high",
        "npm lifecycle hook runs suspicious shell, network, or inline execution command",
        (
            rx(br'"scripts"'),
            rx(br'"(prepare|preinstall|install|postinstall|prepack|postpack)"[ \t]*:[ \t]*"[^"\r\n]{0,260}(curl|wget|Invoke-WebRequest|iwr|bash|sh|cmd|powershell|pwsh|node[ \t]+-e|eval|base64|atob|Buffer\.from)'),
        ),
        2,
    ),
    LiteRule(
        "HEUR_DevelTask_Node_Remote_Fetch_Dynamic_Execute",
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
        "HEUR_DevelTask_ENV_Exfil_AUTH_API",
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
        "HEUR_DevelTask_GitHook_Remote_Pipe",
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
        "HEUR_DevelTask_GitHook_Suspicious_Command",
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
        "Code searches for wallet, seed, private-key, env, or credential files",
        (
            rx(br'(seed( phrase)?|mnemonic|recovery phrase|private[_-]?key|BEGIN (RSA|OPENSSH|EC|PRIVATE) KEY|\.env|\.ssh|\.aws/credentials|wallet|metamask|phantom|keystore|ledger|trezor)'),
            rx(br'(readdirSync|walkSync|recursive|find[ \t]+.*-type[ \t]+f|os\.homedir|process\.env\.HOME)'),
            rx(br'(upload|axios\.post|fetch[ \t]*\(|form-data|FormData)'),
        ),
        3,
    ),
    LiteRule(
        "HEUR_DevelTask_Clipboard_C2_Control",
        "high",
        "Clipboard collection paired with command-control primitives",
        (
            rx(br'(clipboardy|Clipboard|pbpaste|xclip -selection clipboard -o|xsel --clipboard --output)'),
            rx(br'(socket\.io-client|processControl|whour|child_process\.exec|/api/notify)'),
        ),
        2,
    ),
    LiteRule(
        "HEUR_DevelTask_Horizontal_Whitespace_Loader",
        "medium",
        "Long horizontal whitespace hides a staged loader off-screen",
        (
            rx(br'[ \t]{120,}(fetch|axios|get|new[ \t]+Function|curl|wget)'),
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


def load_ignore_patterns(path: Path) -> list[str]:
    """Load path globs, failing closed when the requested config is unusable."""
    lines = path.read_text(encoding="utf-8").splitlines()
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
            return True
        if result.stats.files_selected >= max_files:
            result.stats.skipped_resource_limit += 1
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
                    continue
                try:
                    entry_stat = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    result.errors.append(ScanError("entry-stat", str(exc), str(path)))
                    continue
                mode = entry_stat.st_mode
                if stat.S_ISLNK(mode):
                    result.stats.skipped_symlinks += 1
                elif stat.S_ISDIR(mode):
                    child_directories.append(
                        (path, relative, entry_stat.st_dev, entry_stat.st_ino)
                    )
                elif stat.S_ISREG(mode):
                    if not admit(path, relative, entry_stat):
                        return result
                else:
                    result.stats.skipped_special += 1
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


def load_rule_metadata(rule_files: Iterable[Path]) -> dict[str, dict[str, str]]:
    metadata: dict[str, dict[str, str]] = {}
    rule_re = re.compile(r"\brule\s+([A-Za-z0-9_]+)\s*\{(?P<body>.*?)\n\}", re.DOTALL)
    meta_re = re.compile(r"\b(severity|description)\s*=\s*\"([^\"]*)\"")
    for path in rule_files:
        text = path.read_text(encoding="utf-8")
        for match in rule_re.finditer(text):
            body = match.group("body")
            metadata[match.group(1)] = {key: value for key, value in meta_re.findall(body)}
    return metadata


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


def scan_with_yara_python(
    compiled: Any,
    files: Iterable[ScannableFile],
    max_size: int,
    max_total_bytes: int,
    timeout: int,
    stats: ScanStats,
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
        try:
            matches = compiled.match(data=data, timeout=timeout)
        except Exception as exc:
            result.errors.append(ScanError("file-scan", str(exc), str(candidate.path)))
            continue
        stats.files_scanned += 1
        for match in matches:
            meta = getattr(match, "meta", {}) or {}
            severity = str(meta.get("severity", "medium")).lower()
            result.findings.append(
                Finding(
                    rule=match.rule,
                    severity=severity,
                    path=candidate.display_path,
                    source="yara-python",
                    description=str(meta.get("description", "")),
                )
            )
    return result


def run_yara_cli(command: Sequence[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout,
    )


def yara_cli_exception_message(
    error: OSError | UnicodeError | subprocess.TimeoutExpired,
    timeout: int,
) -> str:
    if isinstance(error, subprocess.TimeoutExpired):
        return f"YARA CLI timed out after {timeout} seconds"
    return str(error)


def validate_yara_cli(yara_bin: str, rule_files: Sequence[Path], timeout: int) -> ScanError | None:
    try:
        process = run_yara_cli(
            [yara_bin, "-w", *(str(path) for path in rule_files), os.devnull], timeout
        )
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as exc:
        return ScanError("rules-compile", yara_cli_exception_message(exc, timeout))
    if process.returncode != 0:
        detail = process.stderr.strip() or f"yara exited with status {process.returncode}"
        return ScanError("rules-compile", detail)
    return None


def scan_with_yara_cli(
    yara_bin: str,
    rule_files: Sequence[Path],
    files: Iterable[ScannableFile],
    max_size: int,
    max_total_bytes: int,
    timeout: int,
    stats: ScanStats,
) -> EngineResult:
    import tempfile

    metadata = load_rule_metadata(rule_files)
    result = EngineResult()
    budget = ReadBudget(max_total_bytes)
    for candidate in files:
        try:
            data = read_regular_file(candidate, max_size, budget, stats)
        except OSError as exc:
            if append_read_error(result, exc, candidate, stats):
                break
            continue
        try:
            with tempfile.NamedTemporaryFile(prefix="reposcan-", suffix=".scan") as safe_copy:
                safe_copy.write(data)
                safe_copy.flush()
                process = run_yara_cli(
                    [yara_bin, "-w", *(str(path) for path in rule_files), safe_copy.name],
                    timeout,
                )
        except (OSError, UnicodeError, subprocess.TimeoutExpired) as exc:
            result.errors.append(
                ScanError(
                    "file-scan",
                    yara_cli_exception_message(exc, timeout),
                    str(candidate.path),
                )
            )
            continue
        if process.returncode != 0:
            detail = process.stderr.strip() or f"yara exited with status {process.returncode}"
            result.errors.append(ScanError("file-scan", detail, str(candidate.path)))
            continue
        stats.files_scanned += 1
        for line in process.stdout.splitlines():
            rule = line.split(maxsplit=1)[0] if line.split() else ""
            if not rule:
                continue
            meta = metadata.get(rule, {})
            result.findings.append(
                Finding(
                    rule=rule,
                    severity=meta.get("severity", "medium").lower(),
                    path=candidate.display_path,
                    source="yara-cli",
                    description=meta.get("description", ""),
                )
            )
    return result


def scan_with_lite(
    files: Iterable[ScannableFile],
    max_size: int,
    max_total_bytes: int,
    stats: ScanStats,
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
        stats.files_scanned += 1
        for rule in LITE_RULES:
            if rule.match(data):
                result.findings.append(
                    Finding(
                        rule=rule.name,
                        severity=rule.severity,
                        path=candidate.display_path,
                        source="heuristic-lite",
                        description=rule.description,
                    )
                )
    return result


def summarize(findings: list[Finding], engine: str) -> tuple[str, int]:
    if engine == "lite":
        return ("heuristic-findings", 1) if findings else ("no-findings", 0)
    if any(f.severity == "critical" for f in findings):
        return "malicious-likely", 2
    if any(f.severity == "high" for f in findings):
        return "suspicious", 1
    if findings:
        return "review-needed", 1
    return "no-findings", 0


def severity_color(severity: str, colors: Colors) -> str:
    return {
        "critical": colors.red,
        "high": colors.yellow,
        "medium": colors.blue,
        "low": colors.gray,
    }.get(severity, colors.gray)


def verdict_color(verdict: str, colors: Colors) -> str:
    return {
        "malicious-likely": colors.red,
        "suspicious": colors.yellow,
        "review-needed": colors.blue,
        "heuristic-findings": colors.yellow,
        "scan-incomplete": colors.red,
        "scan-failed": colors.red,
        "not-scanned": colors.red,
        "no-findings": colors.green,
    }.get(verdict, colors.gray)


def safe_terminal_text(value: object) -> str:
    return "".join(character if character.isprintable() else ascii(character)[1:-1] for character in str(value))


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
) -> None:
    verdict_text = colors.wrap(verdict, colors.bold + verdict_color(verdict, colors))
    print(colors.wrap("RepoScan", colors.bold))
    print(f"Target:   {safe_terminal_text(target)}")
    print(f"Engine:   {safe_terminal_text(engine)}")
    print(f"Status:   {status}")
    print(f"Complete: {'yes' if complete else 'no'}")
    print(f"Verdict:  {verdict_text}")
    print(f"Findings: {len(findings)}")
    print(f"Scanned:  {stats.files_scanned}/{stats.files_selected} selected files")
    if errors:
        print()
        print(colors.wrap("ERRORS", colors.bold + colors.red))
        for error in errors:
            location = f" ({safe_terminal_text(error.path)})" if error.path else ""
            print(f"  - {safe_terminal_text(error.code)}: {safe_terminal_text(error.message)}{location}")
    if not findings and complete:
        print()
        if engine == "lite":
            print(colors.wrap("No heuristic patterns were found; this was not a YARA scan.", colors.green))
        else:
            print(colors.wrap("No matching developer-task malware patterns were found.", colors.green))
        return

    if findings:
        print()
    current_severity = None
    for finding in findings:
        if finding.severity != current_severity:
            current_severity = finding.severity
            label = SEVERITY_LABEL.get(finding.severity, finding.severity.upper())
            colored_label = colors.wrap(label, colors.bold + severity_color(finding.severity, colors))
            print(f"{colored_label}")
        rule = colors.wrap(safe_terminal_text(finding.rule), colors.bold)
        path = colors.wrap(safe_terminal_text(finding.path), colors.blue)
        source = colors.wrap(safe_terminal_text(finding.source), colors.gray)
        print(f"  - {rule}")
        print(f"    path:   {path}")
        print(f"    source: {source}")
        if finding.description:
            print(f"    why:    {safe_terminal_text(finding.description)}")
    print()
    print(colors.wrap(f"Exit code: {exit_code}", colors.dim))


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
    sorted_errors = ordered_errors(errors)
    complete = status == "complete"
    payload = {
        "target": str(target),
        "engine": engine,
        "complete": complete,
        "status": status,
        "verdict": verdict,
        "findings": [asdict(finding) for finding in sorted_findings],
        "errors": [asdict(error) for error in sorted_errors],
        "stats": asdict(stats),
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        display_engine = engine
        if engine == "lite":
            display_engine = "lite (heuristic-only; not YARA)"
        print_text(
            sorted_findings,
            sorted_errors,
            verdict,
            exit_code,
            display_engine,
            target,
            complete,
            status,
            stats,
            Colors(color_enabled(args.color)),
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


def main() -> int:
    parser = RepoScanArgumentParser(description="Scan a developer task or project for malicious patterns.")
    parser.add_argument("target", type=Path, help="Path to the project/dev-task to scan")
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES, help="Directory containing .yar files")
    parser.add_argument("--ignore-config", type=Path, default=DEFAULT_IGNORE_CONFIG, help="Shared ignore pattern file")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto", help="Colorize text output")
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
    parser.add_argument("--timeout", type=positive_integer, default=DEFAULT_TIMEOUT, help="Per-file engine timeout")
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
        ignore_patterns = load_ignore_patterns(ignore_config)
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
                filepaths={f"rule_{index:04d}": str(path) for index, path in enumerate(rule_files)}
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
        )
    elif engine == "yara-cli":
        assert yara_bin is not None
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
            )
        except (OSError, UnicodeError) as exc:
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
        engine_result = scan_with_lite(
            discovery.files,
            args.max_size,
            args.max_total_bytes,
            discovery.stats,
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


if __name__ == "__main__":
    raise SystemExit(main())
