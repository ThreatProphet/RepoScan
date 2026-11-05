"""Stable, deterministic evidence records used by all scan adapters."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TypedDict

from reposcan.settings import (
    DEFAULT_IGNORE_CONFIG,
    DEFAULT_MAX_ENTRIES,
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_SIZE,
    DEFAULT_MAX_TOTAL_BYTES,
    DEFAULT_RULES,
    DEFAULT_TIMEOUT,
    EXIT_USAGE,
    MAX_SKIP_DETAILS,
)


@dataclass(frozen=True)
class Evidence:
    """A bounded match location in the exact bytes scanned (zero-based offset)."""

    identifier: str
    offset: int
    length: int
    line: int


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    path: str
    source: str
    description: str = ""
    category: str = "behavior"
    confidence: str = "medium"
    trigger: str = ""
    prerequisites: tuple[str, ...] = ()
    reports: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    evidence_truncated: bool = False
    sha256: str = ""
    finding_id: str = ""


def evidence_at(data: bytes, identifier: str, offset: int, length: int) -> Evidence:
    """Compute a location without putting source content into an output record."""
    return Evidence(identifier, offset, length, data.count(b"\n", 0, offset) + 1)


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

@dataclass(frozen=True)
class ScannableFile:
    path: Path
    display_path: str
    device: int
    inode: int

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
class ScanOptions:
    """Validated scan inputs, independent of command-line and display choices."""

    target: Path
    rules: Path = DEFAULT_RULES
    ignore_config: Path = DEFAULT_IGNORE_CONFIG
    engine: str = "auto"
    max_size: int = DEFAULT_MAX_SIZE
    max_files: int = DEFAULT_MAX_FILES
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES
    max_entries: int = DEFAULT_MAX_ENTRIES
    timeout: int = DEFAULT_TIMEOUT

    def __post_init__(self) -> None:
        if self.engine not in {"auto", "yara-python", "yara-cli", "lite"}:
            raise ValueError(f"unsupported scan engine: {self.engine}")
        for name in ("max_size", "max_files", "max_total_bytes", "max_entries", "timeout"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


class RulePackFile(TypedDict):
    name: str
    sha256: str


class RulePackIdentity(TypedDict):
    sha256: str
    files: list[RulePackFile]


@dataclass
class ScanResult:
    """One materialized scan outcome; renderers never perform scan operations."""

    options: ScanOptions
    target: Path
    engine: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[ScanError] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    status: str = "failed"
    verdict: str = "not-scanned"
    exit_code: int = EXIT_USAGE
    engine_version: str = ""
    rule_pack: RulePackIdentity = field(default_factory=lambda: {"sha256": "", "files": []})
    ignore_config_sha256: str = ""

    @property
    def complete(self) -> bool:
        return self.status == "complete"
