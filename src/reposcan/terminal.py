"""Human-readable terminal presentation, separate from scan execution."""

from __future__ import annotations

import os
import re
import shutil
import sys
import unicodedata
from pathlib import Path
from typing import Callable

from reposcan import __version__
from reposcan.models import Finding, ScanError, ScanStats
from reposcan.settings import SEVERITY_LABEL


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
    line("SUMMARY", colors.bold)
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
    line()
    if not complete:
        field("Next", "Resolve the reported scan errors and rescan; this result is incomplete.",
              colors.bold + colors.red, indent=0)
    elif findings:
        field("Next", "Review the flagged files and their execution context before running the project.", indent=0)
    line(f"Exit code: {exit_code}", colors.bold)
