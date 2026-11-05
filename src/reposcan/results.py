"""Deterministic finding order, verdicts, and public error normalization."""

from __future__ import annotations

from dataclasses import replace
from typing import Iterable, Mapping

from reposcan.models import Finding, ScanError, ScanResult
from reposcan.settings import SEVERITY_SCORE


def summarize(findings: list[Finding], engine: str) -> tuple[str, int]:
    if engine == "lite":
        return ("heuristic-findings", 1) if findings else ("no-findings", 0)
    if any(f.severity == "critical" and f.confidence == "high" and f.source in {"yara-python", "yara-cli"}
           for f in findings):
        return "high-risk", 2
    if findings:
        return "review-needed", 1
    return "no-findings", 0

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


def finalize_result(result: ScanResult, rule_display_paths: Mapping[str, str]) -> ScanResult:
    """Restore trusted rule paths before temporary snapshots are released."""
    normalized_errors = []
    for error in result.errors:
        message, path = error.message, error.path
        for captured, original in rule_display_paths.items():
            message = message.replace(captured, original)
            if path is not None:
                path = path.replace(captured, original)
        normalized_errors.append(replace(error, message=message, path=path))
    return replace(
        result, findings=ordered_findings(result.findings), errors=ordered_errors(normalized_errors),
    )
