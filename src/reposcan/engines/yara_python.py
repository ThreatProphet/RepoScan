"""Canonical YARA matching through the optional Python binding."""

from __future__ import annotations

import hashlib
from typing import Any, Iterable

from reposcan.engine_support import bounded_matching
from reposcan.engines.common import append_read_error, contextualize, rule_finding
from reposcan.filesystem import ReadBudget, read_regular_file
from reposcan.models import EngineResult, Evidence, Finding, ScanError, ScannableFile, ScanStats, evidence_at
from reposcan.review import review_bytes
from reposcan.settings import MAX_EVIDENCE


def import_yara() -> Any | None:
    try:
        import yara  # type: ignore
    except ModuleNotFoundError as exc:
        if exc.name == "yara":
            return None
        raise
    return yara


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
