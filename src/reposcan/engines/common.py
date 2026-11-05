"""Finding normalization and read-failure handling shared by matching adapters."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any, Sequence

from reposcan.filesystem import ResourceLimitError
from reposcan.models import EngineResult, Evidence, Finding, ScanError, ScannableFile, ScanStats
from reposcan.settings import MAX_EVIDENCE, SEVERITY_SCORE


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
