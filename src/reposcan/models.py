"""Stable, deterministic evidence records used by all scan adapters."""

from __future__ import annotations

from dataclasses import dataclass


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
