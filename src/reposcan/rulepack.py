"""Capture trusted rule sources and preserve their reproducible identity."""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from contextlib import ExitStack
from pathlib import Path
from typing import Sequence

from reposcan.engine_support import MAX_RULE_FILE_BYTES, MAX_RULE_FILES, MAX_RULE_PACK_BYTES
from reposcan.models import RulePackFile, RulePackIdentity


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


def rule_pack_identity(rule_files: Sequence[Path]) -> RulePackIdentity:
    """Hash captured sources using the existing ordered, length-prefixed identity."""
    pack_hash = hashlib.sha256()
    members: list[RulePackFile] = []
    for path in rule_files:
        rule_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        name_bytes = path.name.encode("utf-8")
        pack_hash.update(len(name_bytes).to_bytes(4, "big") + name_bytes + rule_hash.encode("ascii"))
        members.append({"name": path.name, "sha256": rule_hash})
    return {"sha256": pack_hash.hexdigest(), "files": members}
