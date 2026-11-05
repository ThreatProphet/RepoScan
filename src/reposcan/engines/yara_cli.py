"""Canonical YARA subprocess adapter with bounded output and captured input."""

from __future__ import annotations

import hashlib
import os
import re
import selectors
import subprocess
import tempfile
from pathlib import Path
from time import monotonic
from typing import Any, Iterable, Sequence

from reposcan.engine_support import bounded_matching, load_rule_metadata
from reposcan.engines.common import append_read_error, contextualize, rule_finding
from reposcan.filesystem import ReadBudget, read_regular_file
from reposcan.models import EngineResult, Evidence, Finding, ScanError, ScannableFile, ScanStats, evidence_at
from reposcan.review import review_bytes
from reposcan.settings import MAX_ENGINE_OUTPUT, MAX_EVIDENCE


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
