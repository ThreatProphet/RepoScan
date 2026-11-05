"""Coordinate a bounded scan and return data independently of CLI presentation."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from reposcan import __version__, engine_support, filesystem, rulepack
from reposcan.engines import lite, yara_cli, yara_python
from reposcan.models import EngineResult, ScanError, ScannableFile, ScanOptions, ScanResult
from reposcan.results import finalize_result, summarize
from reposcan.settings import EXIT_ENGINE_UNAVAILABLE, EXIT_OPERATIONAL_FAILURE, EXIT_USAGE


class _ScanFailure(Exception):
    """An expected setup failure, translated into one structured scan result."""

    def __init__(
        self, code: str, message: str, exit_code: int, path: Path | None = None,
        *, engine: str | None = None,
    ) -> None:
        super().__init__(message)
        self.error = ScanError(code, message, str(path) if path is not None else None)
        self.exit_code = exit_code
        self.engine = engine


@dataclass(frozen=True)
class _EngineSelection:
    name: str
    module: Any | None = None
    binary: str | None = None


def _validate_target(target: Path) -> os.stat_result:
    try:
        target_stat = target.lstat()
    except OSError as exc:
        raise _ScanFailure("target", str(exc), EXIT_USAGE, target) from exc
    if stat.S_ISLNK(target_stat.st_mode):
        raise _ScanFailure("target-type", "symlink targets are not followed", EXIT_USAGE, target)
    if not (stat.S_ISREG(target_stat.st_mode) or stat.S_ISDIR(target_stat.st_mode)):
        raise _ScanFailure("target-type", "target must be a regular file or directory", EXIT_USAGE, target)
    return target_stat


def _load_ignore_policy(result: ScanResult) -> list[str]:
    ignore_config = Path(os.path.abspath(os.fspath(result.options.ignore_config)))
    try:
        ignore_stat = ignore_config.lstat()
        if not stat.S_ISREG(ignore_stat.st_mode):
            raise OSError("ignore config must be a regular file")
        ignore_bytes = ignore_config.read_bytes()
        patterns = filesystem.load_ignore_patterns(ignore_config, ignore_bytes)
        result.ignore_config_sha256 = hashlib.sha256(ignore_bytes).hexdigest()
        return patterns
    except (OSError, UnicodeError) as exc:
        raise _ScanFailure("ignore-config", str(exc), EXIT_USAGE, ignore_config) from exc


def _prepare_rules(
    result: ScanResult, stack: ExitStack, display_paths: dict[str, str],
) -> tuple[list[Path], dict[str, dict[str, Any]]]:
    if result.engine == "lite":
        return [], {}
    rule_dir = Path(os.path.abspath(os.fspath(result.options.rules)))
    try:
        rule_dir_stat = rule_dir.lstat()
    except OSError as exc:
        raise _ScanFailure("rules-config", str(exc), EXIT_USAGE, rule_dir) from exc
    if not stat.S_ISDIR(rule_dir_stat.st_mode):
        raise _ScanFailure("rules-config", "rules path must be a directory", EXIT_USAGE, rule_dir)
    try:
        rule_files = rulepack.regular_rule_files(rule_dir)
    except OSError as exc:
        raise _ScanFailure("rules-config", str(exc), EXIT_USAGE, rule_dir) from exc
    if not rule_files:
        raise _ScanFailure("rules-config", "rules directory contains no regular .yar files", EXIT_USAGE, rule_dir)
    try:
        rule_files, captured_paths = rulepack.snapshot_rule_files(rule_files, stack)
        display_paths.update(captured_paths)
        metadata = engine_support.load_rule_metadata(rule_files)
        result.rule_pack = rulepack.rule_pack_identity(rule_files)
    except (OSError, UnicodeError, ValueError) as exc:
        raise _ScanFailure("rules-metadata", str(exc), EXIT_OPERATIONAL_FAILURE) from exc
    return rule_files, metadata


def _select_engine(requested: str) -> _EngineSelection:
    if requested in ("auto", "yara-python"):
        try:
            module = yara_python.import_yara()
        except Exception as exc:
            raise _ScanFailure("engine-load", str(exc), EXIT_OPERATIONAL_FAILURE, engine="yara-python") from exc
        if module is not None:
            return _EngineSelection("yara-python", module=module)
        if requested == "yara-python":
            raise _ScanFailure("engine-unavailable", "yara-python is not installed", EXIT_ENGINE_UNAVAILABLE)
    if requested in ("auto", "yara-cli"):
        binary = shutil.which("yara")
        if binary:
            return _EngineSelection("yara-cli", binary=binary)
        message = (
            "install yara-python or the yara CLI, or explicitly select --engine lite"
            if requested == "auto" else "yara CLI is not installed"
        )
        raise _ScanFailure("engine-unavailable", message, EXIT_ENGINE_UNAVAILABLE)
    return _EngineSelection("lite")


def _scan_python(
    result: ScanResult, module: Any, rule_files: list[Path],
    files: list[ScannableFile], metadata: dict[str, dict[str, Any]],
) -> EngineResult:
    result.engine_version = str(getattr(module, "__version__", "unknown"))
    try:
        compiled = module.compile(
            filepaths={f"rule_{index:04d}": str(path) for index, path in enumerate(rule_files)},
            includes=False,
        )
    except Exception as exc:
        raise _ScanFailure("rules-compile", str(exc), EXIT_OPERATIONAL_FAILURE) from exc
    options = result.options
    return yara_python.scan_with_yara_python(
        compiled, files, options.max_size, options.max_total_bytes, options.timeout,
        result.stats, metadata=metadata,
    )


def _scan_cli(
    result: ScanResult, binary: str, rule_files: list[Path],
    files: list[ScannableFile], metadata: dict[str, dict[str, Any]],
) -> EngineResult:
    options = result.options
    try:
        version = yara_cli.run_yara_cli([binary, "--version"], options.timeout)
        result.engine_version = version.stdout.strip() if version.returncode == 0 else "unknown"
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        result.engine_version = "unknown"
    error = yara_cli.validate_yara_cli(binary, rule_files, options.timeout)
    if error is not None:
        raise _ScanFailure(error.code, error.message, EXIT_OPERATIONAL_FAILURE)
    try:
        return yara_cli.scan_with_yara_cli(
            binary, rule_files, files, options.max_size, options.max_total_bytes,
            options.timeout, result.stats, metadata=metadata,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise _ScanFailure("rules-metadata", str(exc), EXIT_OPERATIONAL_FAILURE) from exc


def _run_engine(
    result: ScanResult, selection: _EngineSelection, rule_files: list[Path],
    files: list[ScannableFile], metadata: dict[str, dict[str, Any]],
) -> EngineResult:
    if selection.name == "yara-python":
        assert selection.module is not None
        return _scan_python(result, selection.module, rule_files, files, metadata)
    if selection.name == "yara-cli":
        assert selection.binary is not None
        return _scan_cli(result, selection.binary, rule_files, files, metadata)
    result.engine_version = __version__
    options = result.options
    return lite.scan_with_lite(
        files, options.max_size, options.max_total_bytes, result.stats, timeout=options.timeout,
    )


def scan(options: ScanOptions) -> ScanResult:
    """Inspect eligible files and return an ordered result without printing.

    Setup order is deliberate: target, policy, captured rules, discovery, engine,
    then matching. Errors retain the same phase-specific coverage and verdicts.
    """
    target = Path(os.path.abspath(os.fspath(options.target)))
    result = ScanResult(options=options, target=target, engine=options.engine)
    display_paths: dict[str, str] = {}
    with ExitStack() as stack:
        try:
            target_stat = _validate_target(target)
            patterns = _load_ignore_policy(result)
            rule_files, metadata = _prepare_rules(result, stack, display_paths)
            discovery = filesystem.discover_files(
                target, target_stat, options.max_size, options.max_files,
                options.max_total_bytes, options.max_entries, patterns,
            )
            result.stats = discovery.stats
            selection = _select_engine(options.engine)
            result.engine = selection.name
            engine_result = _run_engine(result, selection, rule_files, discovery.files, metadata)
            result.findings = engine_result.findings
            result.errors = [*discovery.errors, *engine_result.errors]
            result.verdict, result.exit_code = summarize(result.findings, result.engine)
            result.status = "complete"
            if result.errors:
                result.status = "partial"
                result.exit_code = EXIT_OPERATIONAL_FAILURE
                if not result.findings:
                    result.verdict = "scan-incomplete"
        except _ScanFailure as failure:
            result.errors = [failure.error]
            result.exit_code = failure.exit_code
            if failure.engine is not None:
                result.engine = failure.engine
        return finalize_result(result, display_paths)


def main(argv: Sequence[str] | None = None) -> int:
    """Compatibility entry point for callers of the former scanner CLI."""
    from reposcan.cli import main as cli_main

    return cli_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
