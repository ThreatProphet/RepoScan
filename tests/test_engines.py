from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest
from conftest import (
    FIXTURES,
    RULES,
    SCANNER,
    has_yara_cli,
    has_yara_python,
    parse_json_output,
    run_scanner,
)


def load_scanner_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("reposcan_scanner_engine_tests", SCANNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def normalized_findings(payload: dict[str, object]) -> list[tuple[str, str, str, str]]:
    findings = payload["findings"]
    assert isinstance(findings, list)
    return sorted(
        (finding["rule"], finding["severity"], finding["path"], finding["description"])
        for finding in findings
    )


def test_yara_cli_validation_reports_diagnostic_decoding_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scanner = load_scanner_module()
    decoding_error = UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")

    def fail_to_decode(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise decoding_error

    monkeypatch.setattr(scanner, "run_yara_cli", fail_to_decode)
    error = scanner.validate_yara_cli("yara", [RULES / "developer_task_malware.yar"], 10)

    assert error is not None
    assert error.code == "rules-compile"
    assert "invalid start byte" in error.message


def test_yara_cli_timeout_error_is_deterministic_and_hides_temporary_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scanner = load_scanner_module()
    target = tmp_path / "target.txt"
    target.write_text("ordinary inert text\n", encoding="utf-8")
    target_stat = target.stat()
    candidate = scanner.ScannableFile(
        path=target,
        display_path=target.name,
        device=target_stat.st_dev,
        inode=target_stat.st_ino,
    )
    temporary_paths: list[str] = []

    def time_out(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
        temporary_paths.append(command[-1])
        raise subprocess.TimeoutExpired(command, timeout)

    monkeypatch.setattr(scanner, "run_yara_cli", time_out)
    results = [
        scanner.scan_with_yara_cli(
            "yara",
            [RULES / "developer_task_malware.yar"],
            [candidate],
            max_size=1024,
            max_total_bytes=1024,
            timeout=10,
            stats=scanner.ScanStats(),
        )
        for _ in range(2)
    ]

    assert temporary_paths[0] != temporary_paths[1]
    assert results[0].errors == results[1].errors
    assert results[0].errors == [
        scanner.ScanError("file-scan", "YARA CLI timed out after 10 seconds", str(target))
    ]
    assert all(path not in results[0].errors[0].message for path in temporary_paths)


@pytest.mark.parity
@pytest.mark.parametrize(
    "fixture_name",
    [
        "malicious-vscode",
        "malicious-githook",
        "suspicious-env",
        "suspicious-pipe",
        "sensitive-collector",
        "benign",
        "benign-assets",
    ],
)
def test_yara_cli_and_python_have_canonical_parity(fixture_name: str) -> None:
    if not has_yara_python() or not has_yara_cli():
        pytest.skip("canonical parity requires both yara-python and the YARA CLI")

    target = FIXTURES / fixture_name
    python_result = run_scanner(target, "--engine", "yara-python")
    cli_result = run_scanner(target, "--engine", "yara-cli")
    python_payload = parse_json_output(python_result)
    cli_payload = parse_json_output(cli_result)

    assert python_result.returncode == cli_result.returncode
    assert python_payload["complete"] is cli_payload["complete"] is True
    assert python_payload["verdict"] == cli_payload["verdict"]
    assert normalized_findings(python_payload) == normalized_findings(cli_payload)


@pytest.mark.canonical
@pytest.mark.parametrize("engine", ["yara-python", "yara-cli"])
def test_invalid_rules_are_operational_failures_without_fallback(tmp_path: Path, engine: str) -> None:
    if engine == "yara-python" and not has_yara_python():
        pytest.skip("yara-python is not installed")
    if engine == "yara-cli" and not has_yara_cli():
        pytest.skip("YARA CLI is not installed")

    invalid_rules = tmp_path / "rules"
    invalid_rules.mkdir()
    (invalid_rules / "invalid.yar").write_text("rule invalid { condition: }\n", encoding="utf-8")

    result = run_scanner(
        FIXTURES / "benign",
        "--engine",
        engine,
        "--rules",
        str(invalid_rules),
    )
    payload = parse_json_output(result)

    assert result.returncode == 70
    assert payload["complete"] is False
    assert payload["status"] == "failed"
    assert payload["verdict"] not in {"no-findings", "heuristic-findings"}
    assert payload["findings"] == []
    assert payload["errors"]


@pytest.mark.posix
def test_unusable_rule_entry_cannot_be_silently_omitted(tmp_path: Path) -> None:
    if not hasattr(Path, "symlink_to"):
        pytest.skip("symbolic links are unavailable")

    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "valid.yar").write_text("rule valid { condition: false }\n", encoding="utf-8")
    (rules / "broken.yar").symlink_to(rules / "missing.yar")

    result = run_scanner(
        FIXTURES / "benign",
        "--engine",
        "auto",
        "--rules",
        str(rules),
    )
    payload = parse_json_output(result)

    assert result.returncode == 64
    assert payload["complete"] is False
    assert payload["status"] == "failed"
    assert payload["verdict"] == "not-scanned"
    assert payload["findings"] == []
    assert [error["code"] for error in payload["errors"]] == ["rules-config"]


@pytest.mark.canonical
def test_rules_compile_with_yara_cli() -> None:
    yara = shutil.which("yara")
    if yara is None:
        pytest.skip("YARA CLI is not installed")

    result = subprocess.run(
        [yara, "-w", str(RULES / "developer_task_malware.yar"), "/dev/null"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
