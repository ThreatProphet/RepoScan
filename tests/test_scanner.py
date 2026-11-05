from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from conftest import FIXTURES

from reposcan import cli, scanner
from reposcan.engines import yara_python
from reposcan.models import ScanError, ScanOptions, ScanResult
from reposcan.reporting import result_payload


def test_scan_api_and_explicit_cli_arguments_share_one_result_contract(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    target = FIXTURES / "web3market-entry"
    unrelated_argv = ["embedding-application", "--unrelated-option"]
    monkeypatch.setattr(sys, "argv", unrelated_argv)

    result = scanner.scan(ScanOptions(target=target, engine="lite"))

    assert isinstance(result, ScanResult)
    assert result.complete and result.exit_code == 1
    assert capsys.readouterr() == ("", "")

    arguments = [str(target), "--engine", "lite", "--format", "json"]
    assert cli.main(arguments) == result.exit_code
    cli_output = capsys.readouterr()
    assert cli_output.err == ""
    assert cli_output.out == json.dumps(result_payload(result), indent=2, sort_keys=True) + "\n"

    assert scanner.main(arguments) == result.exit_code
    assert capsys.readouterr() == cli_output
    assert sys.argv == unrelated_argv


def test_scan_api_returns_a_typed_failure_without_printing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    target = tmp_path / "missing"

    result = scanner.scan(ScanOptions(target=target, engine="lite"))

    assert isinstance(result, ScanResult)
    assert result.exit_code == 64
    assert result.status == "failed" and not result.complete
    assert result.verdict == "not-scanned"
    assert result.findings == []
    assert len(result.errors) == 1
    assert isinstance(result.errors[0], ScanError)
    assert result.errors[0].code == "target"
    assert result.errors[0].path == str(target)
    assert capsys.readouterr() == ("", "")


def test_repeated_service_scans_do_not_share_mutable_result_state() -> None:
    options = ScanOptions(target=FIXTURES / "web3market-entry", engine="lite")
    first = scanner.scan(options)
    expected = json.dumps(result_payload(first), sort_keys=True)
    assert first.findings

    first.findings.clear()
    first.errors.append(ScanError("caller-note", "A caller changed its own result."))
    first.stats.files_scanned = 999
    first.stats.skip_details.append({"path": "caller-only", "reason": "caller-note"})
    first.rule_pack["files"].append({"name": "caller-only", "sha256": "0" * 64})

    benign = scanner.scan(ScanOptions(target=FIXTURES / "benign", engine="lite"))
    repeated = scanner.scan(options)

    assert benign.complete and benign.exit_code == 0
    assert benign.findings == [] and benign.errors == []
    assert benign.stats.files_scanned == 1
    assert benign.rule_pack["files"] == []
    assert json.dumps(result_payload(repeated), sort_keys=True) == expected


def test_broken_python_binding_is_a_service_failure_without_engine_fallback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    fallback_checks: list[str] = []

    def broken_binding() -> None:
        raise RuntimeError("native binding failed to initialize")

    def available_cli(name: str) -> str:
        fallback_checks.append(name)
        return "/unexpected/yara"

    monkeypatch.setattr(yara_python, "import_yara", broken_binding)
    monkeypatch.setattr(scanner.shutil, "which", available_cli)

    result = scanner.scan(ScanOptions(target=FIXTURES / "benign", engine="auto"))

    assert fallback_checks == []
    assert result.engine == "yara-python"
    assert result.exit_code == 70
    assert result.status == "failed" and not result.complete
    assert result.stats.files_selected == 1 and result.stats.files_scanned == 0
    assert result.findings == []
    assert result.errors == [ScanError("engine-load", "native binding failed to initialize")]
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("max_size", 0),
        ("max_files", -1),
        ("max_total_bytes", 1.5),
        ("max_entries", "2"),
        ("timeout", True),
    ],
)
def test_programmatic_options_reject_invalid_limits(tmp_path: Path, option: str, value: object) -> None:
    with pytest.raises(ValueError, match=option):
        ScanOptions(target=tmp_path, **{option: value})


def test_programmatic_options_reject_an_unknown_engine(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unsupported scan engine"):
        ScanOptions(target=tmp_path, engine="implicit-fallback")
