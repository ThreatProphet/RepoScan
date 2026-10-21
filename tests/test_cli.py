from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import FIXTURES, assert_payload_shape, parse_json_output, run_scanner


@pytest.mark.canonical
@pytest.mark.parametrize(
    "fixture_name",
    ["malicious-vscode", "malicious-githook", "suspicious-env", "suspicious-pipe", "sensitive-collector"],
)
def test_existing_positive_fixtures_match_canonical_engine(canonical_engine: str, fixture_name: str) -> None:
    result = run_scanner(FIXTURES / fixture_name, "--engine", canonical_engine)
    payload = parse_json_output(result)

    assert result.returncode in {1, 2}
    assert_payload_shape(payload)
    assert payload["complete"] is True
    assert payload["status"] == "complete"
    assert payload["engine"] == canonical_engine
    assert payload["findings"]
    assert all(finding["rule"].startswith("TP_DevelTask_") for finding in payload["findings"])


@pytest.mark.canonical
@pytest.mark.parametrize("fixture_name", ["benign", "benign-assets"])
def test_existing_negative_fixtures_are_clean_canonical_engine(canonical_engine: str, fixture_name: str) -> None:
    result = run_scanner(FIXTURES / fixture_name, "--engine", canonical_engine)
    payload = parse_json_output(result)

    assert result.returncode == 0
    assert_payload_shape(payload)
    assert payload["complete"] is True
    assert payload["verdict"] == "no-findings"
    assert payload["findings"] == []


@pytest.mark.canonical
def test_single_file_and_directory_scans_have_equivalent_findings(canonical_engine: str) -> None:
    directory = FIXTURES / "suspicious-pipe"
    file_path = directory / "setup.sh"

    directory_result = run_scanner(directory, "--engine", canonical_engine)
    file_result = run_scanner(file_path, "--engine", canonical_engine)
    directory_payload = parse_json_output(directory_result)
    file_payload = parse_json_output(file_result)

    assert directory_result.returncode == file_result.returncode == 1
    directory_findings = {(item["rule"], item["severity"], item["path"]) for item in directory_payload["findings"]}
    file_findings = {(item["rule"], item["severity"], item["path"]) for item in file_payload["findings"]}
    assert directory_findings == file_findings
    assert {item["path"] for item in file_payload["findings"]} == {file_path.name}


@pytest.mark.canonical
@pytest.mark.parametrize(
    ("fixture_name", "expected_exit", "expected_verdict"),
    [
        ("benign", 0, "no-findings"),
        ("suspicious-pipe", 1, "suspicious"),
        ("malicious-vscode", 2, "malicious-likely"),
    ],
)
def test_canonical_severity_controls_verdict_and_exit_code(
    canonical_engine: str,
    fixture_name: str,
    expected_exit: int,
    expected_verdict: str,
) -> None:
    result = run_scanner(FIXTURES / fixture_name, "--engine", canonical_engine)
    payload = parse_json_output(result)

    assert result.returncode == expected_exit
    assert payload["verdict"] == expected_verdict


def test_lite_mode_is_explicitly_heuristic() -> None:
    result = run_scanner(FIXTURES / "malicious-vscode", "--engine", "lite")
    payload = parse_json_output(result)

    assert result.returncode == 1
    assert_payload_shape(payload)
    assert payload["complete"] is True
    assert payload["engine"] == "lite"
    assert payload["verdict"] == "heuristic-findings"
    assert payload["findings"]
    assert all(finding["rule"].startswith("HEUR_") for finding in payload["findings"])
    assert all(finding["source"] == "heuristic-lite" for finding in payload["findings"])
    assert all(not finding["rule"].startswith("TP_DevelTask_") for finding in payload["findings"])


def test_lite_alias_matches_explicit_engine() -> None:
    target = FIXTURES / "suspicious-pipe"
    engine_result = run_scanner(target, "--engine", "lite")
    alias_result = run_scanner(target, "--lite")

    assert alias_result.returncode == engine_result.returncode
    assert json.loads(alias_result.stdout) == json.loads(engine_result.stdout)


def test_auto_does_not_silently_fall_back_to_lite() -> None:
    result = run_scanner(
        FIXTURES / "benign",
        "--engine",
        "auto",
        isolated=True,
        env={"PATH": ""},
    )
    payload = parse_json_output(result)

    assert result.returncode == 69
    assert_payload_shape(payload)
    assert payload["complete"] is False
    assert payload["status"] == "failed"
    assert payload["engine"] in {"auto", "unavailable"}
    assert payload["errors"]
    assert payload["verdict"] not in {"no-findings", "heuristic-findings"}


def test_json_output_is_byte_for_byte_deterministic() -> None:
    target = FIXTURES / "malicious-vscode"
    first = run_scanner(target, "--engine", "lite")
    second = run_scanner(target, "--engine", "lite")

    assert first.returncode == second.returncode
    assert first.stdout == second.stdout
    assert first.stderr == second.stderr


@pytest.mark.canonical
def test_canonical_json_output_is_byte_for_byte_deterministic(canonical_engine: str) -> None:
    target = FIXTURES / "malicious-vscode"
    first = run_scanner(target, "--engine", canonical_engine)
    second = run_scanner(target, "--engine", canonical_engine)

    assert first.returncode == second.returncode == 2
    assert first.stdout == second.stdout
    assert first.stderr == second.stderr


@pytest.mark.parametrize("value", ["0", "-1", "not-a-number"])
def test_max_size_rejects_invalid_values(value: str) -> None:
    result = run_scanner(FIXTURES / "benign", "--engine", "lite", "--max-size", value)

    assert result.returncode != 0


def test_missing_target_is_a_structured_usage_failure(tmp_path: Path) -> None:
    result = run_scanner(tmp_path / "missing", "--engine", "lite")
    payload = parse_json_output(result)

    assert result.returncode == 64
    assert_payload_shape(payload)
    assert payload["complete"] is False
    assert payload["status"] == "failed"
    assert payload["errors"]


def test_missing_ignore_configuration_is_not_treated_as_empty(tmp_path: Path) -> None:
    result = run_scanner(
        FIXTURES / "benign",
        "--engine",
        "lite",
        "--ignore-config",
        str(tmp_path / "missing-ignore.txt"),
    )
    payload = parse_json_output(result)

    assert result.returncode == 64
    assert payload["complete"] is False
    assert payload["status"] == "failed"
    assert payload["errors"]


def test_missing_canonical_rules_are_not_treated_as_no_findings(tmp_path: Path) -> None:
    result = run_scanner(
        FIXTURES / "benign",
        "--engine",
        "auto",
        "--rules",
        str(tmp_path / "missing-rules"),
        isolated=True,
        env={"PATH": ""},
    )
    payload = parse_json_output(result)

    assert result.returncode == 64
    assert payload["complete"] is False
    assert payload["status"] == "failed"
    assert payload["errors"]
