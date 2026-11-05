from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest
from conftest import (
    FIXTURES,
    SCANNER,
    has_yara_cli,
    has_yara_python,
    parse_json_output,
    run_command,
    run_scanner,
)
from jsonschema import Draft202012Validator

from reposcan import scanner
from reposcan.reporting import escape_markdown

SCHEMA = json.loads(files("reposcan").joinpath("schemas/result.schema.json").read_text(encoding="utf-8"))
VALIDATOR = Draft202012Validator(SCHEMA)


def require_engine(engine: str) -> None:
    if engine == "yara-python" and not has_yara_python():
        pytest.skip("yara-python is not installed")
    if engine == "yara-cli" and not has_yara_cli():
        pytest.skip("YARA CLI is not installed")


@pytest.mark.parametrize("engine", ["lite", "yara-python", "yara-cli"])
def test_result_schema_accepts_complete_and_incomplete_scans(tmp_path: Path, engine: str) -> None:
    require_engine(engine)
    Draft202012Validator.check_schema(SCHEMA)
    (tmp_path / "a.txt").write_text("ordinary inert text\n", encoding="utf-8")
    (tmp_path / "b.txt").write_text("ordinary inert text\n", encoding="utf-8")
    complete = parse_json_output(run_scanner(FIXTURES / "web3market-entry", "--engine", engine))
    partial = parse_json_output(run_scanner(tmp_path, "--engine", engine, "--max-files", "1"))
    failed = parse_json_output(run_scanner(tmp_path / "missing", "--engine", engine))
    assert complete["status"] == "complete"
    assert partial["status"] == "partial"
    assert failed["status"] == "failed"
    for payload in (complete, partial, failed):
        VALIDATOR.validate(payload)


def test_unavailable_engine_and_format_conflict_have_valid_failure_results() -> None:
    unavailable = run_scanner(FIXTURES / "benign", "--engine", "auto", isolated=True, env={"PATH": ""})
    conflict = run_scanner(FIXTURES / "benign", "--engine", "lite", "--format", "markdown")
    assert unavailable.returncode == 69
    assert conflict.returncode == 64
    for result in (unavailable, conflict):
        payload = parse_json_output(result)
        assert payload["complete"] is False
        VALIDATOR.validate(payload)


@pytest.mark.canonical
def test_compact_tagged_rule_preserves_metadata_and_byte_evidence(tmp_path: Path, canonical_engine: str) -> None:
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "compact.yar").write_text(
        'rule Compact : tagged { meta: severity="critical" confidence="high" category="behavior" '
        'description="Inert marker" reports="TP-2026-018" '
        'strings: $marker="evidence-marker" condition: $marker }\n',
        encoding="utf-8",
    )
    content = "// é\nconst marker = 'evidence-marker';\n".encode()
    target = tmp_path / "sample.js"
    target.write_bytes(content)
    result = run_scanner(target, "--engine", canonical_engine, "--rules", str(rules))
    payload = parse_json_output(result)
    assert result.returncode == 2
    assert payload["verdict"] == "high-risk"
    assert len(payload["findings"]) == 1
    finding = payload["findings"][0]
    assert finding["reports"] == ["TP-2026-018"]
    assert finding["severity"] == "critical"
    assert finding["confidence"] == "high"
    assert finding["sha256"] == hashlib.sha256(content).hexdigest()
    assert finding["evidence"] == [{
        "identifier": "$marker", "offset": content.index(b"evidence-marker"), "length": 15, "line": 2,
    }]
    assert len(finding["finding_id"]) == 64
    VALIDATOR.validate(payload)


@pytest.mark.parity
def test_global_rules_have_the_same_namespace_scope_in_both_adapters(tmp_path: Path) -> None:
    require_engine("yara-python")
    require_engine("yara-cli")
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "a.yar").write_text(
        'global rule Gate { meta: severity="low" condition: false }\n', encoding="utf-8"
    )
    (rules / "b.yar").write_text(
        'rule Marker { meta: severity="critical" confidence="high" '
        'strings: $m="inert-marker" condition: $m }\n', encoding="utf-8"
    )
    target = tmp_path / "sample.txt"
    target.write_bytes(b"inert-marker\n")
    payloads = []
    for engine in ("yara-python", "yara-cli"):
        result = run_scanner(target, "--engine", engine, "--rules", str(rules))
        payload = parse_json_output(result)
        assert result.returncode == 2
        assert payload["complete"] is True
        assert [finding["rule"] for finding in payload["findings"]] == ["Marker"]
        payloads.append(payload)
    assert payloads[0]["findings"][0]["finding_id"] == payloads[1]["findings"][0]["finding_id"]
    assert payloads[0]["rule_pack"] == payloads[1]["rule_pack"]


@pytest.mark.parity
def test_repeated_evidence_is_bounded_identically_in_both_adapters(tmp_path: Path) -> None:
    require_engine("yara-python")
    require_engine("yara-cli")
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "marker.yar").write_text(
        'rule Marker { meta: severity="low" strings: $m="inert-marker" condition: $m }\n',
        encoding="utf-8",
    )
    target = tmp_path / "sample.txt"
    target.write_bytes(b"inert-marker\n" * 40)
    findings = []
    for engine in ("yara-python", "yara-cli"):
        payload = parse_json_output(run_scanner(target, "--engine", engine, "--rules", str(rules)))
        assert payload["complete"] is True
        finding = payload["findings"][0]
        assert len(finding["evidence"]) == 32
        assert finding["evidence_truncated"] is True
        findings.append(finding)
        VALIDATOR.validate(payload)
    assert findings[0]["evidence"] == findings[1]["evidence"]
    assert findings[0]["finding_id"] == findings[1]["finding_id"]


@pytest.mark.canonical
def test_ordinary_dynamic_code_remains_a_warning(canonical_engine: str, tmp_path: Path) -> None:
    target = tmp_path / "local.js"
    target.write_text(
        "const local = new Function('require', 'return 1'); const mode = process.env.MODE;\n",
        encoding="utf-8",
    )
    result = run_scanner(target, "--engine", canonical_engine)
    payload = parse_json_output(result)
    assert result.returncode == 1
    assert payload["verdict"] == "review-needed"
    dynamic = next(f for f in payload["findings"] if f["rule"] == "TP_DevelTask_Node_Remote_Fetch_Dynamic_Execute")
    assert dynamic["confidence"] == "medium"
    assert "inspect input flow" in dynamic["description"]


@pytest.mark.canonical
def test_documentation_retains_warnings_without_a_high_risk_verdict(canonical_engine: str, tmp_path: Path) -> None:
    source = FIXTURES / "malicious-vscode" / ".vscode" / "tasks.json"
    target = tmp_path / "example.md"
    target.write_bytes(b"An inert configuration example:\n```json\n" + source.read_bytes() + b"\n```\n")
    result = run_scanner(target, "--engine", canonical_engine)
    payload = parse_json_output(result)
    assert result.returncode == 1
    assert payload["verdict"] == "review-needed"
    assert payload["findings"]
    assert all(finding["confidence"] == "low" for finding in payload["findings"])
    assert all(any("documentation" in note for note in f["prerequisites"]) for f in payload["findings"])


def test_formats_preserve_findings_without_exposing_source_content(tmp_path: Path) -> None:
    target = tmp_path / "unsafe-[name]|<svg>.js"
    target.write_bytes(b"// private-source-marker-83920\neval('inert text');\n")
    json_result = run_scanner(target, "--engine", "lite")
    payload = parse_json_output(json_result)
    outputs = {}
    for format_name in ("text", "markdown"):
        result = run_command([
            sys.executable, str(SCANNER), "--engine", "lite", "--color", "never",
            "--format", format_name, str(target),
        ])
        assert result.returncode == json_result.returncode == 1
        outputs[format_name] = result.stdout
    for finding in payload["findings"]:
        assert finding["rule"] in outputs["text"]
        assert escape_markdown(finding["rule"]) in outputs["markdown"]
    assert "<svg>" not in outputs["markdown"]
    assert escape_markdown(target.name) in outputs["markdown"]
    assert "private-source-marker-83920" not in json_result.stdout + "".join(outputs.values())
    assert "it is not a YARA scan" in outputs["markdown"]


def test_zero_scanned_files_and_skip_cap_are_visible(tmp_path: Path) -> None:
    for index in range(130):
        (tmp_path / f"large-{index:03d}.txt").write_bytes(b"inert text too large")
    result = run_scanner(tmp_path, "--engine", "lite", "--max-size", "1")
    payload = parse_json_output(result)
    assert payload["complete"] is True
    assert payload["stats"]["files_scanned"] == 0
    assert payload["stats"]["skipped_oversize"] == 130
    assert len(payload["coverage"]["skipped"]) == 128
    assert payload["coverage"]["skipped_truncated"] is True
    VALIDATOR.validate(payload)
    for format_name in ("text", "markdown"):
        output = run_command([
            sys.executable, str(SCANNER), "--engine", "lite", "--max-size", "1",
            "--format", format_name, str(tmp_path),
        ])
        assert "No file content was scanned." in output.stdout


def test_lite_whitespace_regression_obeys_a_short_matching_budget(tmp_path: Path) -> None:
    target = tmp_path / "padding.txt"
    target.write_bytes(b" " * 8192)
    result = run_scanner(target, "--engine", "lite", "--timeout", "1", timeout=4)
    payload = parse_json_output(result)
    assert result.returncode == 0
    assert payload["complete"] is True
    assert payload["stats"]["files_scanned"] == 1


def test_cli_adapter_caps_combined_subprocess_output(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scanner, "MAX_ENGINE_OUTPUT", 1024)
    with pytest.raises(OSError, match="output exceeded 1024 bytes"):
        scanner.run_yara_cli([
            sys.executable, "-c", "import os; os.write(1, b'x' * 800); os.write(2, b'x' * 800)",
        ], timeout=2)


@pytest.mark.parametrize("swallow_callback_error", [False, True])
def test_native_runtime_warning_cannot_produce_a_complete_file(
    tmp_path: Path, swallow_callback_error: bool,
) -> None:
    target = tmp_path / "inert.txt"
    target.write_bytes(b"ordinary inert data")
    identity = target.stat()
    candidate = scanner.ScannableFile(target, target.name, identity.st_dev, identity.st_ino)
    stats = scanner.ScanStats()

    class WarningEngine:
        def match(self, **kwargs: Any) -> list[object]:
            try:
                kwargs["warnings_callback"](6, "too many matches")
            except RuntimeError:
                if not swallow_callback_error:
                    raise
            return []

    result = scanner.scan_with_yara_python(WarningEngine(), [candidate], 1024, 1024, 2, stats)
    assert stats.files_scanned == 0
    assert result.findings == []
    assert len(result.errors) == 1
    assert result.errors[0].code == "file-scan"
    assert "runtime warning" in result.errors[0].message


@pytest.mark.parametrize(
    ("diagnostic", "complete"),
    [
        ('warning: rule "Marker": too many matches for $m, results for this rule may be incorrect\n', False),
        ('warning: rule "Marker": scanning with string $m is taking a very long time\n', False),
        ('warning: rule "Marker" in /trusted/rules.yar(1): string "$m" may slow down scanning\n', True),
        ("unexpected engine diagnostic\n", False),
    ],
)
def test_cli_runtime_diagnostics_are_not_suppressed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, diagnostic: str, complete: bool,
) -> None:
    target = tmp_path / "inert.txt"
    target.write_bytes(b"ordinary inert data")
    identity = target.stat()
    candidate = scanner.ScannableFile(target, target.name, identity.st_dev, identity.st_ino)
    stats = scanner.ScanStats()

    def fake_cli(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
        assert "-w" not in command
        return subprocess.CompletedProcess(command, 0, "", diagnostic)

    monkeypatch.setattr(scanner, "run_yara_cli", fake_cli)
    result = scanner.scan_with_yara_cli("yara", [], [candidate], 1024, 1024, 2, stats, metadata={})
    assert stats.files_scanned == (1 if complete else 0)
    assert bool(result.errors) is not complete
    if result.errors:
        assert "runtime diagnostic" in result.errors[0].message


@pytest.mark.parametrize("engine", ["yara-python", "yara-cli"])
def test_rule_snapshot_keeps_metadata_hash_and_matching_consistent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], engine: str,
) -> None:
    require_engine(engine)
    rules = tmp_path / "rules"
    rules.mkdir()
    original = rules / "marker.yar"
    captured_source = (
        b'rule Marker { meta: severity="critical" confidence="high" '
        b'strings: $m="captured-marker" condition: $m }\n'
    )
    original.write_bytes(captured_source)
    target = tmp_path / "inert.txt"
    target.write_bytes(b"captured-marker\n")
    read_metadata = scanner.load_rule_metadata
    temporary_paths: list[Path] = []

    def mutate_original_after_capture(paths: list[Path]) -> dict[str, dict[str, Any]]:
        temporary_paths.extend(paths)
        metadata = read_metadata(paths)
        original.write_text('rule Changed { meta: severity="low" condition: false }\n', encoding="utf-8")
        return metadata

    monkeypatch.setattr(scanner, "load_rule_metadata", mutate_original_after_capture)
    monkeypatch.setattr(sys, "argv", [
        str(SCANNER), str(target), "--engine", engine, "--rules", str(rules), "--format", "json",
    ])
    assert scanner.main() == 2
    output = capsys.readouterr()
    assert output.err == ""
    payload = json.loads(output.out)
    assert payload["complete"] is True
    assert [finding["rule"] for finding in payload["findings"]] == ["Marker"]
    assert payload["rule_pack"]["files"] == [{
        "name": "marker.yar", "sha256": hashlib.sha256(captured_source).hexdigest(),
    }]
    assert temporary_paths and all(not path.exists() for path in temporary_paths)


@pytest.mark.parametrize("engine", ["yara-python", "yara-cli"])
def test_rule_snapshot_errors_keep_original_paths_and_deterministic_output(tmp_path: Path, engine: str) -> None:
    require_engine(engine)
    rules = tmp_path / "rules"
    rules.mkdir()
    original = rules / "invalid.yar"
    original.write_text('rule Invalid { meta: severity="low" condition: absent_identifier }\n', encoding="utf-8")
    results = [run_scanner(FIXTURES / "benign", "--engine", engine, "--rules", str(rules)) for _ in range(2)]
    assert all(result.returncode == 70 for result in results)
    assert results[0].stdout == results[1].stdout
    assert str(original) in results[0].stdout
    assert "reposcan-rules-" not in results[0].stdout
