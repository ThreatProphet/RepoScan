from __future__ import annotations

import io
import re
import sys
from contextlib import redirect_stdout
from dataclasses import replace
from pathlib import Path

import pytest
from conftest import FIXTURES, SCANNER, run_command

from reposcan import scanner
from reposcan.models import Evidence, Finding

SGR = re.compile(r"\x1b\[[0-9;]*m")


def finding() -> Finding:
    return Finding(
        rule="REVIEW_Example",
        severity="high",
        path="src/example.js",
        source="static-review",
        description="An encoded destination warrants review of its use.",
        category="obfuscation",
        confidence="medium",
        trigger="Project startup",
        prerequisites=("Confirm that the surrounding code calls this function.",),
        reports=("TP-2026-018",),
        evidence=(Evidence("$destination", offset=325, length=26, line=7),),
    )


def render(
    findings: list[Finding],
    *,
    colored: bool = False,
    width: int = 100,
    errors: list[scanner.ScanError] | None = None,
    verdict: str = "review-needed",
    exit_code: int = 1,
    status: str = "complete",
    stats: scanner.ScanStats | None = None,
    target: Path = Path("/review/received-project"),
) -> str:
    output = io.StringIO()
    with redirect_stdout(output):
        scanner.print_text(
            findings,
            errors or [],
            verdict,
            exit_code,
            "yara-python",
            target,
            status == "complete",
            status,
            stats or scanner.ScanStats(files_selected=1, files_scanned=1),
            scanner.Colors(colored),
            width=width,
        )
    return output.getvalue()


@pytest.mark.parametrize("tty", [False, True])
@pytest.mark.parametrize("no_color", [None, "", "1"])
def test_color_mode_precedence(monkeypatch: pytest.MonkeyPatch, tty: bool, no_color: str | None) -> None:
    output = io.StringIO()
    monkeypatch.setattr(output, "isatty", lambda: tty)
    monkeypatch.setattr(scanner.sys, "stdout", output)
    if no_color is None:
        monkeypatch.delenv("NO_COLOR", raising=False)
    else:
        monkeypatch.setenv("NO_COLOR", no_color)

    assert scanner.color_enabled("always") is True
    assert scanner.color_enabled("never") is False
    assert scanner.color_enabled("auto") is (tty and no_color is None)


def test_color_only_changes_styling_and_each_finding_keeps_its_severity() -> None:
    first = finding()
    findings = [
        first,
        replace(first, rule="REVIEW_Second", path="src/second.js"),
        replace(first, rule="REVIEW_Third", severity="low", path="src/third.js"),
    ]
    plain = render(findings)
    colored = render(findings, colored=True)

    assert "\x1b[" in colored
    assert "\x1b" not in plain
    assert SGR.sub("", colored) == plain
    assert plain.count("[HIGH]") == 2
    assert plain.count("[LOW]") == 1
    for item in findings:
        assert item.rule in plain
        assert f"{item.path}:7" in plain
    assert re.search(r"confidence\s*:?\s*medium", plain, re.IGNORECASE)
    assert plain.index("src/example.js:7") < plain.index(first.description) < plain.index(first.rule)


def test_untrusted_terminal_fields_are_escaped_before_styling_and_wrapping() -> None:
    hostile = "\x1b[2J\x1b]8;;https://example.invalid\x07CLICK\x1b]8;;\x07\r\n\t\u202e\x9b"
    item = replace(
        finding(),
        rule="rule-field" + hostile,
        path="path-field" + hostile,
        source="source-field" + hostile,
        description="reason-field" + hostile,
        category="category-field" + hostile,
        confidence="confidence-field" + hostile,
        trigger="trigger-field" + hostile,
        prerequisites=("prerequisite-field" + hostile,),
        reports=("report-field" + hostile,),
        evidence=(Evidence("evidence-field" + hostile, offset=1, length=2, line=3),),
    )
    output = render(
        [item],
        colored=True,
        width=240,
        target=Path("/target-field" + hostile),
        status="partial",
        verdict="scan-incomplete",
        exit_code=70,
        errors=[scanner.ScanError("error-code" + hostile, "error-message" + hostile, "error-path" + hostile)],
    )
    plain = SGR.sub("", output)

    assert all(character == "\n" or character.isprintable() for character in plain)
    assert r"\x1b[2J" in plain
    assert r"\x1b]8;;https://example.invalid" in plain
    assert r"\r\n\t\u202e\x9b" in plain
    for marker in (
        "rule-field", "path-field", "source-field", "reason-field", "category-field",
        "confidence-field", "trigger-field", "prerequisite-field", "report-field",
        "evidence-field", "target-field", "error-code", "error-message", "error-path",
    ):
        assert marker in plain


@pytest.mark.parametrize("width", [40, 80, 100])
def test_wrapping_preserves_details_and_fits_wide_and_combining_characters(width: int) -> None:
    path = "src/" + "界" * 18 + "/cafe\u0301.js"
    token = "$" + "long_identifier_" * 10
    item = replace(finding(), path=path, evidence=(Evidence(token, offset=325, length=26, line=7),))
    output = SGR.sub("", render([item], colored=True, width=width))

    # These fixture characters have known cell widths: 界 is two, U+0301 is zero.
    # The assertion does not use the renderer's own width calculation.
    for line in output.splitlines():
        assert len(line.replace("界", "xx").replace("\u0301", "")) <= width, line
    flattened = re.sub(r"\s+", "", output)
    for detail in (path, token, item.description, item.trigger, *item.prerequisites):
        assert re.sub(r"\s+", "", detail) in flattened
    assert "destination" in output
    assert "Exit code: 1" in output


def test_evidence_cap_is_visible_without_hiding_confidence_or_recorded_locations() -> None:
    evidence = tuple(Evidence(f"$marker_{index}", offset=index * 10, length=2, line=index + 1) for index in range(6))
    output = render([replace(finding(), evidence=evidence, evidence_truncated=True)])

    for index in range(4):
        assert f"$marker_{index}" in output
    assert "$marker_4" not in output
    assert "$marker_5" not in output
    assert "JSON" in output and "Markdown" in output
    assert "capped" in output.lower() or "truncated" in output.lower()
    assert re.search(r"confidence\s*:?\s*medium", output, re.IGNORECASE)
    assert "obfuscation" in output


@pytest.mark.parametrize("path", ["  leading.js", "trailing.js  ", "src/" + " " * 40 + "file.js"])
def test_location_wrapping_preserves_significant_filename_spaces(path: str) -> None:
    output = render([replace(finding(), path=path, evidence=())], width=40)
    location_lines = output.split("  Location: ", 1)[1].split("\n  Why:", 1)[0].splitlines()
    displayed_path = location_lines[0] + "".join(line[12:] for line in location_lines[1:])

    assert displayed_path == path


def test_target_and_error_paths_keep_edge_spaces() -> None:
    output = render(
        [],
        target=Path("/review/trailing  "),
        status="failed",
        errors=[scanner.ScanError("file-read", "Read failed", "  leading.js  ")],
    )

    assert "Target:   /review/trailing  \n" in output
    assert "  Location:   leading.js  \n" in output


@pytest.mark.parametrize(
    ("status", "verdict", "exit_code"),
    [("partial", "scan-incomplete", 70), ("failed", "not-scanned", 69)],
)
def test_incomplete_results_keep_errors_coverage_and_actual_exit(status: str, verdict: str, exit_code: int) -> None:
    output = render(
        [finding()] if status == "partial" else [],
        colored=True,
        errors=[scanner.ScanError("file-read", "Read failed", "src/missing.js")],
        stats=scanner.ScanStats(files_selected=2, files_scanned=1 if status == "partial" else 0),
        status=status,
        verdict=verdict,
        exit_code=exit_code,
    )
    plain = SGR.sub("", output)

    assert status in plain and verdict in plain
    assert "file-read" in plain and "Read failed" in plain and "src/missing.js" in plain
    assert ("1/2" if status == "partial" else "0/2") in plain
    assert f"Exit code: {exit_code}" in plain
    assert scanner.Colors(True).green not in output


def test_empty_scope_is_not_styled_as_a_successful_clean_scan() -> None:
    output = render([], colored=True, verdict="no-findings", exit_code=0, stats=scanner.ScanStats())
    plain = SGR.sub("", output)

    assert "No file content was scanned." in plain
    assert "0/0" in plain
    assert "Exit code: 0" in plain
    assert scanner.Colors(True).green not in output


@pytest.mark.parametrize("format_name", ["json", "markdown"])
def test_width_and_forced_color_do_not_change_machine_formats(format_name: str) -> None:
    command = [sys.executable, str(SCANNER), "--engine", "lite", "--format", format_name]
    target = str(FIXTURES / "web3market-entry")
    baseline = run_command([*command, "--color", "never", target])
    styled = run_command([*command, "--color", "always", "--width", "40", target])

    assert styled.returncode == baseline.returncode == 1
    assert styled.stdout == baseline.stdout
    assert "\x1b" not in styled.stdout


@pytest.mark.parametrize("width", ["0", "39", "241", "not-a-number"])
def test_invalid_text_width_is_an_explicit_usage_failure(width: str) -> None:
    result = run_command([
        sys.executable, str(SCANNER), "--engine", "lite", "--width", width, str(FIXTURES / "benign"),
    ])

    assert result.returncode == 64
    assert "width" in result.stderr
