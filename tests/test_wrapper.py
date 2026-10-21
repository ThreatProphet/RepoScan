from __future__ import annotations

import sys
from pathlib import Path

import pytest
from conftest import FIXTURES, SCANNER, WRAPPER, parse_json_output, run_command


def scanner_command(target: Path, *arguments: str) -> list[str]:
    return [sys.executable, str(SCANNER), "--json", *arguments, str(target)]


def wrapper_command(target: Path, *arguments: str) -> list[str]:
    return ["bash", str(WRAPPER), "--json", *arguments, str(target)]


@pytest.mark.parametrize("fixture_name", ["benign", "suspicious-pipe"])
def test_wrapper_preserves_stdout_stderr_and_exit_code(fixture_name: str) -> None:
    target = FIXTURES / fixture_name
    direct = run_command(scanner_command(target, "--engine", "lite"))
    wrapped = run_command(wrapper_command(target, "--engine", "lite"))

    assert wrapped.returncode == direct.returncode
    assert wrapped.stdout == direct.stdout
    assert wrapped.stderr == direct.stderr


@pytest.mark.posix
def test_wrapper_does_not_interpret_hostile_filename(tmp_path: Path) -> None:
    marker = tmp_path / "must-not-exist"
    hostile = tmp_path / f"$(touch {marker.name}); leading - name.txt"
    hostile.write_text("ordinary inert text\n", encoding="utf-8")

    result = run_command(wrapper_command(hostile, "--engine", "lite"))
    payload = parse_json_output(result)

    assert result.returncode == 0
    assert payload["complete"] is True
    assert Path(payload["target"]) == hostile.resolve()
    assert not marker.exists()


def test_wrapper_help_is_python_cli_help() -> None:
    result = run_command(["bash", str(WRAPPER), "--help"])

    assert result.returncode == 0
    assert "--engine" in result.stdout
    assert "--max-files" in result.stdout
