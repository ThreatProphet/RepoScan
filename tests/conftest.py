from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCANNER = REPO_ROOT / "tools" / "scan_task.py"
WRAPPER = REPO_ROOT / "tools" / "scan_task.sh"
FIXTURES = REPO_ROOT / "tests" / "fixtures"
RULES = REPO_ROOT / "rules"


def has_yara_python() -> bool:
    return importlib.util.find_spec("yara") is not None


def has_yara_cli() -> bool:
    return shutil.which("yara") is not None


def run_command(
    command: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout: float = 10,
) -> subprocess.CompletedProcess[str]:
    process_env = os.environ.copy()
    process_env.update({"NO_COLOR": "1", "PYTHONDONTWRITEBYTECODE": "1"})
    if env:
        process_env.update(env)
    return subprocess.run(
        command,
        cwd=REPO_ROOT,
        env=process_env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout,
    )


def run_scanner(
    target: Path | str,
    *arguments: str,
    isolated: bool = False,
    env: dict[str, str] | None = None,
    timeout: float = 10,
) -> subprocess.CompletedProcess[str]:
    python_arguments = [sys.executable]
    if isolated:
        python_arguments.append("-S")
    return run_command(
        [*python_arguments, str(SCANNER), "--json", *arguments, str(target)],
        env=env,
        timeout=timeout,
    )


def parse_json_output(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        pytest.fail(
            f"scanner did not emit valid JSON (exit {result.returncode})\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}\nerror: {exc}"
        )
    assert isinstance(payload, dict)
    return payload


def assert_payload_shape(payload: dict[str, Any]) -> None:
    assert set(payload) >= {"target", "engine", "complete", "status", "verdict", "findings", "errors", "stats"}
    assert payload["status"] in {"complete", "partial", "failed"}
    assert isinstance(payload["complete"], bool)
    assert isinstance(payload["findings"], list)
    assert isinstance(payload["errors"], list)
    assert isinstance(payload["stats"], dict)


@pytest.fixture
def canonical_engine() -> str:
    if has_yara_python():
        return "yara-python"
    if has_yara_cli():
        return "yara-cli"
    pytest.skip("no canonical YARA engine is installed")
