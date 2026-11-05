#!/usr/bin/env python3
"""Verify an exact RepoScan wheel in a fresh, offline installation.

The target fixture is copied and scanned as file bytes. It is never installed,
opened in an IDE, or executed. All child processes run outside the source tree.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from email.parser import BytesParser
from pathlib import Path
from typing import Any


class VerificationError(RuntimeError):
    """A required installed-distribution check failed."""


RESOURCE_PROBE = """
import importlib.metadata
import importlib.resources
import importlib.util
import json
import pathlib
import sys

import reposcan

source = pathlib.Path(sys.argv[1]).resolve()
prefix = pathlib.Path(sys.prefix).resolve()
origin = pathlib.Path(reposcan.__file__).resolve()
assert prefix != pathlib.Path(sys.base_prefix).resolve(), 'not running in a virtual environment'
assert origin.is_relative_to(prefix), 'module did not come from the fresh virtual environment'
assert not origin.is_relative_to(source), 'module came from the source checkout'
assert importlib.util.find_spec('yara') is None, 'unexpected yara-python in the fresh environment'
package = importlib.resources.files('reposcan')
names = (
    'rules/developer_task_malware.yar',
    'rules/web3market.yar',
    'config/scan_ignore.txt',
    'schemas/result.schema.json',
)
for name in names:
    resource = package.joinpath(*name.split('/'))
    assert resource.is_file(), 'missing packaged resource: ' + name
    content = resource.read_text(encoding='utf-8')
    assert content.strip(), 'empty packaged resource: ' + name
    if name.endswith('.json'):
        assert isinstance(json.loads(content), dict), 'schema is not a JSON object'
print(json.dumps({
    'origin': str(origin),
    'version': reposcan.__version__,
    'distribution_version': importlib.metadata.version('threatprophet-reposcan'),
    'resources': names,
}))
"""


def isolated_environment(path: str) -> dict[str, str]:
    """Keep only OS/locale settings; do not inherit Python, pip, or loader overrides."""
    allowed = ("SYSTEMROOT", "WINDIR", "COMSPEC", "LANG", "LC_ALL", "LC_CTYPE", "TZ")
    environment = {key: os.environ[key] for key in allowed if key in os.environ}
    environment.update(
        {
            "PATH": path,
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_NO_INDEX": "1",
            "PIP_NO_INPUT": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "NO_COLOR": "1",
        }
    )
    return environment


def run(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    expected_exit: int = 0,
    timeout: int = 30,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise VerificationError(f"could not complete {command[0]!r}: {error}") from error
    if result.returncode != expected_exit:
        detail = "\n".join(part for part in (result.stdout.strip(), result.stderr.strip()) if part)
        raise VerificationError(
            f"expected exit {expected_exit}, got {result.returncode} from {command[0]!r}\n{detail[:6000]}"
        )
    return result


def json_object(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise VerificationError(f"invalid JSON output: {error}\n{result.stdout[:2000]}") from error
    if not isinstance(value, dict):
        raise VerificationError("expected a JSON object")
    return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def wheel_version(wheel: Path) -> str:
    try:
        with zipfile.ZipFile(wheel) as archive:
            names = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
            require(len(names) == 1, "wheel must contain exactly one distribution METADATA file")
            metadata = BytesParser().parsebytes(archive.read(names[0]))
            require(metadata.get("License-Expression") == "MIT", "wheel must declare the MIT license")
            require(metadata.get_all("License-File") == ["LICENSE"], "wheel must declare its LICENSE file")
            license_path = names[0].removesuffix("METADATA") + "licenses/LICENSE"
            expected_license = (Path(__file__).resolve().parents[1] / "LICENSE").read_bytes()
            require(archive.read(license_path) == expected_license, "wheel license differs from the source license")
    except (OSError, zipfile.BadZipFile, KeyError) as error:
        raise VerificationError(f"cannot read wheel metadata: {error}") from error
    name = str(metadata.get("Name", ""))
    require(
        re.sub(r"[-_.]+", "-", name).lower() == "threatprophet-reposcan",
        "wheel distribution is not threatprophet-reposcan",
    )
    version = str(metadata.get("Version", "")).strip()
    require(bool(version), "wheel has no distribution version")
    return version


def assert_complete(payload: dict[str, Any], verdict: str, version: str, engine: str = "lite") -> None:
    require(payload.get("complete") is True, "scan was not complete")
    require(payload.get("status") == "complete", "unexpected scan status")
    require(payload.get("verdict") == verdict, f"unexpected verdict: {payload.get('verdict')!r}")
    require(payload.get("engine") == engine, f"scan did not use the expected {engine} engine")
    require(payload.get("errors") == [], "complete scan contains errors")
    tool = payload.get("tool")
    require(isinstance(tool, dict), "scan has no tool metadata object")
    require(tool.get("version") == version, "scan reports a different tool version")
    statistics = payload.get("stats")
    require(isinstance(statistics, dict), "scan has no statistics object")
    scanned = statistics.get("files_scanned")
    require(isinstance(scanned, int) and scanned > 0, "scan processed no files")
    require(
        statistics.get("files_scanned") == statistics.get("files_selected"),
        "scan did not process the full selected set",
    )


def verify(wheel: Path) -> None:
    source_root = Path(__file__).resolve().parents[1]
    fixture = source_root / "tests" / "fixtures" / "malicious-vscode"
    require(fixture.is_dir(), f"missing inert fixture directory: {fixture}")
    version = wheel_version(wheel)

    with tempfile.TemporaryDirectory(prefix="reposcan-wheel-") as temporary:
        temporary_root = Path(temporary).resolve()
        require(not temporary_root.is_relative_to(source_root), "temporary directory is inside the source checkout")
        working = temporary_root / "run"
        working.mkdir()
        environment_path = temporary_root / "venv"
        environment = isolated_environment(os.defpath)

        print("[1/6] Create a fresh virtual environment", flush=True)
        run(
            [sys.executable, "-I", "-m", "venv", str(environment_path)],
            cwd=working,
            environment=environment,
            timeout=60,
        )
        binary_directory = environment_path / ("Scripts" if os.name == "nt" else "bin")
        python = binary_directory / ("python.exe" if os.name == "nt" else "python")
        scanner = binary_directory / ("reposcan.exe" if os.name == "nt" else "reposcan")
        environment = isolated_environment(str(binary_directory))

        print("[2/6] Install the exact wheel without indexes or dependencies", flush=True)
        run(
            [str(python), "-I", "-m", "pip", "install", "--no-index", "--no-deps", str(wheel)],
            cwd=working,
            environment=environment,
            timeout=60,
        )
        require(scanner.is_file(), "installed reposcan console entry point is missing")

        print("[3/6] Verify installed origin, version, and packaged rules/config/schema", flush=True)
        probe = json_object(
            run(
                [str(python), "-I", "-c", RESOURCE_PROBE, str(source_root)],
                cwd=working,
                environment=environment,
            )
        )
        require(probe.get("version") == version, "package version differs from wheel metadata")
        require(probe.get("distribution_version") == version, "installed distribution version differs from wheel")
        version_output = run([str(scanner), "--version"], cwd=working, environment=environment).stdout
        require(
            re.search(r"(?<![\w.])" + re.escape(version) + r"(?![\w.])", version_output) is not None,
            "console --version does not report the installed wheel version",
        )

        benign = working / "benign.txt"
        benign.write_text("Ordinary local text for an installed-distribution check.\n", encoding="utf-8")
        print("[4/6] Scan benign text with the installed CLI", flush=True)
        benign_payload = json_object(
            run(
                [str(scanner), str(benign), "--engine", "lite", "--format", "json"],
                cwd=working,
                environment=environment,
            )
        )
        assert_complete(benign_payload, "no-findings", version)
        require(benign_payload.get("findings") == [], "benign text unexpectedly produced findings")

        positive = working / "positive"
        shutil.copytree(fixture, positive, symlinks=True)
        print("[5/6] Scan the copied inert VS Code fixture with the installed CLI", flush=True)
        positive_payload = json_object(
            run(
                [str(scanner), str(positive), "--engine", "lite", "--format", "json"],
                cwd=working,
                environment=environment,
                expected_exit=1,
            )
        )
        assert_complete(positive_payload, "heuristic-findings", version)
        findings = positive_payload.get("findings")
        require(isinstance(findings, list), "positive scan has no findings array")
        identifiers = [str(finding.get("rule", "")) for finding in findings if isinstance(finding, dict)]
        require(any(identifier.startswith("HEUR_") for identifier in identifiers), "Lite findings are missing")
        require(
            any(identifier.startswith("REVIEW_") for identifier in identifiers),
            "common review findings are missing",
        )
        require(
            not any(identifier.startswith("TP_DevelTask_") for identifier in identifiers),
            "Lite mode unexpectedly emitted a canonical rule identifier",
        )

        print("[6/6] Verify canonical-engine absence is an explicit failure", flush=True)
        unavailable = json_object(
            run(
                [str(scanner), str(benign), "--engine", "auto", "--format", "json"],
                cwd=working,
                environment=isolated_environment(""),
                expected_exit=69,
            )
        )
        require(unavailable.get("complete") is False, "missing engine was reported as a complete scan")
        require(unavailable.get("status") == "failed", "missing engine did not produce failed status")
        require(unavailable.get("verdict") == "not-scanned", "missing engine produced a detection verdict")
        errors = unavailable.get("errors")
        require(isinstance(errors, list), "missing engine has no structured errors")
        require(
            any(isinstance(error, dict) and error.get("code") == "engine-unavailable" for error in errors),
            "missing engine did not produce an engine-unavailable error",
        )

    print(f"PASS: RepoScan {version} wheel installs and works outside the source checkout.", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path, help="Exact RepoScan .whl artifact to verify")
    arguments = parser.parse_args()
    try:
        wheel = arguments.wheel.expanduser().resolve(strict=True)
        require(wheel.is_file() and wheel.suffix.lower() == ".whl", "wheel argument must be an existing .whl file")
        verify(wheel)
    except (VerificationError, OSError) as error:
        print(f"FAIL: {error}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
