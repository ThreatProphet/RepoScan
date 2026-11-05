#!/usr/bin/env python3
"""Verify an exact wheel through pipx, native YARA scans, and uninstall.

All pipx state lives in a fresh temporary directory outside the checkout.
Only the trusted scanner and its declared dependencies are installed. The
copied positive fixture is scanned as data and is never executed.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
from pathlib import Path

from verify_wheel import (
    VerificationError,
    assert_complete,
    isolated_environment,
    json_object,
    require,
    run,
    wheel_version,
)

INSTALLED_PROBE = """
import importlib.metadata
import importlib.resources
import json
import pathlib
import sys

import reposcan
import yara

source = pathlib.Path(sys.argv[1]).resolve()
prefix = pathlib.Path(sys.prefix).resolve()
origin = pathlib.Path(reposcan.__file__).resolve()
assert prefix != pathlib.Path(sys.base_prefix).resolve(), 'not a virtual environment'
assert origin.is_relative_to(prefix), 'scanner did not come from its application environment'
assert not origin.is_relative_to(source), 'scanner came from the source checkout'
assert pathlib.Path(yara.__file__).resolve().is_relative_to(prefix), 'YARA came from another environment'
distribution = importlib.metadata.distribution('threatprophet-reposcan')
assert distribution.metadata['License-Expression'] == 'MIT', 'installed MIT metadata missing'
package = importlib.resources.files('reposcan')
for name in ('rules/developer_task_malware.yar', 'rules/web3market.yar',
             'config/scan_ignore.txt', 'schemas/result.schema.json'):
    assert package.joinpath(*name.split('/')).is_file(), 'missing resource: ' + name
print(json.dumps({'origin': str(origin), 'version': reposcan.__version__,
                 'distribution_version': distribution.version, 'yara_version': yara.__version__}))
"""


def verify(wheel: Path, wheelhouse: Path | None) -> None:
    require(sys.platform.startswith("linux"), "this installation gate currently supports Linux")
    source = Path(__file__).resolve().parents[1]
    fixture = source / "tests" / "fixtures" / "web3market-entry"
    require(fixture.is_dir(), f"missing inert fixture: {fixture}")
    version = wheel_version(wheel)

    with tempfile.TemporaryDirectory(prefix="reposcan-install-") as directory:
        temporary = Path(directory).resolve()
        require(not temporary.is_relative_to(source), "temporary state is inside the checkout")
        working = temporary / "run"
        working.mkdir()
        binary_directory = temporary / "bin"
        application_home = temporary / "pipx"
        environment = isolated_environment(os.defpath)
        environment.update(
            {
                "PIPX_HOME": str(application_home),
                "PIPX_BIN_DIR": str(binary_directory),
                "PIPX_MAN_DIR": str(temporary / "man"),
                "PIPX_COMPLETION_DIR": str(temporary / "completions"),
                "PIPX_SHARED_LIBS": str(temporary / "shared"),
                "PIPX_DEFAULT_PYTHON": sys.executable,
                "PIPX_DEFAULT_BACKEND": "pip",
                "XDG_DATA_HOME": str(temporary / "data"),
                "XDG_STATE_HOME": str(temporary / "state"),
                "XDG_CACHE_HOME": str(temporary / "cache"),
                "XDG_CONFIG_HOME": str(temporary / "config"),
                "PIP_CACHE_DIR": str(temporary / "cache"),
                "PIP_ONLY_BINARY": ":all:",
            }
        )
        if wheelhouse is None:
            environment.pop("PIP_NO_INDEX", None)
        else:
            environment["PIP_FIND_LINKS"] = wheelhouse.as_uri()

        pipx = [sys.executable, "-I", "-m", "pipx"]
        print("[1/6] Check pipx and exact wheel identity/license", flush=True)
        run([*pipx, "--version"], cwd=working, environment=environment)

        print("[2/6] Install the exact wheel with YARA into fresh pipx state", flush=True)
        requirement = f"threatprophet-reposcan[yara] @ {wheel.as_uri()}"
        run(
            [*pipx, "install", "--python", sys.executable, requirement],
            cwd=working,
            environment=environment,
            timeout=240,
        )
        scanner = binary_directory / "reposcan"
        require(scanner.is_file(), "pipx did not expose the reposcan command")
        installed_scanner = scanner.resolve(strict=True)
        require(
            installed_scanner.is_relative_to(application_home / "venvs"),
            "exposed command belongs to another environment",
        )
        installed_python = installed_scanner.parent / "python"

        print("[3/6] Verify installed scanner, native engine, metadata, and resources", flush=True)
        probe = json_object(
            run(
                [str(installed_python), "-I", "-c", INSTALLED_PROBE, str(source)],
                cwd=working,
                environment=environment,
            )
        )
        require(probe.get("version") == version, "scanner version differs from the wheel")
        require(probe.get("distribution_version") == version, "distribution version differs from the wheel")
        require(bool(probe.get("yara_version")), "native YARA version was not reported")
        require(
            run([str(scanner), "--version"], cwd=working, environment=environment).stdout.strip()
            == f"RepoScan {version}",
            "console version differs from the wheel",
        )

        benign = working / "benign.txt"
        benign.write_text("Ordinary local text for an installed scanner check.\n", encoding="utf-8")
        print("[4/6] Compile bundled rules and scan benign text with the default engine", flush=True)
        benign_result = json_object(
            run([str(scanner), str(benign), "--format", "json"], cwd=working, environment=environment)
        )
        assert_complete(benign_result, "no-findings", version, engine="yara-python")
        require(benign_result.get("findings") == [], "benign input produced findings")

        positive = working / "positive"
        shutil.copytree(fixture, positive, symlinks=True)
        print("[5/6] Scan the copied inert Web3Market fixture with native YARA", flush=True)
        positive_result = json_object(
            run(
                [str(scanner), str(positive), "--engine", "yara-python", "--format", "json"],
                cwd=working,
                environment=environment,
                expected_exit=1,
            )
        )
        assert_complete(positive_result, "review-needed", version, engine="yara-python")
        findings = positive_result.get("findings")
        require(isinstance(findings, list), "positive scan has no findings array")
        require(
            any(
                isinstance(finding, dict)
                and finding.get("rule") == "TP_DevelTask_Node_InlineArray_Remote_Execution"
                and finding.get("source") == "yara-python"
                for finding in findings
            ),
            "expected report-derived native YARA finding is missing",
        )

        print("[6/6] Uninstall and verify the application command/environment were removed", flush=True)
        run([*pipx, "uninstall", "threatprophet-reposcan"], cwd=working, environment=environment, timeout=60)
        require(not scanner.exists() and not scanner.is_symlink(), "uninstall left the command behind")
        require(not installed_scanner.parent.parent.exists(), "uninstall left the application environment behind")

    print(f"PASS: threatprophet-reposcan {version} installs, scans with YARA, and uninstalls via pipx.", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path, help="Exact trusted RepoScan .whl artifact")
    parser.add_argument(
        "--wheelhouse",
        type=Path,
        help="Optional local directory containing pip and compatible yara-python wheels; disables indexes",
    )
    arguments = parser.parse_args()
    try:
        wheel = arguments.wheel.expanduser().resolve(strict=True)
        require(wheel.is_file() and wheel.suffix == ".whl", "wheel must be an existing .whl file")
        wheelhouse = arguments.wheelhouse
        if wheelhouse is not None:
            wheelhouse = wheelhouse.expanduser().resolve(strict=True)
            require(wheelhouse.is_dir(), "wheelhouse must be an existing directory")
        verify(wheel, wheelhouse)
    except (VerificationError, OSError) as error:
        print(f"FAIL: {error}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
