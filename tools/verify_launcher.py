#!/usr/bin/env python3
"""Exercise the real quick-run launcher with a fresh private runtime.

By default, the checked-in launcher downloads its pinned published wheel.
--wheel seeds only the ordinary, checksum-verified wheel cache for a generated
release launcher whose wheel has not been published yet. uv, Python and YARA
must still be acquired into empty private state. Target fixtures remain data.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shlex
import shutil
import sys
import tempfile
from pathlib import Path

from prepare_launcher import file_sha256, launcher_pins
from verify_wheel import (
    VerificationError,
    assert_complete,
    isolated_environment,
    json_object,
    require,
    run,
    wheel_version,
)


def snapshot(root: Path) -> dict[str, tuple[str, str]]:
    """Observe names and bytes, ignoring access-time changes caused by reads."""
    entries = {}
    for path in sorted(root.rglob("*")):
        name = str(path.relative_to(root))
        if path.is_symlink():
            entries[name] = ("symlink", os.readlink(path))
        elif path.is_file():
            entries[name] = ("file", hashlib.sha256(path.read_bytes()).hexdigest())
        elif path.is_dir():
            entries[name] = ("directory", "")
        else:
            raise VerificationError(f"unexpected special file in owned verification input: {path}")
    return entries


def verify(launcher: Path, wheel: Path | None) -> None:
    require(sys.platform in {"linux", "darwin"}, "launcher verification requires Linux or macOS")
    source = Path(__file__).resolve().parents[1]
    pins = launcher_pins(launcher.read_text(encoding="utf-8"))
    version = pins["REPOSCAN_VERSION"]
    if wheel is not None:
        require(wheel_version(wheel) == version, "seed wheel version differs from launcher pin")
        require(file_sha256(wheel) == pins["REPOSCAN_WHEEL_SHA256"], "seed wheel hash differs from launcher pin")
        require(
            wheel.name == f"threatprophet_reposcan-{version}-py3-none-any.whl",
            "seed wheel filename differs from the release artifact",
        )

    with tempfile.TemporaryDirectory(prefix="reposcan-launcher-") as directory:
        temporary = Path(directory).resolve()
        require(not temporary.is_relative_to(source), "verification state is inside the checkout")
        state = temporary / "private runtime"
        working = temporary / "received project"
        working.mkdir()
        benign = working / "ordinary ' $(touch SHOULD_NOT_EXIST).txt"
        benign.write_text("Ordinary local text for launcher verification.\n", encoding="utf-8")
        positive = working / "review input"
        shutil.copytree(source / "tests/fixtures/web3market-entry", positive, symlinks=True)
        high_risk = working / "high risk input"
        shutil.copytree(source / "tests/fixtures/malicious-vscode", high_risk, symlinks=True)
        (working / "uv.toml").write_text("not valid TOML [[\n", encoding="utf-8")
        (working / "pyproject.toml").write_text("not valid TOML [[\n", encoding="utf-8")
        (working / ".python-version").write_text("999.0\n", encoding="utf-8")
        (working / ".env").write_text("PYTHONHOME=/must-not-be-used\n", encoding="utf-8")
        fake_bin = working / "bin"
        fake_bin.mkdir()
        marker = working / "TARGET_COMMAND_EXECUTED"
        for name in ("uv", "uvx", "python", "python3", "curl", "git"):
            command = fake_bin / name
            command.write_text(f"#!/bin/sh\nprintf wrong > {shlex.quote(str(marker))}\nexit 99\n", encoding="utf-8")
            command.chmod(0o700)
        before = snapshot(working)
        environment = isolated_environment(str(fake_bin) + os.pathsep + os.defpath)
        # Preserve explicitly configured HTTPS transport for managed/corporate
        # networks. These are trusted caller settings, never target config.
        for name in ("HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE"):
            if name in os.environ:
                environment[name] = os.environ[name]
        environment.update(
            {
                "HOME": str(Path.home()),
                "REPOSCAN_RUN_HOME": str(state),
                "UV_ENV_FILE": str(working / ".env"),
                "UV_INDEX_URL": "https://example.invalid/never-query-this-index/",
                "UV_PYTHON_INSTALL_DIR": str(working / "must-not-create-python"),
                "UV_CACHE_DIR": str(working / "must-not-create-cache"),
                "PYTHONPATH": str(working),
                "PYTHONHOME": "/must-not-be-used",
            }
        )
        command = ["/bin/sh", str(launcher)]

        print("[1/7] Check help/version without provisioning anything", flush=True)
        run([*command, "--help"], cwd=working, environment=environment)
        require(
            version in run([*command, "--version"], cwd=working, environment=environment).stdout,
            "launcher does not identify its pinned scanner version",
        )
        require(not state.exists(), "help/version created runtime state")
        if wheel is not None:
            (state / "downloads").mkdir(parents=True, mode=0o700)
            state.chmod(0o700)
            shutil.copyfile(wheel, state / "downloads" / wheel.name)
            print("  Seeded only the exact release wheel; runtime state is otherwise empty.", flush=True)

        print("[2/7] Provision private uv/Python/YARA and scan benign text", flush=True)
        benign_result = json_object(
            run(
                [*command, benign.name, "--format", "json"],
                cwd=working,
                environment=environment,
                timeout=600,
            )
        )
        assert_complete(benign_result, "no-findings", version, engine="yara-python")
        require(benign_result.get("findings") == [], "benign launcher input produced findings")

        print("[3/7] Reuse runtime offline for native review findings (exit 1)", flush=True)
        review_result = json_object(
            run(
                [*command, "--offline", str(positive), "--format", "json"],
                cwd=working,
                environment=environment,
                expected_exit=1,
                timeout=90,
            )
        )
        assert_complete(review_result, "review-needed", version, engine="yara-python")
        findings = review_result.get("findings")
        require(isinstance(findings, list) and len(findings) == 3, "expected three Web3Market findings")
        require(
            any(
                finding.get("rule") == "TP_DevelTask_Node_InlineArray_Remote_Execution"
                and finding.get("source") == "yara-python"
                for finding in findings
            ),
            "expected native report-derived finding is missing",
        )

        print("[4/7] Preserve high-risk findings (exit 2)", flush=True)
        high_result = json_object(
            run(
                [*command, "--offline", str(high_risk), "--format", "json"],
                cwd=working,
                environment=environment,
                expected_exit=2,
                timeout=90,
            )
        )
        assert_complete(high_result, "high-risk", version, engine="yara-python")

        print("[5/7] Preserve usage errors and report JSON without setup messages", flush=True)
        run(
            [*command, "--offline", str(benign), "--not-a-scanner-option"],
            cwd=working,
            environment=environment,
            expected_exit=64,
            timeout=90,
        )
        print("[6/7] Check the received tree and ignore its configuration/tool overrides", flush=True)
        require(snapshot(working) == before, "launcher changed the received project or invoked its commands")

        print("[7/7] Reject a corrupted cached wheel before starting the scanner", flush=True)
        cached_wheel = state / "downloads" / f"threatprophet_reposcan-{version}-py3-none-any.whl"
        require(cached_wheel.is_file(), "verified release wheel was not cached")
        cached_wheel.write_bytes(b"inert corrupt cache entry\n")
        corrupt = run(
            [*command, "--offline", str(benign), "--format", "json"],
            cwd=working,
            environment=environment,
            expected_exit=70,
            timeout=90,
        )
        require(not corrupt.stdout.strip(), "bootstrap corruption emitted a scanner result")
        require(snapshot(working) == before, "failure handling changed the received project")

    print(f"PASS: RepoScan {version} launcher provisioned a fresh runtime and preserved native scan results.", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--launcher", type=Path, default=Path(__file__).resolve().parents[1] / "reposcan-run.sh"
    )
    parser.add_argument("--wheel", type=Path, help="Seed this exact unpublished wheel into its verified cache")
    arguments = parser.parse_args()
    try:
        launcher = arguments.launcher.resolve(strict=True)
        require(launcher.is_file(), "launcher is not a regular file")
        wheel = arguments.wheel.resolve(strict=True) if arguments.wheel else None
        verify(launcher, wheel)
    except (VerificationError, OSError) as error:
        print(f"FAIL: {error}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
