"""Launcher boundary tests use inert artifacts, never project code or a network.

Only a temporary copy of the launcher receives the fixture's trusted command
directory and artifact hashes. Production has no URL/hash/test bypass switches.
Native installation of the actual release artifacts is a separate release gate.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import re
import subprocess
import sys
import tarfile
from dataclasses import dataclass
from pathlib import Path

import pytest
from conftest import REPO_ROOT

LAUNCHER = REPO_ROOT / "reposcan-run.sh"
TRUSTED_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"


@dataclass
class LauncherFixture:
    base: Path
    script: Path
    home: Path
    state: Path
    target: Path
    commands: Path
    downloads_log: Path
    calls_log: Path

    def run(
        self,
        *arguments: str | Path,
        cwd: Path | None = None,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update({"HOME": str(self.home), "REPOSCAN_RUN_HOME": str(self.state)})
        if environment:
            env.update(environment)
        return subprocess.run(
            ["/bin/sh", str(self.script), *map(str, arguments)],
            cwd=cwd or self.base,
            env=env,
            text=True,
            capture_output=True,
            check=False,
            timeout=15,
        )

    def calls(self) -> list[dict[str, object]]:
        if not self.calls_log.exists():
            return []
        return [json.loads(line) for line in self.calls_log.read_text().splitlines()]


@pytest.fixture
def launcher(tmp_path: Path) -> LauncherFixture:
    # Resolve pytest's macOS /var alias, because real state paths reject symlinks.
    base = tmp_path.resolve()
    home = base / "home with spaces"
    home.mkdir(mode=0o700)
    target = base / "received project ' $(touch NEVER_EXECUTED)"
    target.mkdir(mode=0o700)
    (target / "README.md").write_text("Inert received project.\n")
    state = home / "private scanner state"
    commands = base / "trusted-test-commands"
    commands.mkdir(mode=0o700)
    calls_log = base / "calls.jsonl"
    downloads_log = base / "downloads.jsonl"
    failure = base / "preparation-fails"
    scan_status = base / "scanner-status"
    scan_status.write_text("0")

    scanner = base / "inert-scanner.py"
    scanner.write_text(
        f"#!{sys.executable}\n"
        "import json, os, pathlib, sys\n"
        f"log = pathlib.Path({str(calls_log)!r})\n"
        "with log.open('a') as stream:\n"
        "    stream.write(json.dumps({'stage': 'scan', 'args': sys.argv[1:], "
        "'cwd': os.getcwd(), 'environment': dict(os.environ)}) + '\\n')\n"
        "print(json.dumps({'scanner': 'inert fixture', 'args': sys.argv[1:]}))\n"
        "print('inert scanner diagnostic', file=sys.stderr)\n"
        f"sys.exit(int(pathlib.Path({str(scan_status)!r}).read_text()))\n"
    )
    stub_uv = (
        f"#!{sys.executable}\n"
        "import json, os, pathlib, shutil, sys\n"
        f"log = pathlib.Path({str(calls_log)!r})\n"
        "with log.open('a') as stream:\n"
        "    stream.write(json.dumps({'stage': 'prepare', 'args': sys.argv[1:], "
        "'cwd': os.getcwd(), 'environment': dict(os.environ)}) + '\\n')\n"
        f"if pathlib.Path({str(failure)!r}).exists():\n"
        "    print('inert preparation failure', file=sys.stderr)\n"
        "    sys.exit(1)\n"
        "python = pathlib.Path(os.environ['UV_CACHE_DIR']) / 'stub-env' / 'bin' / 'python'\n"
        "python.parent.mkdir(parents=True, exist_ok=True)\n"
        f"shutil.copyfile({str(scanner)!r}, python)\n"
        "python.chmod(0o700)\n"
        "print(python)\n"
    ).encode()
    if sys.platform == "darwin":
        uv_target = "aarch64-apple-darwin" if platform.machine() == "arm64" else "x86_64-apple-darwin"
    else:
        uv_target = "x86_64-unknown-linux-gnu"
    archive = base / "inert-uv.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        member = tarfile.TarInfo(f"uv-{uv_target}/uv")
        member.size = len(stub_uv)
        member.mode = 0o755
        member.uid = os.getuid() + 1000
        member.gid = os.getgid() + 1000
        tar.addfile(member, io.BytesIO(stub_uv))
    wheel = base / "inert-wheel.whl"
    wheel.write_bytes(b"Inert wheel stand-in; the fixture uv does not install it.\n")

    curl = commands / "curl"
    curl.write_text(
        f"#!{sys.executable}\n"
        "import json, pathlib, shutil, sys\n"
        "arguments = sys.argv[1:]\n"
        f"with pathlib.Path({str(downloads_log)!r}).open('a') as stream:\n"
        "    stream.write(json.dumps(arguments) + '\\n')\n"
        "destination = arguments[arguments.index('--output') + 1]\n"
        f"source = {str(wheel)!r} if arguments[-1].endswith('.whl') else {str(archive)!r}\n"
        "shutil.copyfile(source, destination)\n"
    )
    curl.chmod(0o700)
    source = LAUNCHER.read_text()
    source = source.replace(f"PATH='{TRUSTED_PATH}'", f"PATH='{commands}:{TRUSTED_PATH}'", 1)
    source = re.sub(
        r"REPOSCAN_WHEEL_SHA256='[a-f0-9]{64}'",
        f"REPOSCAN_WHEEL_SHA256='{hashlib.sha256(wheel.read_bytes()).hexdigest()}'",
        source,
    )
    source = re.sub(r"uv_sha256=[a-f0-9]{64}", f"uv_sha256={hashlib.sha256(archive.read_bytes()).hexdigest()}", source)
    script = base / "launcher-under-test.sh"
    script.write_text(source)
    return LauncherFixture(base, script, home, state, target, commands, downloads_log, calls_log)


@pytest.mark.parametrize("option", ["--help", "--version"])
def test_information_commands_do_not_create_state_or_download(launcher: LauncherFixture, option: str) -> None:
    result = launcher.run(option)
    assert result.returncode == 0, result.stderr
    assert not launcher.state.exists()
    assert not launcher.downloads_log.exists()
    if option == "--version":
        assert "readiness not checked" in result.stdout


@pytest.mark.parametrize("status", [0, 1, 2, 64])
def test_scanner_status_output_and_literal_arguments_are_preserved(launcher: LauncherFixture, status: int) -> None:
    (launcher.base / "scanner-status").write_text(str(status))
    result = launcher.run(launcher.target.name, "--format", "json", "--width=100")
    assert result.returncode == status, result.stderr
    payload = json.loads(result.stdout)
    assert payload["args"] == ["-I", "-m", "reposcan", str(launcher.target), "--format", "json", "--width=100"]
    assert "RepoScan launcher:" in result.stderr
    assert "inert scanner diagnostic" in result.stderr
    assert [call["stage"] for call in launcher.calls()] == ["prepare", "scan"]
    assert not (launcher.base / "NEVER_EXECUTED").exists()
    assert sorted(path.name for path in launcher.target.iterdir()) == ["README.md"]


def test_untrusted_directory_and_environment_cannot_select_tools(launcher: LauncherFixture) -> None:
    marker = launcher.base / "PROJECT_EXECUTED"
    for name in ("uv", "python", "sitecustomize.py"):
        (launcher.target / name).write_text(f"#!/bin/sh\ntouch '{marker}'\n")
        (launcher.target / name).chmod(0o700)
    for name in ("uv.toml", "pyproject.toml", ".python-version", ".env"):
        (launcher.target / name).write_text("untrusted configuration\n")
    before = {path.name: path.read_bytes() for path in launcher.target.iterdir()}
    hostile = {
        "PATH": str(launcher.target),
        "UV_CONFIG_FILE": str(launcher.target / "uv.toml"),
        "UV_ENV_FILE": str(launcher.target / ".env"),
        "UV_PYTHON": str(launcher.target / "python"),
        "UV_PYTHON_INSTALL_MIRROR": "https://untrusted.invalid/python",
        "UV_INDEX": "https://untrusted.invalid/simple",
        "PYTHONPATH": str(launcher.target),
        "PYTHONHOME": str(launcher.target),
        "PIP_CONFIG_FILE": str(launcher.target / "pip.conf"),
        "VIRTUAL_ENV": str(launcher.target),
        "NO_COLOR": "1",
    }
    result = launcher.run(".", "--json", cwd=launcher.target, environment=hostile)
    assert result.returncode == 0, result.stderr
    preparation, scan = launcher.calls()
    assert preparation["cwd"] == scan["cwd"] == str(launcher.state)
    for call in (preparation, scan):
        environment = call["environment"]
        assert isinstance(environment, dict)
        assert environment["PATH"] == f"{launcher.commands}:{TRUSTED_PATH}"
        assert environment["NO_COLOR"] == "1"
        assert all(key not in environment for key in hostile if key not in {"PATH", "NO_COLOR"})
    assert "--no-config" in preparation["args"]
    assert "--no-env-file" in preparation["args"]
    assert "--no-build" in preparation["args"]
    assert "--managed-python" in preparation["args"]
    assert not marker.exists()
    assert before == {path.name: path.read_bytes() for path in launcher.target.iterdir()}


def test_preparation_failure_is_not_reported_as_scan_findings(launcher: LauncherFixture) -> None:
    (launcher.base / "preparation-fails").touch()
    result = launcher.run(launcher.target)
    assert result.returncode == 70
    assert result.stdout == ""
    assert "no scan was performed" in result.stderr
    assert [call["stage"] for call in launcher.calls()] == ["prepare"]
    assert not (launcher.state / ".bootstrap.lock").exists()
    assert not list(launcher.state.glob(".bootstrap.*"))


def test_offline_requires_cached_artifacts_without_attempting_download(launcher: LauncherFixture) -> None:
    result = launcher.run("--offline", launcher.target)
    assert result.returncode == 70
    assert "offline cache is missing" in result.stderr
    assert not launcher.downloads_log.exists()
    assert not launcher.calls()


def test_warm_offline_run_reuses_verified_artifacts_and_replaces_tampered_binary(launcher: LauncherFixture) -> None:
    first = launcher.run(launcher.target)
    assert first.returncode == 0, first.stderr
    downloads = launcher.downloads_log.read_text()
    assert len(downloads.splitlines()) == 2
    uv_binary = next((launcher.state / "bin").iterdir())
    marker = launcher.base / "CACHED_BINARY_EXECUTED"
    uv_binary.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 99\n")
    second = launcher.run("--offline", launcher.target)
    assert second.returncode == 0, second.stderr
    assert launcher.downloads_log.read_text() == downloads
    assert not marker.exists()
    assert "--offline" in launcher.calls()[2]["args"]


def test_uv_extraction_does_not_restore_foreign_archive_ownership(launcher: LauncherFixture) -> None:
    with tarfile.open(launcher.base / "inert-uv.tar.gz", "r:gz") as archive:
        member = archive.getmembers()[0]
        assert member.uid != os.getuid()
        assert member.gid != os.getgid()
    result = launcher.run(launcher.target)
    assert result.returncode == 0, result.stderr
    executable = next((launcher.state / "bin").iterdir())
    assert executable.stat().st_uid == os.getuid()
    assert executable.stat().st_gid != member.gid
    assert executable.stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize("artifact", ["wheel", "uv"])
def test_corrupt_cached_artifact_stops_before_executing_uv(launcher: LauncherFixture, artifact: str) -> None:
    assert launcher.run(launcher.target).returncode == 0
    launcher.calls_log.unlink()
    pattern = "*.whl" if artifact == "wheel" else "*.tar.gz"
    cached = next((launcher.state / "downloads").glob(pattern))
    cached.write_bytes(b"modified artifact")
    result = launcher.run("--offline", launcher.target)
    assert result.returncode == 70
    assert "SHA-256 mismatch" in result.stderr
    assert not launcher.calls()


@pytest.mark.parametrize("kind", ["state-symlink", "ancestor-symlink", "writable-state", "foreign-artifact-symlink"])
def test_unsafe_state_is_rejected(launcher: LauncherFixture, kind: str) -> None:
    if kind == "state-symlink":
        destination = launcher.base / "outside"
        destination.mkdir()
        launcher.state.symlink_to(destination, target_is_directory=True)
    elif kind == "ancestor-symlink":
        destination = launcher.base / "outside"
        destination.mkdir()
        ancestor = launcher.home / "linked-parent"
        ancestor.symlink_to(destination, target_is_directory=True)
        launcher.state = ancestor / "state"
    elif kind == "writable-state":
        launcher.state.mkdir()
        launcher.state.chmod(0o777)
    else:
        assert launcher.run(launcher.target).returncode == 0
        launcher.calls_log.unlink()
        cached = next((launcher.state / "downloads").glob("*.whl"))
        original = launcher.base / "outside-artifact"
        cached.rename(original)
        cached.symlink_to(original)
    result = launcher.run(launcher.target)
    assert result.returncode == 70
    assert not launcher.calls()
    assert any(word in result.stderr for word in ("symlink", "writable"))


@pytest.mark.parametrize("where", ["target", "descendant", "root-state", "root-target"])
def test_state_and_target_overlap_is_rejected_before_writes(launcher: LauncherFixture, where: str) -> None:
    state = launcher.target if where == "target" else launcher.target / "state"
    target = launcher.target
    if where == "root-state":
        state = Path("/")
    if where == "root-target":
        target = Path("/")
        state = launcher.state
    before = {p.name: p.read_bytes() for p in launcher.target.iterdir()}
    result = launcher.run(target, environment={"REPOSCAN_RUN_HOME": str(state)})
    assert result.returncode == 70
    assert before == {p.name: p.read_bytes() for p in launcher.target.iterdir()}
    assert not launcher.downloads_log.exists()


@pytest.mark.parametrize(
    "arguments",
    [
        ["--rules", "relative"],
        ["--ignore-config=relative"],
        ["--rules"],
        ["--r", "relative"],
        ["--rule=relative"],
        ["--ignore-conf", "relative"],
    ],
)
def test_relative_or_abbreviated_path_options_fail_before_bootstrap(
    launcher: LauncherFixture, arguments: list[str]
) -> None:
    result = launcher.run(launcher.target, *arguments)
    assert result.returncode == 64
    assert not launcher.state.exists()
    assert not launcher.downloads_log.exists()


def test_absolute_configuration_paths_are_forwarded_unchanged(launcher: LauncherFixture) -> None:
    rules = launcher.base / "custom rules"
    ignores = launcher.base / "ignore patterns.txt"
    result = launcher.run(launcher.target, "--rules", rules, f"--ignore-config={ignores}")
    assert result.returncode == 0, result.stderr
    assert launcher.calls()[-1]["args"][-3:] == ["--rules", str(rules), f"--ignore-config={ignores}"]


def test_existing_setup_lock_does_not_modify_cached_state(launcher: LauncherFixture) -> None:
    launcher.state.mkdir(mode=0o700)
    lock = launcher.state / ".bootstrap.lock"
    lock.mkdir(mode=0o700)
    marker = lock / "owned-by-other-launcher"
    marker.write_text("leave this lock intact")
    result = launcher.run(launcher.target)
    assert result.returncode == 70
    assert "setup lock exists" in result.stderr
    assert marker.read_text() == "leave this lock intact"
    assert not launcher.downloads_log.exists()


def test_target_symlink_is_not_resolved_before_scanner_handoff(launcher: LauncherFixture) -> None:
    alias = launcher.base / "target-link"
    alias.symlink_to(launcher.target, target_is_directory=True)
    result = launcher.run(alias)
    assert result.returncode == 0, result.stderr
    assert launcher.calls()[-1]["args"][3] == str(alias)


@pytest.mark.parametrize("platform_case", ["unsupported-architecture", "older-macos", "musl"])
def test_unsupported_platform_stops_before_state_creation(launcher: LauncherFixture, platform_case: str) -> None:
    operating_system = "Darwin" if platform_case == "older-macos" else "Linux"
    architecture = "aarch64" if platform_case == "unsupported-architecture" else "x86_64"
    uname = launcher.commands / "uname"
    uname.write_text(
        f"#!/bin/sh\ncase \"$1\" in -s) printf '%s\\n' '{operating_system}';; "
        f"-m) printf '%s\\n' '{architecture}';; esac\n"
    )
    uname.chmod(0o700)
    if platform_case == "older-macos":
        command = launcher.commands / "sw_vers"
        command.write_text("#!/bin/sh\nprintf '14.7\\n'\n")
        command.chmod(0o700)
    if platform_case == "musl":
        command = launcher.commands / "getconf"
        command.write_text("#!/bin/sh\nexit 1\n")
        command.chmod(0o700)
    result = launcher.run(launcher.target)
    assert result.returncode == 70
    assert not launcher.state.exists()
    assert not launcher.downloads_log.exists()


def test_explicit_corporate_tls_settings_are_preserved(launcher: LauncherFixture) -> None:
    settings = {
        "SSL_CERT_FILE": str(launcher.home / "trusted-ca.pem"),
        "SSL_CERT_DIR": f"{launcher.home / 'certs'}:{launcher.home / 'other-certs'}",
        "CURL_CA_BUNDLE": str(launcher.home / "trusted-curl-ca.pem"),
    }
    result = launcher.run(launcher.target, environment=settings)
    assert result.returncode == 0, result.stderr
    for call in launcher.calls():
        environment = call["environment"]
        assert isinstance(environment, dict)
        assert {name: environment[name] for name in settings} == settings


@pytest.mark.parametrize("name", ["SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE"])
def test_relative_tls_settings_are_not_rebased_to_state(launcher: LauncherFixture, name: str) -> None:
    value = "/absolute:relative" if name == "SSL_CERT_DIR" else "relative"
    result = launcher.run(launcher.target, environment={name: value})
    assert result.returncode == 70
    assert "absolute path" in result.stderr
    assert not launcher.downloads_log.exists()
    assert not launcher.calls()
