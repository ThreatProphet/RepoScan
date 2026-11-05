from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest
from conftest import REPO_ROOT


@pytest.fixture
def installer(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location("reposcan_installer", REPO_ROOT / "tools/install.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    empty_bin = tmp_path / "empty-bin"
    empty_bin.mkdir()
    monkeypatch.setenv("PATH", str(empty_bin))
    return module


def arguments(prefix: Path, binary_directory: Path, python: str = sys.executable) -> list[str]:
    return ["--prefix", str(prefix), "--bin-dir", str(binary_directory), "--python", python]


@pytest.mark.parametrize("kind", ["directory", "file", "dangling-symlink"])
def test_existing_environment_is_never_modified(installer: ModuleType, tmp_path: Path, kind: str) -> None:
    prefix = tmp_path / "existing"
    if kind == "directory":
        prefix.mkdir()
        (prefix / "keep.txt").write_text("keep")
    elif kind == "file":
        prefix.write_text("keep")
    else:
        prefix.symlink_to(tmp_path / "missing")
    binary_directory = tmp_path / "new-bin"

    assert installer.main(arguments(prefix, binary_directory)) == 1
    assert not binary_directory.exists()
    if kind == "directory":
        assert (prefix / "keep.txt").read_text() == "keep"
    elif kind == "file":
        assert prefix.read_text() == "keep"
    else:
        assert prefix.is_symlink() and not prefix.exists()


@pytest.mark.parametrize("kind", ["directory", "file", "dangling-symlink"])
def test_existing_command_is_never_modified(installer: ModuleType, tmp_path: Path, kind: str) -> None:
    binary_directory = tmp_path / "bin"
    binary_directory.mkdir()
    command = binary_directory / "reposcan"
    if kind == "directory":
        command.mkdir()
    elif kind == "file":
        command.write_text("keep")
    else:
        command.symlink_to(tmp_path / "missing")
    prefix = tmp_path / "new-environment"

    assert installer.main(arguments(prefix, binary_directory)) == 1
    assert not prefix.exists()
    assert os.path.lexists(command)
    if kind == "file":
        assert command.read_text() == "keep"


def test_command_elsewhere_on_path_is_reported(installer: ModuleType, tmp_path: Path) -> None:
    existing = Path(os.environ["PATH"]) / "reposcan"
    existing.write_text("#!/bin/sh\nexit 0\n")
    existing.chmod(0o700)
    prefix = tmp_path / "new-environment"
    assert installer.main(arguments(prefix, tmp_path / "new-bin")) == 1
    assert not prefix.exists()
    assert existing.read_text() == "#!/bin/sh\nexit 0\n"


def test_symlink_command_directory_is_rejected(installer: ModuleType, tmp_path: Path) -> None:
    destination = tmp_path / "untouched"
    destination.mkdir()
    binary_directory = tmp_path / "bin-link"
    binary_directory.symlink_to(destination, target_is_directory=True)
    prefix = tmp_path / "new-environment"
    assert installer.main(arguments(prefix, binary_directory)) == 1
    assert not prefix.exists()
    assert list(destination.iterdir()) == []


def test_pip_redirects_cannot_escape_environment(installer: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    redirects = ["PIP_TARGET", "PIP_PREFIX", "PIP_ROOT", "PIP_USER", "PIP_PYTHON", "PYTHONPATH", "PYTHONHOME"]
    for key in redirects:
        monkeypatch.setenv(key, "/outside-environment")
    monkeypatch.setenv("PIP_CONFIG_FILE", "/outside-config")
    monkeypatch.setenv("PIP_FIND_LINKS", "/trusted-wheelhouse")
    monkeypatch.setenv("PIP_NO_INDEX", "1")
    environment = installer.installation_environment()
    assert all(key not in environment for key in redirects)
    assert environment["PIP_CONFIG_FILE"] == os.devnull
    assert environment["PIP_FIND_LINKS"] == "/trusted-wheelhouse"
    assert environment["PIP_NO_INDEX"] == "1"


@pytest.mark.parametrize("data_override", ["", "relative-data"])
def test_invalid_xdg_data_home_uses_user_directory(
    installer: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    data_override: str,
) -> None:
    user_directory = tmp_path / "user-directory"
    monkeypatch.setattr(installer.Path, "home", classmethod(lambda _cls: user_directory))
    monkeypatch.setenv("XDG_DATA_HOME", data_override)
    observed: list[Path] = []

    def capture_prefix(prefix: Path, *_args: object) -> None:
        observed.append(prefix)
        raise installer.InstallationError("stop before installation")

    monkeypatch.setattr(installer, "preflight", capture_prefix)
    assert installer.main([]) == 1
    assert observed == [user_directory / ".local/share/threatprophet-reposcan"]
    assert not user_directory.exists()


def test_failed_install_keeps_partial_environment_without_exposing_command(
    installer: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    prefix = tmp_path / "new-environment"
    binary_directory = tmp_path / "new-bin"

    def fail_install(command: list[str], *_args: object, **_kwargs: object) -> str:
        if "install" in command:
            (prefix / "partial.txt").write_text("diagnostic artifact")
            raise installer.InstallationError("dependency installation failed")
        return ""

    monkeypatch.setattr(installer, "run", fail_install)
    assert installer.main(arguments(prefix, binary_directory)) == 1
    assert (prefix / "partial.txt").read_text() == "diagnostic artifact"
    assert not os.path.lexists(binary_directory / "reposcan")


def test_relative_interpreter_and_quoted_paths_reach_install_without_shell_expansion(
    installer: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    interpreter = tmp_path / "python dir" / "python"
    interpreter.parent.mkdir()
    interpreter.symlink_to(sys.executable)
    prefix = tmp_path / "environment ' $(touch SHOULD_NOT_EXIST)"
    binary_directory = tmp_path / "bin ' space"
    commands: list[list[str]] = []

    def record(command: list[str], working: Path, *_args: object, **_kwargs: object) -> str:
        commands.append(command)
        assert working != tmp_path
        return ""

    monkeypatch.setattr(installer, "run", record)
    monkeypatch.setattr(installer, "verify_installation", lambda *_args: "0.2.0")
    assert installer.main(arguments(prefix, binary_directory, "python dir/python")) == 0
    assert commands[0][0] == str(interpreter)
    assert commands[1][0] == str(interpreter)
    assert commands[1][-1] == str(prefix)
    assert (binary_directory / "reposcan").is_symlink()
    assert (binary_directory / "reposcan").readlink() == prefix / "bin/reposcan"
    assert not (tmp_path / "SHOULD_NOT_EXIST").exists()


def test_failed_health_check_does_not_expose_command(
    installer: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    prefix = tmp_path / "new-environment"
    binary_directory = tmp_path / "new-bin"
    monkeypatch.setattr(installer, "run", lambda *_args, **_kwargs: "")

    def fail_health_check(*_args: object) -> str:
        raise installer.InstallationError("canonical engine unavailable")

    monkeypatch.setattr(installer, "verify_installation", fail_health_check)
    assert installer.main(arguments(prefix, binary_directory)) == 1
    assert prefix.is_dir()
    assert not os.path.lexists(binary_directory / "reposcan")


@pytest.mark.parametrize("problem", ["incomplete", "heuristic", "missing-rules", "malformed-stats"])
def test_unready_engine_cannot_pass_verification(
    installer: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    problem: str,
) -> None:
    prefix = tmp_path / "environment"
    (prefix / "bin").mkdir(parents=True)
    (prefix / "bin/reposcan").write_text("inert placeholder")
    result = {
        "complete": True,
        "status": "complete",
        "verdict": "no-findings",
        "engine": "yara-python",
        "findings": [],
        "errors": [],
        "stats": {"files_scanned": 1, "files_selected": 1},
        "tool": {"version": "0.2.0"},
        "rule_pack": {"files": [{"name": "developer_task_malware.yar"}, {"name": "web3market.yar"}]},
    }
    if problem == "incomplete":
        result["complete"] = False
    elif problem == "heuristic":
        result["engine"] = "lite"
    elif problem == "missing-rules":
        result["rule_pack"] = {"files": []}
    else:
        result["stats"] = []

    def output(command: list[str], *_args: object, **_kwargs: object) -> str:
        return json.dumps({"version": "0.2.0"} if "-c" in command else result)

    monkeypatch.setattr(installer, "run", output)
    with pytest.raises(installer.InstallationError):
        installer.verify_installation(prefix, tmp_path, {})


def test_command_collision_at_publication_is_not_clobbered(
    installer: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    binary_directory = tmp_path / "bin"
    binary_directory.mkdir()
    original_open = os.open

    def collide(path: Path, flags: int) -> int:
        descriptor = original_open(path, flags)
        (binary_directory / "reposcan").mkdir()
        (binary_directory / "reposcan/keep.txt").write_text("keep")
        return descriptor

    monkeypatch.setattr(installer.os, "open", collide)
    with pytest.raises(FileExistsError):
        installer.expose_command(tmp_path / "environment", binary_directory)
    assert (binary_directory / "reposcan/keep.txt").read_text() == "keep"
    assert [path.name for path in (binary_directory / "reposcan").iterdir()] == ["keep.txt"]


def test_launcher_preserves_quoted_paths_and_selected_python(tmp_path: Path) -> None:
    interpreter = tmp_path / "python ' dir" / "python"
    interpreter.parent.mkdir()
    interpreter.symlink_to(sys.executable)
    prefix = tmp_path / "prefix ' $(touch SHOULD_NOT_EXIST)"
    prefix.mkdir()
    result = subprocess.run(
        ["bash", str(REPO_ROOT / "install.sh"), *arguments(prefix, tmp_path / "bin", str(interpreter))],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
    )
    assert result.returncode == 1
    assert str(prefix) in result.stderr
    assert "Environment path already exists" in result.stderr
    assert not (tmp_path / "SHOULD_NOT_EXIST").exists()
