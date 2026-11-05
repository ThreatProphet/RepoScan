#!/usr/bin/env python3
"""Install this trusted RepoScan checkout into a dedicated user environment.

This installer takes no scan target. Its only scan is a temporary benign file
used to check the installed canonical engine and packaged rules.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


class InstallationError(RuntimeError):
    """Installation stopped before the command could be exposed."""


INSTALLED_PROBE = """
import importlib.metadata
import json
import pathlib
import sys
import reposcan
import yara

prefix = pathlib.Path(sys.argv[1]).resolve()
assert pathlib.Path(sys.prefix).resolve() == prefix, 'wrong installation environment'
assert sys.prefix != sys.base_prefix, 'not running in a virtual environment'
origin = pathlib.Path(reposcan.__file__).resolve()
assert origin.is_relative_to(prefix), 'reposcan imported from outside the environment'
assert pathlib.Path(yara.__file__).resolve().is_relative_to(prefix), 'YARA imported from outside the environment'
distribution = importlib.metadata.distribution('threatprophet-reposcan')
assert distribution.locate_file('reposcan/__init__.py').resolve() == origin, 'unexpected distribution origin'
assert distribution.version == reposcan.__version__, 'distribution and module versions differ'
print(json.dumps({'version': distribution.version, 'yara': yara.__version__}))
"""


def run(command: list[str], working: Path, environment: dict[str, str], *, capture: bool = False) -> str:
    try:
        result = subprocess.run(
            command,
            cwd=working,
            env=environment,
            check=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            timeout=600 if not capture else 60,
        )
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or "").strip()[-3000:] if capture else "See the command output above."
        raise InstallationError(f"Command failed with exit {error.returncode}: {detail}") from error
    except subprocess.TimeoutExpired as error:
        raise InstallationError("Installation command timed out; no fallback engine was selected.") from error
    return result.stdout or ""


def installation_environment() -> dict[str, str]:
    environment = os.environ.copy()
    network_options = {
        "PIP_INDEX_URL",
        "PIP_EXTRA_INDEX_URL",
        "PIP_NO_INDEX",
        "PIP_FIND_LINKS",
        "PIP_TRUSTED_HOST",
        "PIP_CERT",
        "PIP_CLIENT_CERT",
        "PIP_PROXY",
        "PIP_TIMEOUT",
        "PIP_DEFAULT_TIMEOUT",
        "PIP_RETRIES",
    }
    for key in list(environment):
        if key.startswith(("PYTHON", "_PYTHON")) or key in {"VIRTUAL_ENV", "__PYVENV_LAUNCHER__"}:
            environment.pop(key)
        elif key.startswith("PIP_") and key not in network_options:
            environment.pop(key)
    environment.update(
        {
            "PYTHONNOUSERSITE": "1",
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_NO_INPUT": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        }
    )
    return environment


def absolute_path(value: str) -> Path:
    if not value or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise InstallationError("Installation paths must be nonempty and contain no control characters.")
    return Path(os.path.abspath(os.path.expanduser(value)))


def reject_command_collision(command: Path) -> None:
    if os.path.lexists(command):
        raise InstallationError(f"Command already exists: {command}. It will not be overwritten.")
    existing = shutil.which("reposcan")
    if existing:
        raise InstallationError(f"A reposcan command is already on PATH: {existing}. Resolve it before installing.")


def preflight(prefix: Path, binary_directory: Path, source: Path) -> None:
    if sys.platform != "linux":
        raise InstallationError("This installer currently supports Linux only.")
    if sys.version_info < (3, 10):
        raise InstallationError("Python 3.10 or later is required; select it with --python.")
    if not (source / "pyproject.toml").is_file() or not (source / "src/reposcan/scanner.py").is_file():
        raise InstallationError("Run install.sh from a complete, trusted RepoScan checkout or source release.")
    if os.path.lexists(prefix):
        raise InstallationError(
            f"Environment path already exists: {prefix}. Choose a new path or inspect and remove it."
        )
    if binary_directory.is_symlink() or (binary_directory.exists() and not binary_directory.is_dir()):
        raise InstallationError(
            f"Command directory must be a real directory, not a symlink or file: {binary_directory}"
        )
    if binary_directory.resolve().is_relative_to(prefix.resolve()):
        raise InstallationError("The command directory must be outside the installation environment.")
    reject_command_collision(binary_directory / "reposcan")


def json_object(text: str) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as error:
        raise InstallationError("Installed verification did not return valid JSON.") from error
    if not isinstance(value, dict):
        raise InstallationError("Installed verification did not return a JSON object.")
    return value


def verify_installation(prefix: Path, working: Path, environment: dict[str, str]) -> str:
    python = prefix / "bin/python"
    scanner = prefix / "bin/reposcan"
    if not scanner.is_file():
        raise InstallationError("Installed reposcan command is missing.")
    probe = json_object(
        run([str(python), "-I", "-c", INSTALLED_PROBE, str(prefix)], working, environment, capture=True)
    )
    version = probe.get("version")
    if not isinstance(version, str) or not version:
        raise InstallationError("Installed distribution has no version.")
    benign = working / "benign.txt"
    benign.write_text("Ordinary local text for an installation check.\n", encoding="utf-8")
    result = json_object(
        run(
            [str(scanner), str(benign), "--engine", "yara-python", "--format", "json"],
            working,
            environment,
            capture=True,
        )
    )
    expected = {"status": "complete", "verdict": "no-findings", "engine": "yara-python"}
    if result.get("complete") is not True or any(result.get(key) != value for key, value in expected.items()):
        raise InstallationError("The installed canonical engine did not complete a clean benign scan.")
    statistics = result.get("stats", {})
    if result.get("findings") != [] or result.get("errors") != []:
        raise InstallationError("The installed benign scan contains unexpected findings or errors.")
    if (
        not isinstance(statistics, dict)
        or statistics.get("files_scanned") != 1
        or statistics.get("files_selected") != 1
    ):
        raise InstallationError("The installed scan did not process the expected benign input.")
    tool = result.get("tool")
    if not isinstance(tool, dict) or tool.get("version") != version:
        raise InstallationError("The installed CLI reported an unexpected version.")
    pack = result.get("rule_pack")
    if not isinstance(pack, dict) or not isinstance(pack.get("files"), list):
        raise InstallationError("The installed scan has no rule-pack metadata.")
    rules = {member.get("name") for member in pack["files"] if isinstance(member, dict)}
    if not {"developer_task_malware.yar", "web3market.yar"}.issubset(rules):
        raise InstallationError("The installed scan did not load the expected bundled rules.")
    return version


def expose_command(prefix: Path, binary_directory: Path) -> None:
    reject_command_collision(binary_directory / "reposcan")
    binary_directory.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(binary_directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        # An exclusive symlink operation also rejects a collision that appeared
        # after preflight. Opening the directory rejects a replaced symlink.
        os.symlink(str(prefix / "bin/reposcan"), "reposcan", dir_fd=descriptor)
    finally:
        os.close(descriptor)


def main(arguments: list[str] | None = None) -> int:
    user_directory = Path.home()
    data_override = os.environ.get("XDG_DATA_HOME")
    data_directory = (
        Path(data_override) if data_override and Path(data_override).is_absolute() else user_directory / ".local/share"
    )
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument(
        "--prefix", default=str(data_directory / "threatprophet-reposcan"), help="New virtual environment path"
    )
    parser.add_argument(
        "--bin-dir", default=str(user_directory / ".local/bin"), help="Directory for the reposcan command"
    )
    parser.add_argument("--python", default=sys.executable, help="Python 3.10+ interpreter command or path")
    options = parser.parse_args(arguments)
    created_prefix = False
    prefix: Path | None = None
    try:
        prefix = absolute_path(options.prefix)
        binary_directory = absolute_path(options.bin_dir)
        source = Path(__file__).resolve().parents[1]
        preflight(prefix, binary_directory, source)
        interpreter = shutil.which(options.python)
        if interpreter is None:
            raise InstallationError(f"Python interpreter not found: {options.python}")
        interpreter = os.path.abspath(interpreter)
        environment = installation_environment()
        with tempfile.TemporaryDirectory(prefix="reposcan-install-") as temporary:
            working = Path(temporary).resolve()
            if working.is_relative_to(source):
                raise InstallationError("Choose a temporary directory outside the source checkout with TMPDIR.")
            run(
                [interpreter, "-I", "-c", "import sys; assert sys.version_info >= (3, 10), 'Python 3.10+ required'"],
                working,
                environment,
                capture=True,
            )
            prefix.parent.mkdir(parents=True, exist_ok=True)
            prefix.mkdir(mode=0o700)
            created_prefix = True
            print(f"Creating isolated environment: {prefix}", flush=True)
            run([interpreter, "-I", "-m", "venv", str(prefix)], working, environment)
            print("Installing this trusted checkout with YARA support. Dependencies may use the network.", flush=True)
            requirement = f"threatprophet-reposcan[yara] @ {source.as_uri()}"
            run(
                [str(prefix / "bin/python"), "-I", "-m", "pip", "--require-virtualenv", "install", requirement],
                working,
                environment,
            )
            print("Checking installed origin, YARA engine, bundled rules, and benign scan.", flush=True)
            version = verify_installation(prefix, working, environment)
            expose_command(prefix, binary_directory)
    except (InstallationError, OSError, KeyboardInterrupt) as error:
        print(f"Installation stopped: {str(error) or 'interrupted'}", file=sys.stderr)
        if created_prefix:
            print(
                f"Environment retained for inspection: {prefix}\nInspect and remove it before retrying this prefix.",
                file=sys.stderr,
            )
        return 1

    command = binary_directory / "reposcan"
    print(f"Installed ThreatProphet RepoScan {version}: {command}")
    print(f"Run: {shlex.quote(str(command))} /absolute/path/to/received-project")
    if str(binary_directory) not in os.environ.get("PATH", "").split(os.pathsep):
        print(f'For this shell: export PATH={shlex.quote(str(binary_directory))}:"$PATH"')
    print("To remove this installation after checking the paths:")
    print(f"  unlink -- {shlex.quote(str(command))}")
    print(f"  rm -rf -- {shlex.quote(str(prefix))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
