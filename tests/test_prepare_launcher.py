from __future__ import annotations

import hashlib
import importlib.util
import zipfile
from pathlib import Path
from types import ModuleType

import pytest
from conftest import REPO_ROOT


@pytest.fixture
def generator(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    monkeypatch.syspath_prepend(str(REPO_ROOT / "tools"))
    spec = importlib.util.spec_from_file_location("reposcan_prepare_launcher", REPO_ROOT / "tools/prepare_launcher.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_wheel(directory: Path, *, version: str = "1.2.3", name: str = "threatprophet-reposcan") -> Path:
    wheel = directory / f"threatprophet_reposcan-{version}-py3-none-any.whl"
    info = f"threatprophet_reposcan-{version}.dist-info/"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            info + "METADATA",
            f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n"
            "License-Expression: MIT\nLicense-File: LICENSE\n",
        )
        archive.writestr(info + "licenses/LICENSE", (REPO_ROOT / "LICENSE").read_bytes())
    return wheel


def template(directory: Path, suffix: str = "") -> Path:
    path = directory / "launcher-template.sh"
    path.write_text(
        "#!/bin/sh\nREPOSCAN_VERSION='0.3.1'\nREPOSCAN_WHEEL_SHA256='" + "0" * 64 + "'\n"
        "printf '%s\\n' \"$REPOSCAN_VERSION\"\n" + suffix,
        encoding="utf-8",
    )
    return path


def test_generated_launcher_is_bound_to_exact_wheel(generator: ModuleType, tmp_path: Path) -> None:
    wheel = make_wheel(tmp_path)
    original = template(tmp_path)
    output = tmp_path / "release" / "reposcan-run.sh"
    pins = generator.prepare(wheel, original, output)
    assert pins == {
        "REPOSCAN_VERSION": "1.2.3",
        "REPOSCAN_WHEEL_SHA256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
    }
    assert generator.launcher_pins(output.read_text()) == pins
    assert generator.launcher_pins(original.read_text())["REPOSCAN_VERSION"] == "0.3.1"
    assert "printf '%s\\n' \"$REPOSCAN_VERSION\"" in output.read_text()
    assert output.stat().st_mode & 0o111


@pytest.mark.parametrize("problem", ["distribution", "filename", "unstable-version", "duplicate-pin"])
def test_invalid_release_inputs_do_not_produce_launcher(
    generator: ModuleType, tmp_path: Path, problem: str
) -> None:
    wheel = make_wheel(
        tmp_path,
        name="unrelated" if problem == "distribution" else "threatprophet-reposcan",
        version="1.2.3rc1" if problem == "unstable-version" else "1.2.3",
    )
    if problem == "filename":
        renamed = tmp_path / "threatprophet_reposcan-9.9.9-py3-none-any.whl"
        wheel.rename(renamed)
        wheel = renamed
    original = template(tmp_path, "REPOSCAN_VERSION='9.9.9'\n" if problem == "duplicate-pin" else "")
    output = tmp_path / "must-not-exist.sh"
    with pytest.raises(generator.VerificationError):
        generator.prepare(wheel, original, output)
    assert not output.exists()
