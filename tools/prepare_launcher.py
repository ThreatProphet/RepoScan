#!/usr/bin/env python3
"""Bind the release launcher to one exact, validated RepoScan wheel.

The checked-in launcher targets an already published release. Release jobs
generate their own copy after building the wheel, so a new release cannot
silently launch an older scanner. This helper does not upload either file.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

from verify_wheel import VerificationError, require, wheel_version

PIN_NAMES = ("REPOSCAN_VERSION", "REPOSCAN_WHEEL_SHA256")


def launcher_pins(text: str) -> dict[str, str]:
    """Read exactly one literal assignment per release pin, without shell eval."""
    pins = {}
    for name in PIN_NAMES:
        matches = re.findall(rf"(?m)^{name}='([^'\n]+)'$", text)
        require(len(matches) == 1, f"launcher must contain one literal {name} assignment")
        pins[name] = matches[0]
    require(
        re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", pins["REPOSCAN_VERSION"]) is not None,
        "launcher version must be a stable X.Y.Z release",
    )
    require(re.fullmatch(r"[a-f0-9]{64}", pins["REPOSCAN_WHEEL_SHA256"]) is not None, "invalid wheel SHA-256")
    return pins


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def prepare(wheel: Path, template: Path, output: Path) -> dict[str, str]:
    version = wheel_version(wheel)
    require(
        re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version) is not None,
        "launcher wheel version must be a stable X.Y.Z release",
    )
    require(
        wheel.name == f"threatprophet_reposcan-{version}-py3-none-any.whl",
        "wheel filename must match its version and the pure-Python release artifact",
    )
    text = template.read_text(encoding="utf-8")
    require(text.startswith("#!/bin/sh\n"), "launcher template must be a POSIX sh script")
    launcher_pins(text)
    pins = {"REPOSCAN_VERSION": version, "REPOSCAN_WHEEL_SHA256": file_sha256(wheel)}
    for name, value in pins.items():
        text, count = re.subn(rf"(?m)^{name}='[^'\n]+'$", f"{name}='{value}'", text)
        require(count == 1, f"could not replace launcher pin {name}")
    require(launcher_pins(text) == pins, "generated launcher does not match the exact wheel")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8")
    output.chmod(0o755)
    return pins


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path, help="Exact trusted wheel that will be uploaded")
    parser.add_argument("--output", type=Path, required=True, help="Destination for the generated release launcher")
    parser.add_argument(
        "--template", type=Path, default=Path(__file__).resolve().parents[1] / "reposcan-run.sh"
    )
    args = parser.parse_args()
    try:
        wheel = args.wheel.resolve(strict=True)
        require(wheel.is_file(), "wheel is not a regular file")
        pins = prepare(wheel, args.template.resolve(strict=True), args.output)
    except (VerificationError, OSError) as error:
        print(f"Launcher preparation failed: {error}", file=sys.stderr)
        return 1
    print(f"Prepared {args.output}: RepoScan {pins['REPOSCAN_VERSION']}, wheel SHA-256 {pins['REPOSCAN_WHEEL_SHA256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
