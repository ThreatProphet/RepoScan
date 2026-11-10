#!/usr/bin/env python3
"""Capture the published launcher's real output against the inert demo fixture.

Run from a trusted RepoScan checkout. This Linux/POSIX maintainer tool creates
a fresh work directory, downloads the release launcher, verifies it, and runs
the same simple scan command shown in the README. The target is never executed.
"""

from __future__ import annotations

import argparse
import errno
import fcntl
import hashlib
import json
import os
import pty
import re
import select
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.4.0"
LAUNCHER_URL = f"https://github.com/ThreatProphet/RepoScan/releases/download/v{VERSION}/reposcan-run.sh"
LAUNCHER_SHA256 = "fbec95c102e3b33691c9b14d232f12eb252c72409813eac9842244b8201ec2bb"
WHEEL_SHA256 = "37b81a1cf574be974d1304885518256b5b65f2f070bbe11630e01e5aa26e2e85"
SGR = re.compile(r"\x1b\[[0-9;]*m")
COLUMNS = 88
ROWS = 32


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture_hashes(root: Path) -> dict[str, str]:
    hashes = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"Demo fixture must not contain symlinks: {path.name}")
        if path.is_file():
            hashes[path.relative_to(root).as_posix()] = sha256(path)
        elif not path.is_dir():
            raise ValueError("Demo fixture contains a special file")
    return hashes


def capture_tty(argv: list[str], cwd: Path, environment: dict[str, str]) -> dict[str, object]:
    """Give stdout a real 88-column PTY; retain stderr separately and verbatim."""
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLUMNS, 0, 0))
    started = time.monotonic()
    chunks: list[bytes] = []
    process = None
    try:
        with tempfile.TemporaryFile() as errors:
            process = subprocess.Popen(
                argv, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                stdout=slave, stderr=errors, start_new_session=True,
            )
            os.close(slave)
            slave = -1
            while True:
                if time.monotonic() - started > 600:
                    raise TimeoutError("Launcher capture exceeded ten minutes")
                readable, _, _ = select.select([master], [], [], 1)
                if not readable:
                    continue
                try:
                    block = os.read(master, 65536)
                except OSError as error:
                    if error.errno == errno.EIO:
                        break
                    raise
                if not block:
                    break
                chunks.append(block)
            status = process.wait(timeout=30)
            errors.seek(0)
            stderr = errors.read().decode("utf-8")
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        if slave != -1:
            os.close(slave)
        os.close(master)
    return {
        "argv": argv,
        "exit_code": status,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "stdout": b"".join(chunks).decode("utf-8"),
        "stderr": stderr,
    }


def validate_report(scan: dict[str, object]) -> None:
    plain = SGR.sub("", str(scan["stdout"])).replace("\r\n", "\n")
    lines = plain.splitlines()
    anchors = {
        0: f"RepoScan {VERSION}",
        6: "[HIGH]  Finding 1/3",
        20: "[MEDIUM]  Finding 2/3",
        30: "[LOW]  Finding 3/3",
        39: "COVERAGE",
        44: "SUMMARY",
        53: "Exit code: 1",
    }
    if scan["exit_code"] != 1:
        raise ValueError(f"Expected the fixture's review exit code 1, got {scan['exit_code']}")
    if len(lines) != 54 or any(lines[index] != expected for index, expected in anchors.items()):
        raise ValueError("Report layout changed; inspect the capture before updating its page boundaries")
    if "\x1b" in plain or "\r" in plain or max(map(len, lines)) > COLUMNS:
        raise ValueError("Report contains unsupported controls or exceeds its captured terminal width")
    if "Verdict:  review-needed" not in lines or "Scanned:  2/2 selected files" not in lines:
        raise ValueError("Unexpected fixture verdict or scan coverage")


def capture(work: Path, output: Path) -> None:
    if not work.is_absolute():
        raise ValueError("--work-dir must be an absolute path")
    work.mkdir(mode=0o700, exist_ok=False)
    target = work / "received-project"
    fixture = ROOT / "tests/fixtures/web3market-entry"
    original = fixture_hashes(fixture)
    if len(original) != 2 or not all(name.endswith(".fixture") for name in original):
        raise ValueError("Expected exactly the two public inert Web3Market fixture files")
    shutil.copytree(fixture, target)

    print("[1/4] Download the published launcher using the README command", flush=True)
    download_argv = ["curl", "-fL", "-o", "reposcan-run.sh", LAUNCHER_URL]
    started = time.monotonic()
    download = subprocess.run(download_argv, cwd=work, capture_output=True, text=True, timeout=120)
    if download.returncode != 0:
        raise ValueError(f"Launcher download failed with exit {download.returncode}")
    if sha256(work / "reposcan-run.sh") != LAUNCHER_SHA256:
        raise ValueError("Downloaded launcher differs from the verified release asset")
    download_result = {
        "argv": download_argv,
        "exit_code": download.returncode,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "stdout": download.stdout,
        "stderr": download.stderr,
    }

    print("[2/4] Capture the real first scan in an 88-column terminal; runtime setup may take a few minutes", flush=True)
    environment = os.environ.copy()
    for name in ("NO_COLOR", "FORCE_COLOR", "CLICOLOR_FORCE"):
        environment.pop(name, None)
    environment.update({
        "TERM": "xterm-256color", "COLORTERM": "truecolor",
        "REPOSCAN_RUN_HOME": str(work / "private-runtime"),
    })
    scan = capture_tty(["sh", "./reposcan-run.sh", str(target)], work, environment)
    (work / "scan-stdout.ansi").write_text(str(scan["stdout"]), encoding="utf-8")
    (work / "scan-stderr.txt").write_text(str(scan["stderr"]), encoding="utf-8")

    print("[3/4] Verify the real exit status, all report pages, and unchanged fixture files", flush=True)
    validate_report(scan)
    if fixture_hashes(target) != original:
        raise ValueError("The fixture copy changed during the scan")
    if sha256(work / "reposcan-run.sh") != LAUNCHER_SHA256:
        raise ValueError("The launcher changed during the scan")
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout.strip()
    document = {
        "schema_version": 1,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "source_commit": commit,
        "capture_method": "POSIX PTY, stdout and stderr captured separately",
        "release": {
            "version": VERSION, "launcher_url": LAUNCHER_URL,
            "launcher_sha256": LAUNCHER_SHA256, "wheel_sha256": WHEEL_SHA256,
        },
        "terminal": {"columns": COLUMNS, "rows": ROWS},
        "runtime_cache": "fresh at scan start",
        "fixture_integrity": "unchanged",
        "fixtures": original,
        "download": download_result,
        "scan": scan,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"[4/4] Saved verified capture to {output}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=Path("/tmp/reposcan-demo-v040"))
    parser.add_argument("--output", type=Path, default=ROOT / "docs/demo/capture.json")
    args = parser.parse_args()
    try:
        capture(args.work_dir, args.output)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"Demo capture failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
