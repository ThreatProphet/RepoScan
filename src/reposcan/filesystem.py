"""Bounded target-file discovery and reads without symbolic-link traversal."""

from __future__ import annotations

import fnmatch
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from reposcan.models import Discovery, ScanError, ScannableFile, ScanStats


@dataclass
class ReadBudget:
    maximum: int
    consumed: int = 0

    @property
    def remaining(self) -> int:
        return self.maximum - self.consumed

    def charge(self, amount: int) -> None:
        if amount > self.remaining:
            raise ResourceLimitError(
                f"maximum total selected bytes exceeded ({self.maximum})"
            )
        self.consumed += amount


class ResourceLimitError(OSError):
    """A configured scan resource bound was reached."""


def load_ignore_patterns(path: Path, data: bytes | None = None) -> list[str]:
    """Load path globs, failing closed when the requested config is unusable."""
    lines = (path.read_bytes() if data is None else data).decode("utf-8").splitlines()
    return [line for raw in lines if (line := raw.strip()) and not line.startswith("#")]


def ignored_relative(relative_path: Path, patterns: Sequence[str]) -> bool:
    """Match normalized POSIX paths; ``dir/**`` also excludes ``dir`` itself."""
    candidate = relative_path.as_posix()
    for raw_pattern in patterns:
        pattern = raw_pattern.replace("\\", "/")
        if pattern.startswith("/"):
            pattern = pattern[1:]
        if pattern.endswith("/**"):
            directory_pattern = pattern[:-3].rstrip("/")
            if fnmatch.fnmatchcase(candidate, directory_pattern):
                return True
        if pattern.endswith("/"):
            directory_pattern = pattern.rstrip("/")
            if fnmatch.fnmatchcase(candidate, directory_pattern):
                return True
            pattern = f"{directory_pattern}/**"
        if fnmatch.fnmatchcase(candidate, pattern):
            return True
    return False


def _resource_error(message: str, path: Path) -> ScanError:
    return ScanError("resource-limit", message, str(path))


def _open_flags(*, directory: bool) -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise OSError("this platform cannot safely disable symbolic-link traversal")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    if directory:
        if not hasattr(os, "O_DIRECTORY"):
            raise OSError("this platform cannot safely open directory descriptors")
        flags |= os.O_DIRECTORY
    return flags


def open_path_without_symlinks(path: Path, *, directory: bool) -> int:
    """Open an absolute path one anchored, non-symlink component at a time."""
    if not path.is_absolute():
        raise OSError("safe path opening requires an absolute path")
    components = path.parts[1:]
    current = os.open(path.anchor, _open_flags(directory=True))
    try:
        if not components:
            if not directory:
                raise OSError("the filesystem root is not a regular file")
            return current
        for index, component in enumerate(components):
            final = index == len(components) - 1
            next_descriptor = os.open(
                component,
                _open_flags(directory=directory if final else True),
                dir_fd=current,
            )
            os.close(current)
            current = next_descriptor
        return current
    except BaseException:
        os.close(current)
        raise


def verify_identity(file_stat: os.stat_result, device: int, inode: int) -> None:
    if (file_stat.st_dev, file_stat.st_ino) != (device, inode):
        raise OSError("entry identity changed after discovery")


def discover_files(
    target: Path,
    target_stat: os.stat_result,
    max_size: int,
    max_files: int,
    max_total_bytes: int,
    max_entries: int,
    ignore_patterns: Sequence[str],
) -> Discovery:
    """Discover regular files via anchored directory descriptors."""
    result = Discovery()

    def admit(path: Path, relative: Path, file_stat: os.stat_result) -> bool:
        result.stats.regular_files += 1
        if file_stat.st_size > max_size:
            result.stats.skipped_oversize += 1
            result.stats.note_skip(relative.as_posix(), "oversize")
            return True
        if result.stats.files_selected >= max_files:
            result.stats.skipped_resource_limit += 1
            result.stats.note_skip(relative.as_posix(), "file-limit")
            result.errors.append(
                _resource_error(f"maximum file count exceeded ({max_files})", path)
            )
            return False
        result.files.append(
            ScannableFile(
                path=path,
                display_path=target.name if path == target else relative.as_posix(),
                device=file_stat.st_dev,
                inode=file_stat.st_ino,
            )
        )
        result.stats.files_selected += 1
        return True

    if stat.S_ISREG(target_stat.st_mode):
        result.stats.entries_seen = 1
        try:
            descriptor = open_path_without_symlinks(target, directory=False)
            try:
                current_stat = os.fstat(descriptor)
                if not stat.S_ISREG(current_stat.st_mode):
                    raise OSError("target is no longer a regular file")
                verify_identity(current_stat, target_stat.st_dev, target_stat.st_ino)
            finally:
                os.close(descriptor)
        except OSError as exc:
            result.errors.append(ScanError("file-admission", str(exc), str(target)))
            return result
        admit(target, Path(target.name), current_stat)
        return result

    pending: list[tuple[Path, Path, int, int]] = [
        (target, Path("."), target_stat.st_dev, target_stat.st_ino)
    ]
    while pending:
        directory, relative_directory, expected_device, expected_inode = pending.pop()
        result.stats.directories_visited += 1
        directory_descriptor: int | None = None
        child_directories: list[tuple[Path, Path, int, int]] = []
        try:
            directory_descriptor = open_path_without_symlinks(directory, directory=True)
            directory_stat = os.fstat(directory_descriptor)
            verify_identity(directory_stat, expected_device, expected_inode)
            entries: list[os.DirEntry[str]] = []
            remaining_entries = max_entries - result.stats.entries_seen
            with os.scandir(directory_descriptor) as iterator:
                for entry in iterator:
                    entries.append(entry)
                    if len(entries) > remaining_entries:
                        result.stats.entries_seen = max_entries + 1
                        result.stats.skipped_resource_limit += 1
                        result.errors.append(
                            _resource_error(
                                f"maximum filesystem entry count exceeded ({max_entries})",
                                directory,
                            )
                        )
                        return result
            result.stats.entries_seen += len(entries)
            for entry in sorted(entries, key=lambda item: os.fsencode(item.name)):
                path = directory / entry.name
                relative = (
                    Path(entry.name)
                    if relative_directory == Path(".")
                    else relative_directory / entry.name
                )
                if ignored_relative(relative, ignore_patterns):
                    result.stats.ignored += 1
                    result.stats.note_skip(relative.as_posix(), "ignore-policy (directory may be pruned)")
                    continue
                try:
                    entry_stat = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    result.errors.append(ScanError("entry-stat", str(exc), str(path)))
                    continue
                mode = entry_stat.st_mode
                if stat.S_ISLNK(mode):
                    result.stats.skipped_symlinks += 1
                    result.stats.note_skip(relative.as_posix(), "symlink")
                elif stat.S_ISDIR(mode):
                    child_directories.append(
                        (path, relative, entry_stat.st_dev, entry_stat.st_ino)
                    )
                elif stat.S_ISREG(mode):
                    if not admit(path, relative, entry_stat):
                        return result
                else:
                    result.stats.skipped_special += 1
                    result.stats.note_skip(relative.as_posix(), "special-file")
        except OSError as exc:
            result.errors.append(ScanError("directory-read", str(exc), str(directory)))
            continue
        finally:
            if directory_descriptor is not None:
                os.close(directory_descriptor)
        pending.extend(reversed(child_directories))
    return result


def read_regular_file(
    candidate: ScannableFile,
    max_size: int,
    budget: ReadBudget,
    stats: ScanStats,
) -> bytes:
    """Read the discovered inode without following any pathname symlink."""
    descriptor = open_path_without_symlinks(candidate.path, directory=False)
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise OSError("entry is no longer a regular file")
        verify_identity(file_stat, candidate.device, candidate.inode)
        chunks: list[bytes] = []
        available_total = budget.remaining
        allowed = min(max_size, available_total)
        remaining = allowed + 1
        file_bytes = 0
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
            file_bytes += len(chunk)
            chargeable = min(len(chunk), budget.remaining)
            budget.charge(chargeable)
            stats.selected_bytes = budget.consumed
            if chargeable < len(chunk):
                raise ResourceLimitError(
                    f"maximum total selected bytes exceeded ({budget.maximum})"
                )
            if file_bytes > max_size:
                raise OSError(f"file grew beyond maximum size ({max_size})")
        data = b"".join(chunks)
        return data
    finally:
        os.close(descriptor)
