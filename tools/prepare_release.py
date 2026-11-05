#!/usr/bin/env python3
"""Validate a stable release tag and prepare its changelog notes.

This maintainer helper runs under the release job's Python 3.12.
It does not change RepoScan's Python 3.10+ runtime requirement.
"""

from __future__ import annotations

import argparse
import ast
import datetime
import re
import subprocess
import sys
import tomllib
from pathlib import Path


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if result.returncode:
        raise ValueError(result.stderr.strip() or f"git {' '.join(arguments)} failed")
    return result.stdout.strip()


def prepare(root: Path, tag: str, output_directory: Path) -> dict[str, str]:
    require(
        re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", tag) is not None,
        "release tags must be stable vX.Y.Z versions, for example v0.2.1",
    )
    version = tag[1:]
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    require(project["name"] == "threatprophet-reposcan", "unexpected Python distribution name")
    require(project["version"] == version, "tag version differs from pyproject.toml")

    tree = ast.parse((root / "src/reposcan/__init__.py").read_text(encoding="utf-8"))
    versions = [
        node.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets)
    ]
    require(
        len(versions) == 1 and isinstance(versions[0], ast.Constant) and versions[0].value == version,
        "tag version differs from the single literal runtime __version__",
    )

    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    heading = re.compile(rf"(?m)^## {re.escape(version)} - (\d{{4}}-\d{{2}}-\d{{2}})[ \t]*$")
    matches = list(heading.finditer(changelog))
    require(len(matches) == 1, "CHANGELOG.md must contain one dated entry for the release version")
    datetime.date.fromisoformat(matches[0].group(1))
    remaining = changelog[matches[0].end():]
    next_heading = re.search(r"(?m)^## ", remaining)
    notes = remaining[:next_heading.start()].strip() if next_heading else remaining.strip()
    require(bool(notes), "the release changelog entry is empty")

    commit = git(root, "rev-parse", "HEAD")
    tag_commit = git(root, "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}")
    require(tag_commit == commit, "the release tag does not identify the checked-out commit")
    main_commit = git(root, "rev-parse", "--verify", "refs/remotes/origin/main^{commit}")
    ancestry = subprocess.run(
        ["git", "-C", str(root), "merge-base", "--is-ancestor", commit, main_commit],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    require(ancestry.returncode == 0, "the release commit must already be merged into origin/main")

    output_directory.mkdir(parents=True, exist_ok=True)
    (output_directory / "release-notes.md").write_text(notes + "\n", encoding="utf-8")
    return {
        "tag": tag,
        "version": version,
        "commit": commit,
        "wheel": f"threatprophet_reposcan-{version}-py3-none-any.whl",
        "sdist": f"threatprophet_reposcan-{version}.tar.gz",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()
    try:
        metadata = prepare(args.root.resolve(), args.tag, args.output_directory.resolve())
    except (OSError, ValueError, KeyError, SyntaxError, subprocess.SubprocessError) as error:
        print(f"Release preparation failed: {error}", file=sys.stderr)
        return 1
    for key, value in metadata.items():
        print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
