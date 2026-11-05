"""Command-line options and output; scan execution lives in scanner.scan."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Sequence

from reposcan import __version__, scanner
from reposcan.models import ScanError, ScanOptions, ScanResult
from reposcan.reporting import render_markdown, result_payload
from reposcan.settings import (
    DEFAULT_IGNORE_CONFIG,
    DEFAULT_MAX_ENTRIES,
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_SIZE,
    DEFAULT_MAX_TOTAL_BYTES,
    DEFAULT_RULES,
    DEFAULT_TIMEOUT,
    EXIT_USAGE,
)
from reposcan.terminal import Colors, color_enabled, print_text


class RepoScanArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")

def positive_integer(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number

def text_width(value: str) -> int:
    number = positive_integer(value)
    if not 40 <= number <= 240:
        raise argparse.ArgumentTypeError("must be between 40 and 240 columns")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = RepoScanArgumentParser(
        prog="reposcan",
        description="Review unfamiliar repositories before trusting, installing, or running their code.",
    )
    parser.add_argument("target", type=Path, help="Path to the project/dev-task to scan")
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES, help="Directory containing .yar files")
    parser.add_argument("--ignore-config", type=Path, default=DEFAULT_IGNORE_CONFIG, help="Shared ignore pattern file")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    parser.add_argument("--format", choices=("text", "json", "markdown"), default="text", help="Output format")
    parser.add_argument("--version", action="version", version=f"RepoScan {__version__}")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto", help="Colorize text output")
    parser.add_argument(
        "--width", type=text_width,
        help="Text width in columns (40-240); default: terminal width up to 120, or 100 when redirected",
    )
    parser.add_argument("--max-size", type=positive_integer, default=DEFAULT_MAX_SIZE, help="Maximum bytes per file")
    parser.add_argument("--max-files", type=positive_integer, default=DEFAULT_MAX_FILES, help="Maximum selected files")
    parser.add_argument(
        "--max-total-bytes",
        type=positive_integer,
        default=DEFAULT_MAX_TOTAL_BYTES,
        help="Maximum total bytes selected",
    )
    parser.add_argument(
        "--max-entries",
        type=positive_integer,
        default=DEFAULT_MAX_ENTRIES,
        help="Maximum filesystem entries visited",
    )
    parser.add_argument("--timeout", type=positive_integer, default=DEFAULT_TIMEOUT,
                        help="Per-file matching timeout, including static review (POSIX main thread)")
    parser.add_argument(
        "--engine",
        choices=("auto", "yara-python", "yara-cli", "lite"),
        default="auto",
        help="Scanning engine; lite is heuristic-only and must be selected explicitly",
    )
    parser.add_argument("--lite", action="store_true", help="Compatibility alias for --engine lite")
    parser.add_argument(
        "--strict-yara",
        action="store_true",
        help="Compatibility option; canonical YARA is now the default",
    )
    return parser


def emit_result(result: ScanResult, *, output_format: str, color: str, width: int | None) -> int:
    """Render a completed service result without changing its exit semantics."""
    if output_format == "json":
        print(json.dumps(result_payload(result), indent=2, sort_keys=True))
    elif output_format == "markdown":
        print(render_markdown(result_payload(result)), end="")
    else:
        print_text(
            result.findings, result.errors, result.verdict, result.exit_code,
            result.engine, result.target, result.complete, result.status, result.stats,
            Colors(color_enabled(color)), width,
        )
    return result.exit_code


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    target = Path(os.path.abspath(os.fspath(args.target)))
    requested_engine = args.engine
    usage_error = ""
    if args.json and args.format not in {"text", "json"}:
        usage_error = "--json conflicts with --format markdown"
    elif args.lite and requested_engine not in ("auto", "lite"):
        usage_error = "--lite cannot be combined with a different --engine"
    else:
        if args.lite:
            requested_engine = "lite"
        if args.strict_yara and requested_engine == "lite":
            usage_error = "--strict-yara cannot be combined with lite mode"

    options = ScanOptions(
        target=target, rules=args.rules, ignore_config=args.ignore_config, engine=requested_engine,
        max_size=args.max_size, max_files=args.max_files, max_total_bytes=args.max_total_bytes,
        max_entries=args.max_entries, timeout=args.timeout,
    )
    if usage_error:
        result = ScanResult(
            options=options, target=target, engine=requested_engine,
            errors=[ScanError("usage", usage_error)], exit_code=EXIT_USAGE,
        )
    else:
        result = scanner.scan(options)
    return emit_result(
        result, output_format="json" if args.json else args.format, color=args.color, width=args.width,
    )
