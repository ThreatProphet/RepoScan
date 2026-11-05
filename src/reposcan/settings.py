"""Packaged defaults and explicit scan/output limits."""

from importlib.resources import files as package_files
from pathlib import Path

ROOT = Path(str(package_files("reposcan")))
DEFAULT_RULES = ROOT / "rules"
DEFAULT_IGNORE_CONFIG = ROOT / "config" / "scan_ignore.txt"
SEVERITY_SCORE = {"critical": 90, "high": 70, "medium": 40, "low": 10}
SEVERITY_LABEL = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
}
DEFAULT_MAX_SIZE = 2 * 1024 * 1024
DEFAULT_MAX_FILES = 10_000
DEFAULT_MAX_TOTAL_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_ENTRIES = 100_000
DEFAULT_TIMEOUT = 30
EXIT_USAGE = 64
EXIT_ENGINE_UNAVAILABLE = 69
EXIT_OPERATIONAL_FAILURE = 70
MAX_EVIDENCE = 32
MAX_SKIP_DETAILS = 128
SCHEMA_VERSION = "1.0"
MAX_ENGINE_OUTPUT = 8 * 1024 * 1024
