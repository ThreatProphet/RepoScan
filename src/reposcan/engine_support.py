"""Bounded matching and shared YARA metadata, independent of the YARA binding.

The metadata reader is a lexer, not a rule compiler. Native YARA must still
compile the rules. Rule files must be self-contained, have globally unique rule
IDs, and declare a supported severity. Includes are deliberately rejected so
both adapters use the same inspected rule set and metadata.
"""

from __future__ import annotations

import math
import signal
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import FrameType
from typing import Any, Iterable, Iterator

MAX_RULE_FILE_BYTES = 4 * 1024 * 1024
MAX_RULE_PACK_BYTES = 16 * 1024 * 1024
MAX_RULE_FILES = 256
MAX_RULES = 10_000
SEVERITIES = frozenset({"low", "medium", "high", "critical"})
CONFIDENCES = frozenset({"low", "medium", "high"})
_SPACE = b" \t\r\n\v\f"
_IDENT_START = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_"
_IDENT_CONTINUE = _IDENT_START + b"0123456789"
_HEX = b"0123456789abcdefABCDEF"
_ESCAPES = {ord("n"): b"\n", ord("r"): b"\r", ord("t"): b"\t", ord('"'): b'"', ord("\\"): b"\\"}


class MatchingTimeout(TimeoutError):
    """A per-file Python matching deadline was exceeded."""


class MatchingUnavailableError(RuntimeError):
    """The current execution context cannot enforce a matching deadline."""


@contextmanager
def bounded_matching(timeout_seconds: float) -> Iterator[None]:
    """Interrupt Python regex/review work on the supported POSIX main thread.

    The CLI owns its matching interval. An existing real-time alarm is rejected
    without changing it, rather than silently postponing or replacing another
    caller's deadline. This also deliberately rejects nested matching intervals.
    A native extension may defer Python signals; this helper does not replace
    native YARA's own timeout or subprocess timeouts.
    """
    timeout = float(timeout_seconds)
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("matching timeout must be a positive finite number")
    if threading.current_thread() is not threading.main_thread():
        raise MatchingUnavailableError("bounded matching requires the main thread")
    required = ("SIGALRM", "ITIMER_REAL", "getitimer", "setitimer")
    if not all(hasattr(signal, name) for name in required):
        raise MatchingUnavailableError("bounded matching requires POSIX real-time signals")
    if hasattr(signal, "pthread_sigmask") and signal.SIGALRM in signal.pthread_sigmask(signal.SIG_BLOCK, set()):
        raise MatchingUnavailableError("bounded matching requires an unblocked SIGALRM")

    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    if previous_timer != (0.0, 0.0):
        raise MatchingUnavailableError("bounded matching cannot replace an active real-time alarm")
    previous_handler = signal.getsignal(signal.SIGALRM)

    def timed_out(signum: int, frame: FrameType | None) -> None:
        raise MatchingTimeout(f"matching timed out after {timeout:g} seconds")

    signal.signal(signal.SIGALRM, timed_out)
    try:
        signal.setitimer(signal.ITIMER_REAL, timeout)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        signal.setitimer(signal.ITIMER_REAL, *previous_timer)


@dataclass(frozen=True, slots=True)
class _Token:
    kind: str
    value: Any
    offset: int


class _RuleTokens:
    """Single-token lookahead keeps memory bounded by source and metadata size."""

    def __init__(self, source: bytes, label: str) -> None:
        self.source = source
        self.label = label
        self.tokens = self._lex()
        self.current = next(self.tokens)

    def error(self, message: str, offset: int | None = None) -> ValueError:
        position = self.current.offset if offset is None else offset
        line = self.source.count(b"\n", 0, position) + 1
        return ValueError(f"{self.label}:{line}: {message}")

    def pop(self) -> _Token:
        result = self.current
        if result.kind != "eof":
            self.current = next(self.tokens)
        return result

    def expect(self, kind: str, value: str | None = None) -> _Token:
        token = self.current
        if token.kind != kind or (value is not None and token.value != value):
            raise self.error(f"expected {value or kind!r}")
        return self.pop()

    def _string(self, start: int) -> tuple[bytes, int]:
        data = self.source
        output = bytearray()
        position = start + 1
        while position < len(data):
            byte = data[position]
            if byte == ord('"'):
                return bytes(output), position + 1
            if byte in b"\r\n":
                raise self.error("unterminated quoted string", start)
            if byte != ord("\\"):
                output.append(byte)
                position += 1
                continue
            position += 1
            if position >= len(data):
                break
            escape = data[position]
            if escape in _ESCAPES:
                output.extend(_ESCAPES[escape])
                position += 1
            elif escape == ord("x"):
                digits = data[position + 1 : position + 3]
                if len(digits) != 2 or any(value not in _HEX for value in digits):
                    raise self.error("invalid hexadecimal string escape", position)
                output.append(int(digits, 16))
                position += 3
            else:
                raise self.error("unsupported quoted-string escape", position)
        raise self.error("unterminated quoted string", start)

    def _regex_end(self, start: int) -> int:
        # YARA uses backslash for arithmetic division. A non-comment slash
        # therefore opens a regular-expression literal, including module args.
        position = start + 1
        while position < len(self.source):
            byte = self.source[position]
            if byte == ord("\\"):
                position += 2
            elif byte == ord("/"):
                return position + 1
            elif byte in b"\r\n":
                raise self.error("unterminated regular expression", start)
            else:
                position += 1
        raise self.error("unterminated regular expression", start)

    def _lex(self) -> Iterator[_Token]:
        data = self.source
        position = 3 if data.startswith(b"\xef\xbb\xbf") else 0
        while position < len(data):
            byte = data[position]
            if byte in _SPACE:
                position += 1
                continue
            if data.startswith(b"//", position):
                end = data.find(b"\n", position + 2)
                position = len(data) if end < 0 else end + 1
                continue
            if data.startswith(b"/*", position):
                end = data.find(b"*/", position + 2)
                if end < 0:
                    raise self.error("unterminated block comment", position)
                position = end + 2
                continue
            start = position
            if byte == ord('"'):
                value, position = self._string(start)
                yield _Token("string", value, start)
            elif byte == ord("/"):
                position = self._regex_end(start)
                yield _Token("regex", None, start)
            elif byte in _IDENT_START:
                position += 1
                while position < len(data) and data[position] in _IDENT_CONTINUE:
                    position += 1
                yield _Token("identifier", data[start:position].decode("ascii"), start)
            elif byte in b"0123456789":
                # Preserve the spelling until a metadata value needs decoding.
                # Long contiguous hex strings are valid pattern bytes, not
                # metadata integers, and must not acquire an integer-size cap.
                position += 1
                while position < len(data) and data[position] in _IDENT_CONTINUE:
                    position += 1
                yield _Token("integer", data[start:position], start)
            else:
                position += 1
                yield _Token("symbol", chr(byte), start)
        yield _Token("eof", None, len(data))


def _metadata_value(tokens: _RuleTokens) -> str | int | bool:
    token = tokens.pop()
    if token.kind == "string":
        if b"\x00" in token.value:
            raise tokens.error("NUL bytes are not supported in metadata", token.offset)
        try:
            return token.value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise tokens.error("metadata strings must be valid UTF-8", token.offset) from exc
    if token.kind == "identifier" and token.value in ("true", "false"):
        return token.value == "true"
    negative = token.kind == "symbol" and token.value == "-"
    if negative:
        token = tokens.expect("integer")
    if token.kind == "integer":
        literal = token.value
        if len(literal) > 26:
            raise tokens.error("metadata integer exceeds the supported 64-bit range", token.offset)
        multiplier = 1
        if literal[-2:] in (b"KB", b"MB"):
            multiplier = 1024 if literal[-2:] == b"KB" else 1024 * 1024
            literal = literal[:-2]
        base = 10
        if literal[:2].lower() in (b"0x", b"0o"):
            base = 16 if literal[1:2].lower() == b"x" else 8
            literal = literal[2:]
        digits = _HEX if base == 16 else (b"01234567" if base == 8 else b"0123456789")
        if not literal or any(byte not in digits for byte in literal):
            raise tokens.error("invalid metadata integer", token.offset)
        value = int(literal, base) * multiplier * (-1 if negative else 1)
        if not -(2**63) <= value < 2**63:
            raise tokens.error("metadata integer exceeds the supported 64-bit range", token.offset)
        return value
    raise tokens.error("metadata values must be strings, integers or booleans", token.offset)


def _metadata_section(tokens: _RuleTokens, metadata: dict[str, Any]) -> None:
    tokens.expect("symbol", ":")
    while tokens.current.kind != "eof":
        token = tokens.current
        if token.kind == "symbol" and token.value == "}":
            return
        if token.kind == "identifier" and token.value in ("strings", "condition"):
            return
        key = tokens.expect("identifier").value
        if key in metadata:
            raise tokens.error(f"duplicate metadata identifier {key!r}")
        tokens.expect("symbol", "=")
        metadata[key] = _metadata_value(tokens)
    raise tokens.error("unterminated metadata section")


def _validate_metadata(tokens: _RuleTokens, name: str, metadata: dict[str, Any]) -> None:
    severity = metadata.get("severity")
    if not isinstance(severity, str) or severity.lower() not in SEVERITIES:
        raise tokens.error(f"rule {name!r} must declare severity as low, medium, high or critical")
    for key in ("description", "category", "confidence", "reports", "reference"):
        if key in metadata and not isinstance(metadata[key], str):
            raise tokens.error(f"rule {name!r} metadata {key!r} must be a string")
    confidence = metadata.get("confidence")
    if confidence is not None and confidence.lower() not in CONFIDENCES:
        raise tokens.error(f"rule {name!r} confidence must be low, medium or high")


def _file_metadata(source: bytes, label: str) -> Iterator[tuple[str, dict[str, Any]]]:
    tokens = _RuleTokens(source, label)
    while tokens.current.kind != "eof":
        while tokens.current.kind == "identifier" and tokens.current.value in ("private", "global"):
            tokens.pop()
        directive = tokens.expect("identifier")
        if directive.value == "include":
            raise tokens.error("include directives are not supported; supply self-contained rule files", directive.offset)
        if directive.value == "import":
            tokens.expect("string")
            continue
        if directive.value != "rule":
            raise tokens.error("expected a rule or module import", directive.offset)
        name = tokens.expect("identifier").value
        if tokens.current.kind == "symbol" and tokens.current.value == ":":
            tokens.pop()
            tokens.expect("identifier")
            while tokens.current.kind == "identifier":
                tokens.pop()
        tokens.expect("symbol", "{")
        metadata: dict[str, Any] = {}
        depth = 1
        seen_metadata = False
        while depth:
            token = tokens.pop()
            if token.kind == "eof":
                raise tokens.error(f"unterminated rule {name!r}")
            if token.kind == "symbol" and token.value == "{":
                depth += 1
            elif token.kind == "symbol" and token.value == "}":
                depth -= 1
            elif (
                depth == 1
                and token.kind == "identifier"
                and token.value == "meta"
                and tokens.current.kind == "symbol"
                and tokens.current.value == ":"
            ):
                if seen_metadata:
                    raise tokens.error(f"duplicate metadata section in rule {name!r}", token.offset)
                seen_metadata = True
                _metadata_section(tokens, metadata)
        _validate_metadata(tokens, name, metadata)
        yield name, metadata


def load_rule_metadata(rule_files: Iterable[Path]) -> dict[str, dict[str, Any]]:
    """Read metadata for every self-contained rule, or fail explicitly.

    Bounds are independent of target-file limits because custom rules are a
    separate, explicitly selected input. Duplicate IDs are rejected across files
    so the shared metadata map and public finding identities remain unambiguous.
    """
    metadata: dict[str, dict[str, Any]] = {}
    total_bytes = 0
    for index, raw_path in enumerate(rule_files):
        if index >= MAX_RULE_FILES:
            raise ValueError(f"rule pack exceeds {MAX_RULE_FILES} source files")
        path = Path(raw_path)
        with path.open("rb") as rule_file:
            source = rule_file.read(MAX_RULE_FILE_BYTES + 1)
        if len(source) > MAX_RULE_FILE_BYTES:
            raise ValueError(f"{path.name}: rule source exceeds {MAX_RULE_FILE_BYTES} bytes")
        total_bytes += len(source)
        if total_bytes > MAX_RULE_PACK_BYTES:
            raise ValueError(f"rule pack exceeds {MAX_RULE_PACK_BYTES} bytes")
        for name, fields in _file_metadata(source, path.name):
            if name in metadata:
                raise ValueError(f"{path.name}: duplicate rule identifier {name!r}")
            if len(metadata) >= MAX_RULES:
                raise ValueError(f"rule pack exceeds {MAX_RULES} rules")
            metadata[name] = fields
    if not metadata:
        raise ValueError("rule pack contains no rules")
    return metadata
