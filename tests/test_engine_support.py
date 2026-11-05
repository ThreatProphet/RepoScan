from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from reposcan import engine_support
from reposcan.engine_support import MatchingUnavailableError, bounded_matching, load_rule_metadata


def write_rule(tmp_path: Path, source: str, name: str = "example.yar") -> Path:
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    return path


@pytest.mark.parametrize(
    "source",
    [
        'rule Example { meta: severity="critical" description="marker" condition: true }',
        'rule Example : triage tagged {meta: severity="critical" description="marker" condition: true}',
        'rule Example\n{\n meta:\n severity="critical"\n description="marker"\n condition: true\n    }',
        'global rule Example { /* formatting */ meta: severity = "critical" description="marker" condition: true}',
    ],
)
def test_valid_rule_forms_preserve_native_metadata(tmp_path: Path, source: str) -> None:
    yara = pytest.importorskip("yara")
    path = write_rule(tmp_path, source)
    actual = load_rule_metadata([path])
    matches = yara.compile(filepath=str(path), includes=False).match(data=b"inert")
    assert len(matches) == 1
    assert actual == {"Example": matches[0].meta}
    assert actual["Example"]["severity"] == "critical"


def test_comments_literals_regex_hex_and_multiple_rules_do_not_confuse_metadata(tmp_path: Path) -> None:
    yara = pytest.importorskip("yara")
    source = r'''
import "math"
// rule Fake { meta: severity="low" condition: true }
rule First : first_tag {
    meta:
        severity = "high"
        description = "brace } and quote \" plus \\ newline\n tab\t utf8 \xc3\xa9"
        reports = "TP-2026-018"
        reference = "https://example.invalid/report"
        category = "report-pattern"
        confidence = "medium"
        enabled = true
        disabled = false
        integer = -7
        hex_integer = 0x2A
        octal_integer = 0o52
        decimal_leading_zero = 0123
        file_size = 4KB
    strings:
        $quoted = "rule Spoof { meta: severity=\"critical\" }"
        $regex = /[{}]{1,2}\/\/rule Fake/
        $hex = { 7B 7D /* } rule Fake { */ ( 41 | 42 ) }
    condition:
        any of them or "a}b" matches /a[}]b/ or 4 \ 2 == 2
}
/* rule AnotherFake { condition: true } */
private rule Helper { meta: severity="low" condition: true }
rule Second {
    meta: severity="medium" description="second"
    condition: Helper
}
'''
    path = write_rule(tmp_path, source)
    actual = load_rule_metadata([path])
    native = yara.compile(filepath=str(path), includes=False).match(data=b"inert")
    assert set(actual) == {"First", "Helper", "Second"}
    assert {match.rule: match.meta for match in native} == {
        "First": actual["First"],
        "Second": actual["Second"],
    }
    assert actual["First"]["description"] == 'brace } and quote " plus \\ newline\n tab\t utf8 é'
    assert actual["First"]["file_size"] == 4096
    assert actual["First"]["enabled"] is True


def test_bundled_metadata_is_available_without_loading_yara() -> None:
    rules = Path(engine_support.__file__).parent / "rules"
    metadata = load_rule_metadata(sorted(rules.glob("*.yar")))
    assert "TP_DevelTask_Node_Remote_Fetch_Dynamic_Execute" in metadata
    assert all(item["severity"] in engine_support.SEVERITIES for item in metadata.values())


def test_contiguous_hex_pattern_does_not_inherit_metadata_integer_limits(tmp_path: Path) -> None:
    yara = pytest.importorskip("yara")
    source = 'rule LongHex { meta: severity="high" strings: $a = { ' + "99" * 64 + ' } condition: $a }'
    path = write_rule(tmp_path, source)
    metadata = load_rule_metadata([path])
    matches = yara.compile(filepath=str(path), includes=False).match(data=b"\x99" * 64)
    assert metadata == {"LongHex": matches[0].meta}


def test_meta_named_string_is_not_a_metadata_section(tmp_path: Path) -> None:
    yara = pytest.importorskip("yara")
    source = 'rule MetaString { meta: severity="medium" strings: $meta = "marker" condition: $meta }'
    path = write_rule(tmp_path, source)
    metadata = load_rule_metadata([path])
    matches = yara.compile(filepath=str(path), includes=False).match(data=b"marker")
    assert metadata == {"MetaString": matches[0].meta}


@pytest.mark.parametrize(
    ("source", "message"),
    [
        ('rule Example { condition: true }', "must declare severity"),
        ('rule Example { meta: severity=2 condition: true }', "must declare severity"),
        ('rule Example { meta: severity="urgent" condition: true }', "must declare severity"),
        ('rule Example { meta: severity="high" confidence="certain" condition: true }', "confidence must"),
        ('rule Example { meta: severity="high" description=false condition: true }', "must be a string"),
        ('rule Example { meta: severity="high" severity="critical" condition: true }', "duplicate metadata"),
        ('include "extra.yar"\nrule Example { meta: severity="high" condition: true }', "include directives"),
        ('/* unterminated', "unterminated block comment"),
        ('rule Example { meta: severity="high" condition: true', "unterminated rule"),
        ('rule Example { meta: severity="high" description="unterminated', "unterminated quoted string"),
        (r'rule Example { meta: severity="high" description="\x00" condition: true }', "NUL bytes"),
        (r'rule Example { meta: severity="high" description="\x80" condition: true }', "valid UTF-8"),
        ('// no rules here', "contains no rules"),
    ],
)
def test_invalid_or_unsupported_metadata_fails_explicitly(tmp_path: Path, source: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        load_rule_metadata([write_rule(tmp_path, source)])


def test_duplicate_rule_ids_across_files_are_rejected(tmp_path: Path) -> None:
    source = 'rule Example { meta: severity="high" condition: true }'
    files = [write_rule(tmp_path, source, "one.yar"), write_rule(tmp_path, source, "two.yar")]
    with pytest.raises(ValueError, match="duplicate rule identifier"):
        load_rule_metadata(files)


def test_source_and_pack_limits_are_enforced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = 'rule Example { meta: severity="high" condition: true }'
    path = write_rule(tmp_path, source)
    monkeypatch.setattr(engine_support, "MAX_RULE_FILE_BYTES", 8)
    with pytest.raises(ValueError, match="rule source exceeds"):
        load_rule_metadata([path])
    monkeypatch.setattr(engine_support, "MAX_RULE_FILE_BYTES", 1024)
    monkeypatch.setattr(engine_support, "MAX_RULE_PACK_BYTES", 8)
    with pytest.raises(ValueError, match="rule pack exceeds"):
        load_rule_metadata([path])


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan")])
def test_invalid_deadlines_are_rejected(timeout: float) -> None:
    with pytest.raises(ValueError, match="positive finite"):
        with bounded_matching(timeout):
            pytest.fail("invalid deadline entered the matching body")


@pytest.mark.posix
def test_matching_restores_signal_state_after_success_and_exception() -> None:
    if not hasattr(signal, "setitimer"):
        pytest.skip("POSIX interval timers are unavailable")
    before_handler = signal.getsignal(signal.SIGALRM)
    before_timer = signal.getitimer(signal.ITIMER_REAL)
    assert before_timer == (0.0, 0.0)
    with bounded_matching(1):
        assert signal.getitimer(signal.ITIMER_REAL)[0] > 0
    assert signal.getsignal(signal.SIGALRM) == before_handler
    assert signal.getitimer(signal.ITIMER_REAL) == before_timer
    with pytest.raises(LookupError):
        with bounded_matching(1):
            raise LookupError("inert failure")
    assert signal.getsignal(signal.SIGALRM) == before_handler
    assert signal.getitimer(signal.ITIMER_REAL) == before_timer


@pytest.mark.posix
def test_regex_near_miss_is_interrupted_with_an_external_test_bound() -> None:
    if not hasattr(signal, "setitimer"):
        pytest.skip("POSIX interval timers are unavailable")
    code = '''
import re
import signal
from reposcan.engine_support import bounded_matching, MatchingTimeout
original = signal.getsignal(signal.SIGALRM)
try:
    with bounded_matching(0.02):
        re.search(b"(a+)+$", b"a" * 28 + b"!")
except MatchingTimeout:
    assert signal.getsignal(signal.SIGALRM) == original
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
    print("deadline enforced")
else:
    raise SystemExit("near miss finished without expected deadline")
'''
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(engine_support.__file__).parents[1])
    result = subprocess.run(
        [sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=3, check=False
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "deadline enforced\n"


@pytest.mark.posix
def test_existing_alarm_is_rejected_without_mutating_it() -> None:
    if not hasattr(signal, "setitimer"):
        pytest.skip("POSIX interval timers are unavailable")
    original_handler = signal.getsignal(signal.SIGALRM)
    signal.setitimer(signal.ITIMER_REAL, 10, 2)
    try:
        with pytest.raises(MatchingUnavailableError, match="active real-time alarm"):
            with bounded_matching(1):
                pytest.fail("existing alarm was replaced")
        remaining, interval = signal.getitimer(signal.ITIMER_REAL)
        assert 0 < remaining <= 10
        assert interval == 2
        assert signal.getsignal(signal.SIGALRM) == original_handler
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


def test_non_main_thread_cannot_silently_drop_deadline() -> None:
    exceptions: list[BaseException] = []

    def call_from_thread() -> None:
        try:
            with bounded_matching(1):
                raise AssertionError("unsupported thread entered matching")
        except BaseException as exc:
            exceptions.append(exc)

    thread = threading.Thread(target=call_from_thread)
    thread.start()
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert len(exceptions) == 1
    assert isinstance(exceptions[0], MatchingUnavailableError)


def test_unavailable_signal_timer_fails_explicitly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(signal, "setitimer", raising=False)
    with pytest.raises(MatchingUnavailableError, match="POSIX real-time"):
        with bounded_matching(1):
            pytest.fail("unsupported platform entered matching")


@pytest.mark.posix
def test_blocked_alarm_cannot_silently_drop_deadline() -> None:
    if not hasattr(signal, "pthread_sigmask") or not hasattr(signal, "SIGALRM"):
        pytest.skip("POSIX signal masks are unavailable")
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
    try:
        with pytest.raises(MatchingUnavailableError, match="unblocked SIGALRM"):
            with bounded_matching(1):
                pytest.fail("blocked deadline entered matching")
        assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
