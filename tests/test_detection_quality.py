from __future__ import annotations

from pathlib import Path

import pytest

from reposcan.review import review_bytes

RULE_DIRECTORY = Path(__file__).resolve().parents[1] / "src" / "reposcan" / "rules"
FIXTURE_DIRECTORY = Path(__file__).parent / "fixtures" / "web3market-entry"
WEB3MARKET_RULE = "TP_DevelTask_Node_InlineArray_Remote_Execution"
DYNAMIC_RULE = "TP_DevelTask_Node_Remote_Fetch_Dynamic_Execute"


@pytest.fixture(scope="module")
def rules():
    yara = pytest.importorskip("yara", reason="canonical detection quality requires yara-python")
    return yara.compile(filepaths={path.stem: str(path) for path in sorted(RULE_DIRECTORY.glob("*.yar"))})


def controller() -> bytes:
    return (FIXTURE_DIRECTORY / "controllers" / "users.js.fixture").read_bytes()


def test_web3market_inert_controller_matches_exact_intended_rule(rules) -> None:
    matches = rules.match(data=controller(), timeout=5)
    assert {match.rule for match in matches} == {WEB3MARKET_RULE}
    meta = matches[0].meta
    assert meta["confidence"] == "medium"
    assert meta["category"] == "report-pattern"
    assert meta["reports"] == "TP-2026-018"
    assert "coexist" in meta["description"]


@pytest.mark.parametrize("change", [
    lambda value: value.replace(b"arrayInline", b"anotherBinding"),
    lambda value: value.replace(b"'", b'"'),
    lambda value: value.replace(b"fetch(", b"fetch \n ( ").replace(b".json()", b".json \t ( )"),
])
def test_supported_web3market_signature_variants(rules, change) -> None:
    assert WEB3MARKET_RULE in {match.rule for match in rules.match(data=change(controller()), timeout=5)}


@pytest.mark.parametrize("content", [
    b'{"dependencies":{"inline-array":"^2.1.3"}}',
    b"const f = require('inline-array'); const result = f('module.exports = [1, 2, 3]', true);",
    b"const f = require('inline-array'); fetch('https://example.invalid/config').then(r => r.json()); "
    b"const result = f('module.exports = [1, 2, 3]', true);",
    b"const response = await fetch(String.fromCharCode(...codes)); const result = await response.json();",
])
def test_package_presence_or_unrelated_components_do_not_match_case_signature(rules, content: bytes) -> None:
    assert WEB3MARKET_RULE not in {match.rule for match in rules.match(data=content, timeout=5)}


@pytest.mark.parametrize("replacement", [b"false", b""])
def test_unsupported_flag_variants_remain_reviewable_not_safe(rules, replacement: bytes) -> None:
    source = controller()
    source = source.replace(b"token,\n    true", b"token,\n    false" if replacement else b"token")
    assert WEB3MARKET_RULE not in {match.rule for match in rules.match(data=source, timeout=5)}
    findings = review_bytes(source, "controllers/users.js")
    assert "REVIEW_Character_Code_Decoder" in {finding.rule for finding in findings}


def test_whole_case_has_review_evidence_before_any_payload_is_available(rules) -> None:
    data_by_path = {path.relative_to(FIXTURE_DIRECTORY).as_posix(): path.read_bytes() for path in FIXTURE_DIRECTORY.rglob("*.fixture")}
    canonical = {match.rule for data in data_by_path.values() for match in rules.match(data=data, timeout=5)}
    observations = {finding.rule for path, data in data_by_path.items() for finding in review_bytes(data, path)}
    assert canonical == {WEB3MARKET_RULE}
    assert observations == {"REVIEW_Character_Code_Decoder", "REVIEW_Encoded_Character_Array"}


@pytest.mark.parametrize("source", [
    b"const local = new Function('require','return 42'); const verbose = process.env.DEBUG;",
    b"Documentation of `new Function`, `'require'`, and `process.env`.",
])
def test_broad_dynamic_pattern_has_review_confidence_and_qualified_description(rules, source: bytes) -> None:
    matches = [match for match in rules.match(data=source, timeout=5) if match.rule == DYNAMIC_RULE]
    assert len(matches) == 1
    assert matches[0].meta["confidence"] == "medium"
    assert "coexist" in matches[0].meta["description"]
    assert "inspect input flow" in matches[0].meta["description"]


def test_dynamic_constructor_allows_normal_extra_whitespace(rules) -> None:
    source = b"const local = new  Function('require','return 42'); const verbose = process.env.DEBUG;"
    assert DYNAMIC_RULE in {match.rule for match in rules.match(data=source, timeout=5)}
