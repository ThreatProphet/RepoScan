from __future__ import annotations

import re

from conftest import FIXTURES, RULES

EXPECTED_RULE_IDS = {
    "TP_DevelTask_Browser_Wallet_Harvester",
    "TP_DevelTask_Clipboard_C2_Control",
    "TP_DevelTask_ENV_Base64_URL_Hidden_Config",
    "TP_DevelTask_ENV_Exfil_AUTH_API",
    "TP_DevelTask_GitHook_Remote_Pipe",
    "TP_DevelTask_GitHook_Suspicious_Command",
    "TP_DevelTask_Horizontal_Whitespace_Loader",
    "TP_DevelTask_NPM_Lifecycle_Server_Execution",
    "TP_DevelTask_NPM_Lifecycle_Suspicious_Command",
    "TP_DevelTask_Node_Remote_Fetch_Dynamic_Execute",
    "TP_DevelTask_PowerShell_Hidden_Encoded",
    "TP_DevelTask_Remote_Content_Piped_To_Shell",
    "TP_DevelTask_Sensitive_File_Collection_Patterns",
    "TP_DevelTask_VSCode_FolderOpen_PipeToShell",
    "TP_DevelTask_VSCode_FolderOpen_Suspicious_AutoTask",
}


def test_canonical_rule_identifiers_are_stable() -> None:
    text = (RULES / "developer_task_malware.yar").read_text(encoding="utf-8")
    actual = set(re.findall(r"(?m)^rule\s+([A-Za-z0-9_]+)\s*$", text))

    assert actual == EXPECTED_RULE_IDS


def test_every_canonical_rule_has_supported_severity() -> None:
    text = (RULES / "developer_task_malware.yar").read_text(encoding="utf-8")
    rule_bodies = re.findall(r"(?ms)^rule\s+([A-Za-z0-9_]+)\s*\{(.*?)(?=^rule\s+|\Z)", text)

    assert {name for name, _ in rule_bodies} == EXPECTED_RULE_IDS
    for name, body in rule_bodies:
        match = re.search(r'(?m)^\s*severity\s*=\s*"([^"]+)"', body)
        assert match is not None, f"missing severity metadata for {name}"
        assert match.group(1) in {"critical", "high", "medium", "low"}


def test_git_hook_fixture_is_inert_and_non_executable() -> None:
    fixture = FIXTURES / "malicious-githook" / "pre-commit.fixture"

    assert fixture.is_file()
    assert fixture.stat().st_mode & 0o111 == 0
