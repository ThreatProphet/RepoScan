"""Bounded static observations for a developer's review before project execution.

These checks do not run Git, JavaScript, package managers, or project commands.
They identify declarations and lexical patterns, not successful execution or
malicious intent. Configuration locations refer to the original input bytes.
"""

from __future__ import annotations

import json
import re
from dataclasses import replace
from pathlib import PurePosixPath
from typing import Any

from reposcan.models import Evidence, Finding, evidence_at

MAX_REVIEW_BYTES = 2 * 1024 * 1024
MAX_CONFIG_BYTES = 256 * 1024
MAX_CONFIG_DEPTH = 32
MAX_CONFIG_VALUES = 4096
MAX_CONFIG_STRING = 32 * 1024
MAX_ARRAY_BYTES = 8192
MAX_ARRAY_VALUES = 1024
MAX_ARRAY_CANDIDATES = 128
MAX_FINDINGS = 64
MAX_EVIDENCE = 6

WEB3MARKET_REFERENCE = "https://threatprophet.com/posts/web3market-polygon-wallet-cache/"
GIT_HOOKS_REFERENCE = "https://git-scm.com/docs/githooks"
GIT_SECURITY_REFERENCE = "https://git-scm.com/docs/git#_security"
VSCODE_TASKS_REFERENCE = "https://code.visualstudio.com/docs/debugtest/tasks#_control-automatic-task-execution"

# This catalog is also suitable for generating documentation. Runtime findings
# may refine severity, confidence, description, or the activating action.
REVIEW_RULES: dict[str, dict[str, str]] = {
    "REVIEW_Git_Hook": {
        "category": "trigger", "severity": "low", "confidence": "high",
        "description": "A supplied hook-directory file deserves inspection before Git operations.",
    },
    "REVIEW_Git_Hook_Suspicious_Command": {
        "category": "trigger", "severity": "high", "confidence": "medium",
        "description": "A supplied hook-directory file contains network, encoded, or hidden-command constructs.",
    },
    "REVIEW_Git_HooksPath": {
        "category": "trigger", "severity": "medium", "confidence": "high",
        "description": "Supplied Git configuration redirects the hooks directory; inspect the destination.",
    },
    "REVIEW_Git_Command_Config": {
        "category": "trigger", "severity": "medium", "confidence": "high",
        "description": "Supplied Git configuration names an external command or command-capable helper.",
    },
    "REVIEW_Git_Config_Include": {
        "category": "trigger", "severity": "low", "confidence": "high",
        "description": "Supplied Git configuration includes another file; its contents were not followed by this check.",
    },
    "REVIEW_Git_Metadata_Pointer": {
        "category": "trigger", "severity": "low", "confidence": "high",
        "description": "A Git metadata pointer names another directory; its configuration and hooks were not followed.",
    },
    "REVIEW_VSCode_FolderOpen_Task": {
        "category": "trigger", "severity": "medium", "confidence": "high",
        "description": "A VS Code task declares folder-open execution; review it before trusting the workspace.",
    },
    "REVIEW_VSCode_Suspicious_Task": {
        "category": "trigger", "severity": "high", "confidence": "medium",
        "description": "A VS Code task contains a network, encoded, inline-execution, or hidden-command construct.",
    },
    "REVIEW_VSCode_Automatic_Tasks_Allowed": {
        "category": "trigger", "severity": "medium", "confidence": "high",
        "description": "Workspace settings allow automatic tasks in a trusted workspace.",
    },
    "REVIEW_VSCode_Debug_Task": {
        "category": "trigger", "severity": "low", "confidence": "high",
        "description": "A debug configuration references a task that can run with debugging; inspect that task.",
    },
    "REVIEW_Package_Lifecycle_Script": {
        "category": "trigger", "severity": "medium", "confidence": "high",
        "description": "A package lifecycle or pre/post script declares an additional command.",
    },
    "REVIEW_Package_Suspicious_Script": {
        "category": "trigger", "severity": "high", "confidence": "medium",
        "description": "A package script contains a network, encoded, inline-execution, or hidden-command construct.",
    },
    "REVIEW_Encoded_Character_Array": {
        "category": "obfuscation", "severity": "medium", "confidence": "medium",
        "description": "A literal character-code array may conceal text; inspect its intended use.",
    },
    "REVIEW_Character_Code_Decoder": {
        "category": "obfuscation", "severity": "low", "confidence": "medium",
        "description": "Character-code construction can conceal strings or perform ordinary text handling.",
    },
    "REVIEW_Encoded_String_Decoder": {
        "category": "obfuscation", "severity": "low", "confidence": "medium",
        "description": "An encoded-string decoder is present; the decoded content and purpose require review.",
    },
    "REVIEW_Escaped_String_Content": {
        "category": "obfuscation", "severity": "medium", "confidence": "medium",
        "description": "Concentrated hexadecimal or Unicode escapes conceal string contents; assets may also use them.",
    },
    "REVIEW_JS_String_Table": {
        "category": "obfuscation", "severity": "medium", "confidence": "medium",
        "description": "A string table appears alongside repeated obfuscator-style identifiers.",
    },
    "REVIEW_Horizontal_Whitespace": {
        "category": "obfuscation", "severity": "medium", "confidence": "medium",
        "description": "A long horizontal whitespace gap places additional content far off-screen.",
    },
    "REVIEW_Dynamic_Execution": {
        "category": "behavior", "severity": "medium", "confidence": "medium",
        "description": "A dynamic evaluation construct is present; inspect the origin of the evaluated input.",
    },
    "REVIEW_Decoding_And_Execution": {
        "category": "behavior", "severity": "high", "confidence": "medium",
        "description": "Decoding and dynamic evaluation coexist; whether decoded data reaches execution is unresolved.",
    },
    "REVIEW_PowerShell_Encoded_Command": {
        "category": "obfuscation", "severity": "high", "confidence": "medium",
        "description": "A PowerShell command includes an encoded-command option; inspect the content without running it.",
    },
    "REVIEW_Configuration_Unparsed": {
        "category": "trigger", "severity": "medium", "confidence": "high",
        "description": "Configuration could not be fully parsed within static-review limits; inspect triggers manually.",
    },
    "REVIEW_Analysis_Limit": {
        "category": "behavior", "severity": "low", "confidence": "high",
        "description": "A static-review bound was reached; this check did not inspect every possible construct.",
    },
}

_SUSPICIOUS_COMMAND = re.compile(
    rb"\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|powershell|pwsh|nohup)\b"
    rb"|\b(?:node|python|python3|bash|sh)\b[^\r\n]{0,80}[ \t]+-[ec]\b"
    rb"|\b(?:eval|atob)[ \t]*\(|\bBuffer\.from[ \t]*\("
    rb"|\b(?:EncodedCommand|Start-Process)\b|WindowStyle[ \t]+Hidden",
    re.IGNORECASE,
)
_CHAR_DECODER = re.compile(rb"\bString\.(?:fromCharCode|fromCodePoint)[ \t\r\n]*\(")
_STRING_DECODER = re.compile(
    rb"\batob[ \t\r\n]*\("
    rb"|\bBuffer\.from[ \t\r\n]*\([^\r\n)]{0,512},[ \t]*['\"](?:base64|hex)['\"]",
    re.IGNORECASE,
)
_DYNAMIC = re.compile(
    rb"\beval[ \t\r\n]*\(|\bnew[ \t\r\n]+Function[ \t\r\n]*\("
    rb"|\bFunction\.constructor[ \t\r\n]*\(|\bvm\.(?:Script|runInNewContext|runInThisContext)\b"
)
_ESCAPED_RUN = re.compile(rb"(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}){8,}")
_NUMERIC_ARRAY = re.compile(rb"\[(?:[ \t\r\n]*(?:[0-9]{1,5}|0[xX][0-9a-fA-F]{1,4})[ \t\r\n]*,){7}")
_HEX_IDENTIFIER = re.compile(rb"\b_0x[0-9a-fA-F]{3,16}\b")
_STRING_ARRAY_START = re.compile(rb"\[[ \t\r\n]*['\"]")
_HORIZONTAL_SPACE = re.compile(rb"[ \t]{120,}")
_ENCODED_POWERSHELL = re.compile(
    rb"\b(?:powershell|pwsh)(?:\.exe)?\b[^\r\n]{0,512}?"
    rb"[ \t]+-(?:enc|encodedcommand)(?=[ \t\r\n'\"]|$)",
    re.IGNORECASE,
)


class _ConfigError(ValueError):
    def __init__(self, offset: int) -> None:
        self.offset = offset
        super().__init__("invalid or bounded configuration")


class _Config:
    """Small JSON/JSONC reader retaining property positions, with explicit bounds."""

    def __init__(self, data: bytes, comments: bool) -> None:
        if len(data) > MAX_CONFIG_BYTES:
            raise _ConfigError(0)
        self.data = data
        self.comments = comments
        self.at = 3 if data.startswith(b"\xef\xbb\xbf") else 0
        self.values = 0
        self.locations: dict[tuple[str | int, ...], tuple[int, int]] = {}
        self.value = self._value((), 0)
        self._space()
        if self.at != len(self.data):
            raise _ConfigError(self.at)

    def _space(self) -> None:
        while self.at < len(self.data):
            if self.data[self.at] in b" \t\r\n":
                self.at += 1
            elif self.comments and self.data.startswith(b"//", self.at):
                end = self.data.find(b"\n", self.at + 2)
                self.at = len(self.data) if end < 0 else end + 1
            elif self.comments and self.data.startswith(b"/*", self.at):
                end = self.data.find(b"*/", self.at + 2)
                if end < 0:
                    raise _ConfigError(self.at)
                self.at = end + 2
            else:
                return

    def _string(self) -> str:
        start = self.at
        self.at += 1
        while self.at < len(self.data) and self.at - start <= MAX_CONFIG_STRING:
            char = self.data[self.at]
            self.at += 1
            if char == 92:
                self.at += 1
            elif char == 34:
                try:
                    value = json.loads(self.data[start:self.at])
                except (ValueError, UnicodeError):
                    raise _ConfigError(start) from None
                if isinstance(value, str):
                    return value
                break
        raise _ConfigError(start)

    def _value(self, path: tuple[str | int, ...], depth: int) -> Any:
        self._space()
        self.values += 1
        if depth > MAX_CONFIG_DEPTH or self.values > MAX_CONFIG_VALUES or self.at >= len(self.data):
            raise _ConfigError(self.at)
        char = self.data[self.at]
        if char == 34:
            return self._string()
        if char in (123, 91):
            self.at += 1
            closing = 125 if char == 123 else 93
            result: Any = {} if char == 123 else []
            self._space()
            if self.at < len(self.data) and self.data[self.at] == closing:
                self.at += 1
                return result
            while True:
                self._space()
                start = self.at
                if char == 123:
                    if self.at >= len(self.data) or self.data[self.at] != 34:
                        raise _ConfigError(self.at)
                    key = self._string()
                    if key in result:
                        raise _ConfigError(start)
                    self.locations[(*path, key)] = (start, self.at - start)
                    self._space()
                    if self.at >= len(self.data) or self.data[self.at] != 58:
                        raise _ConfigError(self.at)
                    self.at += 1
                    result[key] = self._value((*path, key), depth + 1)
                else:
                    key = len(result)
                    self.locations[(*path, key)] = (start, 1)
                    result.append(self._value((*path, key), depth + 1))
                self._space()
                if self.at >= len(self.data):
                    raise _ConfigError(self.at)
                separator = self.data[self.at]
                self.at += 1
                if separator == closing:
                    return result
                if separator != 44:
                    raise _ConfigError(self.at - 1)
                self._space()
                if self.comments and self.at < len(self.data) and self.data[self.at] == closing:
                    self.at += 1
                    return result
        start = self.at
        while self.at < len(self.data) and self.data[self.at] not in b" \t\r\n,]}":
            if self.comments and self.data[self.at:self.at + 2] in (b"//", b"/*"):
                break
            self.at += 1
            if self.at - start > 128:
                raise _ConfigError(start)
        try:
            value = json.loads(self.data[start:self.at])
        except (ValueError, UnicodeError):
            raise _ConfigError(start) from None
        # json.loads accepts non-standard NaN/Infinity; configuration does not.
        if self.data[start:self.at] in (b"NaN", b"Infinity", b"-Infinity"):
            raise _ConfigError(start)
        return value


class _Review:
    def __init__(self, data: bytes, path: str) -> None:
        self.data = data[:MAX_REVIEW_BYTES]
        self.path = path
        self.findings: list[Finding] = []
        self.limited = False
        if len(data) > MAX_REVIEW_BYTES:
            self.limit()

    def add(self, rule: str, evidence: tuple[Evidence, ...] = (), **changes: Any) -> None:
        if len(self.findings) >= MAX_FINDINGS:
            self.limit()
            return
        self.findings.append(Finding(
            rule=rule, path=self.path, source="static-review", evidence=evidence[:MAX_EVIDENCE],
            **(REVIEW_RULES[rule] | changes),
        ))

    def limit(self) -> None:
        if not self.limited:
            self.limited = True
            self.findings.append(Finding(
                rule="REVIEW_Analysis_Limit", path=self.path, source="static-review",
                **REVIEW_RULES["REVIEW_Analysis_Limit"],
            ))

    def match(self, expression: re.Pattern[bytes], label: str) -> tuple[Evidence, ...]:
        match = expression.search(self.data)
        return (evidence_at(self.data, label, match.start(), match.end() - match.start()),) if match else ()

    def location(self, config: _Config, path: tuple[str | int, ...], label: str) -> tuple[Evidence, ...]:
        position = config.locations.get(path)
        if position is None:
            return ()
        return (evidence_at(self.data, label, *position),)


def _command_text(value: dict[str, Any]) -> str:
    """Inspect only command/argument declarations, including platform variants."""
    commands: list[str] = []
    for container in (value, *(value.get(platform) for platform in ("linux", "osx", "windows"))):
        if not isinstance(container, dict):
            continue
        command = container.get("command")
        if isinstance(command, dict):
            command = command.get("value")
        if isinstance(command, str):
            commands.append(command)
        arguments = container.get("args", [])
        if isinstance(arguments, list):
            for argument in arguments:
                if isinstance(argument, str):
                    commands.append(argument)
                elif isinstance(argument, dict) and isinstance(argument.get("value"), str):
                    commands.append(argument["value"])
    return " ".join(commands)


def _vscode(review: _Review, config: _Config, workspace: bool, name: str) -> None:
    root = config.value
    if not isinstance(root, dict):
        return
    task_root = root.get("tasks") if workspace else root
    prefix: tuple[str | int, ...] = ("tasks",) if workspace else ()
    tasks = task_root.get("tasks", []) if isinstance(task_root, dict) else []
    if isinstance(tasks, list):
        for index, task in enumerate(tasks):
            if not isinstance(task, dict):
                continue
            task_path = (*prefix, "tasks", index)
            run_options = task.get("runOptions")
            folder_open = isinstance(run_options, dict) and run_options.get("runOn") == "folderOpen"
            suspicious = bool(_SUSPICIOUS_COMMAND.search(_command_text(task).encode("utf-8", "replace")))
            if folder_open:
                review.add(
                    "REVIEW_VSCode_FolderOpen_Task",
                    review.location(config, (*task_path, "runOptions", "runOn"), "runOn"),
                    severity="high" if suspicious else "medium",
                    confidence="medium" if suspicious else "high",
                    trigger=f"Opening a trusted workspace with automatic tasks allowed (task {index + 1}).",
                    prerequisites=(
                        "Workspace trust and automatic-task policy permit execution.",
                        "Referenced commands, task dependencies, and platform overrides require separate inspection.",
                    ),
                    references=(VSCODE_TASKS_REFERENCE,),
                )
            elif suspicious:
                review.add(
                    "REVIEW_VSCode_Suspicious_Task",
                    review.location(config, task_path, "task"),
                    trigger=f"Invoking task {index + 1}, or another configured action that depends on it.",
                    prerequisites=("Task activation and referenced dependencies are not established by this check.",),
                    references=(VSCODE_TASKS_REFERENCE,),
                )
    settings = root.get("settings") if workspace else root if name == "settings.json" else None
    if isinstance(settings, dict) and settings.get("task.allowAutomaticTasks") == "on":
        key_path = ("settings", "task.allowAutomaticTasks") if workspace else ("task.allowAutomaticTasks",)
        review.add(
            "REVIEW_VSCode_Automatic_Tasks_Allowed",
            review.location(config, key_path, "task.allowAutomaticTasks"),
            trigger="Opening a trusted workspace containing automatic tasks.",
            prerequisites=("Workspace trust is still required; task definitions must also be inspected.",),
            references=(VSCODE_TASKS_REFERENCE,),
        )
    launch = root.get("launch") if workspace else root if name == "launch.json" else None
    configurations = launch.get("configurations", []) if isinstance(launch, dict) else []
    if isinstance(configurations, list):
        for index, entry in enumerate(configurations):
            if not isinstance(entry, dict):
                continue
            for key in ("preLaunchTask", "postDebugTask"):
                if isinstance(entry.get(key), str) and entry[key]:
                    key_path = (("launch",) if workspace else ()) + ("configurations", index, key)
                    review.add(
                        "REVIEW_VSCode_Debug_Task", review.location(config, key_path, key),
                        trigger="Starting or ending the associated debug configuration.",
                        prerequisites=("The referenced task and its commands are not resolved by this check.",),
                    )


def _package(review: _Review, config: _Config) -> None:
    if not isinstance(config.value, dict) or not isinstance(config.value.get("scripts"), dict):
        return
    scripts = config.value["scripts"]
    for script, command in scripts.items():
        if not isinstance(command, str):
            continue
        lifecycle = script in {
            "preinstall", "install", "postinstall", "preprepare", "prepare", "postprepare",
            "prepublish", "prepublishOnly", "publish", "postpublish", "prepack", "postpack",
            "prestart", "poststart", "prestop", "poststop", "prerestart", "postrestart", "pretest", "posttest",
        }
        lifecycle = lifecycle or any(
            script.startswith(prefix) and script[len(prefix):] in scripts for prefix in ("pre", "post")
        )
        suspicious = bool(_SUSPICIOUS_COMMAND.search(command.encode("utf-8", "replace")))
        if not lifecycle and not suspicious:
            continue
        # The script name is a key, not command content. Truncate it to keep
        # explanations bounded; output renderers still escape control characters.
        display = script[:80]
        review.add(
            "REVIEW_Package_Suspicious_Script" if suspicious else "REVIEW_Package_Lifecycle_Script",
            review.location(config, ("scripts", script), "script-key"),
            trigger=f"Package-manager invocation of the '{display}' script.",
            prerequisites=(
                "Lifecycle behavior depends on the package manager, invoked operation, and script policy.",
                "This check does not install dependencies or resolve commands into other files.",
            ),
        )


def _git_value(raw: bytes) -> bytes:
    """Remove quoting and comments for boolean/helper classification, not execution."""
    value = bytearray()
    quoted = False
    escaped = False
    for byte in raw:
        if escaped:
            value.append(byte)
            escaped = False
        elif byte == 92:
            escaped = True
        elif byte == 34:
            quoted = not quoted
        elif not quoted and byte in (35, 59):
            break
        else:
            value.append(byte)
    return bytes(value).strip()


def _git(review: _Review, path: PurePosixPath) -> None:
    parts = path.parts
    if path.name == ".git" and review.data.startswith(b"gitdir:"):
        review.add(
            "REVIEW_Git_Metadata_Pointer", (evidence_at(review.data, "gitdir-pointer", 0, 7),),
            trigger="Git operations resolving this metadata pointer.",
            prerequisites=("The referenced metadata is outside this byte-only check and was not opened.",),
            references=(GIT_SECURITY_REFERENCE,),
        )
    in_hooks = any(parts[index:index + 2] == (".git", "hooks") for index in range(len(parts) - 2))
    managed_hooks = ".githooks" in parts[:-1] or ".husky" in parts[:-1]
    if (in_hooks or managed_hooks) and not path.name.endswith(".sample") and review.data.strip():
        suspicious = review.match(_SUSPICIOUS_COMMAND, "command-construct")
        review.add(
            "REVIEW_Git_Hook_Suspicious_Command" if suspicious else "REVIEW_Git_Hook",
            suspicious or (evidence_at(review.data, "hook-file", 0, min(len(review.data), 1)),),
            trigger="A Git hook event or configured hook-manager invocation.",
            prerequisites=(
                "Hook name, effective hooks path, executable permissions, and platform determine activation.",
                "This byte-only check does not establish executable permissions or run Git.",
            ),
            references=(GIT_HOOKS_REFERENCE, GIT_SECURITY_REFERENCE),
        )
    is_config = path.name in ("config", "config.worktree") and ".git" in parts[:-1]
    if not is_config:
        return
    section = ""
    offset = 0
    for line in review.data.splitlines(keepends=True):
        if len(review.findings) >= MAX_FINDINGS:
            review.limit()
            break
        stripped = line.strip()
        if stripped.startswith(b"["):
            match = re.match(rb"\[([A-Za-z][A-Za-z0-9.-]*)(?:[ \t]+|\])", stripped)
            section = match.group(1).decode("ascii").lower() if match else ""
        elif stripped and not stripped.startswith((b"#", b";")):
            match = re.match(rb"[ \t]*([A-Za-z][A-Za-z0-9.-]*)[ \t]*=[ \t]*(.*)", line.rstrip(b"\r\n"))
            if match:
                key = match.group(1).decode("ascii").lower()
                value = _git_value(match.group(2))
                # Counting newlines in the input prefix is only necessary for
                # observed settings. Doing it for every ordinary key would make
                # a large, repetitive Git configuration quadratic to inspect.
                def setting_evidence() -> tuple[Evidence, ...]:
                    return (evidence_at(
                        review.data, "git-config-key", offset + match.start(1), len(match.group(1)),
                    ),)

                if section == "core" and key == "hookspath":
                    review.add(
                        "REVIEW_Git_HooksPath", setting_evidence(),
                        trigger="Subsequent Git operations that consult the configured hooks directory.",
                        prerequisites=("The destination is not followed and the effective Git configuration is unresolved.",),
                        references=(GIT_HOOKS_REFERENCE, GIT_SECURITY_REFERENCE),
                    )
                elif section in ("include", "includeif") and key == "path":
                    review.add("REVIEW_Git_Config_Include", setting_evidence(), references=(GIT_SECURITY_REFERENCE,))
                else:
                    command = (
                        section == "core" and key in ("sshcommand", "editor", "pager", "fsmonitor")
                        or section == "filter" and key in ("smudge", "clean", "process")
                        or section == "diff" and key in ("external", "command", "textconv")
                        or section == "merge" and key == "driver"
                        or section == "credential" and key == "helper"
                        or section == "alias" and value.startswith(b"!")
                    )
                    boolean_fsmonitor = section == "core" and key == "fsmonitor" and value.lower() in (
                        b"true", b"false", b"0", b"1", b"yes", b"no", b"on", b"off",
                    )
                    if command and value and not boolean_fsmonitor:
                        review.add(
                            "REVIEW_Git_Command_Config", setting_evidence(),
                            trigger=f"A Git operation that uses {section}.{key}.",
                            prerequisites=("Activation depends on the Git operation and effective configuration.",),
                            references=(GIT_SECURITY_REFERENCE,),
                        )
        offset += len(line)


def _numeric_arrays(review: _Review, decoder: tuple[Evidence, ...]) -> None:
    for index, start in enumerate(_NUMERIC_ARRAY.finditer(review.data)):
        if index >= MAX_ARRAY_CANDIDATES:
            review.limit()
            break
        end = review.data.find(b"]", start.start() + 1, start.start() + MAX_ARRAY_BYTES)
        if end < 0:
            # A decoder plus an oversized literal is still unresolved content,
            # not evidence that the static decoding completed successfully.
            if decoder:
                review.limit()
            continue
        tokens = [token.strip() for token in review.data[start.start() + 1:end].split(b",")]
        if tokens and not tokens[-1]:
            tokens.pop()
        if not 8 <= len(tokens) <= MAX_ARRAY_VALUES:
            if len(tokens) > MAX_ARRAY_VALUES:
                review.limit()
            continue
        values: list[int] = []
        for token in tokens:
            if re.fullmatch(rb"[0-9]{1,5}", token):
                number = int(token)
            elif re.fullmatch(rb"0[xX][0-9a-fA-F]{1,4}", token):
                number = int(token, 16)
            else:
                break
            if number > 255:
                break
            values.append(number)
        if len(values) != len(tokens):
            continue
        decoded = bytes(values)
        printable = sum(32 <= byte < 127 or byte in b"\t\r\n" for byte in decoded)
        if printable * 10 < len(decoded) * 9:
            continue
        url = decoded.lower().startswith((b"https://", b"http://", b"hxxps://", b"hxxp://"))
        if not url and not decoder:
            continue
        review.add(
            "REVIEW_Encoded_Character_Array",
            (evidence_at(review.data, "numeric-url-array" if url else "character-array", start.start(), end - start.start() + 1),),
            description=(
                "A literal character-code array statically decodes to a URL; its use and destination require review."
                if url else "A printable character-code array coexists with a character decoder; their relationship is unresolved."
            ),
            confidence="high" if url else "medium",
            reports=("TP-2026-018",), references=(WEB3MARKET_REFERENCE,),
        )


def _string_tables(review: _Review) -> None:
    identifiers: list[Evidence] = []
    for match in _HEX_IDENTIFIER.finditer(review.data):
        identifiers.append(evidence_at(review.data, "obfuscator-style-identifier", match.start(), match.end() - match.start()))
        if len(identifiers) == 4:
            break
    if len(identifiers) < 4:
        return
    for index, start in enumerate(_STRING_ARRAY_START.finditer(review.data)):
        if index >= MAX_ARRAY_CANDIDATES:
            review.limit()
            return
        position = start.end() - 1
        count = 0
        bound = min(len(review.data), start.start() + MAX_ARRAY_BYTES)
        while position < bound and review.data[position] in (34, 39) and count < 3:
            quote = review.data[position]
            position += 1
            closed = False
            while position < bound:
                char = review.data[position]
                position += 1
                if char == 92:
                    position += 1
                elif char == quote:
                    closed = True
                    break
            if not closed:
                break
            count += 1
            while position < bound and review.data[position] in b" \t\r\n":
                position += 1
            if position < bound and review.data[position] == 44:
                position += 1
                while position < bound and review.data[position] in b" \t\r\n":
                    position += 1
            else:
                break
        if count >= 3:
            review.add(
                "REVIEW_JS_String_Table",
                (evidence_at(review.data, "string-table", start.start(), min(position, bound) - start.start()), *identifiers),
            )
            return


def _obfuscation(review: _Review) -> None:
    character_decoder = review.match(_CHAR_DECODER, "character-decoder")
    string_decoder = review.match(_STRING_DECODER, "string-decoder")
    dynamic = review.match(_DYNAMIC, "dynamic-evaluation")
    escaped = review.match(_ESCAPED_RUN, "escaped-string-run")
    if character_decoder:
        review.add("REVIEW_Character_Code_Decoder", character_decoder)
    if string_decoder:
        review.add("REVIEW_Encoded_String_Decoder", string_decoder)
    if escaped:
        review.add("REVIEW_Escaped_String_Content", escaped)
    if dynamic:
        review.add("REVIEW_Dynamic_Execution", dynamic)
        if character_decoder or string_decoder or escaped:
            review.add("REVIEW_Decoding_And_Execution", (*dynamic, *character_decoder, *string_decoder, *escaped))
    _numeric_arrays(review, character_decoder)
    _string_tables(review)
    for gap in _HORIZONTAL_SPACE.finditer(review.data):
        following = review.data[gap.end():gap.end() + 1]
        if following and following not in b"\r\n\x00":
            review.add("REVIEW_Horizontal_Whitespace", (evidence_at(review.data, "horizontal-gap", gap.start(), gap.end() - gap.start()),))
            break
    powershell = review.match(_ENCODED_POWERSHELL, "encoded-command-option")
    if powershell:
        review.add("REVIEW_PowerShell_Encoded_Command", powershell)


def review_bytes(data: bytes, path: str) -> list[Finding]:
    """Inspect supplied bytes only; return observations even if reachability is unknown."""
    review = _Review(data, path)
    normalized = PurePosixPath(path.replace("\\", "/"))
    _git(review, normalized)
    name = normalized.name
    vscode = ".vscode" in normalized.parts[:-1] and name in ("tasks.json", "settings.json", "launch.json")
    workspace = name.endswith(".code-workspace")
    package = name == "package.json"
    if vscode or workspace or package:
        try:
            config = _Config(review.data, comments=not package)
            if not isinstance(config.value, dict):
                raise _ConfigError(0)
        except _ConfigError as error:
            offset = min(error.offset, len(review.data))
            review.add("REVIEW_Configuration_Unparsed", (evidence_at(review.data, "configuration-limit-or-syntax", offset, 0),))
        else:
            if package:
                _package(review, config)
            else:
                _vscode(review, config, workspace, name)
    _obfuscation(review)
    if normalized.suffix.lower() in (".md", ".rst"):
        review.findings = [replace(
            finding, confidence="low",
            description=f"{finding.description} This is a documentation match; execution is not established.",
        ) for finding in review.findings]
    return review.findings
