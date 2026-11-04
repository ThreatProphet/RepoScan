"""Markdown rendering of the same evidence model used by JSON and the CLI."""

from __future__ import annotations

from typing import Any


def escape_markdown(value: object) -> str:
    text = str(value)
    text = "".join(char if char.isprintable() else ascii(char)[1:-1] for char in text)
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    for char in ("\\", "`", "*", "_", "[", "]", "|", "#"):
        text = text.replace(char, "\\" + char)
    return text


def render_markdown(payload: dict[str, Any]) -> str:
    esc = escape_markdown
    stats = payload["stats"]
    lines = [
        "# RepoScan repository review", "",
        f"**Result:** {esc(payload['verdict'])}  ",
        f"**Scan status:** {esc(payload['status'])}  ",
        f"**Target:** {esc(payload['target'])}  ",
        f"**Tool:** RepoScan {esc(payload['tool']['version'])}  ",
        f"**Engine:** {esc(payload['engine'])} {esc(payload['engine_version'])}", "",
        "This is a static review of supplied files. Findings identify material to inspect before trusting, "
        "installing, or running the project. No findings is not a guarantee of safety.", "",
        "## Coverage", "",
        f"Scanned **{stats['files_scanned']} of {stats['files_selected']} selected files**. "
        "Completeness applies to the configured policy, not every byte in the repository.", "",
        "| Policy skip | Count |", "| --- | ---: |",
        f"| Ignored entries (directories may be pruned) | {stats['ignored']} |",
        f"| Oversized files | {stats['skipped_oversize']} |",
        f"| Symlinks | {stats['skipped_symlinks']} |",
        f"| Special files | {stats['skipped_special']} |", "",
    ]
    if stats["files_scanned"] == 0:
        lines.extend(["**No file content was scanned.** Review the selection policy and any errors before proceeding.", ""])
    if payload["engine"] == "lite":
        lines.extend(["Lite uses heuristic patterns and shared review checks; it is not a YARA scan.", ""])
    if payload["errors"]:
        lines.extend(["## Errors", ""])
        for error in payload["errors"]:
            where = f" ({esc(error['path'])})" if error.get("path") else ""
            lines.append(f"- **{esc(error['code'])}:** {esc(error['message'])}{where}")
        lines.append("")
    lines.extend(["## Findings", ""])
    if not payload["findings"]:
        lines.append("No findings in the inspected scope." if payload["complete"] else "The scan did not complete.")
        lines.append("")
    for index, finding in enumerate(payload["findings"], 1):
        lines.extend([
            f"### {index}. {esc(finding['rule'])}", "",
            f"**Priority:** {esc(finding['severity'])} | **Confidence:** {esc(finding['confidence'])} | "
            f"**Category:** {esc(finding['category'])}  ",
            f"**File:** {esc(finding['path'])}  ",
            f"**Source:** {esc(finding['source'])}", "",
            esc(finding["description"]), "",
        ])
        if finding["trigger"]:
            lines.extend([f"**Potential trigger:** {esc(finding['trigger'])}", ""])
        for prerequisite in finding["prerequisites"]:
            lines.append(f"- {esc(prerequisite)}")
        if finding["prerequisites"]:
            lines.append("")
        if finding["evidence"]:
            lines.extend(["| Evidence | Line | Byte offset | Length |", "| --- | ---: | ---: | ---: |"])
            for match in finding["evidence"]:
                lines.append(f"| {esc(match['identifier'])} | {match['line']} | {match['offset']} | {match['length']} |")
            lines.append("")
        if finding["evidence_truncated"]:
            lines.extend(["Evidence locations are capped; additional matches were omitted.", ""])
        if finding["reports"]:
            lines.extend(["**Reports:** " + ", ".join(esc(value) for value in finding["reports"]), ""])
        if finding["references"]:
            lines.extend(["**References:** " + ", ".join(esc(value) for value in finding["references"]), ""])
        lines.extend([f"**Scanned file SHA-256:** {esc(finding['sha256'])}", ""])
    skipped = payload["coverage"]["skipped"]
    if skipped:
        lines.extend(["## Skipped entries", "", "| Path | Reason |", "| --- | --- |"])
        lines.extend(f"| {esc(item['path'])} | {esc(item['reason'])} |" for item in skipped)
        lines.append("")
    if payload["coverage"]["skipped_truncated"]:
        lines.extend(["The skipped-entry list is capped; use the counters for totals.", ""])
    lines.extend([
        "## Reproducibility", "",
        f"**Schema:** {esc(payload['schema_version'])}  ",
        "**Rule-pack SHA-256:** " + (
            esc(payload["rule_pack"]["sha256"])
            or ("not applicable (Lite mode)" if payload["engine"] == "lite" else "not available")
        ) + "  ",
        f"**Ignore policy SHA-256:** {esc(payload['policy']['ignore_config_sha256'])}", "",
        "| Limit | Value |", "| --- | ---: |",
    ])
    lines.extend(f"| {esc(key)} | {value} |" for key, value in payload["policy"].items() if isinstance(value, int))
    return "\n".join(lines) + "\n"
