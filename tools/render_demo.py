#!/usr/bin/env python3
"""Render an annotated replay of captured RepoScan output, without running it.

Pillow draws the captured SGR text; FFmpeg encodes GIF and MP4. Download/setup
waits and command typing are presentation, not measured execution time.
The --terminal path prints the same scenes for VHS and needs no Pillow.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unicodedata
from dataclasses import dataclass, replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WIDTH, HEIGHT, COLUMNS = 1440, 900, 88
LEFT, TOP, CELL_WIDTH, LINE_HEIGHT = 60, 164, 15, 29
BACKGROUND, FOREGROUND = "#111b2b", "#e4edf7"
PALETTE = (
    "#172335", "#ff818f", "#83d9a6", "#f4cc77", "#92baff", "#c9a5f7", "#73d9ed", "#e4edf7",
    "#abbcd0", "#ff9aa5", "#a1e7b8", "#ffdda0", "#b1ceff", "#dfbfff", "#a3eaf7", "#ffffff",
)
RESET, BOLD, CYAN, DIM = "\x1b[0m", "\x1b[1m", "\x1b[36m", "\x1b[90m"
SGR = re.compile(r"\x1b\[([0-9;]*)m")
NAMES = ("intro", "download", "scan", "high", "medium", "low", "summary", "close")
FOOTER = "Captured output replay | Download/setup waits shortened"


@dataclass(frozen=True)
class Style:
    foreground: str = FOREGROUND
    background: str = BACKGROUND
    bold: bool = False
    dim: bool = False


@dataclass(frozen=True)
class Scene:
    name: str
    title: str
    subtitle: str
    body: str
    duration: float


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def styled_rows(text: str) -> list[list[tuple[str, Style]]]:
    """Accept single-column printable text and SGR; reject other terminal controls."""
    text = text.replace("\r\n", "\n")
    rows: list[list[tuple[str, Style]]] = [[]]
    style = Style()
    position = 0
    while position < len(text):
        character = text[position]
        if character == "\x1b":
            match = SGR.match(text, position)
            require(match is not None, f"Unsupported escape sequence at character {position}")
            for value in (int(item or 0) for item in match[1].split(";")):
                if value == 0:
                    style = Style()
                elif value in (1, 2):
                    style = replace(style, **{"bold" if value == 1 else "dim": True})
                elif value == 22:
                    style = replace(style, bold=False, dim=False)
                elif value in (39, 49):
                    style = replace(style, **{"foreground": FOREGROUND} if value == 39 else {"background": BACKGROUND})
                elif 30 <= value <= 37 or 90 <= value <= 97:
                    style = replace(style, foreground=PALETTE[value - (30 if value < 90 else 82)])
                elif 40 <= value <= 47 or 100 <= value <= 107:
                    style = replace(style, background=PALETTE[value - (40 if value < 100 else 92)])
                else:
                    raise ValueError(f"Unsupported SGR code {value}")
            position = match.end()
            continue
        if character == "\n":
            rows.append([])
        else:
            require(character.isprintable(), f"Unsupported control character {ord(character):#x}")
            require(not unicodedata.combining(character) and unicodedata.east_asian_width(character) not in "WF",
                    "The demo renderer requires single-column characters")
            rows[-1].append((character, style))
            require(len(rows[-1]) <= COLUMNS, f"Line exceeds the {COLUMNS}-column viewport")
        position += 1
    if not rows[-1]:
        rows.pop()
    require(len(rows) <= 21, "Scene exceeds the terminal viewport height")
    return rows


def scenes_from_capture(path: Path) -> list[Scene]:
    capture = json.loads(path.read_text(encoding="utf-8"))
    require(capture["schema_version"] == 1, "Unsupported capture schema")
    require(capture["terminal"]["columns"] == COLUMNS, "Capture must use 88 terminal columns")
    release, download, scan = capture["release"], capture["download"], capture["scan"]
    require(release["version"] == "0.4.0", "This demo layout requires RepoScan 0.4.0")
    expected_url = "https://github.com/ThreatProphet/RepoScan/releases/download/v0.4.0/reposcan-run.sh"
    require(release["launcher_url"] == expected_url, "Unexpected release launcher URL")
    for key in ("launcher_sha256", "wheel_sha256"):
        require(re.fullmatch(r"[a-f0-9]{64}", release[key]) is not None, f"Invalid {key}")
    require(download["exit_code"] == 0 and scan["exit_code"] == 1, "Unexpected command exit codes")
    require(download["argv"] == ["curl", "-fL", "-o", "reposcan-run.sh", expected_url],
            "Download command differs from the README flow")
    require(len(scan["argv"]) == 3 and scan["argv"][:2] == ["sh", "./reposcan-run.sh"],
            "Scan command must use the launcher without extra flags")
    require(Path(scan["argv"][2]).is_absolute(), "Scan target must be an absolute path")
    require(capture["runtime_cache"] == "fresh at scan start", "Capture must record a fresh runtime")
    require(capture["fixture_integrity"] == "unchanged", "Capture must preserve the inert fixture")
    report = scan["stdout"].replace("\r\n", "\n")
    lines = report.splitlines(keepends=True)
    require(len(lines) == 54 and report.endswith("\n"), "Expected the complete 54-line CLI report")
    anchors = {1: "RepoScan 0.4.0", 7: "[HIGH]", 21: "[MEDIUM]", 31: "[LOW]",
               40: "COVERAGE", 45: "SUMMARY", 54: "Exit code: 1"}
    for number, prefix in anchors.items():
        require(SGR.sub("", lines[number - 1]).startswith(prefix), f"Report anchor changed at line {number}")
    command = shlex.join(download["argv"][:-1]) + " \\\n  " + download["argv"][-1]
    scenes = [
        Scene("intro", "REPOSCAN 0.4.0", "Check the coding assignment before you run it.",
              "\n" + BOLD + "1  Download the script\n2  Scan the project" + RESET + "\n\n"
              "Static review before installing dependencies or running code.\n\n"
              + DIM + "Demonstration: inert Web3Market fixture" + RESET + "\n", 3.0),
        Scene("download", "01  DOWNLOAD", "Download the published launcher. Network wait shortened.",
              CYAN + "$ " + RESET + command + "\n", 5.5),
        Scene("scan", "02  SCAN", "Fresh private runtime. Setup wait shortened.",
              CYAN + "$ " + RESET + shlex.join(scan["argv"]) + "\n", 4.5),
    ]
    ranges = (
        ("high", 1, 20, "03  HIGH FINDING", "Inspect the file, reason and match locations.", 8.5),
        ("medium", 21, 30, "04  ENCODED DESTINATION", "Review the destination and how the code uses it.", 5.0),
        ("low", 31, 39, "05  CHARACTER DECODER", "Context determines whether the construct is suspicious.", 4.0),
        ("summary", 40, 54, "06  COVERAGE AND SUMMARY", "Read the verdict after the findings and coverage.", 7.0),
    )
    replayed = []
    for name, first, last, title, subtitle, duration in ranges:
        body = "".join(lines[first - 1:last])
        replayed.append(body)
        scenes.append(Scene(name, title, f"{subtitle} | Lines {first}-{last}/54", body, duration))
    require("".join(replayed) == report, "Report replay must preserve every line in order")
    scenes.append(Scene("close", "REVIEW BEFORE YOU RUN", "Use findings to guide your review.",
                        "\nInspect the flagged files and their execution context.\n\n"
                        + BOLD + "ThreatProphet / RepoScan" + RESET + "\n"
                        + CYAN + "github.com/ThreatProphet/RepoScan" + RESET + "\n\n"
                        + DIM + "No findings is not a guarantee of safety." + RESET + "\n", 3.5))
    for scene in scenes:
        styled_rows(scene.body)
    return scenes


def rgb(value: str) -> tuple[int, int, int]:
    number = int(value.lstrip("#"), 16)
    return number >> 16 & 255, number >> 8 & 255, number & 255


def render_media(scenes: list[Scene], output: Path, frames: Path | None, font_dir: Path) -> None:
    from PIL import Image, ImageDraw, ImageFont

    require(shutil.which("ffmpeg") is not None, "FFmpeg is required to render media")
    regular = str(font_dir / "DejaVuSansMono.ttf")
    bold = str(font_dir / "DejaVuSansMono-Bold.ttf")
    fonts = {False: ImageFont.truetype(regular, 24), True: ImageFont.truetype(bold, 24),
             "title": ImageFont.truetype(bold, 26), "label": ImageFont.truetype(regular, 17)}
    parsed = {scene.name: styled_rows(scene.body) for scene in scenes}

    def frame(scene: Scene, visible: int | None = None):
        image = Image.new("RGB", (WIDTH, HEIGHT), "#080e18")
        draw = ImageDraw.Draw(image)
        draw.rounded_rectangle((20, 20, WIDTH - 20, HEIGHT - 20), radius=16,
                               fill=BACKGROUND, outline="#26364c", width=1)

        def label(x: int, y: int, text: str, font, fill: str) -> None:
            box = draw.textbbox((x, y), text, font=font, anchor="lt")
            require(box[0] >= 40 and box[2] <= WIDTH - 40 and box[3] <= HEIGHT - 35,
                    f"Text clips the viewport: {text!r}")
            draw.text((x, y), text, font=font, fill=fill, anchor="lt")

        label(LEFT, 41, "THREATPROPHET / REPOSCAN", fonts["label"], PALETTE[6])
        label(WIDTH - 185, 41, "v0.4.0", fonts["label"], PALETTE[8])
        draw.line((LEFT, 72, WIDTH - LEFT, 72), fill="#26364c", width=1)
        label(LEFT, 92, scene.title, fonts["title"], FOREGROUND)
        label(LEFT, 132, scene.subtitle, fonts["label"], PALETTE[8])
        count = 0
        for row_number, row in enumerate(parsed[scene.name]):
            for column, (character, style) in enumerate(row):
                if visible is not None and count >= visible:
                    continue
                count += 1
                x, y = LEFT + column * CELL_WIDTH, TOP + row_number * LINE_HEIGHT
                if style.background != BACKGROUND:
                    draw.rectangle((x, y, x + CELL_WIDTH - 1, y + LINE_HEIGHT - 1), fill=style.background)
                fill = rgb(style.foreground)
                if style.dim:
                    fill = tuple(round(f * 0.65 + b * 0.35) for f, b in zip(fill, rgb(style.background)))
                baseline = y + fonts[style.bold].getmetrics()[0]
                bounds = draw.textbbox((x, baseline), character, font=fonts[style.bold], anchor="ls")
                require(bounds[0] >= LEFT and bounds[2] <= WIDTH - LEFT and bounds[3] < 800,
                        f"Scene {scene.name} clips row {row_number + 1}, column {column + 1}")
                draw.text((x, baseline), character, font=fonts[style.bold], fill=fill, anchor="ls")
        label(LEFT, 818, FOOTER, fonts["label"], PALETTE[8])
        index = NAMES.index(scene.name)
        label(WIDTH - 105, 818, f"{index + 1}/8", fonts["label"], PALETTE[6])
        for step in range(8):
            x = LEFT + step * 165
            draw.rounded_rectangle((x, 852, x + 150, 856), radius=2,
                                   fill=PALETTE[6] if step <= index else "#26364c")
        return image

    # Validate every complete scene before creating output files.
    keyframes = {scene.name: frame(scene) for scene in scenes}
    with tempfile.TemporaryDirectory(prefix="reposcan-demo-render-") as temporary:
        work = Path(temporary)
        timeline = ["ffconcat version 1.0"]
        count = 0

        def add(image, duration: float) -> None:
            nonlocal count
            name = f"frame-{count:04d}.png"
            image.save(work / name)
            timeline.extend([f"file '{name}'", f"duration {duration:.3f}"])
            count += 1

        for scene in scenes:
            if scene.name in ("download", "scan"):
                length = sum(len(row) for row in parsed[scene.name])
                reveals = list(range(2, length, 4))
                step_time = min(0.08, (scene.duration - 1.5) / len(reveals))
                for visible in reveals:
                    add(frame(scene, visible), step_time)
                add(keyframes[scene.name], scene.duration - len(reveals) * step_time)
            else:
                add(keyframes[scene.name], scene.duration)
        timeline.append(f"file 'frame-{count - 1:04d}.png'")
        playlist = work / "frames.ffconcat"
        playlist.write_text("\n".join(timeline) + "\n", encoding="utf-8")
        duration = sum(scene.duration for scene in scenes)
        common = ["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-threads", "2",
                  "-filter_threads", "1", "-filter_complex_threads", "1",
                  "-f", "concat", "-safe", "0", "-i", str(playlist)]
        commands = (
            [*common, "-vf", "fps=25", "-c:v", "libx264", "-threads", "2", "-preset", "medium",
             "-crf", "18", "-pix_fmt", "yuv420p", "-movflags", "+faststart", "-t", str(duration),
             str(work / "reposcan-demo.mp4")],
            [*common, "-filter_complex",
             "split[a][b];[a]palettegen=max_colors=256:stats_mode=diff[p];"
             "[b][p]paletteuse=dither=none:diff_mode=rectangle",
             "-fps_mode", "vfr", "-loop", "0", "-final_delay", str(round(scenes[-1].duration * 100)),
             "-t", str(duration), str(work / "reposcan-demo.gif")],
        )
        for command in commands:
            result = subprocess.run(command, capture_output=True, text=True, timeout=180)
            require(result.returncode == 0, f"FFmpeg failed: {result.stderr.strip()}")
        keyframes["high"].save(work / "reposcan-demo-poster.png")
        output.mkdir(parents=True, exist_ok=True)
        for name in ("reposcan-demo.gif", "reposcan-demo.mp4", "reposcan-demo-poster.png"):
            shutil.copyfile(work / name, output / name)
        if frames:
            frames.mkdir(parents=True, exist_ok=True)
            for name, image in keyframes.items():
                image.save(frames / f"{name}.png")
    print(f"Rendered {duration:.1f}s GIF/MP4 and poster at {WIDTH}x{HEIGHT}; all 54 report lines preserved.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, default=ROOT / "docs/demo/capture.json")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "docs/assets")
    parser.add_argument("--frames-dir", type=Path, help="Also save the eight full scene frames for review")
    parser.add_argument("--font-dir", type=Path, default=Path("/usr/share/fonts/truetype/dejavu"))
    parser.add_argument("--terminal", choices=NAMES, help="Print one ANSI replay scene; no Pillow or FFmpeg needed")
    args = parser.parse_args()
    try:
        scenes = scenes_from_capture(args.capture)
        if args.terminal:
            scene = next(item for item in scenes if item.name == args.terminal)
            print(f"{BOLD}{CYAN}{scene.title}{RESET}\n{DIM}{scene.subtitle}{RESET}\n\n{scene.body}", end="")
        else:
            render_media(scenes, args.output_dir, args.frames_dir, args.font_dir)
    except (OSError, ValueError, KeyError, TypeError, ImportError, subprocess.SubprocessError) as error:
        print(f"Demo rendering failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
