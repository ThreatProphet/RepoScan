# Reproduce the RepoScan 0.4.0 demonstration

The demo follows the README's two-step flow: download the launcher, then scan a
project. It uses the published **RepoScan 0.4.0** launcher and public inert
Web3Market fixtures, showing all three findings and the summary at the end.

The GIF, MP4 and poster are rendered replays of a real terminal capture.
`tools/capture_demo.py` downloads the release script, verifies its SHA-256 and
runs the simple scan command through an 88-column pseudo-terminal (PTY).
`tools/render_demo.py` turns that capture into the media using Pillow and
FFmpeg. The scanner's report text and ANSI colors are retained; scene headings
and opening/closing cards are presentation annotations.

Download, typing and setup pauses are edited for readability. First-run runtime
provisioning occurs during capture; its actual duration is recorded in the
capture data. The displayed setup time is shortened.

## 1. Prepare the recording environment

Run these commands from the root of a trusted RepoScan checkout on Linux.
You need **Python 3.12**, **FFmpeg**, **DejaVu Sans Mono**, and the launcher's
usual shell utilities, including `curl`, `tar` and a SHA-256 utility. Network
access is required for the release script and the launcher's private runtime.
An existing RepoScan installation is not required.

Create a rendering environment:

```bash
python3.12 -m venv .venv-demo
. .venv-demo/bin/activate
python3 -m pip install 'Pillow==13.0.0'
```

Install FFmpeg and DejaVu fonts through your distribution if needed. On Ubuntu
or Debian, their packages are `ffmpeg` and `fonts-dejavu-core`. Keep this Python
environment active for the remaining commands.

## 2. Capture and render

The default capture directory is `/tmp/reposcan-demo-v040`. It must not already
exist. The capture step copies the public fixture into that directory and uses
a fresh private launcher state. The target files are scanned as data.

```bash
python3 tools/capture_demo.py
python3 tools/render_demo.py
```

The first command records the real download and this scan invocation:

```sh
sh ./reposcan-run.sh /tmp/reposcan-demo-v040/received-project
```

The capture checks the release identity, fixture integrity and expected scan
result before recording the report. The received-project fixture should produce
`review-needed`, three findings across two files, and process exit status `1`.
That status is an expected scan result and is handled by the capture tool.

The second command renders the saved capture. It does not rerun the download or
scan. The outputs are:

| File | Purpose |
| --- | --- |
| `docs/demo/capture.json` | Captured output, process status, timing and provenance |
| `docs/assets/reposcan-demo.gif` | Animated README demonstration |
| `docs/assets/reposcan-demo.mp4` | Video for sharing |
| `docs/assets/reposcan-demo-poster.png` | Still image of the high-severity finding |

The capture preserves the scan's stdout and stderr. Curl's progress output is
stored as text with normalized newlines. `source_commit` identifies the checkout
that supplied the fixtures; tool changes are tracked by the commit containing
this capture and its media.

The complete 54-line report appears in order across four scenes:

| Scene | Report lines | Content |
| --- | --- | --- |
| High finding | 1–20 | Version, target, engine and high-severity finding |
| Encoded destination | 21–30 | Medium-severity finding |
| Character decoder | 31–39 | Low-severity finding |
| Coverage and summary | 40–54 | Coverage, verdict, counts, next step and exit code |

The main presentation uses a 1440 × 900 canvas, 24-pixel DejaVu Sans Mono and the
RepoScan terminal palette. It runs for approximately 40 seconds. The poster is
selected from the high-finding scene.

## 3. Review the result

Open the GIF, MP4 and poster before committing them. Check that:

- The download and scan commands match the simple README workflow.
- The version is `RepoScan 0.4.0`, and the fixture paths contain no personal data.
- All three findings and their evidence are readable without clipping.
- Coverage and the summary follow the findings, with `Exit code: 1` visible.
- The setup-time annotation is visible and the media loops cleanly.

Review the resulting changes:

```bash
git diff --stat -- docs/demo docs/assets docs/demo.md docs/demo.tape
git status --short -- docs/demo docs/assets docs/demo.md docs/demo.tape
```

For presentation-only changes, rerun `python3 tools/render_demo.py` using the
existing capture. To make a fresh capture, move the old working directory aside
first, then rerun both commands:

```bash
demo_backup="$(mktemp -d /tmp/reposcan-demo-backup.XXXXXX)"
mv -- /tmp/reposcan-demo-v040 "$demo_backup/"
python3 tools/capture_demo.py
python3 tools/render_demo.py
```

For a new scanner release, update the release constants in `tools/capture_demo.py`
and the version checks and report layout in `tools/render_demo.py`, then capture
and review fresh output. Keep the capture and all three media assets in the same
update.

## Optional: replay the capture with VHS

The canonical renderer above does not require a browser or local terminal
server. Contributors who have **VHS 0.12.1**, `ttyd` and its browser dependencies
can replay the same captured scenes using [docs/demo.tape](demo.tape):

```bash
vhs validate docs/demo.tape
vhs docs/demo.tape
```

Run this from the repository root with the rendering environment active. VHS
uses `python3 tools/render_demo.py --terminal SCENE` to display the saved scenes;
it does not perform another scan. It replaces the same GIF, MP4 and poster.
Record which renderer produced the committed assets when changing the method.

The tape clears both the visible screen and scrollback between scenes. It checks
the final exit-code line only on the compact summary scene, where it is visible.
A successful syntax check does not establish that VHS can start its browser or
terminal server in the current environment.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| Capture directory already exists | Render the existing capture, or use the backup procedure before capturing again. |
| Download or provisioning fails | Check the network and release URL; keep checksum verification enabled. |
| Version, findings or report layout differ | Inspect the capture error and the fixture contents before changing expectations. |
| Text is clipped or a font is missing | Install DejaVu Sans Mono and check the intended canvas, font size and page boundaries. |
| VHS cannot start its browser or terminal server | Use the canonical Pillow/FFmpeg renderer, or run VHS in an environment that supports those components. |

When reporting a recording issue, include the Python, Pillow and FFmpeg versions,
the failed command, and the error text. Remove personal paths from logs.
