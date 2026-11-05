# Reproduce the README recording

The [recording source](demo.tape) demonstrates the **development terminal
layout** against public, inert fixtures. It shows a benign baseline, three
Web3Market review findings, and the scanner's actual exit status. The fixture
files are read as data. The CLI still identifies itself as RepoScan 0.2.0;
the opening card labels this as a development preview.

The checked-in media is a rendered replay of captured CLI output. The tape
below provides a native terminal recording workflow for the same demonstration.
Its syntax has been validated; a native VHS browser capture was not used to
produce these assets.

Run these commands in **Bash on Linux**, from the root of a trusted RepoScan
checkout that contains this guide and `docs/demo.tape`. Keep that documentation
checkout separate from any unfamiliar project you are inspecting.

## 1. Prepare the recording tools

You need:

- **This RepoScan checkout with `yara-python`**, installed into a development
  environment. The released `v0.2.0` build has the previous layout and cannot
  reproduce this recording. A separate YARA CLI does not satisfy the tape's
  explicit Python engine choice.
- **[VHS](https://github.com/charmbracelet/vhs/tree/v0.12.1#installation)**,
  with `ttyd` and `ffmpeg` available on `PATH`. The commands below use the VHS
  0.12.1 interface. Its browser and local terminal server must be able to start.
- **DejaVu Sans Mono** to match the intended layout. A fallback font can change
  line wrapping even when the tape's syntax is valid.
- **Bash, `sed`, and `wc`**, supplied by the usual Linux shell utilities.

Activate your working Python/YARA development environment in the same shell
that will run VHS. From this trusted checkout, install its current source and
verify that the import resolves here:

```bash
python -m pip install --editable '.[yara]'
python -c 'from pathlib import Path; import reposcan; assert Path(reposcan.__file__).resolve().parent == Path("src/reposcan").resolve()'
```

Use a dedicated virtual environment if you do not already have one; see the
[development setup](../CONTRIBUTING.md#verify-changes) and
[installation guide](installation.md) for Python/YARA requirements. Check the
commands that the active shell will use:

```bash
command -v reposcan vhs ttyd ffmpeg bash sed wc
reposcan --version
vhs --version
```

The scanner currently prints `RepoScan 0.2.0`, but the version alone does not
identify the updated renderer. The preflight below also checks its 88-column
layout, findings, and footer. This recording does not change RepoScan's Python
3.10+ support. Keep the development environment active when launching VHS.

On systems with Fontconfig, `fc-match 'DejaVu Sans Mono'` shows the selected
font. Install the font through your distribution if it resolves to a substitute.

## 2. Copy the public fixtures once

The tape uses a fixed temporary path so the recording does not show a personal
home directory. Create a fresh directory and copy only the two fixture trees:

```bash
(
  set -eu
  test -f docs/demo.tape
  test "$(reposcan --version)" = 'RepoScan 0.2.0'
  demo_root=/tmp/reposcan-demo-terminal-ux
  mkdir -m 700 "$demo_root"
  cp -R tests/fixtures/benign "$demo_root/benign-project"
  cp -R tests/fixtures/web3market-entry "$demo_root/received-project"
)
```

This step deliberately stops if the temporary directory already exists.
For an unchanged fixture copy, continue with the preflight and recording steps.
To replace an old copy, use the backup procedure under
[Repeat or refresh a recording](#repeat-or-refresh-a-recording).
Do not repeat the copy commands over existing destination directories: doing
so can nest a second fixture tree and change the scan results.

The resulting inputs are one benign `package.json` and two Web3Market
`.fixture` files. Do not install dependencies or run commands from these inputs.

## 3. Check the scanner and expected report

This preflight uses the same working directory, engine, colour setting, and
explicit width as the tape. It handles the positive fixture's expected nonzero
exit status and checks the page boundaries before recording:

```bash
(
  set -eu
  cd /tmp/reposcan-demo-terminal-ux

  reposcan benign-project --engine yara-python --color always --width 88

  if reposcan received-project --engine yara-python --color always --width 88 > review.txt; then
    demo_scan_status=0
  else
    demo_scan_status=$?
  fi

  printf 'Received-project exit status: %s\n' "$demo_scan_status"
  test "$demo_scan_status" -eq 1
  test "$(wc -l < review.txt)" -eq 52
  sed -E 's/\x1B\[[0-9;]*m//g' review.txt > review-plain.txt
  test "$(sed -n '12p' review-plain.txt)" = '[HIGH]  Finding 1/3'
  test "$(sed -n '26p' review-plain.txt)" = '[MEDIUM]  Finding 2/3'
  test "$(sed -n '36p' review-plain.txt)" = '[LOW]  Finding 3/3'
  test "$(sed -n '$p' review-plain.txt)" = "Exit code: $demo_scan_status"
  printf 'Preflight passed: expected status, 52 report lines, page boundaries, and footer.\n'
)
```

Compare the results with these expectations:

| Input | Verdict | Findings | Selected files scanned | Process exit status |
| --- | --- | --- | --- | --- |
| `benign-project` | `no-findings` | 0 | 1/1 | 0 |
| `received-project` | `review-needed` | 3 | 2/2 | 1 |

The [full example result](../examples/web3market.txt) lists the expected rule
IDs and evidence locations. Exit `1` means review findings are present; it is
not a recording failure. A result with no findings is not a safety guarantee.
The saved `review.txt` contains ANSI colour sequences because the tape displays
the scanner's original formatted output. `review-plain.txt` removes only SGR
styling for assertions. The footer check does not depend on a particular ANSI
bold or dim sequence.

The four report pages cover every saved line exactly once:

| Page | Saved lines | Content |
| --- | --- | --- |
| Scan result | 1-11 | Verdict, finding counts, severity counts, and scan status |
| Matched pattern | 12-25 | High-severity finding and its evidence |
| Encoded destination | 26-35 | Medium-severity finding and its evidence |
| Decoder and result | 36-52 | Low-severity finding, coverage, next step, and exit code |

## 4. Validate and render

From the repository root, run:

```bash
vhs validate docs/demo.tape && vhs docs/demo.tape
```

Validation parses the tape without running its commands. Rendering then runs
the trusted scanner against the fixture copies and writes these tracked assets:

| Output | Purpose |
| --- | --- |
| `docs/assets/reposcan-demo.gif` | Animated README demonstration |
| `docs/assets/reposcan-demo.mp4` | Video version for sharing |
| `docs/assets/reposcan-demo-poster.png` | Still image of the high-severity finding |

VHS replaces the existing assets, and the scanner overwrites
`/tmp/reposcan-demo-terminal-ux/review.txt`. A successful render returns exit `0`;
the displayed scanner exit `1` remains the expected review result.

Open the generated media and check that:

- The opening card and complete benign baseline are visible.
- All four saved-report pages are readable, including the three findings.
- The final report page shows `Exit code: 1`, followed by the closing guidance.
- The prompt and displayed paths contain no personal information.

The numbered headings and opening/closing cards are presentation annotations.
The report pages display all 52 saved report lines, without rewriting them.
Keep that distinction when changing the presentation. Check the asset changes
before committing:

```bash
git diff --stat -- docs/assets
git status --short -- docs/assets
```

## Repeat or refresh a recording

For another render with the same fixtures, rerun steps 3 and 4. Reuse the
temporary directory rather than copying the fixture trees into it again.

If the fixture copy is stale or has extra files, move it aside before repeating
step 2. This preserves the previous report and inputs:

```bash
(
  set -eu
  demo_backup=$(mktemp -d /tmp/reposcan-demo-backup.XXXXXX)
  mv -- /tmp/reposcan-demo-terminal-ux "$demo_backup/"
  printf 'Previous demo saved in %s\n' "$demo_backup"
)
```

For a future scanner version or changed fixtures, update the development label,
version check, expected findings, report line count, page ranges, and waits
together. Generate and inspect the new report before choosing page boundaries,
then refresh all three media assets. Keep `--width 88` explicit in both the
preflight and tape, so redirected output uses the same layout as the baseline.
The current tape intentionally rejects a different version or report layout.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| `reposcan` is missing or the version check times out | Activate the development environment, check `command -v reposcan`, and confirm `reposcan --version` prints `RepoScan 0.2.0`. |
| `--width` is unrecognized or the old layout appears | Install this checkout with `python -m pip install --editable '.[yara]'`; check the source import and command paths. The released 0.2.0 build does not contain the new renderer. |
| The Python YARA engine is unavailable | Install the scanner with `[yara]` in the environment supplying `reposcan`. Do not switch to Lite to make the recording pass. |
| The exit status, 52-line check, or page-boundary check fails | Run the preflight, inspect `review-plain.txt`, and confirm the fixture directories contain only the documented files. Resolve the mismatch before rendering. |
| A screen wait shows an old heading or never sees the footer | Use the current tape, including `demo_clear` with `\033[2J\033[3J\033[H`. Clearing scrollback is required as well as the visible screen. |
| Text wraps differently or a report page is cut off | Check the font and the tape's dimensions. Recheck all four pages after any layout change. |
| VHS cannot launch its browser or terminal server | Check the upstream VHS setup and use an environment where those components can run. Tape validation alone does not establish that rendering will work. |

When reporting a recording problem, include the RepoScan, VHS, ttyd, and ffmpeg
versions; the failing wait or command; and whether the preflight passed. Remove
personal paths from logs. There is no need to share private repositories or live
malware to reproduce this demonstration.
