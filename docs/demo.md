# Reproduce the README recording

The [recording source](demo.tape) demonstrates RepoScan 0.2.0 against public,
inert fixtures. It shows a benign baseline, three Web3Market review findings,
and the scanner's actual exit status. The fixture files are read as data.

Run these commands in **Bash on Linux**, from the root of a trusted RepoScan
checkout that contains this guide and `docs/demo.tape`. Keep that documentation
checkout separate from any unfamiliar project you are inspecting.

## 1. Prepare the recording tools

You need:

- **RepoScan 0.2.0 with `yara-python`**, installed using the
  [installation guide](installation.md). Keep `[yara]` in the install command.
  A separate YARA CLI does not satisfy this tape's explicit Python engine choice.
- **[VHS](https://github.com/charmbracelet/vhs/tree/v0.12.1#installation)**,
  with `ttyd` and `ffmpeg` available on `PATH`. The commands below use the VHS
  0.12.1 interface. Its browser and local terminal server must be able to start.
- **DejaVu Sans Mono** to match the intended layout. A fallback font can change
  line wrapping even when the tape's syntax is valid.
- **Bash, `sed`, and `wc`**, supplied by the usual Linux shell utilities.

If RepoScan is installed in a virtual environment, activate it in the same
shell that will run VHS. If using pipx, its application directory must be on
`PATH`. Check the commands and version:

```bash
command -v reposcan vhs ttyd ffmpeg bash sed wc
reposcan --version
vhs --version
```

The scanner must print `RepoScan 0.2.0`. This is a requirement of this specific
recording, whose report layout and expected findings are fixed. It does not
change RepoScan's Python 3.10+ support. The tagged `v0.2.0` checkout supplies
the scanner; this guide and the tape were added later, so run VHS from the
checkout containing the recording source.

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
  demo_root=/tmp/reposcan-demo-v0.2.0
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

This preflight uses the same working directory, engine, and colour setting as
the tape. It also handles the positive fixture's expected nonzero exit status:

```bash
(
  set -eu
  cd /tmp/reposcan-demo-v0.2.0

  reposcan benign-project --engine yara-python --color always

  if reposcan received-project --engine yara-python --color always > review.txt; then
    demo_scan_status=0
  else
    demo_scan_status=$?
  fi

  printf 'Received-project exit status: %s\n' "$demo_scan_status"
  test "$demo_scan_status" -eq 1
  test "$(wc -l < review.txt)" -eq 40
  test "$(sed -n '$p' review.txt)" = \
    "$(printf '\033[2mExit code: %s\033[0m' "$demo_scan_status")"
  printf 'Preflight passed: expected status, 40 report lines, and matching footer.\n'
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
the scanner's original formatted output.

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
`/tmp/reposcan-demo-v0.2.0/review.txt`. A successful render returns exit `0`;
the displayed scanner exit `1` remains the expected review result.

Open the generated media and check that:

- The opening card and complete benign baseline are visible.
- All four saved-report pages are readable, including the three findings.
- The final report page shows `Exit code: 1`, followed by the closing guidance.
- The prompt and displayed paths contain no personal information.

The numbered headings and opening/closing cards are presentation annotations.
The report pages display all 40 saved report lines, without rewriting them.
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
  mv -- /tmp/reposcan-demo-v0.2.0 "$demo_backup/"
  printf 'Previous demo saved in %s\n' "$demo_backup"
)
```

For a future scanner version or changed fixtures, update the version check,
expected findings, report line count, page ranges, and waits together. Generate
and inspect the new report before choosing the page boundaries, then refresh
all three media assets. The current tape intentionally rejects a different
version or report layout.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| `reposcan` is missing or the version check times out | Check `command -v reposcan`, activate the intended environment, and confirm `reposcan --version` prints `RepoScan 0.2.0`. |
| The Python YARA engine is unavailable | Use the installation guide to install the scanner with `[yara]` in the environment supplying `reposcan`. Do not switch to Lite to make the recording pass. |
| The exit status or 40-line check fails | Run the preflight, inspect `review.txt`, and confirm the fixture directories contain only the documented files. Resolve the mismatch before rendering. |
| A screen wait shows an old heading or never sees the footer | Use the current tape, including `demo_clear` with `\033[2J\033[3J\033[H`. Clearing scrollback is required as well as the visible screen. |
| Text wraps differently or a report page is cut off | Check the font and the tape's dimensions. Recheck all four pages after any layout change. |
| VHS cannot launch its browser or terminal server | Check the upstream VHS setup and use an environment where those components can run. Tape validation alone does not establish that rendering will work. |

When reporting a recording problem, include the RepoScan, VHS, ttyd, and ffmpeg
versions; the failing wait or command; and whether the preflight passed. Remove
personal paths from logs. There is no need to share private repositories or live
malware to reproduce this demonstration.
