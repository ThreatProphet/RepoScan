# Run from the trusted checkout with its updated renderer installed and YARA.
# Setup, reruns, and troubleshooting: docs/demo.md (from the repository root).
# Reuse the public fixtures copied into /tmp/reposcan-demo-terminal-ux.
# Requires VHS, ttyd and ffmpeg. No target code is executed.
# Titles are demo annotations; every report page is unmodified scanner output.
# The CLI still reports 0.2.0; this is a development terminal preview.

Output docs/assets/reposcan-demo.gif
Output docs/assets/reposcan-demo.mp4

Require bash
Require reposcan
Require sed
Require wc

Set Shell "bash"
Set FontFamily "DejaVu Sans Mono, monospace"
Set FontSize 24
Set LineHeight 1.05
Set Width 1440
Set Height 900
Set Padding 28
Set Margin 20
Set MarginFill "#080e18"
Set BorderRadius 12
Set WindowBar Colorful
Set WindowBarSize 36
Set TypingSpeed 18ms
Set Framerate 25
Set CursorBlink false
Set Theme { "name": "RepoScan", "background": "#111b2b", "foreground": "#e4edf7", "black": "#172335", "red": "#ff818f", "green": "#83d9a6", "yellow": "#f4cc77", "blue": "#92baff", "magenta": "#c9a5f7", "cyan": "#73d9ed", "white": "#e4edf7", "brightBlack": "#abbcd0", "brightRed": "#ff9aa5", "brightGreen": "#a1e7b8", "brightYellow": "#ffdda0", "brightBlue": "#b1ceff", "brightMagenta": "#dfbfff", "brightCyan": "#a3eaf7", "brightWhite": "#ffffff", "selection": "#294361", "cursor": "#73d9ed" }

Env PROMPT "$ "

Hide
Type@1ms "exec bash --noprofile --norc"
Enter
Sleep 500ms
Type@1ms `set +e; unset PROMPT_COMMAND; export PS1='\[\e[36m\]$\[\e[0m\] '; demo_clear() { printf '\033[2J\033[3J\033[H'; }; cd /tmp/reposcan-demo-terminal-ux || exit 1; demo_clear`
Enter
Wait+Line /^\$ *$/
Type@1ms `demo_version=$(reposcan --version); demo_clear; test "$demo_version" = 'RepoScan 0.2.0' && printf 'REPOSCAN_VERSION_OK\n'`
Enter
Wait+Screen /(?m)^REPOSCAN_VERSION_OK$/
# Clear visible content AND scrollback. VHS Screen waits can otherwise read old
# buffer rows after output or hidden command typing has caused the terminal to scroll.
Type@1ms `demo_heading() { demo_clear; printf '\033[1;36m%s\033[0m\n\033[90m%s\033[0m\n\n' "$1" "$2"; }`
Enter
Wait+Line /^\$ *$/

# Opening card. Version is read from the installed CLI above.
Type@1ms `PS1=''; demo_clear; printf '\033[?25l\n\n\033[1;36mTHREATPROPHET\033[0m\n\n\033[1m%s\033[0m\nDevelopment terminal preview\nCheck the coding assignment before you run it.\n\n\033[90mStatic review | YARA + review checks\nPublic inert fixtures | scanned as file data\033[0m\n' "$demo_version"`
Enter
Wait+Screen /(?m)^Public inert fixtures \| scanned as file data$/
Show
Sleep 3s

# Baseline: show the real command and the complete benign report.
Hide
Type@1ms `export PS1='\[\e[36m\]$\[\e[0m\] '; demo_heading '01  BASELINE' 'A benign fixture | review the inspected scope'; printf '\033[?25h'`
Enter
Wait+Line /^\$ *$/
Show
Type "reposcan benign-project --engine yara-python --color always --width 88"
Enter
Wait+Screen /No matching review patterns were found/
Wait+Screen /(?m)^Exit code: 0$/
Wait+Line /^\$ *$/
Sleep 6s

# Check the actual process status before another shell command changes it.
Hide
Type@1ms `demo_benign_status=$?; demo_clear; printf 'REPOSCAN_BENIGN_STATUS=%s\n' "$demo_benign_status"`
Enter
Wait+Screen /(?m)^REPOSCAN_BENIGN_STATUS=0$/
Type@1ms `demo_heading '02  RECEIVED PROJECT' 'Public Web3Market fixture | scan before installation'`
Enter
Wait+Line /^\$ *$/
Show
Type "reposcan received-project --engine yara-python --color always --width 88 > review.txt"
Enter
Wait+Line /^\$ *$/
Sleep 2s

Hide
Type@1ms `demo_scan_status=$?; demo_clear; printf 'REPOSCAN_POSITIVE_STATUS=%s\n' "$demo_scan_status"`
Enter
Wait+Screen /(?m)^REPOSCAN_POSITIVE_STATUS=1$/
# This development layout has 52 lines at width 88. Stop if it changes.
Type@1ms `demo_report_lines=$(wc -l < review.txt); demo_clear; printf 'REPOSCAN_REPORT_LINES=%s\n' "$demo_report_lines"`
Enter
Wait+Screen /(?m)^REPOSCAN_REPORT_LINES=52$/

# Check the saved footer independently of its position in the recording.
# Strip SGR styling for assertions only; displayed pages keep the original ANSI.
Type@1ms `sed -E 's/\x1B\[[0-9;]*m//g' review.txt > review-plain.txt && test "$(sed -n '$p' review-plain.txt)" = "Exit code: $demo_scan_status"; demo_footer_status=$?; demo_clear; printf 'REPOSCAN_FOOTER_STATUS=%s\n' "$demo_footer_status"`
Enter
Wait+Screen /(?m)^REPOSCAN_FOOTER_STATUS=0$/
Type@1ms `test "$(sed -n '12p' review-plain.txt)" = '[HIGH]  Finding 1/3' && test "$(sed -n '26p' review-plain.txt)" = '[MEDIUM]  Finding 2/3' && test "$(sed -n '36p' review-plain.txt)" = '[LOW]  Finding 3/3'; demo_layout_status=$?; demo_clear; printf 'REPOSCAN_LAYOUT_STATUS=%s\n' "$demo_layout_status"`
Enter
Wait+Screen /(?m)^REPOSCAN_LAYOUT_STATUS=0$/

# All 52 report lines appear exactly once across the four saved-report pages.
# Hide only the presentation commands, not the evidence they print.
Type@1ms `PS1=''; printf '\033[?25l'; demo_heading '02  SCAN RESULT' 'Saved CLI report 1/4 | Web3Market fixture'; sed -n '1,11p' review.txt`
Enter
Wait+Screen /Verdict:  review-needed/
Wait+Screen /Severity: \[HIGH 1\]  \[MEDIUM 1\]  \[LOW 1\]/
Wait+Screen /Scanned:  2\/2 selected files/
Sleep 100ms
Show
Sleep 5s

Hide
Type@1ms `demo_heading '03  MATCHED PATTERN' 'Saved CLI report 2/4 | Inspect the file and match locations'; sed -n '12,25p' review.txt`
Enter
Wait+Screen /\[HIGH\]  Finding 1\/3/
Wait+Screen /TP_DevelTask_Node_InlineArray_Remote_Execution/
Wait+Screen /Report:   TP-2026-018/
Show
Sleep 9s
Screenshot docs/assets/reposcan-demo-poster.png

Hide
Type@1ms `demo_heading '04  ENCODED DESTINATION' 'Saved CLI report 3/4 | Review the URL and its use'; sed -n '26,35p' review.txt`
Enter
Wait+Screen /\[MEDIUM\]  Finding 2\/3/
Wait+Screen /REVIEW_Encoded_Character_Array/
Wait+Screen /Report:   TP-2026-018/
Show
Sleep 6s

Hide
Type@1ms `demo_heading '05  DECODER AND RESULT' 'Saved CLI report 4/4 | Review the surrounding code'; sed -n '36,$p' review.txt`
Enter
Wait+Screen /\[LOW\]  Finding 3\/3/
Wait+Screen /REVIEW_Character_Code_Decoder/
Wait+Screen /(?m)^Exit code: 1$/
Show
Sleep 7s

# Closing guidance is an editorial card, separate from the scanner report.
Hide
Type@1ms `demo_clear; printf '\n\n\033[1;36mREVIEW BEFORE YOU RUN\033[0m\n\nInspect the flagged files and their execution context.\n\n\033[1mThreatProphet / RepoScan\033[0m\n\033[36mgithub.com/ThreatProphet/RepoScan\033[0m\n\n\033[90mResearch: TP-2026-018\nNo findings is not a guarantee of safety.\033[0m\n'`
Enter
Wait+Screen /(?m)^No findings is not a guarantee of safety\.$/
Show
Sleep 4s
