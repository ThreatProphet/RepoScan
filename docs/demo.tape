# Optional native VHS replay of the canonical RepoScan 0.4.0 capture.
# First run tools/capture_demo.py. For the canonical renderer, use render_demo.py.
# Run VHS from the trusted repository root with python3 available.
# All scanner output comes from docs/demo/capture.json; no target code is executed.
# Scene titles and opening/closing cards are presentation annotations.

Output docs/assets/reposcan-demo.gif
Output docs/assets/reposcan-demo.mp4

Require bash
Require python3
Require stty

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

Hide
Type@1ms "exec bash --noprofile --norc"
Enter
Sleep 500ms
# Clear the visible screen AND scrollback before every scene. This prevents
# waits from seeing stale report rows after hidden shell commands have scrolled.
Type@1ms `unset PROMPT_COMMAND; export PS1=''; stty cols 88; printf '\033[?25l'; demo_scene() { printf '\033[2J\033[3J\033[H'; python3 tools/render_demo.py --terminal "$1"; }; demo_scene intro`
Enter
Wait+Screen /(?m)^REPOSCAN 0\.4\.0$/
Show
Sleep 2s

Hide
Type@1ms `demo_scene download`
Enter
Wait+Screen /(?m)^01  DOWNLOAD$/
Wait+Screen /reposcan-run\.sh/
Show
Sleep 5s

Hide
Type@1ms `demo_scene scan`
Enter
Wait+Screen /(?m)^02  SCAN$/
Wait+Screen /received-project/
Show
Sleep 4s

Hide
Type@1ms `demo_scene high`
Enter
Wait+Screen /(?m)^03  HIGH FINDING$/
Wait+Screen /TP_DevelTask_Node_InlineArray_Remote_Execution/
Wait+Screen /Report:\s+TP-2026-018/
Show
Sleep 9s
Screenshot docs/assets/reposcan-demo-poster.png

Hide
Type@1ms `demo_scene medium`
Enter
Wait+Screen /(?m)^04  ENCODED DESTINATION$/
Wait+Screen /REVIEW_Encoded_Character_Array/
Show
Sleep 6s

Hide
Type@1ms `demo_scene low`
Enter
Wait+Screen /(?m)^05  CHARACTER DECODER$/
Wait+Screen /REVIEW_Character_Code_Decoder/
Show
Sleep 4s

Hide
Type@1ms `demo_scene summary`
Enter
Wait+Screen /(?m)^06  COVERAGE AND SUMMARY$/
Wait+Screen /(?m)^SUMMARY$/
Wait+Screen /Verdict:\s+review-needed/
Wait+Screen /(?m)^Exit code: 1$/
Show
Sleep 7s

Hide
Type@1ms `demo_scene close`
Enter
Wait+Screen /(?m)^REVIEW BEFORE YOU RUN$/
Show
Sleep 3s
