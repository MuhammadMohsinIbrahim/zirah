# Zirah demo for the README. Rendered by .github/workflows/demo.yml on ubuntu with VHS
# (https://github.com/charmbracelet/vhs); the workflow uploads docs/demo.gif as an artifact,
# which is committed. Do not render it locally.

Output docs/demo.gif

Require zirah
Require less

Set Shell "bash"
Set FontSize 15
Set Width 1200
Set Height 760
Set Padding 24
Set Theme { "name": "Zirah Navy", "background": "#0b1d3a", "foreground": "#f2f5fa", "selection": "#2b4a7a", "cursor": "#f2f5fa", "black": "#0b1d3a", "red": "#ff6b6b", "green": "#5fd38d", "yellow": "#ffd166", "blue": "#6ea8fe", "magenta": "#c39bff", "cyan": "#5ccfe6", "white": "#d8dee9", "brightBlack": "#6b7a90", "brightRed": "#ff8787", "brightGreen": "#7ee2a8", "brightYellow": "#ffe08a", "brightBlue": "#9ec5ff", "brightMagenta": "#d6b8ff", "brightCyan": "#8ee3f0", "brightWhite": "#ffffff" }
Set TypingSpeed 45ms
Set PlaybackSpeed 1

# Keep colours when the report is paged through less.
Env FORCE_COLOR "1"

Hide
Type "export PS1='$ ' && clear"
Enter
Show

Sleep 500ms
Type "zirah scan examples/benign/manifest.json"
Sleep 300ms
Enter
Sleep 3.5s

Type "zirah scan examples/malicious/manifest.json | less -R"
Sleep 300ms
Enter
Sleep 5s
Space
Sleep 3.5s
Space
Sleep 3.5s
Type "q"
Sleep 500ms

Type "zirah scan examples/malicious/manifest.json --format sarif -o zirah.sarif"
Sleep 300ms
Enter
Sleep 4s
