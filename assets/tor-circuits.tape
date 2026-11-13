# Saved output of one real run of the definition-of-done command
# (413.7 s on this machine, three circuits). Committed verbatim at
# docs/tables/tor-demo-run.txt so the table can be diffed in review.
Set Width 1280
Set Height 780
Set Theme "Dracula"
Set FontSize 13
Set TypingSpeed 8ms
Set MarginFill "#101418"
Set Margin 30
Type "# hardvoy scan --egress direct --egress tor --circuits 3   (364.1 s)"
Enter
Sleep 1s
Type "sed -n '/== tor circuits ==/,/^note:/p' docs/tables/tor-demo-run.txt"
Enter
Sleep 3s
Output "assets/tor-circuits.gif"
