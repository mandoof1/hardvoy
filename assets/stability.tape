# Committed verbatim at docs/tables/stability-direct.txt (5 runs x 3 profiles on
# the direct egress). The profile-difference half of the table is what makes a
# profile switch measurable: 9 of 17 families change, 8 do not.
Set Width 1280
Set Height 820
Set Theme "Dracula"
Set FontSize 13
Set TypingSpeed 8ms
Set MarginFill "#101418"
Set Margin 30
Type "sed -n '/profile differences/,$p' docs/tables/stability-direct.txt"
Enter
Sleep 3s
Output "assets/stability-table.gif"
