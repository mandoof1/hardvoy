# A real run: the lab is started by hardvoy itself on 127.0.0.1, the browser is
# a real Firefox driven over WebDriver, and the TLS/SSH probes go through the
# forwarder so the ClientHello and the SSH KEXINIT are captured, not guessed.
Set Width 1220
Set Height 700
Set Theme "Dracula"
Set FontSize 14
Set TypingSpeed 18ms
Set MarginFill "#101418"
Set Margin 30
Type "./target/release/hardvoy scan --egress direct --workdir /tmp/hardvoy-demo-wd --out /tmp/hardvoy-demo"
Enter
Sleep 16s
Output "assets/scan-terminal.gif"
