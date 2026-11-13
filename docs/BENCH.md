== direct scans (3 runs, egress=direct) ==
| stage | runs | mean s | min s | max s |
|---|---|---|---|---|
| scan_total | 3 | 4.26 | 3.42 | 5.67 |
| egress_direct | 3 | 3.61 | 3.15 | 4.40 |

### the committed Tor run (`--egress direct --egress tor --circuits 3`)

| stage | seconds |
|---|---|
| scan_total | 364.1 |
| egress_direct | 5.6 |
| egress_tor | 147.9 |
| tor_ready | 208.8 |

egress paths measured: 4; findings: 10; tor version/notes: tor 0.4.9.16 started in 0.2s

== test suite ==
test result: ok. 133 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.52s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
wall time: 705 ms for 133 test binaries' results
