#!/usr/bin/env bash
# Timings for the README, from real runs on this machine.
#
#   make bench
#
# Every number printed here is reproducible: the scans below are the same
# `hardvoy scan` the README quotes, and the stage timings are read back out of
# the JSON the tool wrote, not from the terminal. The Tor columns are taken from
# the report committed at tests/fixtures/report-tor-and-direct.json, so they are
# in the repository and diffable rather than quoted from a terminal.
set -euo pipefail

BIN=${BIN:-./target/release/hardvoy}
OUT=${OUT:-/tmp/hardvoy-bench}
RUNS=${RUNS:-3}
FIXTURE=${FIXTURE:-tests/fixtures/report-tor-and-direct.json}

command -v python3 >/dev/null || { echo "python3 needed to format the table" >&2; exit 1; }
[ -x "$BIN" ] || { echo "build first: make release" >&2; exit 1; }

rm -rf "$OUT"
echo "== direct scans ($RUNS runs, egress=direct) =="
for i in $(seq 1 "$RUNS"); do
	"$BIN" scan --egress direct --workdir /tmp/hardvoy-bench-wd --out "$OUT" >/dev/null
done

python3 - "$OUT" "$FIXTURE" <<'PY'
import glob, json, statistics, os, sys
rows = {}
for f in sorted(glob.glob(sys.argv[1] + "/*.json")):
    d = json.load(open(f))
    for k, v in d.get("timings", {}).items():
        rows.setdefault(k, []).append(v)

print("| stage | runs | mean s | min s | max s |")
print("|---|---|---|---|---|")
order = ["scan_total"] + sorted(k for k in rows if k != "scan_total")
for k in order:
    v = rows[k]
    print(f"| {k} | {len(v)} | {statistics.mean(v):.2f} | {min(v):.2f} | {max(v):.2f} |")

if os.path.exists(sys.argv[2]):
    d = json.load(open(sys.argv[2]))
    print()
    print("### the committed Tor run (`--egress direct --egress tor --circuits 3`)")
    print()
    print("| stage | seconds |")
    print("|---|---|")
    for k in sorted(d.get("timings", {}), key=lambda k: (k != "scan_total", k)):
        print(f"| {k} | {d['timings'][k]:.1f} |")
    print()
    print(f"egress paths measured: {len(d['egresses'])}; findings: {len(d['findings'])}; "
          f"tor version/notes: {d['notes'][0].split(';')[0] if d.get('notes') else 'n/a'}")
PY

echo
echo "== test suite =="
t0=$(date +%s%N)
cargo test --all-targets > /tmp/hardvoy-bench-test.log 2>&1 || { cat /tmp/hardvoy-bench-test.log; exit 1; }
t1=$(date +%s%N)
grep -E "^test result" /tmp/hardvoy-bench-test.log
passed=$(grep -oE "^test result: ok\. [0-9]+" /tmp/hardvoy-bench-test.log | awk '{s+=$5} END {print s+0}')
ignored=$(grep -oE "[0-9]+ ignored" /tmp/hardvoy-bench-test.log | awk '{s+=$1} END {print s+0}')
echo "wall time: $(( (t1 - t0) / 1000000 )) ms — $passed tests passed, $ignored live tests ignored"
