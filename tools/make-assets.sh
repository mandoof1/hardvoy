#!/usr/bin/env bash
# Regenerate every image the README shows.
#
#   make assets
#
# Needs: firefox, geckodriver, vhs, asciinema. Nothing is sent to a third party:
# the scan runs against the lab this tool hosts itself on 127.0.0.1.
set -euo pipefail

BIN=${BIN:-./target/release/hardvoy}
W=${W:-/tmp/hardvoy-assets}
OUT=${OUT:-assets}

for t in vhs asciinema firefox; do
	command -v "$t" >/dev/null || { echo "$t not installed (needed to rebuild images)" >&2; exit 1; }
done
[ -x "$BIN" ] || { echo "build first: make release" >&2; exit 1; }

mkdir -p "$OUT" docs/tables

echo "[1/6] a real direct scan (lab on 127.0.0.1, screenshot enabled)"
rm -rf "$W"
"$BIN" scan --egress direct --screenshot --workdir "$W" --out "$W/reports" | tee "$OUT/scan-terminal.txt"

report_json=$(ls -1t "$W"/reports/*.json | grep -v stability | head -1)
report_html=$(readlink -f "${report_json%.json}.html")
lab_shot=$(ls -1t "$W"/screenshot-*.png | head -1)

echo "[2/6] lab page screenshot -> $OUT/lab-page.png"
cp "$lab_shot" "$OUT/lab-page.png"

echo "[3/6] report page screenshot -> $OUT/report.png"
# firefox --screenshot only accepts an absolute output path
shot=$(mktemp -d)/report.png
timeout 180 firefox --headless --screenshot "$shot" --window-size 1400,1100 "file://$report_html" 2>/dev/null
test -s "$shot" || { echo "firefox screenshot produced nothing" >&2; exit 1; }
cp "$shot" "$OUT/report.png"

echo "[4/6] tables from the real run (these are the README's evidence files)"
"$BIN" stability --egress direct --profiles stock,rfp,leaky --runs 5 --workdir "$W/stab" --out "$W/stab" \
	> "$W/stability.log" 2>&1
sed -n '/== stability across runs ==/,/^wrote /p' "$W/stability.log" \
	| sed '$d' > docs/tables/stability-direct.txt
echo "wrote docs/tables/stability-direct.txt"

echo "[5/6] terminal images from the committed tapes"
for tape in "$OUT"/*.tape; do
	[ -e "$tape" ] || continue
	echo "  vhs $tape"
	vhs "$tape"
done

# vhs 0.12 only writes GIF/MP4/WebM, and its very last frame is a bare cursor,
# so the still the README uses is taken one second before the end of the
# recording (every tape sleeps at the end, so that frame is the settled screen).
for g in "$OUT"/*.gif; do
	[ -e "$g" ] || continue
	ffmpeg -loglevel error -sseof -1.0 -i "$g" -frames:v 1 -y "${g%.gif}.png"
done

echo "[6/6] asciinema recording of the same scan (assets/demo.cast)"
COLUMNS=140 LINES=40 asciinema rec --overwrite --quiet --idle-time-limit 1.2 \
	-c "$BIN scan --egress direct --workdir $W/cast-wd --out $W/cast" "$OUT/demo.cast"

echo "done. images in $OUT:"
ls -la "$OUT"

# The definition-of-done Tor run costs about seven minutes, so its table is only
# refreshed on request: `RUN_TOR=1 make assets`.
if [ "${RUN_TOR:-0}" = 1 ]; then
	echo "[tor] re-running the definition-of-done scan (three circuits)"
	"$BIN" scan --egress direct --egress tor --circuits 3 --workdir "$W/tor" --out "$W/tor" \
		> "$W/tor.log" 2>&1
	sed -n '/== egress paths ==/,$p' "$W/tor.log" > docs/tables/tor-demo-run.txt
	echo "wrote docs/tables/tor-demo-run.txt"
fi
