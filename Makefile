CARGO ?= cargo
BIN  := ./target/release/hardvoy
OUT  := hardvoy-reports

.PHONY: build release test fmt clippy lint demo demo-direct stability stability-tor bench assets clean

build:
	$(CARGO) build

release:
	$(CARGO) build --release

## Unit tests only: no browser, no Tor, no network. This is what CI runs.
test:
	$(CARGO) test --all-targets

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

clippy:
	$(CARGO) clippy --all-targets -- -D warnings

lint: fmt-check clippy

## The definition-of-done run: direct egress plus three distinct Tor circuits.
demo: release
	$(BIN) scan --egress direct --egress tor --circuits 3 --screenshot --out $(OUT)

## The same audit without Tor (works in a sandbox with no circuit to build).
demo-direct: release
	$(BIN) scan --egress direct --screenshot --out $(OUT)

## Stability rate per fingerprint, 5 runs per profile, over Tor as well.
stability: release
	$(BIN) stability --egress direct --profiles stock,rfp,leaky --runs 5 --out $(OUT)

stability-tor: release
	$(BIN) stability --egress tor --profiles stock --runs 5 --out $(OUT)

## Timings for the README tables: repeated direct scans + the test suite.
bench: release
	./tools/bench.sh | tee docs/BENCH.md

## Regenerate the README images from the committed .tape files.
assets: release
	./tools/make-assets.sh

clean:
	$(CARGO) clean
	rm -rf $(OUT)
