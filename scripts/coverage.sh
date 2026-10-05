#!/usr/bin/env bash
# Line and region coverage for the four library crates that carry protocol logic:
# core, relay, gateway and wallet-kit.
#
#   ./scripts/coverage.sh                                   # text summary + lcov + HTML
#   XCHONNECT_TEST_DATABASE_URL=postgres://... ./scripts/coverage.sh   # also the Postgres store
#
# Output (XCHONNECT_COVERAGE_OUT, default target/coverage):
#   lcov.info        for external coverage services
#   html/index.html  browsable report
#   summary.txt      per-crate table, the thing to read in review
#   crypto-parsing.txt  per-file numbers for the crypto and parsing modules, which are
#                       the files the fuzzing/coverage review looks at (docs/fuzzing.md)
#
# Requirements: cargo-llvm-cov and the llvm-tools component:
#   rustup component add llvm-tools-preview
#   cargo install cargo-llvm-cov --locked
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=${XCHONNECT_COVERAGE_OUT:-target/coverage}
PKGS=(-p xchonnect-core -p xchonnect-relay -p xchonnect-gateway -p xchonnect-wallet-kit)
# Report on the crates under review only; test harnesses, examples, bindings and the
# conformance runner would otherwise dilute the numbers.
IGNORE='(^|/)(fuzz|conformance|examples|bindings)/|/tests?/|/target/|^/rustc|/\.cargo/'

if ! command -v cargo-llvm-cov >/dev/null 2>&1; then
  echo "cargo-llvm-cov not found: cargo install cargo-llvm-cov --locked" >&2
  exit 1
fi

mkdir -p "$OUT"

echo "==> running instrumented tests"
cargo llvm-cov clean --workspace
cargo llvm-cov --locked --no-report "${PKGS[@]}" --all-features

report() { cargo llvm-cov report --locked "${PKGS[@]}" --ignore-filename-regex "$IGNORE" "$@"; }

echo "==> reports"
report --lcov --output-path "$OUT/lcov.info"
report --html --output-dir "$OUT/html" >/dev/null
report > "$OUT/summary.txt"

# Crypto and parsing are where a gap matters most (spec threat model T1-T21): pull those
# files out, with the lines no test reached, so the review has them in one place.
parsing='/src/(crypto|cbor|envelope|uri|origin|pairing|session|message|pow|push|ohttp|domain|keys|b64|creation|binding|policy)\.rs'
{
  echo "Crypto and parsing modules (coverage review, docs/fuzzing.md)"
  echo
  grep -E "^Filename|^-{20}" "$OUT/summary.txt" | head -2
  grep -E "$parsing" "$OUT/summary.txt" || true
  echo
  echo "Lines no test reached:"
  report --show-missing-lines --summary-only 2>/dev/null |
    sed -n '/^Uncovered Lines:/,$p' | grep -E "$parsing|^Uncovered" || true
} > "$OUT/crypto-parsing.txt"

cat "$OUT/summary.txt"
echo
echo "==> done: $OUT (html/index.html, lcov.info, summary.txt, crypto-parsing.txt)"
