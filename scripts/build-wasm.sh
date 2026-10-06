#!/usr/bin/env bash
# Build the WASM core for @maximedogawa/xchonnect into sdk-ts/wasm/.
# Requires wasm-bindgen-cli with the exact version pinned in bindings/wasm/Cargo.toml:
#   cargo install wasm-bindgen-cli --version 0.2.129 --locked
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -p xchonnect-wasm --target wasm32-unknown-unknown --release --locked
rm -rf sdk-ts/wasm
wasm-bindgen --target web --out-dir sdk-ts/wasm --out-name xchonnect \
  target/wasm32-unknown-unknown/release/xchonnect_wasm.wasm
if command -v wasm-opt >/dev/null 2>&1; then
  wasm-opt -Oz --enable-bulk-memory --enable-nontrapping-float-to-int -o sdk-ts/wasm/xchonnect_bg.wasm sdk-ts/wasm/xchonnect_bg.wasm
fi
raw=$(wc -c < sdk-ts/wasm/xchonnect_bg.wasm | tr -d ' ')
gz=$(gzip -9 -c sdk-ts/wasm/xchonnect_bg.wasm | wc -c | tr -d ' ')
echo "xchonnect_bg.wasm: ${raw} bytes (${gz} gzip)"
# Size budget (gzip). Raise deliberately, never silently.
# 2026-10-04: 200 KB -> 220 KB for BLS signature aggregation (multi-party partialSign, TASK-57).
budget=${XCHONNECT_WASM_BUDGET:-220000}
if [ "$gz" -gt "$budget" ]; then
  echo "WASM size budget exceeded: ${gz} > ${budget} bytes gzip" >&2
  exit 1
fi
