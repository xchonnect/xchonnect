#!/usr/bin/env bash
# Start a local Xchonnect stack: relay (in-memory) + example dApp. The CLI wallet is
# started by you with the URI shown in the browser. Development only.
set -euo pipefail
cd "$(dirname "$0")/.."

RELAY_PORT=${RELAY_PORT:-8787}
echo "==> building WASM core, SDK, relay and CLI wallet"
./scripts/build-wasm.sh
npm install --no-fund --no-audit >/dev/null
npm run build -w @xchonnect/dapp >/dev/null
cargo build -q -p xchonnect-relay -p xchonnect-wallet-cli

echo "==> starting relay on http://127.0.0.1:${RELAY_PORT}"
XCHONNECT_LISTEN="127.0.0.1:${RELAY_PORT}" XCHONNECT_POW_DIFFICULTY="${XCHONNECT_POW_DIFFICULTY:-12}" \
  ./target/debug/xchonnect-relay &
RELAY_PID=$!
trap 'kill $RELAY_PID 2>/dev/null || true' EXIT INT TERM

cat <<MSG

  1. Open http://localhost:5173 and click "Connect wallet".
  2. In another terminal run the test wallet with the URI from the page:

       ./target/debug/xchonnect-wallet-cli pair '<URI>' --dev

  3. Compare the 6-digit codes, confirm on both sides, then send requests.

MSG
VITE_RELAY="http://127.0.0.1:${RELAY_PORT}" npm run dev -w xchonnect-example-dapp
