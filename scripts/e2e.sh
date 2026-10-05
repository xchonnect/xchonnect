#!/usr/bin/env bash
# The suites are called through `run`, which shellcheck cannot follow.
# shellcheck disable=SC2329
# End-to-end across the three repositories, against one local reference relay:
#
#   xchonnect  the wallet conformance suite, driving the reference CLI wallet
#   klimper    Klimper's Xchonnect plugin: its tests, then its live-relay tests
#   pengui     Pengui in headless Chromium paired with the reference CLI wallet
#
#   scripts/e2e.sh                     # every suite whose repository is found
#   scripts/e2e.sh pengui klimper      # just these
#
# The sibling repositories are found at the usual layout next to this one; override with
# KLIMPER_DIR (the klimper/ folder inside clapandpay) and PENGUI_DIR. A suite whose
# repository or prerequisites are missing is reported as skipped, not failed.
#
# Lean on purpose: one relay for everything, incremental builds in each repository's own
# target directory, and Pengui on a dev server only for as long as its spec runs. Set
# E2E_PENGUI_URL to use a Pengui server you started yourself instead (it must use this
# script's relay, see below). Development only: plain-HTTP loopback, development keys.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD

KLIMPER_DIR=${KLIMPER_DIR:-$ROOT/../../clapandpay/clapandpay/klimper}
PENGUI_DIR=${PENGUI_DIR:-$ROOT/../../pengui/pengui}
RELAY_PORT=${E2E_RELAY_PORT:-18790}
PENGUI_PORT=${E2E_PENGUI_PORT:-3100}
RELAY="http://127.0.0.1:${RELAY_PORT}"
WALLET_BIN="$ROOT/target/debug/xchonnect-wallet-cli"
# Development seed, testnet only: the example wallet refuses it on mainnet.
SEED="xchonnect wallet conformance development seed"
LIMIT=1000000

if [ $# -eq 0 ]; then set -- xchonnect klimper pengui; fi
for s in "$@"; do
  case $s in xchonnect | klimper | pengui) ;; *) echo "unknown suite: $s" >&2; exit 2 ;; esac
done

PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM

LOGS=$(mktemp -d "${TMPDIR:-/tmp}/xchonnect-e2e.XXXXXX")
RESULTS=()
FAILED=0
# run <name> <function>: run a suite in a subshell (its own cwd, and errexit in force, which
# an `if` around it would switch off), keep its output in $LOGS/<name>.log, record the result.
run() {
  local name=$1 start=$SECONDS rc
  shift
  echo "==> $name"
  set +e
  (set -e; "$@") >"$LOGS/$name.log" 2>&1
  rc=$?
  set -e
  if [ $rc -eq 0 ]; then
    RESULTS+=("PASS  $name  $((SECONDS - start))s")
  else
    RESULTS+=("FAIL  $name  $((SECONDS - start))s  (log: $LOGS/$name.log)")
    FAILED=1
    tail -n 30 "$LOGS/$name.log" | sed 's/^/    /'
  fi
}
skip() { RESULTS+=("SKIP  $1  ($2)"); }
wait_for() { # wait_for <url> <tries of 0.25 s>
  for _ in $(seq 1 "$2"); do curl -fsS -o /dev/null "$1" 2>/dev/null && return 0; sleep 0.25; done
  return 1
}

echo "==> building the relay, the reference wallet and the conformance suite"
cargo build -q --locked -p xchonnect-relay -p xchonnect-wallet-cli -p xchonnect-conformance

echo "==> starting the reference relay on $RELAY"
# Proof-of-work mailbox creation at a low difficulty, so the clients' PoW path is exercised
# without costing time; OHTTP with an ephemeral key, as in development.
env XCHONNECT_LISTEN="127.0.0.1:${RELAY_PORT}" XCHONNECT_CREATION=pow \
  XCHONNECT_POW_DIFFICULTY=12 XCHONNECT_GATEWAY_POLICY=open XCHONNECT_OHTTP=ephemeral \
  XCHONNECT_LOG=warn ./target/debug/xchonnect-relay >"$LOGS/relay.log" 2>&1 &
PIDS+=($!)
wait_for "$RELAY/healthz" 40 || { echo "the relay did not start; see $LOGS/relay.log" >&2; exit 1; }

xchonnect_suite() {
  local base="$WALLET_BIN pair '{uri}' --dev --dev-key '$SEED' --limit-xch-per-request $LIMIT"
  # A refusal check passes only when nothing arrives, so the shorter wait (default 8 s)
  # cannot fail the loopback reference wallet; it only shortens proving silence.
  ./target/debug/xchonnect-conformance wallet --relay "$RELAY" \
    --wallet "$base --auto-approve" --xch-per-request-limit "$LIMIT" \
    --wallet-sas-mismatch "printf 'y\nn\n' | $base" \
    --wallet-reject "printf 'y\ny\nn\n' | $base" \
    --refusal-timeout 3
}

klimper_suite() {
  cd "$KLIMPER_DIR"
  # Klimper's CI runs no Rust (clapandpay AGENTS.md), so this is where its plugin is tested.
  cargo test -q -p tauri-plugin-klimper-xchonnect
  XCHONNECT_TEST_RELAY="$RELAY" \
    cargo test -q -p tauri-plugin-klimper-xchonnect --test live_relay -- --ignored --test-threads=1
}

pengui_suite() {
  # The SDK is consumed unpublished: rebuild it from this checkout and copy it in, so the
  # run tests this repository's SDK rather than whatever Pengui last copied.
  [ -f sdk-ts/wasm/xchonnect_bg.wasm ] || ./scripts/build-wasm.sh
  [ -d node_modules ] || npm ci --ignore-scripts --no-audit --no-fund
  npm run -s build -w @xchonnect/dapp
  cd "$PENGUI_DIR"
  bun run prepare:xchonnect

  local url=${E2E_PENGUI_URL:-}
  if [ -z "$url" ]; then
    url="http://localhost:${PENGUI_PORT}"
    # The origin key comes from Pengui's .env.local; the domain must match this port, and
    # the relay must be this script's.
    env XCHONNECT_DOMAIN="localhost:${PENGUI_PORT}" \
      NEXT_PUBLIC_XCHONNECT_DOMAIN="localhost:${PENGUI_PORT}" \
      NEXT_PUBLIC_XCHONNECT_RELAY_URL="$RELAY" \
      bun next dev -p "$PENGUI_PORT" >"$LOGS/pengui-server.log" 2>&1 &
    # This runs in a subshell, so the server is stopped here rather than by `cleanup`;
    # `bun` runs Next as a child, which has to be stopped too.
    PENGUI_SERVER=$!
    trap 'pkill -P "$PENGUI_SERVER" 2>/dev/null; kill "$PENGUI_SERVER" 2>/dev/null || true' EXIT
    wait_for "$url/login" 480 || { echo "Pengui did not start; see $LOGS/pengui-server.log"; return 1; }
  fi
  PLAYWRIGHT_TEST_BASE_URL="$url" XCHONNECT_WALLET_CLI="$WALLET_BIN" \
    NEXT_PUBLIC_XCHONNECT_RELAY_URL="$RELAY" \
    bunx playwright test tests/e2e/xchonnect --project=chromium --reporter=list
}

for suite in "$@"; do
  case $suite in
    xchonnect) run xchonnect xchonnect_suite ;;
    klimper)
      if [ ! -d "$KLIMPER_DIR/tauri-plugin-klimper-xchonnect" ]; then
        skip klimper "no Klimper Xchonnect plugin at $KLIMPER_DIR; set KLIMPER_DIR"
      else
        run klimper klimper_suite
      fi
      ;;
    pengui)
      if [ ! -f "$PENGUI_DIR/tests/e2e/xchonnect/real-wallet.spec.ts" ]; then
        skip pengui "no tests/e2e/xchonnect/real-wallet.spec.ts in $PENGUI_DIR; set PENGUI_DIR"
      elif [ -z "${E2E_PENGUI_URL:-}" ] && ! grep -q '^XCHONNECT_ORIGIN_PRIVATE_KEY=.' "$PENGUI_DIR/.env.local" 2>/dev/null; then
        skip pengui "no XCHONNECT_ORIGIN_PRIVATE_KEY in $PENGUI_DIR/.env.local"
      else
        run pengui pengui_suite
      fi
      ;;
  esac
done

echo
printf '%s\n' "${RESULTS[@]}"
exit $FAILED
