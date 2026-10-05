#!/usr/bin/env bash
# Run the wallet conformance suite against a wallet, with a freshly started reference
# relay (target/debug/xchonnect-relay) for the two sides to meet on.
#
#   scripts/wallet-conformance.sh                       # the example CLI wallet
#   scripts/wallet-conformance.sh --manual              # a phone wallet, paired by hand
#   WALLET="my-wallet pair '{uri}'" scripts/wallet-conformance.sh
#
# WALLET is a shell command in which {uri} is replaced by the pairing URI. It must not
# need interactive input: either auto-approve, or pipe the answers in (see below).
# Extra suite flags can be passed as arguments or via CONFORMANCE_FLAGS, e.g. --slow.
#
# `cargo test --workspace` runs the same suite against the example wallet
# (conformance/tests/reference_wallet.rs); this script is for running it by hand and
# against other wallets.
set -euo pipefail
cd "$(dirname "$0")/.."

PORT=${CONFORMANCE_PORT:-18788}
RELAY=./target/debug/xchonnect-relay
SUITE=./target/debug/xchonnect-conformance
WALLET_BIN=./target/debug/xchonnect-wallet-cli
# Development seed, testnet only: the example wallet refuses it on mainnet.
SEED=${SEED:-"xchonnect wallet conformance development seed"}
LIMIT=${LIMIT:-1000000}

cargo build -q -p xchonnect-relay -p xchonnect-conformance -p xchonnect-wallet-cli --locked

BASE="$WALLET_BIN pair '{uri}' --dev --dev-key '$SEED' --limit-xch-per-request $LIMIT"
ARGS=(--relay "http://127.0.0.1:${PORT}")
if [ "${1:-}" = "--manual" ]; then
  shift
  ARGS+=(--manual)
  echo "==> manual mode: you will be asked to pair the wallet for each check"
else
  ARGS+=(--wallet "${WALLET:-$BASE --auto-approve}" --xch-per-request-limit "$LIMIT")
  # Variants that answer "no" at a particular prompt, so the suite can check the SAS
  # mismatch and user rejection paths. Only for the example wallet.
  if [ -z "${WALLET:-}" ]; then
    ARGS+=(--wallet-sas-mismatch "printf 'y\nn\n' | $BASE")
    ARGS+=(--wallet-reject "printf 'y\ny\nn\n' | $BASE")
  fi
fi

echo "==> starting the reference relay on http://127.0.0.1:${PORT}"
env XCHONNECT_LISTEN="127.0.0.1:${PORT}" XCHONNECT_CREATION=open \
  XCHONNECT_GATEWAY_POLICY=open XCHONNECT_OHTTP=ephemeral XCHONNECT_LOG=warn "$RELAY" &
RELAY_PID=$!
trap 'kill $RELAY_PID 2>/dev/null || true' EXIT INT TERM
for _ in $(seq 1 50); do
  curl -fsS "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1 && break
  sleep 0.2
done

# shellcheck disable=SC2086
"$SUITE" wallet "${ARGS[@]}" "$@" ${CONFORMANCE_FLAGS:-}
