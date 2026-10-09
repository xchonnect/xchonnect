#!/usr/bin/env bash
# Run the relay conformance suite against a freshly started reference relay
# (target/debug/xchonnect-relay). Used by CI; handy locally too.
#
#   scripts/relay-conformance.sh                    # in-memory store
#   scripts/relay-conformance.sh postgres://...     # Postgres store
#
# Two profiles are run per backend: "hosted" (pow + tickets + API keys, gateway
# allowlist, small quota) and "self-hosted" (open creation, open gateway policy).
# Extra suite flags can be passed via CONFORMANCE_FLAGS (e.g. "--slow").
set -euo pipefail
cd "$(dirname "$0")/.."

DB_URL=${1:-}
BACKEND=in-memory
STORE=memory
[ -n "$DB_URL" ] && BACKEND=postgres && STORE=postgres
PORT=${CONFORMANCE_PORT:-18787}
API_KEY=conformance-test-key-0123
RELAY=./target/debug/xchonnect-relay
SUITE=./target/debug/xchonnect-conformance
cargo build -q -p xchonnect-relay -p xchonnect-conformance --locked

run_profile() {
  local name=$1; shift
  echo "==> conformance: ${name} profile, ${BACKEND} store"
  env XCHONNECT_LISTEN="127.0.0.1:${PORT}" XCHONNECT_DATABASE_URL="${DB_URL}" XCHONNECT_STORE="${STORE}" XCHONNECT_LOG=warn XCHONNECT_OHTTP=ephemeral \
    "$@" "$RELAY" &
  local pid=$!
  for _ in $(seq 1 50); do
    curl -fsS "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1 && break
    sleep 0.2
  done
  local status=0
  # shellcheck disable=SC2086
  "$SUITE" relay "http://127.0.0.1:${PORT}" --aggressive --api-key "$API_KEY" ${CONFORMANCE_FLAGS:-} || status=$?
  kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
  return "$status"
}

run_profile hosted \
  XCHONNECT_CREATION=pow,ticket,api_key XCHONNECT_POW_DIFFICULTY=10 \
  XCHONNECT_API_KEYS="conformance:${API_KEY}" \
  XCHONNECT_GATEWAY_POLICY=allowlist XCHONNECT_GATEWAY_ALLOWLIST=https://push.example-wallet.app/ \
  XCHONNECT_MAX_MESSAGES=40
run_profile self-hosted \
  XCHONNECT_CREATION=open XCHONNECT_GATEWAY_POLICY=open
