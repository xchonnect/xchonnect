#!/usr/bin/env bash
# Live privacy scan: run the relay and the push gateway as real processes, drive a full
# pairing, signing and push session through them, then scan the database dump, both
# service logs and both metrics endpoints for anything `docs/privacy/data-inventory.md`
# forbids. Exits non-zero on any finding (TASK-54; spec 13.4 invariants 2 and 5, 13.5, 14).
#
#   scripts/privacy-scan.sh                    # in-memory store (no database dump)
#   scripts/privacy-scan.sh postgres://...     # Postgres store, dumped with pg_dump
#
# The in-process checks (`cargo test -p xchonnect-privacy-check`) cover the surfaces a
# running process cannot show from outside: the per-customer billing counters, the
# relay-to-gateway wake-up payload and what the gateway hands to the push platform.
#
# Without a local Postgres client, point the dump at a container's own:
#   PRIVACY_PG_DUMP="docker exec some-pg pg_dump" \
#   PRIVACY_PG_DUMP_URL=postgres://postgres:test@127.0.0.1:5432/xchonnect \
#   scripts/privacy-scan.sh postgres://postgres:test@127.0.0.1:55439/xchonnect
set -euo pipefail
cd "$(dirname "$0")/.."

DB_URL=${1:-}
read -r -a PG_DUMP <<<"${PRIVACY_PG_DUMP:-pg_dump}"
PG_DUMP_URL=${PRIVACY_PG_DUMP_URL:-$DB_URL}
RELAY_PORT=${PRIVACY_RELAY_PORT:-18799}
GATEWAY_PORT=${PRIVACY_GATEWAY_PORT:-18798}
RELAY_URL="http://127.0.0.1:${RELAY_PORT}"
GATEWAY_URL="http://127.0.0.1:${GATEWAY_PORT}"
# Development X25519 key: 32 bytes of 0x33, base64url. Never used anywhere else.
GATEWAY_KEY="MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM"
# The flow's planted business customer and API key (see privacy/src/flow.rs).
API_KEY="privacy-probe-api-key-0123456789"
CUSTOMER="privacy-probe-customer"

RUN=$(mktemp -d "${TMPDIR:-/tmp}/xchonnect-privacy.XXXXXX")
RELAY_PID=""
GATEWAY_PID=""

cleanup() {
  for pid in "$GATEWAY_PID" "$RELAY_PID"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    [ -n "$pid" ] && wait "$pid" 2>/dev/null || true
  done
  # The run directory holds the synthetic planted values and the captured artefacts.
  [ -n "${PRIVACY_KEEP_ARTEFACTS:-}" ] || rm -rf "$RUN"
}
trap cleanup EXIT

wait_for() {
  for _ in $(seq 1 100); do
    curl -fsS "$1/healthz" >/dev/null 2>&1 && return 0
    sleep 0.2
  done
  echo "privacy-scan: $1 did not become healthy" >&2
  return 1
}

echo "==> building"
cargo build -q -p xchonnect-relay -p xchonnect-gateway -p xchonnect-privacy-check --locked
RELAY=./target/debug/xchonnect-relay
GATEWAY=./target/debug/xchonnect-gateway
SCAN=./target/debug/xchonnect-privacy-scan

echo "==> starting the push gateway on ${GATEWAY_URL}"
# Only the project's own crates log at TRACE; dependencies stay at warn, so the scan
# measures this project's logging policy and not a dependency's debug output.
env XCHONNECT_GATEWAY_LISTEN="127.0.0.1:${GATEWAY_PORT}" \
    XCHONNECT_GATEWAY_KEYS="$GATEWAY_KEY" \
    XCHONNECT_GATEWAY_TEST_PLATFORM=true \
    XCHONNECT_LOG="xchonnect_gateway=trace,warn" \
    "$GATEWAY" >"$RUN/gateway.log" 2>&1 &
GATEWAY_PID=$!
wait_for "$GATEWAY_URL"
GATEWAY_PK=$(curl -fsS "${GATEWAY_URL}/v1/keys" | sed 's/.*\["\([^"]*\)".*/\1/')
[ -n "$GATEWAY_PK" ] || { echo "privacy-scan: no gateway public key" >&2; exit 1; }

BACKEND=in-memory
[ -n "$DB_URL" ] && BACKEND=postgres
echo "==> starting the relay on ${RELAY_URL} (${BACKEND} store)"
env XCHONNECT_LISTEN="127.0.0.1:${RELAY_PORT}" \
    XCHONNECT_DATABASE_URL="$DB_URL" \
    XCHONNECT_CREATION=open,api_key \
    XCHONNECT_API_KEYS="${CUSTOMER}:${API_KEY}" \
    XCHONNECT_GATEWAY_POLICY=open \
    XCHONNECT_DEV_ALLOW_INSECURE_GATEWAYS=true \
    XCHONNECT_OHTTP=ephemeral \
    XCHONNECT_METRICS=true \
    XCHONNECT_LOG="xchonnect_relay=trace,warn" \
    "$RELAY" >"$RUN/relay.log" 2>&1 &
RELAY_PID=$!
wait_for "$RELAY_URL"

echo "==> driving a full pairing, signing and push session"
"$SCAN" drive \
  --relay "$RELAY_URL" \
  --gateway-url "${GATEWAY_URL}/v1/wake" \
  --gateway-pk "$GATEWAY_PK" \
  --out "$RUN"

# The wake-up is dispatched in the background.
sleep 2

echo "==> collecting artefacts"
curl -fsS "${RELAY_URL}/metrics" >"$RUN/relay_metrics.txt"
curl -fsS "${GATEWAY_URL}/metrics" >"$RUN/gateway_metrics.txt"
cat "$RUN/relay.log" "$RUN/gateway.log" >"$RUN/service_logs.txt"
SURFACES=(
  "service_logs=$RUN/service_logs.txt"
  "relay_metrics=$RUN/relay_metrics.txt"
  "gateway_metrics=$RUN/gateway_metrics.txt"
)
if [ -n "$DB_URL" ]; then
  "${PG_DUMP[@]}" --no-owner --no-privileges "$PG_DUMP_URL" >"$RUN/database.sql"
  SURFACES+=("database=$RUN/database.sql")
else
  echo "privacy-scan: no database URL given, skipping the database dump" >&2
fi

# The gateway must actually have been woken, or the run proved nothing about push.
grep -q "xchonnect_gateway_delivered_total 1" "$RUN/gateway_metrics.txt" || {
  echo "privacy-scan: the gateway was never woken; the push path was not exercised" >&2
  cat "$RUN/gateway_metrics.txt" >&2
  exit 1
}

echo "==> scanning"
# 127.0.0.1 is allowed where the inventory says so: the services log their own bind
# address. Every other IP-, address-, key- or user-agent-shaped string is a finding.
"$SCAN" scan --secrets "$RUN/secrets.json" "${SURFACES[@]}"
echo "privacy-scan: ok (${BACKEND} store)"
