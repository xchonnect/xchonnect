#!/usr/bin/env bash
# Everything that proves a change, run on this machine before a push. GitHub Actions runs
# only on a release tag (release.yml), so this is the check that counts; it is what the
# pull-request CI ran until 3c72c0b, as local commands.
#
#   scripts/verify.sh            Rust (fmt, clippy -D warnings, workspace tests), the relay
#                                conformance suite and the privacy scan on the in-memory
#                                store, cargo deny, the core on wasm32 (build and tests),
#                                the TypeScript SDK (build, typecheck, tests), the scripts
#                                and the workflow linted
#   scripts/verify.sh --full     also a throwaway Postgres (Docker) for the relay's store
#                                tests, the conformance suite and the privacy scan; the
#                                core type-checked for Android; the SDK interop test;
#                                npm audit; the fuzz seed corpus; 30 s of every fuzz
#                                target (nightly)
#   scripts/verify.sh --bindings also the Swift and Kotlin bindings (needs Xcode, a JDK)
#
# Needs: the toolchain of rust-toolchain.toml with the wasm32 target, wasm-bindgen-cli at
# the version scripts/build-wasm.sh names, wasm-bindgen-test-runner, cargo-deny, Node 22,
# ShellCheck and actionlint; --full adds Docker, cargo-fuzz and a nightly toolchain.
set -euo pipefail
cd "$(dirname "$0")/.."

full=0
bindings=0
for arg in "$@"; do
  case "$arg" in
    --full) full=1 ;;
    --bindings) bindings=1 ;;
    *) echo "verify: unknown option $arg" >&2; exit 2 ;;
  esac
done

say() { printf '\n== %s\n' "$*"; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "verify: $1 is missing. $2" >&2; exit 1; }; }
need cargo "Install Rust: https://rustup.rs"
need node "Install Node 22 or later"
need cargo-deny "cargo install cargo-deny --locked"
need wasm-bindgen "see scripts/build-wasm.sh for the exact version"
need wasm-bindgen-test-runner "cargo install wasm-bindgen-cli --version <as build-wasm.sh> --locked"
need shellcheck "brew install shellcheck"
need actionlint "brew install actionlint"
[ "$full" = 0 ] || { need docker "Install Docker"; need cargo-fuzz "cargo install cargo-fuzz --locked"; }

# A throwaway Postgres for --full, removed however this run ends.
PG_CONTAINER=xchonnect-verify-pg
PG_PORT=${XCHONNECT_VERIFY_PG_PORT:-55432}
cleanup() { docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true; }
if [ "$full" = 1 ]; then
  trap cleanup EXIT INT TERM
fi

say "Rust: fmt, clippy -D warnings, workspace tests"
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked

say "Relay conformance suite and privacy scan, in-memory store"
./scripts/relay-conformance.sh
./scripts/privacy-scan.sh

say "Dependencies: cargo deny (advisories, bans, licences, sources)"
cargo deny check

say "Core on wasm32: tests under Node, then the build the SDK uses"
cargo test -p xchonnect-core --target wasm32-unknown-unknown --lib --locked
cargo build -p xchonnect-core -p xchonnect-wasm --target wasm32-unknown-unknown --locked

say "TypeScript: WASM core (size budget), SDK build, typecheck, tests"
./scripts/build-wasm.sh
npm ci --ignore-scripts
npm run build -w @xchonnect/dapp
npm run typecheck
npm test

say "Scripts and the workflow"
shellcheck -S warning scripts/*.sh
actionlint

if [ "$full" = 1 ]; then
  say "Postgres store: relay tests, conformance suite, privacy scan"
  cleanup
  docker run -d --name "$PG_CONTAINER" -e POSTGRES_PASSWORD=test -e POSTGRES_DB=xchonnect \
    -p "127.0.0.1:$PG_PORT:5432" postgres:17-alpine >/dev/null
  for _ in $(seq 1 60); do
    docker exec "$PG_CONTAINER" pg_isready -U postgres >/dev/null 2>&1 && break
    sleep 1
  done
  url="postgres://postgres:test@127.0.0.1:$PG_PORT/xchonnect"
  XCHONNECT_TEST_DATABASE_URL="$url" cargo test -p xchonnect-relay --locked
  ./scripts/relay-conformance.sh "$url"
  PRIVACY_PG_DUMP="docker exec $PG_CONTAINER pg_dump" \
    PRIVACY_PG_DUMP_URL="postgres://postgres:test@127.0.0.1:5432/xchonnect" \
    ./scripts/privacy-scan.sh "$url"

  say "Core type-checks for Android"
  cargo check -p xchonnect-core --target aarch64-linux-android --locked

  say "SDK interop: SDK, reference relay and the CLI wallet"
  cargo build -p xchonnect-relay -p xchonnect-wallet-cli --locked
  npm run test:interop -w @xchonnect/dapp

  say "npm audit"
  npm audit --audit-level=moderate

  say "Fuzzing: seed corpus, every target for 30 s (nightly)"
  ./scripts/fuzz-seeds-relay-http.py --check
  cargo +nightly fuzz build
  for target in fuzz/fuzz_targets/*.rs; do
    name=$(basename "$target" .rs)
    corpus=fuzz/corpus/$name
    tmp=$corpus/.tmp
    mkdir -p "$corpus" "$tmp"
    cargo +nightly fuzz run "$name" "$tmp" "$corpus" -- -max_total_time=30
  done
fi

if [ "$bindings" = 1 ]; then
  say "Bindings: Swift round trip, published vectors through Swift and Kotlin"
  ./scripts/test-swift.sh
  ./scripts/test-bindings-native.sh
fi

say "verify: ok$([ "$full" = 1 ] && printf ' (full)')$([ "$bindings" = 1 ] && printf ' (bindings)')"
