#!/usr/bin/env bash
# Kotlin round trip on the JVM: compile the generated Kotlin bindings together with
# bindings/uniffi/tests/kotlin/RoundTrip.kt and run them against a host build of the
# core with the `test-helpers` feature (loaded through JNA).
#
# Requirements: a JDK (`java`), `kotlinc`, and the JNA jar in JNA_JAR
# (e.g. https://repo1.maven.org/maven2/net/java/dev/jna/jna/5.17.0/jna-5.17.0.jar).
set -euo pipefail
cd "$(dirname "$0")/.."

missing=()
command -v java >/dev/null 2>&1 && java -version >/dev/null 2>&1 || missing+=("a JDK (java)")
command -v kotlinc >/dev/null 2>&1 || missing+=("kotlinc")
[ -n "${JNA_JAR:-}" ] && [ -f "${JNA_JAR:-}" ] || missing+=("JNA_JAR pointing to the JNA jar")
if [ ${#missing[@]} -gt 0 ]; then
  echo "Kotlin round trip skipped; missing: ${missing[*]}" >&2
  exit 2
fi

OUT=target/kotlin-test
echo "==> building host library (test-helpers)"
cargo build -p xchonnect-uniffi --lib --features test-helpers --locked
rm -rf "$OUT"
mkdir -p "$OUT"
./scripts/uniffi-bindgen.sh generate --library target/debug/libxchonnect_uniffi.a \
  --language kotlin --out-dir "$OUT/src" --no-format

echo "==> compiling Kotlin round trip"
kotlinc -nowarn -cp "$JNA_JAR" "$OUT/src/xchonnect/uniffi/xchonnect.kt" \
  bindings/uniffi/tests/kotlin/RoundTrip.kt -include-runtime -d "$OUT/roundtrip.jar"

echo "==> running"
java -Djna.library.path="$PWD/target/debug" -cp "$OUT/roundtrip.jar:$JNA_JAR" RoundTripKt
