#!/usr/bin/env bash
# Host tests for the UniFFI bindings (TASK-33 AC3 and AC4):
#
#   1. The generated Swift and Kotlin surfaces are checked for one typed error
#      case/class per `XchonnectError` variant, and for the OHTTP client surface
#      (TASK-52 AC3).
#   2. The published test vectors (docs/spec/vectors/) are driven through both
#      generated bindings: pairing URIs, reply envelopes, SAS, epoch keys, rotation,
#      every padding bucket and every negative case except `session_receive`.
#   3. Every negative vector must surface as the typed error the vector names, with a
#      message that echoes none of the case's key material.
#   4. The encrypted notification preview (spec 7.3.3) is driven through both bindings:
#      a tampered or stale preview falls back to the generic alert, and the sender's
#      detail line is dropped unless the wallet opted in (TASK-48 AC3-AC5).
#
# Swift needs only a Swift toolchain (Xcode or swift.org). Kotlin needs a JDK,
# `kotlinc` and the JNA jar; set JNA_JAR, or let XCHONNECT_FETCH_KOTLIN=1 download both
# into target/kotlin-tools (pinned versions, SHA-256 checked).
#
# Environment:
#   XCHONNECT_SKIP_SWIFT=1    skip the Swift half (no Swift toolchain)
#   XCHONNECT_SKIP_KOTLIN=1   skip the Kotlin half (no JVM toolchain)
#   XCHONNECT_FETCH_KOTLIN=1  download kotlinc and JNA if they are missing
#   JNA_JAR                   path to the JNA jar
set -euo pipefail
cd "$(dirname "$0")/.."

KOTLIN_VERSION=2.1.0
KOTLIN_SHA256=b6698d5728ad8f9edcdd01617d638073191d8a03139cc538a391b4e3759ad297
JNA_VERSION=5.17.0
JNA_SHA256=b3a9408e7c51e08ef0e3bfcc08f443f6ec0f6191ba8cd7c18d53d2b22e5bdbc0

say() { printf '==> %s\n' "$*"; }

sha256_of() {
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
  else sha256sum "$1" | cut -d' ' -f1; fi
}

say "building the host library (test-helpers)"
cargo build -p xchonnect-uniffi --lib --features test-helpers --locked
HOST_LIB=target/debug/libxchonnect_uniffi.a

OUT=target/bindings-native
rm -rf "$OUT"
mkdir -p "$OUT/swift/include" "$OUT/kotlin"

say "generating Swift and Kotlin bindings"
./scripts/uniffi-bindgen.sh generate --library "$HOST_LIB" \
  --language swift --out-dir "$OUT/swift" --no-format
./scripts/uniffi-bindgen.sh generate --library "$HOST_LIB" \
  --language kotlin --out-dir "$OUT/kotlin" --no-format
mv "$OUT/swift/XchonnectFFI.h" "$OUT/swift/include/"
mv "$OUT/swift/XchonnectFFI.modulemap" "$OUT/swift/include/module.modulemap"
KT="$OUT/kotlin/xchonnect/uniffi/xchonnect.kt"

# --- 1. the generated surfaces are typed ----------------------------------------------
say "checking the generated error surfaces"
# Every variant of XchonnectError must exist as its own Swift case and Kotlin class, so
# hosts can branch on the kind instead of parsing a message.
variants=$(sed -n 's/^    \([A-Z][A-Za-z]*\)(String),$/\1/p' bindings/uniffi/src/error.rs)
if [ -z "$variants" ]; then echo "could not read XchonnectError variants" >&2; exit 1; fi
missing=0
for v in $variants; do
  grep -q "case $v(message: String)" "$OUT/swift/Xchonnect.swift" ||
    { echo "Swift is missing XchonnectError.$v" >&2; missing=1; }
  grep -q "class $v(message: String)" "$KT" ||
    { echo "Kotlin is missing XchonnectException.$v" >&2; missing=1; }
done
# The OHTTP client is exposed through both bindings (TASK-52 AC3).
# The encrypted notification preview is exposed through both (TASK-48 AC5): the
# discriminated outcome, the record, the kind enum and the entry point. Its two
# behavioural properties are driven in the Swift and Kotlin runners below.
for sym in OhttpClient ohttpSelectKey decapsulate decapsulateKeyRotation encapsulate \
           OpenedPreview PreviewKind openNotificationPreview; do
  grep -q "$sym" "$OUT/swift/Xchonnect.swift" || { echo "Swift is missing $sym" >&2; missing=1; }
  grep -q "$sym" "$KT" || { echo "Kotlin is missing $sym" >&2; missing=1; }
done
# `open_notification_preview` must stay infallible: an NSE/FCM handler has to be able to
# render something, so a failure may never cross the boundary (spec 7.3.3, AC4).
grep -q 'func openNotificationPreview(.*) -> OpenedPreview' "$OUT/swift/Xchonnect.swift" ||
  { echo "Swift openNotificationPreview must return OpenedPreview and not throw" >&2; missing=1; }
grep -q 'fun `openNotificationPreview`(.*): OpenedPreview' "$KT" ||
  { echo "Kotlin openNotificationPreview must return OpenedPreview and not throw" >&2; missing=1; }
if grep -q '@Throws(XchonnectException::class) fun `openNotificationPreview`' "$KT"; then
  echo "Kotlin openNotificationPreview must not be declared @Throws" >&2; missing=1
fi
[ "$missing" -eq 0 ] || exit 1
echo "    $(printf '%s\n' $variants | wc -l | tr -d ' ') typed error variants in Swift and Kotlin;" \
     "OHTTP and the notification preview exposed in both"

# --- 2. Swift ------------------------------------------------------------------------
if [ "${XCHONNECT_SKIP_SWIFT:-0}" = "1" ]; then
  say "Swift vectors skipped (XCHONNECT_SKIP_SWIFT=1)"
elif ! command -v swiftc >/dev/null 2>&1; then
  echo "swiftc not found: set XCHONNECT_SKIP_SWIFT=1 to skip the Swift half" >&2
  exit 1
else
  say "compiling the Swift vector runner"
  swiftc -module-name XchonnectVectors -I "$OUT/swift/include" \
    "$OUT/swift/Xchonnect.swift" bindings/uniffi/tests/swift/vectors/main.swift \
    "$HOST_LIB" -o "$OUT/swift-vectors"
  say "running the Swift vector runner"
  XCHONNECT_VECTORS="$PWD/docs/spec/vectors" "$OUT/swift-vectors"
fi

# --- 3. Kotlin -----------------------------------------------------------------------
if [ "${XCHONNECT_SKIP_KOTLIN:-0}" = "1" ]; then
  say "Kotlin vectors skipped (XCHONNECT_SKIP_KOTLIN=1)"
  exit 0
fi

TOOLS=target/kotlin-tools
if [ "${XCHONNECT_FETCH_KOTLIN:-0}" = "1" ]; then
  mkdir -p "$TOOLS"
  if ! command -v kotlinc >/dev/null 2>&1 && [ ! -x "$TOOLS/kotlinc/bin/kotlinc" ]; then
    say "downloading kotlinc $KOTLIN_VERSION"
    curl -fsSL -o "$TOOLS/kotlin.zip" \
      "https://github.com/JetBrains/kotlin/releases/download/v${KOTLIN_VERSION}/kotlin-compiler-${KOTLIN_VERSION}.zip"
    got=$(sha256_of "$TOOLS/kotlin.zip")
    [ "$got" = "$KOTLIN_SHA256" ] || { echo "kotlin-compiler digest mismatch: $got" >&2; exit 1; }
    unzip -q -o "$TOOLS/kotlin.zip" -d "$TOOLS"
  fi
  if [ -z "${JNA_JAR:-}" ] || [ ! -f "${JNA_JAR:-}" ]; then
    say "downloading JNA $JNA_VERSION"
    curl -fsSL -o "$TOOLS/jna.jar" \
      "https://repo1.maven.org/maven2/net/java/dev/jna/jna/${JNA_VERSION}/jna-${JNA_VERSION}.jar"
    got=$(sha256_of "$TOOLS/jna.jar")
    [ "$got" = "$JNA_SHA256" ] || { echo "JNA digest mismatch: $got" >&2; exit 1; }
    JNA_JAR="$PWD/$TOOLS/jna.jar"
  fi
fi
if [ -x "$TOOLS/kotlinc/bin/kotlinc" ]; then PATH="$PWD/$TOOLS/kotlinc/bin:$PATH"; fi
# CI images often ship a JDK without putting it on PATH.
if ! command -v java >/dev/null 2>&1; then
  if [ -x "${JAVA_HOME:-}/bin/java" ]; then
    PATH="$JAVA_HOME/bin:$PATH"
  elif [ -x /usr/libexec/java_home ] && home=$(/usr/libexec/java_home 2>/dev/null); then
    PATH="$home/bin:$PATH"
  fi
fi

missing=()
command -v java >/dev/null 2>&1 && java -version >/dev/null 2>&1 || missing+=("a JDK (java)")
command -v kotlinc >/dev/null 2>&1 || missing+=("kotlinc")
[ -n "${JNA_JAR:-}" ] && [ -f "${JNA_JAR:-}" ] || missing+=("JNA_JAR pointing to the JNA jar")
if [ ${#missing[@]} -gt 0 ]; then
  echo "Kotlin vectors cannot run; missing: ${missing[*]}" >&2
  echo "Install them, set XCHONNECT_FETCH_KOTLIN=1, or set XCHONNECT_SKIP_KOTLIN=1." >&2
  exit 1
fi

say "compiling the Kotlin vector runner"
kotlinc -nowarn -cp "$JNA_JAR" "$KT" \
  bindings/uniffi/tests/kotlin/Vectors.kt -include-runtime -d "$OUT/kotlin-vectors.jar"
say "running the Kotlin vector runner"
XCHONNECT_VECTORS="$PWD/docs/spec/vectors" \
  java -Djna.library.path="$PWD/target/debug" \
  -cp "$OUT/kotlin-vectors.jar:$JNA_JAR" VectorsKt
