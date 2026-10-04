#!/usr/bin/env bash
# Build the Kotlin (Android) package of the Xchonnect core into target/kotlin/, laid out
# like an Android library module (AAR sources):
#
#   target/kotlin/
#     src/main/kotlin/xchonnect/uniffi/xchonnect.kt   generated UniFFI bindings (JNA)
#     src/main/jniLibs/<abi>/libxchonnect_uniffi.so   native libraries (needs the NDK)
#
# Consumers add `net.java.dev.jna:jna:<version>@aar` as a dependency.
#
# Native libraries need the Android NDK and cargo-ndk (`cargo install cargo-ndk`) with
# ANDROID_NDK_HOME set. Without them the Kotlin sources are still generated, the crate
# is type-checked for aarch64-linux-android, and the .so step is skipped.
#
# Environment:
#   XCHONNECT_UNIFFI_FEATURES  extra cargo features (e.g. "test-helpers"; never in releases)
#   XCHONNECT_KOTLIN_OUT       output directory (default target/kotlin)
#   XCHONNECT_ANDROID_ABIS     ABIs to build (default "arm64-v8a armeabi-v7a x86_64")
#   XCHONNECT_ANDROID_API      minimum API level (default 24)
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=${XCHONNECT_KOTLIN_OUT:-target/kotlin}
FEATURES=${XCHONNECT_UNIFFI_FEATURES:-}
ABIS=${XCHONNECT_ANDROID_ABIS:-arm64-v8a armeabi-v7a x86_64}
API=${XCHONNECT_ANDROID_API:-24}

feature_args=()
if [ -n "$FEATURES" ]; then feature_args=(--features "$FEATURES"); fi

# Bindings are generated from a host build of the same crate and features: the
# interface metadata is target-independent.
echo "==> generating Kotlin bindings"
cargo build -p xchonnect-uniffi --lib --locked --release ${feature_args[@]+"${feature_args[@]}"}
rm -rf "$OUT"
mkdir -p "$OUT/src/main/kotlin"
./scripts/uniffi-bindgen.sh generate --library target/release/libxchonnect_uniffi.a \
  --language kotlin --out-dir "$OUT/src/main/kotlin" --no-format

if [ -n "${ANDROID_NDK_HOME:-}" ] && command -v cargo-ndk >/dev/null 2>&1; then
  echo "==> building native libraries (${ABIS})"
  ndk_args=()
  for abi in $ABIS; do ndk_args+=(-t "$abi"); done
  cargo ndk "${ndk_args[@]}" -P "$API" -o "$OUT/src/main/jniLibs" \
    build -p xchonnect-uniffi --lib --locked --release ${feature_args[@]+"${feature_args[@]}"}
  find "$OUT/src/main/jniLibs" -name '*.so' -exec ls -l {} \;
else
  echo "==> ANDROID_NDK_HOME / cargo-ndk not available: type-checking only" >&2
  cargo check -p xchonnect-uniffi --lib --locked --target aarch64-linux-android \
    ${feature_args[@]+"${feature_args[@]}"}
  echo "Install the Android NDK and cargo-ndk, set ANDROID_NDK_HOME and rerun to build" >&2
  echo "src/main/jniLibs/<abi>/libxchonnect_uniffi.so." >&2
fi
echo "==> done: $OUT"
