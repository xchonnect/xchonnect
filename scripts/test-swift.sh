#!/usr/bin/env bash
# Swift round trip: compile the generated Swift bindings together with
# bindings/uniffi/tests/swift/main.swift against a host (macOS) build of the core with
# the `test-helpers` feature, and run a full pairing / request / rotation / end flow
# against the core's dApp side. Requires a Swift toolchain (Xcode or swift.org).
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=target/swift-test
echo "==> building host library (test-helpers)"
cargo build -p xchonnect-uniffi --lib --features test-helpers --locked
rm -rf "$OUT"
mkdir -p "$OUT/include"
./scripts/uniffi-bindgen.sh generate --library target/debug/libxchonnect_uniffi.a \
  --language swift --out-dir "$OUT" --no-format
mv "$OUT/XchonnectFFI.h" "$OUT/include/"
mv "$OUT/XchonnectFFI.modulemap" "$OUT/include/module.modulemap"

echo "==> compiling Swift round trip"
swiftc -module-name XchonnectRoundTrip -I "$OUT/include" \
  "$OUT/Xchonnect.swift" bindings/uniffi/tests/swift/main.swift \
  target/debug/libxchonnect_uniffi.a -o "$OUT/roundtrip"

echo "==> running"
"$OUT/roundtrip"
