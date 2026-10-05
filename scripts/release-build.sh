#!/usr/bin/env bash
# Deterministic release build of the relay and gateway binaries.
#
#   ./scripts/release-build.sh                         # host target
#   XCHONNECT_RELEASE_TARGET=x86_64-unknown-linux-gnu ./scripts/release-build.sh
#
# Output (XCHONNECT_RELEASE_OUT, default target/release-artifacts/<triple>):
#   xchonnect-relay, xchonnect-gateway   stripped release binaries
#   SHA256SUMS                           digests, the only thing releases are compared on
#   BUILD-INFO.txt                       how the build was parameterised (not hashed)
#
# Determinism rules, all of which a verifier must reproduce (docs/release.md):
#   * toolchain pinned by rust-toolchain.toml;
#   * `--locked`, so Cargo.lock decides every dependency version;
#   * RUSTFLAGS is set here and ignores the environment, because any extra flag changes
#     the machine code;
#   * absolute paths (checkout, CARGO_HOME, sysroot) are remapped to fixed names, so the
#     build does not depend on where it ran;
#   * a fixed target directory path, because build scripts can embed OUT_DIR;
#   * SOURCE_DATE_EPOCH, TZ and LC_ALL fixed.
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET=${XCHONNECT_RELEASE_TARGET:-}
TARGET_DIR=${XCHONNECT_RELEASE_TARGET_DIR:-target/release-build}
BINS=(xchonnect-relay xchonnect-gateway)

triple=${TARGET:-$(rustc -vV | sed -n 's/^host: //p')}
OUT=${XCHONNECT_RELEASE_OUT:-target/release-artifacts/$triple}

# Commit time, so rebuilding the same commit gives the same value anywhere.
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
  SOURCE_DATE_EPOCH=$(git -c log.showsignature=false log -1 --pretty=%ct 2>/dev/null || echo 1)
fi
export SOURCE_DATE_EPOCH TZ=UTC LC_ALL=C
export CARGO_INCREMENTAL=0 CARGO_TERM_COLOR=never

cargo_home=${CARGO_HOME:-$HOME/.cargo}
sysroot=$(rustc --print sysroot)
export RUSTFLAGS="-C strip=symbols --remap-path-prefix=$PWD=/xchonnect --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$sysroot=/rust"

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

target_args=()
if [ -n "$TARGET" ]; then target_args=(--target "$TARGET"); fi

echo "==> building ${BINS[*]} for $triple (SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH)"
cargo build --release --locked --target-dir "$TARGET_DIR" \
  ${target_args[@]+"${target_args[@]}"} \
  -p xchonnect-relay -p xchonnect-gateway

bin_dir=$TARGET_DIR/${TARGET:+$TARGET/}release

rm -rf "$OUT"
mkdir -p "$OUT"
for b in "${BINS[@]}"; do
  cp "$bin_dir/$b" "$OUT/$b"
  # Fixed mtime: tarballs and image layers made from these must not carry build times.
  touch -t "$(date -u -r "$SOURCE_DATE_EPOCH" +%Y%m%d%H%M.%S 2>/dev/null || date -u -d "@$SOURCE_DATE_EPOCH" +%Y%m%d%H%M.%S)" "$OUT/$b"
done

(cd "$OUT" && sha256 "${BINS[@]}" > SHA256SUMS)

{
  echo "target:             $triple"
  echo "commit:             $(git rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "rustc:              $(rustc -V)"
  echo "cargo:              $(cargo -V)"
  echo "SOURCE_DATE_EPOCH:  $SOURCE_DATE_EPOCH"
  echo "RUSTFLAGS:          $RUSTFLAGS"
} > "$OUT/BUILD-INFO.txt"

echo "==> done: $OUT"
cat "$OUT/SHA256SUMS"
