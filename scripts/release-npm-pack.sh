#!/usr/bin/env bash
# Build and pack @xchonnect/dapp the way the release publishes it. Run by the `npm-pack`
# and `npm-pack-repro` jobs of .github/workflows/release.yml, each from a fresh checkout:
# the `npm` job publishes only when both made a tarball with the same SHA-256.
#
#   ./scripts/release-npm-pack.sh <out-dir> <version>
#
# Needs the pinned wasm-bindgen CLI (bindings/wasm/Cargo.toml) and the
# wasm32-unknown-unknown target. Leaves xchonnect-dapp-<version>.tgz in <out-dir> and,
# when GITHUB_OUTPUT is set, appends `file=` and `sha256=` to it.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=${1:?usage: $0 <out-dir> <version>}
VERSION=${2:?usage: $0 <out-dir> <version>}

./scripts/build-wasm.sh # enforces the gzip size budget
npm ci --ignore-scripts
npm run build -w @xchonnect/dapp

mkdir -p "$OUT"
pack_json=$(mktemp)
trap 'rm -f "$pack_json"' EXIT
# --ignore-scripts: prepack would rebuild what the steps above just built.
npm pack -w @xchonnect/dapp --ignore-scripts --pack-destination "$OUT" --json > "$pack_json"
file=$(jq -r '.[0].filename' "$pack_json")
if [ "$file" != "xchonnect-dapp-$VERSION.tgz" ] || [ ! -f "$OUT/$file" ]; then
  echo "::error::npm pack made '$file', expected xchonnect-dapp-$VERSION.tgz"
  exit 1
fi
tar -tzf "$OUT/$file" | sort
sha256=$(sha256sum "$OUT/$file" | cut -d' ' -f1)
echo "$sha256  $file"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  { echo "file=$file"; echo "sha256=$sha256"; } >> "$GITHUB_OUTPUT"
fi
