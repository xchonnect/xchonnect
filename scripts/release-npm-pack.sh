#!/usr/bin/env bash
# Build and pack @xchonnect/dapp and @xchonnect/mcp the way the release publishes them. Run
# by the `npm-pack` and `npm-pack-repro` jobs of .github/workflows/release-publish.yml, each
# from a fresh checkout: the `npm` job publishes only when both made tarballs with the same
# SHA-256.
#
#   ./scripts/release-npm-pack.sh <out-dir> <version>
#
# Needs the pinned wasm-bindgen CLI (bindings/wasm/Cargo.toml) and the
# wasm32-unknown-unknown target. Leaves xchonnect-dapp-<version>.tgz and
# xchonnect-mcp-<version>.tgz in <out-dir> and, when GITHUB_OUTPUT is set, appends `file=`
# and `sha256=` (dapp), `mcp_file=` and `mcp_sha256=` to it.
#
# Both are members of the npm workspace: @xchonnect/mcp requires @xchonnect/dapp at
# exactly this version (the gate checks it), which the workspace links to the SDK built
# here, so packing needs nothing of this release from npm.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=${1:?usage: $0 <out-dir> <version>}
VERSION=${2:?usage: $0 <out-dir> <version>}

./scripts/build-wasm.sh # enforces the gzip size budget
# After the install: the registry's signatures over every installed package (and its
# provenance where it has one) must verify; the lockfile's integrity pins the bytes.
npm ci --ignore-scripts
npm audit signatures
npm run build -w @xchonnect/dapp
rm -rf agent-mcp/dist
npm run build -w @xchonnect/mcp

mkdir -p "$OUT"
pack_json=$(mktemp)
trap 'rm -f "$pack_json"' EXIT

# pack <workspace> <expected tarball>: packs, lists the files and leaves the tarball's
# SHA-256 in $packed.
pack() {
  local name=$1 want=$2 file
  # --ignore-scripts: prepack would rebuild what the steps above just built.
  npm pack -w "$name" --ignore-scripts --pack-destination "$OUT" --json > "$pack_json"
  file=$(jq -r '.[0].filename' "$pack_json")
  if [ "$file" != "$want" ] || [ ! -f "$OUT/$file" ]; then
    echo "::error::npm pack made '$file' for $name, expected $want"
    exit 1
  fi
  tar -tzf "$OUT/$file" | sort
  packed=$(sha256sum "$OUT/$file" | cut -d' ' -f1)
  echo "$packed  $file"
}

pack @xchonnect/dapp "xchonnect-dapp-$VERSION.tgz"
sha256=$packed
pack @xchonnect/mcp "xchonnect-mcp-$VERSION.tgz"
mcp_sha256=$packed
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "file=xchonnect-dapp-$VERSION.tgz"
    echo "sha256=$sha256"
    echo "mcp_file=xchonnect-mcp-$VERSION.tgz"
    echo "mcp_sha256=$mcp_sha256"
  } >> "$GITHUB_OUTPUT"
fi
