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
# agent-mcp is a package of its own (its own lockfile, outside the npm workspace): it runs
# on the @xchonnect/dapp it pins from npm, which the gate requires to be an exact version
# that its lockfile resolves from registry.npmjs.org.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=${1:?usage: $0 <out-dir> <version>}
VERSION=${2:?usage: $0 <out-dir> <version>}

./scripts/build-wasm.sh # enforces the gzip size budget
npm ci --ignore-scripts
npm run build -w @xchonnect/dapp
(cd agent-mcp && npm ci --ignore-scripts && rm -rf dist && npm run build)

mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd) # npm pack runs in two directories below
pack_json=$(mktemp)
trap 'rm -f "$pack_json"' EXIT

# pack <dir> <name> <expected tarball> [npm pack arguments...]: packs, lists the files and
# leaves the tarball's SHA-256 in $packed.
pack() {
  local dir=$1 name=$2 want=$3 file
  shift 3
  # --ignore-scripts: prepack would rebuild what the steps above just built.
  (cd "$dir" && npm pack "$@" --ignore-scripts --pack-destination "$OUT" --json) > "$pack_json"
  file=$(jq -r '.[0].filename' "$pack_json")
  if [ "$file" != "$want" ] || [ ! -f "$OUT/$file" ]; then
    echo "::error::npm pack made '$file' for $name, expected $want"
    exit 1
  fi
  tar -tzf "$OUT/$file" | sort
  packed=$(sha256sum "$OUT/$file" | cut -d' ' -f1)
  echo "$packed  $file"
}

pack . @xchonnect/dapp "xchonnect-dapp-$VERSION.tgz" -w @xchonnect/dapp
sha256=$packed
pack agent-mcp @xchonnect/mcp "xchonnect-mcp-$VERSION.tgz"
mcp_sha256=$packed
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "file=xchonnect-dapp-$VERSION.tgz"
    echo "sha256=$sha256"
    echo "mcp_file=xchonnect-mcp-$VERSION.tgz"
    echo "mcp_sha256=$mcp_sha256"
  } >> "$GITHUB_OUTPUT"
fi
