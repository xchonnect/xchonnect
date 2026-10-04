#!/usr/bin/env bash
# CycloneDX software bills of material for every release artifact.
#
#   ./scripts/sbom.sh                       # all SBOMs into target/sbom/
#   XCHONNECT_SBOM_OUT=/tmp/sbom ./scripts/sbom.sh
#
# Produces, in CycloneDX 1.5 JSON:
#   xchonnect-relay.cdx.json        relay binary, default features (postgres)
#   xchonnect-gateway.cdx.json      gateway binary
#   xchonnect-core.cdx.json         core crate, all features
#   xchonnect-wallet-kit.cdx.json   wallet-kit crate
#   xchonnect-uniffi.cdx.json       Swift / Kotlin bindings library
#   xchonnect-wasm.cdx.json         WASM package used by @xchonnect/dapp
#   xchonnect-dapp-npm.cdx.json     npm package dependency tree (runtime only)
#   SHA256SUMS                      digests of the SBOMs themselves
#
# Requirements: cargo-cyclonedx (version pinned below, matching the release workflow)
# and npm. The dependency sets come from Cargo.lock and package-lock.json, and
# cargo-cyclonedx honours SOURCE_DATE_EPOCH, so the SBOMs are reproducible too.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=${XCHONNECT_SBOM_OUT:-target/sbom}
# Keep in step with .github/workflows/release.yml.
CYCLONEDX_VERSION=${XCHONNECT_CYCLONEDX_VERSION:-0.5.9}

if ! command -v cargo-cyclonedx >/dev/null 2>&1; then
  echo "cargo-cyclonedx not found. Install the pinned version:" >&2
  echo "  cargo install cargo-cyclonedx --version $CYCLONEDX_VERSION --locked" >&2
  exit 1
fi

if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
  SOURCE_DATE_EPOCH=$(git -c log.showsignature=false log -1 --pretty=%ct 2>/dev/null || echo 1)
fi
export SOURCE_DATE_EPOCH TZ=UTC LC_ALL=C

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

rm -rf "$OUT"
mkdir -p "$OUT"

# sbom <dir> <crate> [extra cargo-cyclonedx args...]
sbom() {
  local dir=$1 crate=$2; shift 2
  echo "==> SBOM: $crate"
  cargo cyclonedx --manifest-path "$dir/Cargo.toml" --format json --spec-version 1.5 --all \
    --quiet "$@"
  mv "$dir/$crate.cdx.json" "$OUT/$crate.cdx.json"
}

sbom crates/core xchonnect-core --all-features
sbom crates/relay xchonnect-relay
sbom crates/gateway xchonnect-gateway
sbom crates/wallet-kit xchonnect-wallet-kit
sbom bindings/uniffi xchonnect-uniffi
sbom bindings/wasm xchonnect-wasm --target wasm32-unknown-unknown

echo "==> SBOM: @xchonnect/dapp (npm)"
# Runtime tree only: the package ships no runtime dependencies, so dev tooling would
# only add noise an integrator never installs.
#
# Two things need fixing afterwards. npm names the workspace component after its
# directory ("sdk-ts") rather than the package, and it stamps a fresh uuid and clock
# time into every document, which would make the SBOM differ on every run; the release
# publishes digests, so that has to go.
iso=$(date -u -r "$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null ||
  date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)
npm sbom --sbom-format cyclonedx --omit dev --omit peer --omit optional \
  --package-lock-only -w @xchonnect/dapp |
  jq --arg ts "$iso" '
    def fix: if (.purl // "") | startswith("pkg:npm/%40xchonnect/dapp@")
             then .name = "@xchonnect/dapp" | .type = "library" else . end;
    del(.serialNumber)
    | .metadata.timestamp = $ts
    | .components = [.components[] | fix]
    | .metadata.component = (
        [.components[] | select(.name == "@xchonnect/dapp")] | first // .metadata.component
      )
  ' > "$OUT/xchonnect-dapp-npm.cdx.json"

(cd "$OUT" && sha256 ./*.cdx.json > SHA256SUMS)

echo "==> done: $OUT"
ls -1 "$OUT"
