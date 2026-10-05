#!/usr/bin/env bash
# Reproducibility gate: build the release binaries twice from scratch and require the
# digests to match. Used by the release workflow and by anyone checking the claim.
#
#   ./scripts/release-repro-check.sh                       # host target
#   XCHONNECT_RELEASE_TARGET=x86_64-unknown-linux-gnu ./scripts/release-repro-check.sh
#
# With a reference manifest, also compare against a published release:
#   ./scripts/release-repro-check.sh --manifest downloaded/SHA256SUMS
set -euo pipefail
cd "$(dirname "$0")/.."

REF=""
while [ $# -gt 0 ]; do
  case "$1" in
    --manifest) REF=${2:?--manifest needs a file}; shift 2 ;;
    -h | --help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

triple=${XCHONNECT_RELEASE_TARGET:-$(rustc -vV | sed -n 's/^host: //p')}
work=${XCHONNECT_REPRO_DIR:-target/release-repro}
# Both passes must use the same target directory path: build scripts can embed OUT_DIR,
# so two different paths would differ for a reason that is not a reproducibility bug.
build_dir=${XCHONNECT_RELEASE_TARGET_DIR:-target/release-build}
export XCHONNECT_RELEASE_TARGET_DIR=$build_dir
rm -rf "$work"
mkdir -p "$work"

for pass in a b; do
  echo "::group::reproducibility pass $pass"
  # A cold target directory each pass: a cached object file would hide a difference.
  rm -rf "$build_dir"
  XCHONNECT_RELEASE_OUT="$work/$pass" ./scripts/release-build.sh
  echo "::endgroup::"
done

if diff -u "$work/a/SHA256SUMS" "$work/b/SHA256SUMS"; then
  echo "reproducible: two independent builds of $triple produced identical digests"
else
  echo "NOT reproducible: digests differ between two builds of $triple" >&2
  exit 1
fi

if [ -n "$REF" ]; then
  if diff -u "$REF" "$work/a/SHA256SUMS"; then
    echo "matches the reference manifest $REF"
  else
    echo "does NOT match the reference manifest $REF" >&2
    exit 1
  fi
fi
