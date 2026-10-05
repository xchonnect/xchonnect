#!/usr/bin/env bash
# Verify a downloaded Xchonnect release: digests, Sigstore signature, provenance.
#
#   ./scripts/release-verify.sh --dir ./dl --tag v1.0.0
#   ./scripts/release-verify.sh --dir ./dl --tag v1.0.0 --image ghcr.io/maximedogawa/xchonnect-relay:v1.0.0
#
# `--dir` holds the release assets as published: the binaries, the SBOMs, SHA256SUMS
# and SHA256SUMS.sigstore.json. Requirements: cosign (signature), gh (provenance,
# optional), sha256sum/shasum.
#
# What each step proves:
#   digests      the files you downloaded are the files the manifest names;
#   signature    the manifest was signed by the release workflow of this repository,
#                running on a tag, via Sigstore keyless OIDC - no long-lived key exists;
#   provenance   GitHub attests which workflow, commit and runner produced the files;
#   rebuild      scripts/release-repro-check.sh --manifest <dir>/SHA256SUMS rebuilds
#                from source and must arrive at the same digests.
set -euo pipefail

DIR="" TAG="" IMAGE=""
REPO=${XCHONNECT_REPO:-maximedogawa/xchonnect}
ISSUER=https://token.actions.githubusercontent.com

while [ $# -gt 0 ]; do
  case "$1" in
    --dir) DIR=${2:?}; shift 2 ;;
    --tag) TAG=${2:?}; shift 2 ;;
    --image) IMAGE=${2:?}; shift 2 ;;
    --repo) REPO=${2:?}; shift 2 ;;
    -h | --help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$DIR" ] || { echo "--dir is required" >&2; exit 2; }
[ -n "$TAG" ] || { echo "--tag is required" >&2; exit 2; }

sha256check() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum -c "$@"; else shasum -a 256 -c "$@"; fi
}

fail=0
step() { echo; echo "==> $1"; }

step "digests against SHA256SUMS"
(cd "$DIR" && sha256check SHA256SUMS) || fail=1

step "Sigstore signature over SHA256SUMS"
if command -v cosign >/dev/null 2>&1; then
  # The certificate identity is the release workflow at the signed tag: a signature made
  # by any other workflow, repository or ref does not verify.
  cosign verify-blob \
    --bundle "$DIR/SHA256SUMS.sigstore.json" \
    --certificate-oidc-issuer "$ISSUER" \
    --certificate-identity "https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$TAG" \
    "$DIR/SHA256SUMS" || fail=1
else
  echo "cosign not installed: skipped (install from https://docs.sigstore.dev/cosign/installation/)" >&2
  fail=1
fi

step "build provenance attestation"
if command -v gh >/dev/null 2>&1; then
  for f in "$DIR"/xchonnect-relay "$DIR"/xchonnect-gateway; do
    [ -f "$f" ] || continue
    gh attestation verify "$f" --repo "$REPO" || fail=1
  done
else
  echo "gh not installed: skipped" >&2
fi

if [ -n "$IMAGE" ]; then
  step "container image signature and provenance ($IMAGE)"
  if command -v cosign >/dev/null 2>&1; then
    cosign verify "$IMAGE" \
      --certificate-oidc-issuer "$ISSUER" \
      --certificate-identity "https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$TAG" || fail=1
  fi
  if command -v gh >/dev/null 2>&1; then
    gh attestation verify "oci://$IMAGE" --repo "$REPO" || fail=1
  fi
fi

echo
if [ "$fail" -eq 0 ]; then
  echo "release $TAG verified"
else
  echo "release $TAG NOT fully verified (see the failures above)" >&2
  exit 1
fi
