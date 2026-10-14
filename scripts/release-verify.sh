#!/usr/bin/env bash
# Verify a downloaded Xchonnect release: digests, Sigstore signature, provenance.
#
#   ./scripts/release-verify.sh --dir ./dl --tag v1.0.0
#   ./scripts/release-verify.sh --dir ./dl --tag v1.0.0 --image ghcr.io/xchonnect/xchonnect-relay:v1.0.0
#   ./scripts/release-verify.sh --dir ./dl --tag v1.0.0 --no-provenance   # private repository
#
# `--dir` holds the release assets as published: the binaries, the SBOMs, SHA256SUMS
# and SHA256SUMS.sigstore.json. Requirements: cosign (signature), gh (provenance;
# --no-provenance skips it, for a release made while the repository was private),
# sha256sum/shasum. A missing tool fails the run rather than skipping its check.
#
# What each step proves:
#   digests      the files you downloaded are the files the manifest names;
#   signature    the manifest was signed by the release workflow of this repository
#                (.github/workflows/release-publish.yml) running on this tag, via
#                Sigstore keyless OIDC - no long-lived key exists;
#   provenance   GitHub attests that the same workflow, on this tag, produced each
#                binary (xchonnect-relay-*, xchonnect-gateway-*; none found fails);
#   rebuild      scripts/release-repro-check.sh --manifest <dir>/SHA256SUMS rebuilds
#                from source and must arrive at the same digests.
set -euo pipefail

DIR="" TAG="" IMAGE="" PROVENANCE=1
REPO=${XCHONNECT_REPO:-xchonnect/xchonnect}
ISSUER=https://token.actions.githubusercontent.com
# The release workflow's file. Releases up to v0.1.0-rc.4 were made by release.yml, which
# is disabled and no longer trusted (docs/release.md, "The old release.yml").
WORKFLOW=.github/workflows/release-publish.yml

while [ $# -gt 0 ]; do
  case "$1" in
    --dir) DIR=${2:?}; shift 2 ;;
    --tag) TAG=${2:?}; shift 2 ;;
    --image) IMAGE=${2:?}; shift 2 ;;
    --repo) REPO=${2:?}; shift 2 ;;
    --no-provenance) PROVENANCE=0; shift ;;
    -h | --help) sed -n '2,/^set /{/^#/p;}' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$DIR" ] || { echo "--dir is required" >&2; exit 2; }
[ -n "$TAG" ] || { echo "--tag is required" >&2; exit 2; }
IDENTITY="https://github.com/$REPO/$WORKFLOW@refs/tags/$TAG"

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
    --certificate-identity "$IDENTITY" \
    "$DIR/SHA256SUMS" || fail=1
else
  echo "cosign not installed: skipped (install from https://docs.sigstore.dev/cosign/installation/)" >&2
  fail=1
fi

# gh attestation verify: the attestation must come from the release workflow on this tag,
# not merely from some workflow of the repository.
attest() {
  gh attestation verify "$1" --repo "$REPO" \
    --signer-workflow "$REPO/$WORKFLOW" --source-ref "refs/tags/$TAG"
}

step "build provenance attestation"
binaries=()
for f in "$DIR"/xchonnect-relay-* "$DIR"/xchonnect-gateway-*; do
  [ -f "$f" ] && binaries+=("$f")
done
if [ "${#binaries[@]}" -eq 0 ]; then
  echo "no xchonnect-relay-* or xchonnect-gateway-* in $DIR" >&2
  fail=1
elif [ "$PROVENANCE" -eq 0 ]; then
  echo "--no-provenance: skipped for ${#binaries[@]} binaries (a private repository has no attestations)" >&2
elif command -v gh >/dev/null 2>&1; then
  for f in "${binaries[@]}"; do
    echo "$f"
    attest "$f" || fail=1
  done
else
  echo "gh not installed: skipped (install from https://cli.github.com/)" >&2
  fail=1
fi

if [ -n "$IMAGE" ]; then
  step "container image signature and provenance ($IMAGE)"
  if command -v cosign >/dev/null 2>&1; then
    cosign verify "$IMAGE" \
      --certificate-oidc-issuer "$ISSUER" \
      --certificate-identity "$IDENTITY" || fail=1
  else
    fail=1
  fi
  if [ "$PROVENANCE" -eq 1 ] && command -v gh >/dev/null 2>&1; then
    attest "oci://$IMAGE" || fail=1
  fi
fi

echo
if [ "$fail" -eq 0 ]; then
  echo "release $TAG verified"
else
  echo "release $TAG NOT fully verified (see the failures above)" >&2
  exit 1
fi
