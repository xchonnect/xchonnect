#!/usr/bin/env bash
# Verify a downloaded Xchonnect release: digests, Sigstore signature, provenance, and
# optionally the container images, which it pins by digest.
#
#   ./scripts/release-verify.sh --dir ./dl --tag v1.0.0
#   ./scripts/release-verify.sh --dir ./dl --tag v1.0.0 \
#     --image ghcr.io/xchonnect/xchonnect-relay:1.0.0 --image ghcr.io/xchonnect/xchonnect-gateway:1.0.0
#   ./scripts/release-verify.sh --dir ./dl --tag v1.0.0 --no-provenance   # private repository
#
# `--dir` holds the release assets as published: the binaries, the SBOMs, SHA256SUMS
# and SHA256SUMS.sigstore.json, and nothing else (a file the manifest does not name
# fails the run). Requirements: cosign (signature), gh (provenance; --no-provenance
# skips it, for a release made while the repository was private), sha256sum/shasum, and
# jq with --image. A missing tool fails the run rather than skipping its check.
#
# What each step proves:
#   digests      the files you downloaded are the files the manifest names, and no
#                other file sits beside them;
#   signature    the manifest was signed by the release workflow of this repository
#                (.github/workflows/release-publish.yml) running on this tag, via
#                Sigstore keyless OIDC - no long-lived key exists;
#   provenance   GitHub attests that the same workflow, on this tag, produced each
#                binary (xchonnect-relay-*, xchonnect-gateway-*; none found fails);
#   images       --image (repeatable; a tag or an @sha256: reference): cosign verifies
#                the signature by the same identity and reports the digest it verified;
#                the attestation is checked for that digest. Prints the digest as
#                XCHONNECT_RELAY_DIGEST= / XCHONNECT_GATEWAY_DIGEST= for deploy/.env:
#                pull and run that digest, never the tag, which can be pushed again.
#                Without gh or with --no-provenance the image attestation cannot be
#                checked and the run fails, unless --skip-image-attestation says so;
#   rebuild      scripts/release-repro-check.sh --manifest <dir>/SHA256SUMS rebuilds
#                from source and must arrive at the same digests.
set -euo pipefail

DIR="" TAG="" PROVENANCE=1 SKIP_IMAGE_ATTESTATION=0
IMAGES=()
REPO=${XCHONNECT_REPO:-xchonnect/xchonnect}
ISSUER=https://token.actions.githubusercontent.com
# The release workflow's file. Releases up to v0.1.0-rc.4 were made by release.yml, which
# is disabled and no longer trusted (docs/release.md, "The old release.yml").
WORKFLOW=.github/workflows/release-publish.yml

while [ $# -gt 0 ]; do
  case "$1" in
    --dir) DIR=${2:?}; shift 2 ;;
    --tag) TAG=${2:?}; shift 2 ;;
    --image) IMAGES+=("${2:?}"); shift 2 ;;
    --repo) REPO=${2:?}; shift 2 ;;
    --no-provenance) PROVENANCE=0; shift ;;
    --skip-image-attestation) SKIP_IMAGE_ATTESTATION=1; shift ;;
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

if [ "$PROVENANCE" -eq 0 ]; then
  # Attestations exist for every release made while the repository was public. Someone
  # who asks you to skip them for such a release is asking you to skip a check.
  visibility=""
  if command -v gh >/dev/null 2>&1; then
    visibility=$(gh api "repos/$REPO" --jq .visibility 2>/dev/null || true)
  elif command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
    visibility=$(curl -fsS -A release-verify "https://api.github.com/repos/$REPO" 2>/dev/null | jq -r .visibility 2>/dev/null || true)
  fi
  if [ "$visibility" = "public" ]; then
    {
      echo
      echo "!!! WARNING: --no-provenance, but $REPO is PUBLIC."
      echo "!!! A release made while it was public has provenance attestations; skipping"
      echo "!!! them is only right for a release made while it was private. If you were"
      echo "!!! told to pass --no-provenance for a current release, do not trust that advice."
      echo
    } >&2
  else
    echo "--no-provenance: repository visibility ${visibility:-unknown}" >&2
  fi
fi

step "digests against SHA256SUMS"
(cd "$DIR" && sha256check SHA256SUMS) || fail=1
# Nothing beside the manifest (as the sign job requires): a file SHA256SUMS does not name
# was not signed, and would otherwise sit there looking verified.
unlisted=$(cd "$DIR" && comm -23 \
  <(find . -type f ! -name SHA256SUMS ! -name SHA256SUMS.sigstore.json | sed 's|^\./||' | LC_ALL=C sort) \
  <(awk '{sub(/^\*/, "", $2); print $2}' SHA256SUMS | LC_ALL=C sort))
if [ -n "$unlisted" ]; then
  echo "not in SHA256SUMS (unsigned; remove them or download into an empty directory):" >&2
  printf '%s\n' "$unlisted" | sed 's/^/  /' >&2
  fail=1
fi

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

pinned=()
for image in ${IMAGES[@]+"${IMAGES[@]}"}; do
  step "container image ($image)"
  # The repository without a tag or digest: strip "@…", then a ":tag" after the last "/".
  repo_ref=${image%%@*}
  last=${repo_ref##*/}
  case "$last" in *:*) repo_ref=${repo_ref%:*} ;; esac
  want=""
  case "$image" in *@*) want=${image#*@} ;; esac
  if ! command -v cosign >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
    echo "cosign and jq are needed to verify an image and read its digest" >&2
    fail=1
    continue
  fi
  # cosign resolves a tag to a digest once and checks the signatures of that digest; its
  # output names the digest it verified. That digest, not the tag, is what to run.
  if ! out=$(cosign verify "$image" \
    --certificate-oidc-issuer "$ISSUER" \
    --certificate-identity "$IDENTITY" --output json); then
    fail=1
    continue
  fi
  digests=$(printf '%s\n' "$out" | jq -r '.[].critical.image."docker-manifest-digest"' | sort -u)
  if [ "$(printf '%s\n' "$digests" | grep -c .)" -ne 1 ] ||
    ! printf '%s\n' "$digests" | grep -Eqx 'sha256:[0-9a-f]{64}'; then
    echo "cosign reported no single sha256 digest for $image: $digests" >&2
    fail=1
    continue
  fi
  if [ -n "$want" ] && [ "$digests" != "$want" ]; then
    echo "verified $digests, but $image names $want" >&2
    fail=1
    continue
  fi
  echo "signature verified for $repo_ref@$digests"
  if [ "$PROVENANCE" -eq 1 ] && command -v gh >/dev/null 2>&1; then
    attest "oci://$repo_ref@$digests" || { fail=1; continue; }
  elif [ "$SKIP_IMAGE_ATTESTATION" -eq 1 ]; then
    echo "image attestation not checked (--skip-image-attestation)" >&2
  else
    echo "image attestation not checked ($([ "$PROVENANCE" -eq 0 ] && echo --no-provenance || echo gh not installed)); pass --skip-image-attestation to accept that" >&2
    fail=1
    continue
  fi
  case "${repo_ref##*/}" in
    xchonnect-relay) pinned+=("XCHONNECT_RELAY_DIGEST=$digests") ;;
    xchonnect-gateway) pinned+=("XCHONNECT_GATEWAY_DIGEST=$digests") ;;
  esac
  pinned+=("# $repo_ref@$digests")
done

echo
if [ "$fail" -eq 0 ]; then
  echo "release $TAG verified"
  if [ "${#pinned[@]}" -gt 0 ]; then
    echo
    echo "Verified image digests (pull and run these, never the tag; deploy/.env takes the variables):"
    printf '%s\n' "${pinned[@]}"
  fi
else
  echo "release $TAG NOT fully verified (see the failures above)" >&2
  exit 1
fi
