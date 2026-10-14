#!/usr/bin/env bash
# Is this tag still releasable, as GitHub has it now? Run by the gate of a publishing run
# and again by every job of .github/workflows/release.yml that pushes, signs or
# publishes, because "Re-run failed jobs" does not repeat the gate and an owner may have
# changed the release (or someone the tag) in between.
#
#   GH_TOKEN=... ./scripts/release-state-check.sh <tag> <commit>
#
# Checks
#   1. a GitHub release exists for <tag> and is published (not a draft);
#   2. its pre-release flag matches the version: set for vX.Y.Z-pre, clear for vX.Y.Z;
#   3. <tag> still points at <commit>, the commit the gate checked and the run builds.
# A release without notes is a warning, not a failure.
set -euo pipefail

TAG=${1:?usage: $0 <tag> <commit>}
COMMIT=${2:?usage: $0 <tag> <commit>}
REPO=${XCHONNECT_REPO:-${GITHUB_REPOSITORY:-xchonnect/xchonnect}}

fail() { echo "::error::release state: $1"; exit 1; }
[ -n "${GH_TOKEN:-}" ] || fail "GH_TOKEN is not set"

release=$(gh api "repos/$REPO/releases/tags/$TAG") ||
  fail "$TAG has no published GitHub release; create it from the tag in the web UI (docs/release.md)"
[ "$(jq -r .draft <<<"$release")" = "false" ] ||
  fail "the GitHub release for $TAG is a draft; publish it to release"
want=false
case "$TAG" in *-*) want=true ;; esac
[ "$(jq -r .prerelease <<<"$release")" = "$want" ] ||
  fail "the GitHub release for $TAG has 'pre-release' set to $(jq -r .prerelease <<<"$release"); it must be $want for this version. Edit the release, then re-run"
if [ -z "$(jq -r '.body // ""' <<<"$release" | tr -d '[:space:]')" ]; then
  echo "::warning::the GitHub release for $TAG has no notes; add them (a pre-release starts with the warning in docs/release.md)"
fi

ref=$(gh api "repos/$REPO/git/ref/tags/$TAG") || fail "$TAG no longer exists"
sha=$(jq -r .object.sha <<<"$ref")
if [ "$(jq -r .object.type <<<"$ref")" = "tag" ]; then
  sha=$(gh api "repos/$REPO/git/tags/$sha" --jq .object.sha)
fi
[ "$sha" = "$COMMIT" ] ||
  fail "$TAG now points at $sha, but this run checked and built $COMMIT; a release tag is never moved (docs/release.md)"

echo "release state: $TAG is published (pre-release: $want) and points at $COMMIT"
