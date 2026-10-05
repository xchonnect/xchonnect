#!/usr/bin/env bash
# Release gate: refuse to build a release whose tag, versions, changelog or signature do
# not agree. Run by the first job of .github/workflows/release.yml, and usable locally:
#
#   ./scripts/release-gate.sh v1.0.0
#
# Checks
#   1. the tag is `v<semver>`;
#   2. the Cargo workspace version and the @xchonnect/dapp version are that version;
#   3. CHANGELOG.md has a released section for it, with a protocol-version line;
#   4. the tag is an annotated tag with a signature GitHub could verify - the first of
#      the two humans a release needs (docs/release.md). Locally, `git tag -v`.
set -euo pipefail
cd "$(dirname "$0")/.."

TAG=${1:-${GITHUB_REF_NAME:-}}
REPO=${XCHONNECT_REPO:-${GITHUB_REPOSITORY:-maximedogawa/xchonnect}}
[ -n "$TAG" ] || { echo "usage: $0 <tag>" >&2; exit 2; }

fail() { echo "release gate: $1" >&2; exit 1; }

case "$TAG" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) fail "tag '$TAG' is not v<major>.<minor>.<patch>[-pre]" ;;
esac
version=${TAG#v}

cargo_version=$(sed -n '/^\[workspace.package\]/,/^\[/p' Cargo.toml |
  sed -n 's/^version *= *"\(.*\)"/\1/p' | head -1)
[ "$cargo_version" = "$version" ] ||
  fail "Cargo workspace version is $cargo_version, tag says $version"

npm_version=$(node -p "require('./sdk-ts/package.json').version")
[ "$npm_version" = "$version" ] ||
  fail "@xchonnect/dapp version is $npm_version, tag says $version"

grep -q "^## \[$version\]" CHANGELOG.md ||
  fail "CHANGELOG.md has no '## [$version]' section"
section=$(awk "/^## \\[$version\\]/{f=1;next} /^## /{f=0} f" CHANGELOG.md)
echo "$section" | grep -qi "protocol version" ||
  fail "the CHANGELOG section for $version does not state the protocol version"
echo "$section" | grep -q '[^[:space:]]' ||
  fail "the CHANGELOG section for $version is empty"

echo "==> tag signature"
if [ -n "${GH_TOKEN:-}" ] && command -v gh >/dev/null 2>&1; then
  ref=$(gh api "repos/$REPO/git/ref/tags/$TAG")
  [ "$(echo "$ref" | jq -r .object.type)" = "tag" ] ||
    fail "$TAG is a lightweight tag; releases need a signed annotated tag (git tag -s)"
  obj=$(gh api "repos/$REPO/git/tags/$(echo "$ref" | jq -r .object.sha)")
  verified=$(echo "$obj" | jq -r .verification.verified)
  [ "$verified" = "true" ] ||
    fail "$TAG signature not verified: $(echo "$obj" | jq -r .verification.reason)"
  echo "    signed by $(echo "$obj" | jq -r '.tagger.name + " <" + .tagger.email + ">"')"
elif git rev-parse "$TAG" >/dev/null 2>&1; then
  git tag -v "$TAG" || fail "$TAG has no valid signature (git tag -s)"
else
  fail "cannot check the tag signature: no GH_TOKEN and no local tag"
fi

echo "release gate passed: $TAG (version $version)"
