#!/usr/bin/env bash
# Release gate: refuse to build a release whose tag, versions, changelog or signature do
# not agree. Run by the first job of .github/workflows/release.yml, and usable locally:
#
#   ./scripts/release-gate.sh v1.0.0
#
# Checks
#   1. the tag is `v<semver>`;
#   2. the Cargo workspace version and the @xchonnect/dapp version are that version;
#   3. the crates published to crates.io (xchonnect-core, xchonnect-wallet-kit) carry that
#      version, require each other at exactly that version and, for a pre-release, name
#      it in the dependency line of their README;
#   4. CHANGELOG.md has a released section for it, with a protocol-version line;
#   5. the tag is an annotated tag on a commit, signed with an SSH signing key that one of
#      the logins in .github/release-maintainers.txt has on their GitHub account (the
#      keys come from api.github.com/users/<login>/ssh_signing_keys and the signature is
#      checked with ssh-keygen here, not taken from GitHub's "verified" mark alone).
#
# With GH_TOKEN set (the workflow) the tag is read through the GitHub API, as it is on
# GitHub now; without it, from the local clone. When XCHONNECT_GATE_OUTPUT names a file
# (the workflow passes $GITHUB_OUTPUT), `commit=<sha the tag points to>` and
# `signer=<maintainer login>` are appended to it.
set -euo pipefail
cd "$(dirname "$0")/.."

TAG=${1:-${GITHUB_REF_NAME:-}}
REPO=${XCHONNECT_REPO:-${GITHUB_REPOSITORY:-xchonnect/xchonnect}}
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

# A crates.io version is permanent, so what the tag would publish is checked here, before
# anything is built. `version.workspace = true` makes the first check redundant today; it
# is what catches a crate that later sets its own version.
meta=$(cargo metadata --no-deps --format-version 1)
for crate in xchonnect-core xchonnect-wallet-kit; do
  pkg=$(echo "$meta" | jq --arg n "$crate" '.packages[] | select(.name == $n)')
  crate_version=$(echo "$pkg" | jq -r .version)
  [ "$crate_version" = "$version" ] ||
    fail "$crate version is ${crate_version:-missing}, tag says $version"
  # Crates released together resolve together: wallet-kit X.Y.Z with any other core is a
  # combination nobody built.
  loose=$(echo "$pkg" | jq -r --arg r "=$version" \
    '[.dependencies[] | select(.path != null and .kind != "dev" and .req != $r) | "\(.name) \"\(.req)\""] | join(", ")')
  [ -z "$loose" ] ||
    fail "$crate requires $loose; workspace crates must be required as \"=$version\" (Cargo.toml, [workspace.dependencies])"
  # Cargo never picks a pre-release for a plain requirement, so the README a wallet team
  # copies from has to name this one exactly.
  case "$version" in
    *-*)
      readme=$(dirname "$(echo "$pkg" | jq -r .manifest_path)")/README.md
      grep -Fq "$crate = \"=$version\"" "$readme" ||
        fail "${readme#"$PWD"/} does not show the dependency as $crate = \"=$version\""
      ;;
  esac
done

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
LIST=.github/release-maintainers.txt
[ -f "$LIST" ] || fail "$LIST is missing"
maintainers=$(grep -v '^[[:space:]]*#' "$LIST" | tr -d ' \t' | grep -v '^$' || true)
[ -n "$maintainers" ] || fail "$LIST lists no maintainer"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if [ -n "${GH_TOKEN:-}" ] && command -v gh >/dev/null 2>&1; then
  ref=$(gh api "repos/$REPO/git/ref/tags/$TAG") || fail "$TAG does not exist on GitHub"
  [ "$(echo "$ref" | jq -r .object.type)" = "tag" ] ||
    fail "$TAG is a lightweight tag; releases need a signed annotated tag (git tag -s)"
  obj=$(gh api "repos/$REPO/git/tags/$(echo "$ref" | jq -r .object.sha)")
  [ "$(echo "$obj" | jq -r .object.type)" = "commit" ] || fail "$TAG does not point at a commit"
  commit=$(echo "$obj" | jq -r .object.sha)
  [ "$(echo "$obj" | jq -r .verification.verified)" = "true" ] ||
    fail "$TAG signature not verified by GitHub: $(echo "$obj" | jq -r .verification.reason)"
  # The bytes GitHub verified; checked again below against the maintainers' keys only.
  echo "$obj" | jq -j '.verification.payload // ""' > "$tmp/payload"
  echo "$obj" | jq -j '.verification.signature // ""' > "$tmp/sig"
  keys() { gh api "users/$1/ssh_signing_keys" --jq '.[].key'; }
else
  [ "$(git cat-file -t "$TAG" 2>/dev/null)" = "tag" ] ||
    fail "no annotated tag $TAG in this clone (git fetch --tags; releases need git tag -s)"
  commit=$(git rev-parse "$TAG^{commit}")
  git cat-file tag "$TAG" | awk '/^-----BEGIN SSH SIGNATURE-----$/{f=1} !f' > "$tmp/payload"
  git cat-file tag "$TAG" | awk '/^-----BEGIN SSH SIGNATURE-----$/{f=1} f' > "$tmp/sig"
  keys() {
    curl -fsS --retry 3 -H 'Accept: application/vnd.github+json' \
      "https://api.github.com/users/$1/ssh_signing_keys" | jq -r '.[].key'
  }
fi

grep -q '^-----BEGIN SSH SIGNATURE-----$' "$tmp/sig" ||
  fail "$TAG is not signed with an SSH key; release tags are signed with an SSH signing key of a maintainer (docs/release.md)"
# What was signed must be this tag on this commit, not another tag object's payload.
if [ "$(sed -n 's/^object //p' "$tmp/payload" | head -1)" != "$commit" ] ||
  [ "$(sed -n 's/^tag //p' "$tmp/payload" | head -1)" != "$TAG" ]; then
  fail "the signed payload of $TAG names another object or tag"
fi

signer=""
while read -r login; do
  [ -n "$login" ] || continue
  case "$login" in *[!A-Za-z0-9-]*) fail "'$login' in $LIST is not a GitHub login" ;; esac
  # namespaces="git": the namespace git signs tags and commits in.
  keys "$login" | sed "s/^/$login namespaces=\"git\" /" > "$tmp/allowed" ||
    fail "cannot read the SSH signing keys of $login from GitHub"
  [ -s "$tmp/allowed" ] || continue
  if ssh-keygen -Y verify -f "$tmp/allowed" -I "$login" -n git -s "$tmp/sig" \
    < "$tmp/payload" >/dev/null 2>&1; then
    signer=$login
    break
  fi
done <<<"$maintainers"
[ -n "$signer" ] ||
  fail "$TAG is not signed by an SSH signing key of any login in $LIST ($(echo "$maintainers" | tr '\n' ' '| sed 's/ $//'))"
echo "    signed by $signer (listed in $LIST); tag points at $commit"

if [ -n "${XCHONNECT_GATE_OUTPUT:-}" ]; then
  { echo "commit=$commit"; echo "signer=$signer"; } >> "$XCHONNECT_GATE_OUTPUT"
fi

echo "release gate passed: $TAG (version $version)"
