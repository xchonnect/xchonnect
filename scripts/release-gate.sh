#!/usr/bin/env bash
# Release gate: refuse to build a release whose tag, versions, changelog or signature do
# not agree. Run by the first job of .github/workflows/release-publish.yml, and usable locally:
#
#   ./scripts/release-gate.sh v1.0.0
#
# Checks
#   1. the tag is `v<semver>`;
#   2. the Cargo workspace version and the @xchonnect/dapp and @xchonnect/mcp versions are
#      that version, and @xchonnect/mcp requires one exact @xchonnect/dapp that its
#      lockfile resolves from registry.npmjs.org with the integrity npm serves for it, and
#      that npm has with provenance (it is packed against npm, not this tree); every
#      package both lockfiles fetch is pinned by a sha512 integrity;
#   3. the crates published to crates.io (xchonnect-core, xchonnect-wallet-kit) carry that
#      version, require each other at exactly that version and, for a pre-release, name
#      it in the dependency line of their README;
#   4. CHANGELOG.md has a released section for it, with a protocol-version line;
#   5. the tag is an annotated tag on a commit that is on `main` (main or an ancestor of
#      it: a commit only a side branch has cannot be released);
#   6. the tag is signed with an SSH signing key that one of the logins in
#      .github/release-maintainers.txt has on their GitHub account AND whose fingerprint
#      the file pins for that login (the keys come from
#      api.github.com/users/<login>/ssh_signing_keys and the signature is checked with
#      ssh-keygen here, not taken from GitHub's "verified" mark alone).
#
# The maintainer list is read from `main`, never from the tagged commit: a tag on a
# commit that changes the list would otherwise vouch for itself.
#
# With GH_TOKEN set (the workflow) the tag, `main` and the list are read through the
# GitHub API, as they are on GitHub now; without it, from the local clone (`origin/main`;
# run `git fetch origin main --tags` first). When XCHONNECT_GATE_OUTPUT names a file
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

# The plugin is released with the SDK but packed outside the npm workspace, on the
# @xchonnect/dapp it pins: an exact version already on npm (the one of this release is
# not, until the `npm` job publishes it), or `npm install @xchonnect/mcp` would not resolve.
mcp=agent-mcp/package.json
mcp_lock=agent-mcp/package-lock.json
mcp_version=$(jq -r .version "$mcp")
[ "$mcp_version" = "$version" ] ||
  fail "@xchonnect/mcp version is $mcp_version, tag says $version"
[ "$(jq -r '.version + " " + .packages[""].version' "$mcp_lock")" = "$version $version" ] ||
  fail "$mcp_lock is not at $version (npm install --package-lock-only in agent-mcp)"
mcp_dapp=$(jq -r '.dependencies["@xchonnect/dapp"] // ""' "$mcp")
[[ "$mcp_dapp" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] ||
  fail "$mcp requires @xchonnect/dapp '$mcp_dapp'; it must be one exact version that is on npm"
[ "$(jq -r '.packages["node_modules/@xchonnect/dapp"] | "\(.version) \(.resolved)"' "$mcp_lock")" = \
  "$mcp_dapp https://registry.npmjs.org/@xchonnect/dapp/-/dapp-$mcp_dapp.tgz" ] ||
  fail "$mcp_lock does not resolve @xchonnect/dapp@$mcp_dapp from registry.npmjs.org"
# The very bytes npm serves, published by release-publish.yml with provenance: the plugin
# never ships on a hand-published SDK (docs/release.md, "If something goes wrong").
dapp_meta=$(curl -fsS --retry 3 "https://registry.npmjs.org/@xchonnect%2fdapp/$mcp_dapp") ||
  fail "cannot read @xchonnect/dapp@$mcp_dapp from registry.npmjs.org (is it published?)"
[ "$(jq -r '.dist.integrity // ""' <<<"$dapp_meta")" = \
  "$(jq -r '.packages["node_modules/@xchonnect/dapp"].integrity // ""' "$mcp_lock")" ] ||
  fail "$mcp_lock records another integrity for @xchonnect/dapp@$mcp_dapp than npm serves"
jq -e '.dist.attestations.provenance' <<<"$dapp_meta" >/dev/null ||
  fail "@xchonnect/dapp@$mcp_dapp has no provenance on npm; the plugin requires a version release-publish.yml published"

# Every package a lockfile fetches is pinned by its sha512 (links and workspace members
# are this tree's own and carry none).
for lock in package-lock.json "$mcp_lock"; do
  loose=$(jq -r '.packages | to_entries[]
    | select((.key | contains("node_modules/")) and (.value.link != true))
    | select((.value.integrity // "") | startswith("sha512-") | not) | .key' "$lock")
  [ -z "$loose" ] || fail "$lock has entries without a sha512 integrity: $(tr '\n' ' ' <<<"$loose")"
done

grep -q "^## \[$version\]" CHANGELOG.md ||
  fail "CHANGELOG.md has no '## [$version]' section"
section=$(awk "/^## \\[$version\\]/{f=1;next} /^## /{f=0} f" CHANGELOG.md)
echo "$section" | grep -qi "protocol version" ||
  fail "the CHANGELOG section for $version does not state the protocol version"
echo "$section" | grep -q '[^[:space:]]' ||
  fail "the CHANGELOG section for $version is empty"

echo "==> tag signature"
LIST=.github/release-maintainers.txt
MAIN=main

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if [ -n "${GH_TOKEN:-}" ] && command -v gh >/dev/null 2>&1; then
  list_from_main() {
    gh api -H 'Accept: application/vnd.github.raw+json' "repos/$REPO/contents/$LIST?ref=$MAIN"
  }
  # identical: the commit is main's head; behind: main contains it.
  on_main() {
    case "$(gh api "repos/$REPO/compare/$MAIN...$1" --jq .status)" in
      identical | behind) return 0 ;;
      *) return 1 ;;
    esac
  }
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
  git rev-parse -q --verify "origin/$MAIN^{commit}" >/dev/null ||
    fail "no origin/$MAIN in this clone (git fetch origin $MAIN)"
  list_from_main() { git show "origin/$MAIN:$LIST"; }
  on_main() { git merge-base --is-ancestor "$1" "origin/$MAIN"; }
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

on_main "$commit" ||
  fail "$TAG points at $commit, which is not on $MAIN; a release is cut from a commit merged to $MAIN"
echo "    $commit is on $MAIN"

# `<login> SHA256:<fingerprint> [SHA256:<fingerprint> ...]` per line, from main.
list=$(list_from_main) || fail "cannot read $LIST from $MAIN"
maintainers=$(grep -v '^[[:space:]]*#' <<<"$list" | grep -v '^[[:space:]]*$' || true)
[ -n "$maintainers" ] || fail "$LIST on $MAIN lists no maintainer"

signer=""
signer_key=""
while read -r login pinned; do
  case "$login" in "" | *[!A-Za-z0-9-]*) fail "'$login' in $LIST is not a GitHub login" ;; esac
  [ -n "$pinned" ] || fail "$LIST pins no signing key fingerprint for $login"
  for fp in $pinned; do
    case "$fp" in SHA256:?*) ;; *) fail "'$fp' for $login in $LIST is not an SSH key fingerprint (SHA256:...)" ;; esac
  done
  keys "$login" > "$tmp/keys" || fail "cannot read the SSH signing keys of $login from GitHub"
  # Only keys that are both on the account and pinned in the list. A key added to the
  # account (a stolen session or token can add one) is not enough.
  : > "$tmp/allowed"
  while read -r key; do
    [ -n "$key" ] || continue
    fp=$(ssh-keygen -lf - <<<"$key" | awk '{print $2}')
    case " $pinned " in
      *" $fp "*) echo "$login namespaces=\"git\" $key" >> "$tmp/allowed" ;;
    esac
  done < "$tmp/keys"
  [ -s "$tmp/allowed" ] || continue
  # namespaces="git": the namespace git signs tags and commits in.
  if out=$(ssh-keygen -Y verify -f "$tmp/allowed" -I "$login" -n git -s "$tmp/sig" \
    < "$tmp/payload" 2>&1); then
    signer=$login
    signer_key=$(grep -o 'SHA256:[A-Za-z0-9+/=]*' <<<"$out" | head -1)
    break
  fi
done <<<"$maintainers"
[ -n "$signer" ] ||
  fail "$TAG is not signed by a pinned SSH signing key of any login in $LIST on $MAIN ($(awk '{print $1}' <<<"$maintainers" | tr '\n' ' ' | sed 's/ $//'))"
echo "    signed by $signer with ${signer_key:-a pinned key} (listed in $LIST on $MAIN); tag points at $commit"

if [ -n "${XCHONNECT_GATE_OUTPUT:-}" ]; then
  { echo "commit=$commit"; echo "signer=$signer"; } >> "$XCHONNECT_GATE_OUTPUT"
fi

echo "release gate passed: $TAG (version $version)"
