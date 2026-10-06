#!/usr/bin/env bash
# The crates that go to crates.io: xchonnect-core and xchonnect-wallet-kit.
#
#   ./scripts/release-crates.sh             # package both and check the tarballs
#   ./scripts/release-crates.sh --pending   # print the crates whose version is not on crates.io
#   ./scripts/release-crates.sh --publish   # publish what is pending, core before wallet-kit
#
# Without an option nothing leaves the machine: `cargo package --locked` builds each crate
# from its own tarball (wallet-kit against the packaged core, as a registry would serve
# it), and the tarballs are checked for the licence, the readme and the dependency on the
# core. `--allow-dirty` lets that run on uncommitted changes, for trying it out locally.
#
# `--publish` uploads with `--no-verify`: the tarballs were verified by the run above (in
# the release workflow, by the `crates-package` job on the same tag), and not building
# here means no dependency's build script runs while the registry token is in the
# environment. A version that is already on crates.io is skipped, so a failed release can
# be re-run. The token comes from CARGO_REGISTRY_TOKEN (trusted publishing in the release
# workflow) or `cargo login` (the first, manual publish) - docs/release.md.
set -euo pipefail
cd "$(dirname "$0")/.."

# Dependency order: wallet-kit requires the core at exactly its own version.
CRATES=(xchonnect-core xchonnect-wallet-kit)
# Sparse index of the registry `cargo publish` uploads to.
INDEX=${XCHONNECT_CRATES_INDEX:-https://index.crates.io}

MODE=package
ALLOW_DIRTY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --pending) MODE=pending; shift ;;
    --publish) MODE=publish; shift ;;
    --allow-dirty) ALLOW_DIRTY=1; shift ;;
    -h | --help) sed -n '2,19p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

fail() { echo "release crates: $1" >&2; exit 1; }

meta=$(cargo metadata --no-deps --format-version 1)
version=$(echo "$meta" | jq -r --arg n "${CRATES[0]}" '.packages[] | select(.name == $n) | .version')
[ -n "$version" ] || fail "${CRATES[0]} is not in the workspace"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Is <crate> at $version in the index? A yanked version counts: its number is taken.
published() {
  local crate=$1 code
  # Index path of a name of four or more characters: <first two>/<next two>/<name>.
  code=$(curl -sS --retry 3 -o "$tmp/index" -w '%{http_code}' \
    "$INDEX/${crate:0:2}/${crate:2:2}/$crate") || fail "cannot reach $INDEX"
  case "$code" in
    200) jq -r .vers "$tmp/index" | grep -Fxq "$version" ;;
    404) return 1 ;; # the crate does not exist yet
    *) fail "$INDEX answered $code for $crate" ;;
  esac
}

pending=()
if [ "$MODE" != package ]; then
  for crate in "${CRATES[@]}"; do
    published "$crate" || pending+=("$crate")
  done
fi

case "$MODE" in
  pending)
    echo "${pending[*]-}"
    ;;

  publish)
    [ -z "$ALLOW_DIRTY" ] || fail "--publish takes a clean checkout of the release tag"
    for crate in "${CRATES[@]}"; do
      case " ${pending[*]-} " in
        *" $crate "*) ;;
        *) echo "==> $crate $version is already on crates.io, skipping"; continue ;;
      esac
      echo "==> publishing $crate $version"
      # cargo waits until the version is in the index, so the core is resolvable by the
      # time wallet-kit is uploaded.
      cargo publish --locked --no-verify -p "$crate"
    done
    ;;

  package)
    args=()
    for crate in "${CRATES[@]}"; do args+=(-p "$crate"); done
    cargo package --locked ${ALLOW_DIRTY:+--allow-dirty} "${args[@]}"

    target_dir=$(echo "$meta" | jq -r .target_directory)
    for crate in "${CRATES[@]}"; do
      echo "==> $crate-$version.crate"
      tarball="$target_dir/package/$crate-$version.crate"
      [ -f "$tarball" ] || fail "cargo package left no $tarball"
      # Unpacked outside the repository, so cargo reads the packaged manifest on its own
      # and not as a stray member of this workspace.
      tar -xzf "$tarball" -C "$tmp"
      pkg="$tmp/$crate-$version"
      cmp -s LICENSE "$pkg/LICENSE" ||
        fail "$crate: the packaged LICENSE is missing or differs from the repository's (copy LICENSE into the crate directory)"
      [ -s "$pkg/README.md" ] || fail "$crate: no README.md in the package"
      # What crates.io will record: no dependency by path, and the core at this version only.
      deps=$(cargo metadata --no-deps --format-version 1 --manifest-path "$pkg/Cargo.toml" |
        jq -r '.packages[0].dependencies[] | "\(.name) \(.req) \(.path // "-")"')
      ! echo "$deps" | grep -qv ' -$' || fail "$crate: packaged with a path dependency"
      while read -r name req _; do
        case "$name" in
          xchonnect-*) [ "$req" = "=$version" ] ||
            fail "$crate requires $name \"$req\", expected \"=$version\"" ;;
        esac
      done <<<"$deps"
      echo "    LICENSE, README.md, $(echo "$deps" | grep -c .) dependencies, none by path"
    done
    echo "crates packaged and checked: ${CRATES[*]} $version"
    ;;
esac
