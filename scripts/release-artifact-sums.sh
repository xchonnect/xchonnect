#!/usr/bin/env bash
# Digests that travel between the jobs of .github/workflows/release-publish.yml as job outputs,
# not as artifacts. Any job of a run can replace an artifact of that run (the runtime
# token every job holds can delete and upload artifacts), but only a job itself can set
# its outputs; so a job that uploads an artifact also states its digests as an output,
# and every job that downloads it checks the download against that output.
#
#   ./scripts/release-artifact-sums.sh <dir>                  # print the manifest
#   ./scripts/release-artifact-sums.sh --output <name> <dir>  # append it to $GITHUB_OUTPUT
#   EXPECTED=<manifest> ./scripts/release-artifact-sums.sh --check <dir>
#
# The manifest is `sha256sum` output over every file under <dir>, by path relative to
# <dir>, sorted. --check fails unless <dir> holds exactly those files with those digests:
# a file changed, missing or added fails it.
set -euo pipefail

manifest() {
  (cd "$1" && find . -type f | sed 's|^\./||' | LC_ALL=C sort | while IFS= read -r f; do
    sha256sum -- "$f"
  done)
}

case "${1:-}" in
  --output)
    name=${2:?usage: $0 --output <name> <dir>}
    dir=${3:?usage: $0 --output <name> <dir>}
    [ -n "${GITHUB_OUTPUT:-}" ] || { echo "GITHUB_OUTPUT is not set" >&2; exit 2; }
    sums=$(manifest "$dir")
    [ -n "$sums" ] || { echo "release artifact: $dir is empty" >&2; exit 1; }
    echo "$sums"
    delim="EOF_$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    { echo "$name<<$delim"; echo "$sums"; echo "$delim"; } >> "$GITHUB_OUTPUT"
    ;;
  --check)
    dir=${2:?usage: EXPECTED=... $0 --check <dir>}
    [ -n "${EXPECTED:-}" ] ||
      { echo "::error::release artifact: no expected digests for $dir (job output missing)"; exit 1; }
    [ -d "$dir" ] || { echo "::error::release artifact: $dir was not downloaded"; exit 1; }
    if ! diff -u <(printf '%s\n' "$EXPECTED") <(manifest "$dir"); then
      echo "::error::release artifact: $dir is not what the job that made it uploaded (above: - its job output, + the download). Do not release; find out what replaced the artifact."
      exit 1
    fi
    echo "release artifact: $dir matches its job output ($(printf '%s\n' "$EXPECTED" | grep -c .) files)"
    ;;
  -h | --help | "")
    sed -n '2,15p' "$0"
    ;;
  *)
    manifest "$1"
    ;;
esac
