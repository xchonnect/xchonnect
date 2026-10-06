#!/usr/bin/env bash
# Report fuzzing crashes privately.
#
#   ./scripts/fuzz-crash-report.sh [artifacts-dir]      # default fuzz/artifacts
#
# A crash found by the continuous fuzzing workflow may be an exploitable parser bug, so
# it must not become a public issue before it is fixed (SECURITY.md). This opens a
# *draft* GitHub repository security advisory, which only maintainers can see, one per
# fuzz target, with the reproducer attached as base64 inside the advisory body.
#
# Environment:
#   GH_TOKEN      token with `repo` + `security_events` on this repository. The default
#                 GITHUB_TOKEN cannot create advisories: the workflow passes the
#                 FUZZ_ADVISORY_TOKEN secret (see docs/fuzzing.md).
#   XCHONNECT_REPO   owner/name, default from GITHUB_REPOSITORY.
#   XCHONNECT_FUZZ_DRY_RUN=1   print what would be filed and exit 1 (local use).
#
# Exit status is non-zero whenever a crash exists, so the job fails even if filing fails.
set -euo pipefail
cd "$(dirname "$0")/.."

DIR=${1:-fuzz/artifacts}
REPO=${XCHONNECT_REPO:-${GITHUB_REPOSITORY:-xchonnect/xchonnect}}

if [ ! -d "$DIR" ]; then
  echo "no crash artifacts in $DIR"
  exit 0
fi

# bash 3 compatible: no mapfile.
crash_count=$(find "$DIR" -type f ! -name '.*' | wc -l | tr -d ' ')
if [ "$crash_count" -eq 0 ]; then
  echo "no crash artifacts in $DIR"
  exit 0
fi

echo "$crash_count crash artifact(s) found" >&2

filed=0
# One advisory per target, however many inputs it produced.
for target_dir in "$DIR"/*; do
  [ -d "$target_dir" ] || continue
  target=$(basename "$target_dir")
  files=$(find "$target_dir" -type f ! -name '.*' | sort)
  [ -n "$files" ] || continue
  n=$(echo "$files" | wc -l | tr -d ' ')

  body=$(
    echo "Continuous fuzzing found $n crashing input(s) in the \`$target\` target."
    echo
    echo "- commit: \`${GITHUB_SHA:-$(git rev-parse HEAD 2>/dev/null || echo unknown)}\`"
    echo "- workflow run: ${GITHUB_SERVER_URL:-https://github.com}/$REPO/actions/runs/${GITHUB_RUN_ID:-local}"
    echo
    echo "Reproduce:"
    echo '```sh'
    echo "# write the base64 below to fuzz/artifacts/$target/crash-1, then"
    echo "cargo +nightly fuzz run $target fuzz/artifacts/$target/crash-1"
    echo "cargo +nightly fuzz tmin $target fuzz/artifacts/$target/crash-1"
    echo '```'
    echo "$files" | while read -r f; do
      echo
      echo "### $(basename "$f") ($(wc -c < "$f" | tr -d ' ') bytes)"
      echo '```'
      base64 < "$f"
      echo '```'
    done
    echo
    echo "Triage checklist (docs/fuzzing.md): minimise, add a regression test in the"
    echo "crate that owns the parser, fix, then record the finding in fuzz/README.md."
  )
  title="Fuzzing crash in $target"

  if [ "${XCHONNECT_FUZZ_DRY_RUN:-0}" = "1" ] || [ -z "${GH_TOKEN:-}" ]; then
    echo "=== would file a draft advisory on $REPO: $title" >&2
    echo "$body" | head -8 >&2
    continue
  fi

  # Draft advisories are private to maintainers until they are published.
  gh api --method POST "repos/$REPO/security-advisories" \
    -f summary="$title" \
    -f description="$body" \
    -f severity=high >/dev/null
  echo "filed a draft advisory: $title" >&2
  filed=$((filed + 1))
done

echo "crashes: $crash_count, advisories filed: $filed" >&2
exit 1
