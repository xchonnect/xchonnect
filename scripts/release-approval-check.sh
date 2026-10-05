#!/usr/bin/env bash
# Two-person rule for releases (docs/release.md, "The two-person rule").
#
# GitHub environments require only one approval, so one approval alone is not two
# people. A release therefore needs both:
#
#   1. a signed annotated tag - checked by scripts/release-gate.sh;
#   2. an environment approval on this workflow run by a maintainer who is NOT the
#      person who started the release - checked here, against the run's approval list.
#
# Both logins must appear in .github/release-maintainers.txt.
#
#   GH_TOKEN=... GITHUB_REPOSITORY=owner/name GITHUB_RUN_ID=123 \
#     ./scripts/release-approval-check.sh <initiator-login>
set -euo pipefail
cd "$(dirname "$0")/.."

INITIATOR=${1:-${GITHUB_ACTOR:-}}
REPO=${XCHONNECT_REPO:-${GITHUB_REPOSITORY:-}}
RUN=${GITHUB_RUN_ID:-}
LIST=.github/release-maintainers.txt

fail() { echo "two-person rule: $1" >&2; exit 1; }

[ -n "$INITIATOR" ] || fail "no initiator login"
[ -n "$REPO" ] || fail "GITHUB_REPOSITORY is not set"
[ -n "$RUN" ] || fail "GITHUB_RUN_ID is not set"
[ -f "$LIST" ] || fail "$LIST is missing"
[ -n "${GH_TOKEN:-}" ] || fail "GH_TOKEN is not set"

maintainers=$(grep -v '^[[:space:]]*#' "$LIST" | tr -d ' \t' | grep -v '^$')
is_maintainer() { echo "$maintainers" | grep -Fxq "$1"; }

is_maintainer "$INITIATOR" || fail "$INITIATOR is not listed in $LIST"

approvals=$(gh api "repos/$REPO/actions/runs/$RUN/approvals")
approvers=$(echo "$approvals" | jq -r '.[] | select(.state == "approved") | .user.login' | sort -u)

[ -n "$approvers" ] || fail "the run carries no environment approval"

second=""
while read -r login; do
  [ -n "$login" ] || continue
  if [ "$login" != "$INITIATOR" ] && is_maintainer "$login"; then
    second=$login
    break
  fi
done <<< "$approvers"

[ -n "$second" ] ||
  fail "approved only by $(echo "$approvers" | tr '\n' ' ')- a release needs a second maintainer who did not start it"

echo "two-person rule satisfied: started by $INITIATOR, approved by $second"
