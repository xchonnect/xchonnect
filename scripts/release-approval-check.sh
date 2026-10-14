#!/usr/bin/env bash
# Who approved the `release` environment for this run? Run by every job of
# .github/workflows/release-publish.yml that pushes, signs or publishes (those jobs wait for that
# approval; docs/release.md, "Who can release").
#
#   GH_TOKEN=... GITHUB_REPOSITORY=owner/name GITHUB_RUN_ID=123 \
#     ./scripts/release-approval-check.sh <signer-login>
#
# <signer-login> is the maintainer whose SSH key signed the tag (scripts/release-gate.sh
# finds it). The run must carry an approval of the `release` environment by a login in
# .github/release-maintainers.txt as it is on `main` now (read through the API, never
# from the checkout). Once that file lists two or more logins, the approval must come
# from a maintainer other than the signer: the two-person rule switches itself on with
# the second maintainer. With one listed maintainer, signer and approver are the
# same person, and the approval is a deliberate second step, not a second person.
set -euo pipefail
cd "$(dirname "$0")/.."

SIGNER=${1:?usage: $0 <signer-login>}
REPO=${XCHONNECT_REPO:-${GITHUB_REPOSITORY:-}}
RUN=${GITHUB_RUN_ID:-}
LIST=.github/release-maintainers.txt
MAIN=main
ENVIRONMENT=release

fail() { echo "::error::release approval: $1"; exit 1; }

[ -n "$REPO" ] || fail "GITHUB_REPOSITORY is not set"
[ -n "$RUN" ] || fail "GITHUB_RUN_ID is not set"
[ -n "${GH_TOKEN:-}" ] || fail "GH_TOKEN is not set"

list=$(gh api -H 'Accept: application/vnd.github.raw+json' "repos/$REPO/contents/$LIST?ref=$MAIN") ||
  fail "cannot read $LIST from $MAIN"
# The first field of each line is the login (the gate reads the pinned key fingerprints).
maintainers=$(grep -v '^[[:space:]]*#' <<<"$list" | awk 'NF {print $1}')
[ -n "$maintainers" ] || fail "$LIST on $MAIN lists no maintainer"
is_maintainer() { grep -Fxq -- "$1" <<<"$maintainers"; }
count=$(grep -c . <<<"$maintainers" || true)

is_maintainer "$SIGNER" || fail "the tag signer $SIGNER is not listed in $LIST on $MAIN"

approvers=$(gh api "repos/$REPO/actions/runs/$RUN/approvals" |
  jq -r --arg env "$ENVIRONMENT" \
    '.[] | select(.state == "approved") | select(any(.environments[]; .name == $env)) | .user.login' |
  sort -u)
[ -n "$approvers" ] ||
  fail "this run carries no approval of the '$ENVIRONMENT' environment; approve it on the run's page (docs/release.md, \"Who can release\")"

ok=""
while read -r login; do
  if [ -z "$login" ] || ! is_maintainer "$login"; then
    continue
  fi
  if [ "$count" -lt 2 ] || [ "$login" != "$SIGNER" ]; then
    ok=$login
    break
  fi
done <<<"$approvers"

if [ -z "$ok" ]; then
  if [ "$count" -ge 2 ]; then
    fail "approved only by $(tr '\n' ' ' <<<"$approvers")- $LIST lists $count maintainers, so a maintainer other than the signer $SIGNER must approve"
  fi
  fail "approved only by $(tr '\n' ' ' <<<"$approvers")- none of them is listed in $LIST"
fi

if [ "$count" -ge 2 ]; then
  echo "two-person rule satisfied: tag signed by $SIGNER, '$ENVIRONMENT' approved by $ok"
else
  echo "release approval: tag signed by $SIGNER, '$ENVIRONMENT' approved by $ok (single listed maintainer: no second person)"
fi
