# Branch protection (for repository administrators)

Apply on GitHub under *Settings → Rules → Rulesets* for `main` (and release branches):

- Require a pull request; at least **1 approving review**, **2** for PRs touching
  `crates/core`, `crates/wallet-kit`, `docs/spec/` or `.github/` (enforced via CODEOWNERS
  with "Require review from Code Owners").
- Dismiss stale approvals on new commits; require approval of the most recent push.
- No required status checks: GitHub Actions runs only on a release tag (3c72c0b), so the
  checks are `scripts/verify.sh` on the contributor's machine, stated in the pull request.
- Require signed commits and linear history; block force pushes and deletions.
- Enable *private vulnerability reporting*, Dependabot security alerts and secret
  scanning with push protection.
- Restrict who can create release tags (`v*`, `spec-v*`) to maintainers.
