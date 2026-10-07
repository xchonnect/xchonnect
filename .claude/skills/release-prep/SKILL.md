---
name: release-prep
description: Prepare an Xchonnect release on a branch (version bump, changelog section, lockfiles, local gate and packaging checks) and hand the signed tag to the owner. Use when asked to "prepare", "cut" or "bump" a release or release candidate. It never tags, pushes a tag or publishes.
---

# Release preparation

The reference is `docs/release.md`, "Cutting a release"; this is the same in the order it
is done, with the checks that proved the last releases (0.1.0-rc.2, rc.3). The tag and
everything after it are the owner's: a tag starts `release.yml`, which publishes to npm
and crates.io, and neither can be undone.

## 1. Decide the version

- `X.Y.Z-rc.N` while the spec is a draft (`docs/versioning.md` maps protocol, spec and
  package versions). Every published version is permanent, so a bump is never reused.
- Read the `Unreleased` section of `CHANGELOG.md`: it must say what the release is for.
  If it is empty, there is nothing to release.

## 2. Branch and bump

```sh
git switch main && git pull --ff-only
git switch -c release-X.Y.Z
```

Replace the previous version with the new one in exactly these places (nowhere in
history, changelog entries or "images up to …" notes):

- `Cargo.toml`: `[workspace.package] version` and the three `=X.Y.Z` requirements under
  `[workspace.dependencies]`;
- `privacy/Cargo.toml`: the `xchonnect-gateway` requirement;
- `sdk-ts/package.json`: `version`;
- for a pre-release, the dependency line of `crates/core/README.md` and
  `crates/wallet-kit/README.md` (`= "=X.Y.Z-rc.N"`);
- `CHANGELOG.md`: `## [Unreleased]` keeps its two version lines and becomes empty; a new
  `## [X.Y.Z] - YYYY-MM-DD` with the same `Protocol version:` and `Spec version:` lines
  takes the entries. Use the day the tag will be made.

Then the lockfiles, which must change only in version lines:

```sh
cargo update --workspace --offline
npm install --package-lock-only --ignore-scripts
git diff --stat                 # Cargo.lock, package-lock.json: version lines only
```

`fuzz/Cargo.lock` is outside the workspace and is not part of a release.

## 3. Check

```sh
cargo check --workspace --locked
./scripts/release-gate.sh vX.Y.Z   # must reach "==> tag signature" and stop there
scripts/verify.sh                  # the full local gate (minutes)
```

Commit, then the packaging checks that need a clean tree:

```sh
git commit -S -s -m "Release X.Y.Z: versions and changelog" -m "<what the release is for; Threats affected: none.>"
./scripts/release-crates.sh                                   # packages and builds both crates
cargo publish --dry-run --locked --no-verify -p xchonnect-core
cargo publish --dry-run --locked --no-verify -p xchonnect-wallet-kit
RUSTDOCFLAGS='-D warnings' cargo doc --no-deps -p xchonnect-core -p xchonnect-wallet-kit
git push -u origin release-X.Y.Z
```

## 4. Hand back

Report: the branch and commit, every check with its result, and the two commands the
owner runs after merging:

```sh
git switch main && git pull --ff-only
git tag -s vX.Y.Z -m "xchonnect vX.Y.Z" && git push origin vX.Y.Z
```

Then the owner watches the run (its page in the browser; the API needs a login).
Afterwards `./scripts/release-crates.sh --pending` prints what did not reach crates.io:
re-running the failed job publishes only that, and a trusted publisher must exist on
crates.io for each crate (`docs/release.md`, "Once, before the first automated publish").

## After the release

- Downstream pins: Klimper's `tauri-plugin-klimper-xchonnect/Cargo.toml` requires the
  crates at an exact version; nodexch's `scripts/nx` and the nodexch wiki name the image
  tag. Say which of them should move.
- Record the release in the backlog task that asked for it.
