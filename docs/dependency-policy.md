# Dependency policy

Xchonnect is security infrastructure (threat T15: malicious dependency or build). Every
dependency is attack surface, so adding one is a reviewed decision.

## Rules

1. **Necessity.** Prefer the standard library or a few lines of our own code over a new
   crate. Crypto primitives come only from the crates listed in
   [`design/crate-selection.md`](design/crate-selection.md).
2. **Review on addition.** A PR that adds or upgrades a dependency (direct or new
   transitive) states in its description: purpose, maintainer, licence, download count,
   `unsafe` usage, whether it is audited, and why existing dependencies do not suffice.
   CODEOWNERS for `Cargo.toml`, `Cargo.lock`, `package.json`, `package-lock.json` must
   approve.
3. **Supply-chain checks**, run locally before merging a dependency change and before
   every release (they are not run in GitHub Actions):
   - `cargo deny check` — licence allowlist, banned crates, crates.io only, yanked crates
     denied, RustSec advisories;
   - `npm audit` for the TypeScript workspace.
4. **Lockfiles** (`Cargo.lock`, `package-lock.json`) are committed; the release pipeline
   builds with `--locked` / `npm ci` and fails when they are stale.
5. **No install scripts** in the release pipeline (`npm ci --ignore-scripts`).
6. **CI actions** are pinned by full commit SHA and run with `contents: read`.
7. **Runtime vs dev.** The published `@xchonnect/dapp` package has no runtime npm
   dependencies other than the WASM core built from this repository.

## cargo-vet

`cargo vet` will be adopted before the first crates.io release (TASK-59), importing the
audit sets published by Mozilla, Google and the Bytecode Alliance; until then rule 2 is
the review record.
