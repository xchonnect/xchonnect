# AGENTS.md

Xchonnect is a privacy-preserving transport between Chia dApps and wallets: a Rust core
(`crates/core`), a reference relay and a push gateway (`crates/relay`, `crates/gateway`),
a wallet library (`crates/wallet-kit`), the TypeScript dApp SDK (`sdk-ts`) and bindings
(`bindings/wasm`, `bindings/uniffi`). `README.md` has the layout; `CONTRIBUTING.md` the
rules for people, which apply to agents too. Sibling repositories: `../xchonnect-backlog`
(tasks, Backlog.md CLI, run `backlog` there; `TASK-NN` in commits and docs refers to it)
and `../xchonnect-wiki` (planning pages that are not public). The first wallet is Klimper
(`../../clapandpay/clapandpay/klimper`), the first dApp Pengui (`../../pengui/pengui`);
the relay and the gateway run on the nodexch server (`../../nodexch/nodexch`,
`docs/operations.md` "Xchonnect").

## Git workflow

- **Never push to `main`**, never force-push, never rewrite or delete a tag. `main` changes
  through a pull request that the owner opens and merges: commit and push your branch
  without being asked, and **never open a pull request** yourself (`gh`, the API, the
  browser). Say in the hand-back which branch holds the work and what was checked.
- Branch names: `feat/<slug>`, `fix/<slug>`, `docs/<slug>`, `chore/<slug>`,
  `release-X.Y.Z`. One change per branch; crypto and parsing changes apart from refactors.
- **Every commit: `git commit -S -s`.** Signed (SSH, configured in this clone) and signed
  off (DCO). Nothing sets this automatically. The identity is the repository's
  (`git config user.name` / `user.email`; check before the first commit in a fresh clone).
- Commit subject: `<component>: <what changed>` or a conventional prefix
  (`docs(operating): …`, `fix(release): …`), lower case after the colon, `(TASK-NN)` at the
  end when a task exists. Body: why; a `Checked:` paragraph with the commands run and their
  result; `Not checked:` for what was not; `Threats affected: <T-ids or none>` (spec 13.3).
- Never run `scripts/release-crates.sh --publish`, `cargo publish` (other than
  `--dry-run`), `npm publish`, `git push origin v*` or `scripts/fuzz-crash-report.sh` without
  `XCHONNECT_FUZZ_DRY_RUN=1`: a registry version is permanent, a tag starts the release
  workflow, an advisory is public. These are the owner's.

## Checks

GitHub Actions runs only on a release tag (`release.yml`). Everything else is local:

```sh
scripts/verify.sh            # before every push: fmt, clippy, tests, conformance, privacy
                             # scan, cargo deny, wasm, the SDK, shellcheck, actionlint
scripts/verify.sh --full     # a change to the relay, its store, the gateway or the SDK's
                             # transport: Postgres, Android, interop, npm audit, fuzzing
scripts/verify.sh --bindings # a change to bindings/ (Xcode, a JDK)
```

Say in the commit and the hand-back which of these ran. Postgres tests skip silently
without `XCHONNECT_TEST_DATABASE_URL`; `--full` provides one. Fuzzing needs
`cargo +nightly`; `fuzz/` is outside the workspace and its `Cargo.lock` lags.

## Code

- **Privacy is structural.** Relay handlers must not read client identity: the test
  `handlers_do_not_read_client_identity` (`crates/relay/src/lib.rs`) fails when any relay
  source but `lib.rs` even mentions `ConnectInfo`, `user-agent`, `x-forwarded-for`,
  `forwarded`, `x-real-ip`, `remote_addr` or `peer_addr`, comments included. No request
  logging. Logs, errors and metrics never carry tokens, keys, mailbox ids, IPs or message
  contents (spec 13.5); `scripts/privacy-scan.sh` and the `privacy/` crate check that
  against `docs/privacy/data-inventory.md`, so a new log line, metric or column must fit
  the inventory.
- No `unsafe` outside the FFI crates; no `unwrap`/`expect`/panic on data from the network,
  a QR code or storage; secrets in the zeroizing types, without `Debug`/`Display`,
  compared in constant time. Every parser gets property tests and, if it faces untrusted
  input, a fuzz target (`fuzz/fuzz_targets/`).
- **Wire changes.** Bytes on the wire, an error code, a limit or a derivation changed:
  `docs/spec/` changes with it (`docs/spec/PROCESS.md`, `docs/spec/CHANGELOG.md`), the
  vectors are regenerated (`XCHONNECT_WRITE_VECTORS=1 cargo test -p xchonnect-core --lib
  vectors`; `… -p xchonnect-wallet-kit multiparty` for `multiparty.json`), the SDK's
  vector test runs after `scripts/build-wasm.sh`, and the CHANGELOG entry names the
  threats. `docs/chip/` is derived from the spec by hand: say when it falls behind.
- Normative text lives only in `docs/spec/`; `docs/design/` is history, not a contract.
- Any command or path a document mentions must exist and work at that commit. A
  limitation removed names the commit that removed it; one added goes into
  `docs/guides/security-and-privacy.md` in the same change.
- Every manifest says `license = "Apache-2.0"`; new dependencies follow
  `docs/dependency-policy.md` and pass `cargo deny check`.

## Releases

`docs/release.md`. A release is a version bump on a branch (`release-X.Y.Z`:
`Cargo.toml` workspace version and the three `=` requirements, `sdk-ts/package.json`,
the crate READMEs for a pre-release, both lockfiles, the CHANGELOG section), merged, then a
signed annotated tag pushed by the owner. `scripts/release-gate.sh vX.Y.Z` stops at the
missing tag and checks everything else; `scripts/release-crates.sh` packages the crates.
npm and crates.io are public before the GitHub release is; nothing there can be undone.
The `.claude/skills/` folder has the procedure (`release-prep`) and the audit
(`security-audit`).

## This machine

- Disk is tight: build what the task needs; no release or reproducibility builds to see
  whether code compiles; `cargo clean -p <crate>`, never a bare `cargo clean`.
- GitHub API calls are anonymous unless `gh auth login` was run; the anonymous limit is 60
  an hour, so do not poll a workflow run. The run's page in a browser needs no token.
- Docker is Colima; a throwaway Postgres is `postgres:17-alpine`.

## Backlog and wiki

`../xchonnect-backlog` and `../xchonnect-wiki` are committed and pushed straight to
`main`, as the work happens. In the backlog use the CLI only (`backlog instructions
task-execution` first; `backlog task edit TASK-NN --append-notes …`, `--check-ac n`); a
note is dated, names the branch and commit, says what was checked and what was not, and
what the owner still has to do. Subject: `TASK-NN: <one line of status>`.
