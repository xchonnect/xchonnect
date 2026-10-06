# Contributing to Xchonnect

Thank you for helping. Xchonnect is security-critical infrastructure, so the rules below
are stricter than in most projects.

## Licensing of contributions

- Code contributions are licensed under the Apache License, Version 2.0. Every Cargo
  and npm manifest MUST declare `license = "Apache-2.0"` (`"license": "Apache-2.0"`).
- Contributions to the specification and documents under `docs/` are dedicated to the
  public domain under CC0 1.0.

## Developer Certificate of Origin

Every commit must be signed off (`git commit -s`), certifying the
[Developer Certificate of Origin 1.1](https://developercertificate.org/): you wrote the
change or otherwise have the right to submit it under the project licence.

## Signed commits

Commits merged into `main` must be cryptographically signed (SSH or GPG) and show as
"Verified" on GitHub.

## Pull requests

- One logical change per PR; keep crypto/parsing changes separate from refactors.
- Fill in the PR template, including the **threat IDs** (T1–T21, spec Section 13.3) the
  change affects, or "none".
- Changes to `crates/core`, wire formats or the spec require approval from the
  designated CODEOWNERS and must update test vectors when bytes on the wire change.
- New dependencies follow [docs/dependency-policy.md](docs/dependency-policy.md).
- CI must be green: `cargo fmt`, `cargo clippy -- -D warnings`, `cargo test`,
  `npm run typecheck`, `npm test`, supply-chain checks.

## Coding standards

- Rust: no `unsafe` outside the FFI binding crates; no `unwrap`/`expect`/panics on data
  from the network, a QR code or storage; secrets use the zeroizing types from
  `xchonnect-core` and never implement `Debug`/`Display` with their contents; compare
  secrets in constant time.
- Logs and errors never contain tokens, keys, mailbox ids, IPs or message contents
  (spec Section 13.5).
- Every parser gets property tests and, where it faces untrusted input, a fuzz target.
- TypeScript: `strict` mode, no runtime dependencies in `@maximedogawa/xchonnect` beyond the
  WASM core.

## Documentation

- Normative text lives only in `docs/spec/`; changes there follow
  [`docs/spec/PROCESS.md`](docs/spec/PROCESS.md) and need a CHANGELOG entry. The CHIP draft
  in `docs/chip/` is regenerated from the spec, never edited independently.
- Audience guides live in `docs/guides/` (dApp quickstart, API references, security and
  privacy, WalletConnect comparison, incident response), with
  [`docs/wallet-integration.md`](docs/wallet-integration.md) for wallet teams and
  [`docs/operating.md`](docs/operating.md) for relay operators. `docs/design/` holds
  historical planning notes, which are not authoritative.
- **Keep the limitations honest.** Spec Section 13.6 requires the known limitations to be
  stated plainly in public documentation. If a PR removes a limitation, it must say which
  commit removed it; if it adds or widens one — including "this part is not implemented
  yet" — it must add it to
  [`docs/guides/security-and-privacy.md`](docs/guides/security-and-privacy.md) in the same
  PR. Do not describe planned work as if it exists.
- Any command or file path a document mentions must exist and work at that commit.

## Task references

Commit messages, comments and some documents cite `TASK-NN`. Those are entries in the
maintainers' own task tracker, which is not public. Each one is explained where it is
cited, so you can ignore the number; new contributions should link a GitHub issue instead.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Never discuss vulnerabilities in public issues. Maintainer
and operator runbooks are in
[`docs/guides/incident-response.md`](docs/guides/incident-response.md).
