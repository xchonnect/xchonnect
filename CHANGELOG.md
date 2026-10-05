# Changelog

All notable changes to the Xchonnect implementation. The specification has its own
changelog in [`docs/spec/CHANGELOG.md`](docs/spec/CHANGELOG.md); the policy that governs
both, and the mapping between the protocol version and package versions, is in
[`docs/versioning.md`](docs/versioning.md).

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Protocol version: 1
Spec version: 0.2 (draft)

### Added

- Pre-release tags (`v0.1.0-rc.1`) are drafted as GitHub pre-releases.
- npm publishing of `@xchonnect/dapp` from the release workflow (TASK-67): trusted
  publishing over GitHub OIDC with provenance, no `NPM_TOKEN`; pre-releases go to the
  `next` dist-tag. One-time setup in [`docs/release.md`](docs/release.md).
- Release pipeline (TASK-59): reproducible builds of the relay and gateway binaries
  (`scripts/release-build.sh`) with a two-build digest gate
  (`scripts/release-repro-check.sh`), CycloneDX SBOMs for every artifact
  (`scripts/sbom.sh`), Sigstore keyless signatures and SLSA build provenance over the
  release manifest and the container images, a two-person release rule, and a
  verification procedure a third party can run (`scripts/release-verify.sh`,
  [`docs/release.md`](docs/release.md)).
- Continuous fuzzing and coverage (TASK-60): nightly ten-minutes-per-target fuzzing with
  a persistent corpus, crashes reported as private draft advisories, a request-level
  fuzz target for the relay's HTTP surface (`relay_http`), and coverage reporting for
  core, relay, gateway and wallet-kit (`scripts/coverage.sh`,
  [`docs/fuzzing.md`](docs/fuzzing.md)).
- Encrypted notification previews (TASK-48) exposed to native wallets:
  `openNotificationPreview(hintKey, sealed, now, allowDetail)` with `PreviewKind`,
  `Preview` and the `OpenedPreview` outcome in the Swift and Kotlin packages. The call
  cannot fail — anything that does not authenticate, decode or pass the wallet's policy
  returns the generic alert — and the sender's detail line is dropped unless the wallet
  passes `allowDetail` (T11, T12).
- Versioning and changelog policy ([`docs/versioning.md`](docs/versioning.md)) and this
  changelog.
- Per-crate READMEs and complete registry metadata for the publishable crates and for
  `@xchonnect/dapp` (TASK-67).

### Fixed

- Relay: every error response now uses the uniform `{"error":"<code>"}` model
  (`docs/spec/wire/relay-api.md` §Errors). Rejections raised by the HTTP framework
  before a handler ran — an unmatched path, a method a route does not declare, a path
  that does not percent-decode to UTF-8 — used to answer with an empty or plain-text
  body (found by the `relay_http` fuzz target, F-1). 405 responses keep their `Allow`
  header and now carry the new `method_not_allowed` code.

### Security

- Core enforces the origin document's `return_url` same-domain rule
  (`xchonnect_core::origin::OriginDocument::check_bound_to`, called from
  `pairing::VerifiedUri::new`): the URL's authority must be byte-identical to the domain
  the pairing URI claims, so a dApp whose origin key leaked cannot turn a wallet's
  same-device return into a one-tap redirect off the domain the wallet just displayed
  (T18, T3). The rule previously existed only as prose in
  `docs/spec/wire/xchonnect.schema.json`, leaving every wallet to re-implement the host
  check. The comparison is on the whole authority and exact, so a subdomain, a port,
  userinfo, a trailing dot, a lookalike registration and a differently-spelled form of
  the same name are all refused; the document is rejected, not silently stripped.
- The `relay_http` fuzz target asserts that no request produces a 500, that every
  response carries the privacy headers, that a presented capability token is never
  echoed back (spec 13.5, T15), and that every error body is the uniform model.
- Regression tests for two pieces of hardening that had none: the redacting `Debug`
  impls of the HPKE contexts cannot emit key material (T5, T13), and `ed25519_verify`
  refuses all eight small-order Ed25519 public keys (T20).

## [0.1.0] - unreleased

Protocol version: 1
Spec version: 0.1

Initial implementation: protocol core, reference relay, reference push gateway,
wallet-kit, WASM and UniFFI bindings, TypeScript dApp SDK, conformance suites and
examples. Not released to any registry; see TASK-67.
