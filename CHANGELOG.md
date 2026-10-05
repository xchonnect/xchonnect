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
- Versioning and changelog policy ([`docs/versioning.md`](docs/versioning.md)) and this
  changelog.
- Per-crate READMEs and complete registry metadata for the publishable crates and for
  `@xchonnect/dapp` (TASK-67).

### Security

- The `relay_http` fuzz target asserts that no request produces a 500, that every
  response carries the privacy headers, and that a presented capability token is never
  echoed back (spec 13.5, T15).

## [0.1.0] - unreleased

Protocol version: 1
Spec version: 0.1

Initial implementation: protocol core, reference relay, reference push gateway,
wallet-kit, WASM and UniFFI bindings, TypeScript dApp SDK, conformance suites and
examples. Not released to any registry; see TASK-67.
