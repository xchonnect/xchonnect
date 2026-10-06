# Versioning and changelog policy

Three version numbers exist in this project and they are deliberately not the same
number. This file says what each one means, how they relate, and what a change to one
obliges you to do to the others.

## The three versions

| Version | Where it lives | Form | Changed by |
|---|---|---|---|
| Protocol version `v` | inside every envelope and pairing URI (spec 5, 17) | a single integer, currently `1` | a change to bytes on the wire or to verification rules |
| Specification version | header of `docs/spec/xchonnect-spec.md`, tag `spec-vX.Y` | `MAJOR.MINOR` | any normative edit (`docs/spec/PROCESS.md`) |
| Package version | `Cargo.toml` (`[workspace.package] version`), `sdk-ts/package.json`, release tag `vX.Y.Z` | semver | every release of the implementation |

### Protocol version to package version

`v` is a property of the wire format, not of the code that speaks it. One package
version supports exactly the set of protocol versions it implements, and v1 has no
downgrade negotiation: an implementation rejects every `v` it does not know (spec 11.2).

- A package release states its protocol versions in its CHANGELOG section, as
  `Protocol version: 1`. The release gate (`scripts/release-gate.sh`) refuses a release
  whose CHANGELOG section does not state it, so the mapping can never be missing.
- Adding support for a new `v` is a **minor** package release (new capability, old peers
  keep working).
- Dropping support for a `v` is a **major** package release, because peers that only
  speak it stop interoperating.
- An implementation fix that changes no bytes is a patch or minor release and never
  touches `v`.

The authoritative table is kept here and updated in the same commit that adds or drops
support:

| Protocol version `v` | Spec version | Package versions that speak it |
|---|---|---|
| 1 | 0.2 (draft) | 0.1.0 and later |

### Specification version to package version

The spec moves independently and is tagged separately (`spec-v0.2`). A package release
records which spec version it implements in its CHANGELOG section. Until the spec
reaches 1.0, any spec change may be breaking; package releases therefore stay in 0.x.

## Package semver rules

Applies to `xchonnect-core`, `xchonnect-relay`, `xchonnect-gateway`,
`xchonnect-wallet-kit`, `xchonnect-uniffi`, `xchonnect-wasm` and `@maximedogawa/xchonnect`,
which are released together under one version so that a tag identifies one coherent set.

| Change | Bump |
|---|---|
| Breaking Rust or TypeScript API, dropped protocol version, dropped platform | major |
| New API, new protocol version, new optional relay endpoint or configuration | minor |
| Bug fix, dependency bump, documentation, performance | patch |
| Security fix | patch, or minor if the fix had to change an API |

Pre-1.0 (now): minor releases may break APIs, as semver allows for 0.x. The 1.0 release
is cut only after the external audit (TASK-63).

Rust MSRV is pinned in `[workspace.package] rust-version` and the exact toolchain in
`rust-toolchain.toml`. Raising the MSRV is a minor bump and is called out in the
CHANGELOG.

## Changelog policy

`CHANGELOG.md` at the repository root covers the implementation; `docs/spec/CHANGELOG.md`
covers the specification. They are separate because they version separately.

- Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), newest first.
- Every pull request that changes behaviour adds an entry under `## [Unreleased]`, in
  one of `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`.
- A security entry names the threat ID from the spec threat model (T1–T21) and, once
  published, the advisory id.
- Each released section begins with the `Protocol version:` and `Spec version:` lines.
  The release gate checks the protocol line.
- Releasing moves `Unreleased` to `## [X.Y.Z] - YYYY-MM-DD`.

## What a release does with these numbers

1. A maintainer moves the `Unreleased` section to the new version, sets the date, and
   bumps `[workspace.package] version` and `sdk-ts/package.json` to the same value.
2. `scripts/release-gate.sh` refuses the release unless the tag, both package versions
   and the CHANGELOG section agree. See [`release.md`](release.md).
