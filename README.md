# Xchonnect

Push-native, privacy-preserving signing relay protocol for Chia dApps and wallets.

Xchonnect lets a dApp send [CHIP-0002](https://github.com/Chia-Network/chips/blob/main/CHIPs/chip-0002.md)
signing requests to a mobile wallet and receive signatures back without persistent
connections, without custody, and without the relay learning message contents, Chia
addresses, or (with Oblivious HTTP) client IP addresses.

> [!WARNING]
> **Pre-audit pre-release: testnet only, no real funds.** No external security audit has
> been completed. Do not use any 0.x release to move, sign for or protect mainnet funds.
> Read [known limitations](docs/guides/security-and-privacy.md#known-limitations) before
> you depend on this, and report vulnerabilities privately per [SECURITY.md](SECURITY.md).

## Start here

| You are | Read this | Then |
|---|---|---|
| A **dApp** developer | [dApp quickstart](docs/guides/dapp-quickstart.md) — a first pairing from npm, origin key, pairing, CHIP-0002 requests, OHTTP | [`examples/dapp-web/`](examples/dapp-web) |
| A **wallet** developer | [Wallet integration guide](docs/wallet-integration.md) — pairing and SAS, keychain storage, push gateway, safe request handling | [`bindings/uniffi/README.md`](bindings/uniffi/README.md) |
| A **relay operator** | [Operating a relay](docs/operating.md) — deploy, hardening defaults, OHTTP, retention, conformance | [`deploy/`](deploy/README.md) — Compose files and the release images |
| Coming from **WalletConnect** | [Comparison and migration](docs/guides/walletconnect-comparison.md) | — |
| Evaluating the **security model** | [Security and privacy](docs/guides/security-and-privacy.md) — guarantees, data inventory, honest limitations | [`docs/spec/xchonnect-spec.md`](docs/spec/xchonnect-spec.md) §13–14 |

Other references:

- Specification (normative): [`docs/spec/xchonnect-spec.md`](docs/spec/xchonnect-spec.md)
- Generated API references: [`docs/guides/api-reference.md`](docs/guides/api-reference.md)
- CHIP draft: [`docs/chip/chip-xchonnect.md`](docs/chip/chip-xchonnect.md)
- Reporting a vulnerability: [SECURITY.md](SECURITY.md);
  runbooks: [`docs/guides/incident-response.md`](docs/guides/incident-response.md)
- What the relay and the gateway may store, log and count, machine-checked:
  [`docs/privacy/data-inventory.md`](docs/privacy/data-inventory.md)
- Releases: [`CHANGELOG.md`](CHANGELOG.md), [`docs/release.md`](docs/release.md)
  (including [verifying a release as a third party](docs/release.md#verifying-a-release-as-a-third-party)),
  [`docs/versioning.md`](docs/versioning.md)
- Conformance suites: [`conformance/README.md`](conformance/README.md); fuzzing and
  coverage: [`docs/fuzzing.md`](docs/fuzzing.md)

## Repository layout

| Path | Crate / package | Purpose |
|---|---|---|
| `crates/core` | `xchonnect-core` | Protocol core: canonical CBOR, envelopes, pairing, sessions. No Chia dependency, no `unsafe`. |
| `crates/relay` | `xchonnect-relay` | Reference relay (mailboxes, TTL, rate limits, push dispatch, OHTTP gateway). |
| `crates/gateway` | `xchonnect-gateway` | Reference push gateway (APNs, FCM). |
| `crates/wallet-kit` | `xchonnect-wallet-kit` | Optional wallet-side signing safety on `chia-wallet-sdk` (simulation, policy, binding checks). |
| `bindings/wasm` | `xchonnect-wasm` | WASM build of the core for browsers and Node. |
| `bindings/uniffi` | `xchonnect-uniffi` | Swift and Kotlin bindings for wallets. |
| `sdk-ts` | `@xchonnect/dapp` | TypeScript dApp SDK with CHIP-0002 adapter. |
| `conformance` | `xchonnect-conformance` | Black-box conformance suites for relays and wallets. |
| `examples/` | | Minimal web dApp and CLI wallet; `push-probe`, the kit for a real-device push run. |
| `privacy/` | `xchonnect-privacy-check` | Live check of relay and gateway against the data inventory (`scripts/privacy-scan.sh`). |
| `fuzz/` | | Fuzz targets for every parser and its seed corpus (`docs/fuzzing.md`). |
| `docs/` | | Specification (normative), guides, CHIP draft, design notes. |

**Scope.** This repository contains only the open protocol and its reference
implementation. Product code (the Klimper wallet apps, the Pengui dApp, relayxch
billing, tiers and webhooks, production infrastructure) lives elsewhere.

## Building and testing

Requirements: Rust (version pinned in `rust-toolchain.toml`, installed automatically by
rustup), Node.js ≥ 22 (see `.nvmrc`), and `wasm-bindgen-cli` at the version pinned in
`bindings/wasm/Cargo.toml` for the TypeScript side.

```sh
cargo build --workspace                  # all Rust crates
cargo test --workspace --locked          # Rust tests
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
./scripts/relay-conformance.sh           # black-box suite against the reference relay
```

The TypeScript workspace needs the WASM core built first — `@xchonnect/dapp` imports it,
so `npm test` fails without it:

```sh
cargo install wasm-bindgen-cli --version 0.2.129 --locked
./scripts/build-wasm.sh                  # -> sdk-ts/wasm/
npm ci --ignore-scripts                  # TypeScript workspace (sdk-ts, examples)
npm run typecheck && npm test
```

To run the whole stack locally (relay, example dApp, CLI wallet), see the
[dApp quickstart](docs/guides/dapp-quickstart.md). To generate API references for any
language surface, see [`docs/guides/api-reference.md`](docs/guides/api-reference.md).

## Licensing

| What | License |
|---|---|
| Source code (all crates and packages) | [Apache-2.0](LICENSE) |
| Specification and documents under `docs/` | [CC0 1.0](docs/LICENSE) (public domain dedication) |

Package manifests use the SPDX identifier `Apache-2.0`. Contributions are accepted
under the same terms; see [CONTRIBUTING.md](CONTRIBUTING.md).
