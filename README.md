# Xchonnect

Push-native, privacy-preserving signing relay protocol for Chia dApps and wallets.

Xchonnect lets a dApp send [CHIP-0002](https://github.com/Chia-Network/chips/blob/main/CHIPs/chip-0002.md)
signing requests to a mobile wallet and receive signatures back without persistent
connections, without custody, and without the relay learning message contents, Chia
addresses, or (with Oblivious HTTP) client IP addresses.

- Specification: [`docs/spec/xchonnect-spec.md`](docs/spec/xchonnect-spec.md)

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
| `conformance` | `xchonnect-conformance` | Black-box test suites for relays and wallets. |
| `examples/` | | Minimal web dApp and CLI wallet. |
| `docs/` | | Specification (normative), CHIP draft, design notes. |

**Scope.** This repository contains only the open protocol and its reference
implementation. Product code (the Klimper wallet apps, the Pengui dApp, relayxch
billing, tiers and webhooks, production infrastructure) lives elsewhere.

## Building and testing

Requirements: Rust (version pinned in `rust-toolchain.toml`, installed automatically by
rustup) and Node.js ≥ 22 (see `.nvmrc`).

```sh
cargo build --workspace          # all Rust crates
cargo test --workspace           # Rust tests
cargo clippy --workspace -- -D warnings
npm install                      # TypeScript workspace (sdk-ts, examples)
npm run typecheck && npm test
```

## Licensing

| What | License |
|---|---|
| Source code (all crates and packages) | [Apache-2.0](LICENSE) |
| Specification and documents under `docs/` | [CC0 1.0](docs/LICENSE) (public domain dedication) |

Package manifests use the SPDX identifier `Apache-2.0`. Contributions are accepted
under the same terms; see [CONTRIBUTING.md](CONTRIBUTING.md).
