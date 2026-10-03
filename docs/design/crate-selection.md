# Crate selection (TASK-13 spike, 2026-10-04)

A throwaway crate (`docs/design/spike/`, Cargo manifest stored as `Cargo.toml.txt` so it
is not part of the workspace) exercised every primitive the core needs.

## Results

| Check | Native (aarch64-apple-darwin) | wasm32-unknown-unknown (Node 26) | aarch64-apple-ios / -sim | aarch64-linux-android |
|---|---|---|---|---|
| CSPRNG (`getrandom` 0.4) | ok | ok (`wasm_js` feature, no extra cfg needed) | builds | `cargo check` ok |
| X25519 (`x25519-dalek` 3.0) | ok | ok | builds | check ok |
| HPKE PSK seal/open/export (`hpke` 0.14) | ok | ok | builds | check ok |
| XChaCha20-Poly1305 (`chacha20poly1305` 0.11) | ok | ok | builds | check ok |
| Ed25519 strict verify (`ed25519-dalek` 3.0) | ok | ok | builds | check ok |
| HKDF/SHA-256 (`hkdf` 0.13, `sha2` 0.11) | ok | ok | builds | check ok |
| OHTTP encapsulate/decapsulate (`ohttp` 0.8, `rust-hpke` backend) | ok | ok | builds | check ok |

Android was only type-checked: linking needs the NDK, which CI must install (TASK-15).
Rust 1.98.1; wasm run via `wasm-bindgen-cli` 0.2.129 (`--target nodejs`).

**WASM size** (release, all of the above including OHTTP): 561 KB raw, 177 KB gzip. `ohttp`
enables `hpke`'s AES-GCM, P-256/384/521 and ML-KEM features, which dominates the size; the
dApp bundle should keep OHTTP behind a cargo feature and enable `wasm-opt` (budget set in
TASK-32).

## Selection

| Purpose | Crate | Licence | Notes |
|---|---|---|---|
| X25519 | `x25519-dalek` 3.0 | BSD-3-Clause | dalek-cryptography; curve25519-dalek audited (Quarkslab 2019) — re-confirm audit coverage for 3.x before the external audit |
| Ed25519 | `ed25519-dalek` 3.0 | BSD-3-Clause | use `verify_strict` only |
| HPKE | `hpke` 0.14 (rozbb) | MIT/Apache-2.0 | RFC 9180 KATs in crate; deterministic `setup_sender_with_rng` enables test vectors. No public third-party audit known — flagged for the external audit. Alternative: `hpke-rs` (Cryspen, used by OpenMLS) |
| AEAD | `chacha20poly1305` 0.11 (`XChaCha20Poly1305`) | MIT/Apache-2.0 | RustCrypto; earlier versions audited (NCC Group 2020) |
| KDF / hash | `hkdf` 0.13, `sha2` 0.11 | MIT/Apache-2.0 | RustCrypto |
| CSPRNG | `getrandom` 0.4 | MIT/Apache-2.0 | `wasm_js` feature on wasm32 |
| OHTTP | `ohttp` 0.8 + `bhttp` 0.8 | MIT/Apache-2.0 | Mozilla (used in Firefox with NSS); we use the pure-Rust `rust-hpke` backend |
| Zeroization | `zeroize` 1 | MIT/Apache-2.0 | |
| CBOR | **in-house codec** in `xchonnect-core` | Apache-2.0 | see below |

### CBOR: in-house strict codec instead of `minicbor`/`ciborium`

The spec's canonical profile (5.4) needs a decoder that *rejects* every non-canonical
input (non-shortest integers, indefinite lengths, unsorted or duplicate map keys, tags,
floats, trailing bytes). Neither `minicbor` (BlueOak-1.0.0) nor `ciborium` enforces this on
decode, so we would need a second validation pass anyway. The profile only allows seven
data types, so a dedicated codec of a few hundred lines with no dependencies is smaller
to audit than a general library plus a validator, and is fuzzed directly (TASK-25).

## No blockers

All targets work with pure-Rust crates; no C dependencies are required.
