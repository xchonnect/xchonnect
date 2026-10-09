# xchonnect-core

> [!WARNING]
> **Pre-audit pre-release: testnet only, no real funds.** Xchonnect has not had an
> external security audit. Do not use any 0.x release to move, sign for or protect mainnet
> funds. Report vulnerabilities privately:
> [SECURITY.md](https://github.com/xchonnect/xchonnect/blob/main/SECURITY.md).

The Xchonnect protocol core: canonical CBOR, sealed envelopes, the pairing handshake and
session state machine, pairing URIs and origin documents — everything that decides bytes
on the wire. No Chia dependency, no `unsafe`, no I/O: the caller does the networking and
passes the clock in, which is what makes the crate testable and portable to WebAssembly
and mobile.

Normative behaviour is the specification, not this implementation:
[`docs/spec/xchonnect-spec.md`](https://github.com/xchonnect/xchonnect/blob/main/docs/spec/xchonnect-spec.md).

```toml
[dependencies]
xchonnect-core = "=0.1.0-rc.4"
```

Pre-releases need the exact requirement: Cargo never selects a pre-release for a plain one
such as `"0.1"`, and release candidates may break each other's API.

## What is in here

| Module | Purpose |
|---|---|
| `cbor` | the canonical CBOR profile (spec 5.4): one encoding per value, total parser |
| `envelope` | outer envelope seal/open with padding buckets (spec 5) |
| `pairing` | HPKE PSK handshake, transcript-bound key schedule, SAS (spec 6) |
| `session` | session state, `seq` replay protection, rotation, persistence (spec 9) |
| `message` / `rpc` | inner message types and CHIP-0002 request correlation |
| `uri` | pairing URI grammar and the byte-exact signature input (spec 6.1) |
| `origin` | `/.well-known/xchonnect.json` parsing and key lookup |
| `push` | sealed push tokens the relay cannot read (spec 7.3.2) |
| `pow` | stateless proof of work for keyless mailbox creation (spec 7.4) |
| `ohttp` | optional Oblivious HTTP client (spec 10), feature `ohttp` |

Features: `idna` (default, IDN display for wallets), `ohttp`, and `test-vectors`
(deterministic entropy for generating published vectors — never enable in production).

## Guarantees this crate is built to keep

- Keys are typed and zeroizing; secret comparisons are constant time.
- Parsers are total: no panic on attacker-controlled input, every bound enforced.
- `unsafe_code = "forbid"` at the crate level.

## Licence and security

Apache-2.0 ([`LICENSE`](https://github.com/xchonnect/xchonnect/blob/main/LICENSE)).
The specification is CC0.

Report vulnerabilities privately — **not** as a public issue — per
[`SECURITY.md`](https://github.com/xchonnect/xchonnect/blob/main/SECURITY.md).
This crate is pre-audit: do not use a pre-1.0 release to protect mainnet funds without
your own review.
