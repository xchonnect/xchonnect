# xchonnect-wallet-kit

> [!WARNING]
> **Pre-audit pre-release: testnet only, no real funds.** Xchonnect has not had an
> external security audit. Do not use any 0.x release to move, sign for or protect mainnet
> funds. Report vulnerabilities privately:
> [SECURITY.md](https://github.com/maximedogawa/xchonnect/blob/main/SECURITY.md).

Wallet-side signing safety for Xchonnect wallets on Chia (spec Section 11).

A wallet must never trust what a dApp claims a spend does. This crate runs every
requested spend locally with the same CLVM interpreter the chain uses and derives what
actually happens to the user's assets, which signatures the request would produce and
whether they are allowed, and whether it fits the permissions and spending limits granted
to that dApp. Keys never enter this crate: signing goes through a host-provided signer.

```toml
[dependencies]
xchonnect-wallet-kit = "0.1"
```

| Module | What it decides |
|---|---|
| `simulate` | the net effect on the user's assets, plus what is only conditional |
| `policy` | which signatures would be produced, network match, `AGG_SIG_UNSAFE` and infinity-key refusals |
| `binding` | whether a partial multi-party spend is actually bound to the counterparty's side (spec 11.2) |
| `permissions` | per-dApp permissions and daily spending limits |
| `handlers` | CHIP-0002 request handling over a pluggable signer and approval callback |

The refusals are the point: a spend that cannot be shown to the user, or a partial
signature that is not bound, is not signed.

Wallet integration guide:
[`docs/wallet-integration.md`](https://github.com/maximedogawa/xchonnect/blob/main/docs/wallet-integration.md).
For Swift and Kotlin wallets the same logic is exposed through `xchonnect-uniffi`.

## Licence and security

Apache-2.0 ([`LICENSE`](https://github.com/maximedogawa/xchonnect/blob/main/LICENSE)).

Report vulnerabilities privately — **not** as a public issue — per
[`SECURITY.md`](https://github.com/maximedogawa/xchonnect/blob/main/SECURITY.md).
This crate is pre-audit; the binding checks in particular are an audit priority (threat
T2). Do not ship it to users holding mainnet funds without your own review.
