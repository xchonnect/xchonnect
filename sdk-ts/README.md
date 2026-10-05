# @xchonnect/dapp

TypeScript dApp SDK for [Xchonnect](https://github.com/maximedogawa/xchonnect): pair with
a mobile Chia wallet by QR or deep link, then send [CHIP-0002](https://github.com/Chia-Network/chips/blob/main/CHIPs/chip-0002.md)
signing requests to it — with no persistent connection, so a request still arrives when
the wallet app is closed.

The protocol core is Rust compiled to WebAssembly; this package is the thin layer around
it. All cryptography happens in the browser: the relay sees only padded ciphertext.

```sh
npm install @xchonnect/dapp
```

```ts
import { initXchonnect, XchonnectClient } from "@xchonnect/dapp";

await initXchonnect();                       // loads the WASM core
const client = new XchonnectClient({ relayUrl: "https://relay.example" });

const pairing = await client.pair();          // show pairing.uri as a QR / link
console.log(pairing.sas);                     // 6 digits; the user confirms they match
await pairing.waitForSession();

const provider = client.chip0002();           // window.chia-style provider
const keys = await provider.request({ method: "getPublicKeys" });
```

- `XchonnectClient` — pair, request, delivery state, rotate, end
- `createChip0002Provider` — the CHIP-0002 method set over an established session
- `OhttpTransport` — Oblivious HTTP, so the relay never sees the browser's IP
- `IndexedDbSessionStore` — session persistence per spec 12.1 (never `localStorage`)
- `requestPartialSignature`, `aggregateSignatures`, `pushSpendBundle` — multi-party spends

Requires Node.js ≥ 22 or a browser with `WebAssembly.instantiateStreaming`. The module
needs `script-src 'wasm-unsafe-eval'` in a Content-Security-Policy, never `unsafe-eval`.

Guides: [wallet integration](https://github.com/maximedogawa/xchonnect/blob/main/docs/wallet-integration.md),
[specification](https://github.com/maximedogawa/xchonnect/blob/main/docs/spec/xchonnect-spec.md).

## Licence and security

Apache-2.0 (`LICENSE` in this package).

Report vulnerabilities privately — **not** as a public issue — per
[`SECURITY.md`](https://github.com/maximedogawa/xchonnect/blob/main/SECURITY.md).
Pre-audit software: do not use a pre-1.0 release to protect mainnet funds without your own
review. Session secrets live in the page, so an XSS on the dApp origin is a real risk
(spec 12.1).
