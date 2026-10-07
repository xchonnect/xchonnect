# @xchonnect/dapp

> [!WARNING]
> **Pre-audit pre-release: testnet only, no real funds.** Xchonnect has not had an
> external security audit. Do not use any 0.x release to move, sign for or protect mainnet
> funds. Report vulnerabilities privately:
> [SECURITY.md](https://github.com/xchonnect/xchonnect/blob/main/SECURITY.md).

TypeScript dApp SDK for [Xchonnect](https://github.com/xchonnect/xchonnect): pair with
a mobile Chia wallet by QR or deep link, then send [CHIP-0002](https://github.com/Chia-Network/chips/blob/main/CHIPs/chip-0002.md)
signing requests to it — with no persistent connection, so a request still arrives when
the wallet app is closed.

The protocol core is Rust compiled to WebAssembly; this package is the thin layer around
it. All cryptography happens in the browser: the relay sees only padded ciphertext.

```sh
npm install @xchonnect/dapp@next     # pre-releases are on the `next` tag; pin an exact version in production
```

```ts
import { XchonnectClient, createChip0002Provider } from "@xchonnect/dapp";

// Loads the WASM core, then restores any stored session.
const client = await XchonnectClient.create({
  relay: "https://relay.example.org",
  domain: "dapp.example",                      // as published in /.well-known/xchonnect.json
  kid: "k1",
  sign: (sigInput) => signOnYourBackend(sigInput),   // the origin key never reaches the browser
});

const pairing = await client.pair();          // show pairing.uri as a QR / link
const { sas } = await pairing.waitForWallet(); // 6 digits; the user confirms they match
await pairing.confirm();                       // only after the user says they match

const provider = createChip0002Provider(client);   // window.chia-style provider
const keys = await provider.request<string[]>({ method: "getPublicKeys" });
```

- `XchonnectClient` — pair, request, delivery state, rotate, end
- `client.permissions` / `client.canRequest(method)` — the scopes the wallet declared for
  the session: allowed methods, exposed keys and spending limits (spec 9.3), so the UI can
  show what is on offer without sending a request to find out. **A hint for the UI, never
  an authorisation decision:** the wallet holds the permissions and the wallet enforces
  them, this is only a copy of what it said, and it may refuse something it declared — so
  keep handling refusals on every request
- `createChip0002Provider` — the CHIP-0002 method set over an established session
- `createSignClientShim` — the `@walletconnect/sign-client` call shape (`connect`,
  `approval`, `request`, `disconnect`), so migrating is a dependency swap plus a SAS
  screen. Deliberately not a silent drop-in: the SAS callback is required and unsupported
  parts of the API throw
  ([comparison guide](https://github.com/xchonnect/xchonnect/blob/main/docs/guides/walletconnect-comparison.md#the-sign-client-shim))
- `OhttpTransport` — Oblivious HTTP, so the relay never sees the browser's IP
- `IndexedDbSessionStore` — session persistence per spec 12.1 (never `localStorage`)
- `requestPartialSignature`, `aggregateSignatures`, `pushSpendBundle` — multi-party spends
- `@xchonnect/dapp/testing` — `FakeWallet` (a wallet that answers with the answers you
  give it) and `MockRelay` (the relay API in memory), so your tests pair and send requests
  with no wallet app and no server. Not for production, not under semantic versioning.
  The [quickstart](https://github.com/xchonnect/xchonnect/blob/main/docs/guides/dapp-quickstart.md)
  starts with them

Requires Node.js ≥ 22 or a browser with `WebAssembly.instantiateStreaming`. The module
needs `script-src 'wasm-unsafe-eval'` in a Content-Security-Policy, never `unsafe-eval`.

Guides: [dApp quickstart](https://github.com/xchonnect/xchonnect/blob/main/docs/guides/dapp-quickstart.md),
[wallet integration](https://github.com/xchonnect/xchonnect/blob/main/docs/wallet-integration.md),
[specification](https://github.com/xchonnect/xchonnect/blob/main/docs/spec/xchonnect-spec.md).

## Licence and security

Apache-2.0 (`LICENSE` in this package).

Report vulnerabilities privately — **not** as a public issue — per
[`SECURITY.md`](https://github.com/xchonnect/xchonnect/blob/main/SECURITY.md).
Pre-audit software: do not use a pre-1.0 release to protect mainnet funds without your own
review. Session secrets live in the page, so an XSS on the dApp origin is a real risk
(spec 12.1).
