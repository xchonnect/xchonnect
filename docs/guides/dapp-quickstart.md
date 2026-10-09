# dApp quickstart

This guide takes a dApp from nothing to a signed `signCoinSpends` over Xchonnect, using
[`@xchonnect/dapp`](../../sdk-ts). It assumes you already speak
[CHIP-0002](https://github.com/Chia-Network/chips/blob/main/CHIPs/chip-0002.md); Xchonnect
only replaces the transport.

Normative behaviour is in the [specification](../spec/xchonnect-spec.md) (Sections 6, 9,
10, 12). Wallet-side duties are in the [wallet integration guide](../wallet-integration.md);
relay-side duties in [operating a relay](../operating.md).

## 1. A first pairing from npm (5 minutes)

Requirements: Node.js ≥ 22 and Docker. No Rust, no clone of this repository.

```sh
mkdir xchonnect-quickstart && cd xchonnect-quickstart
npm init -y >/dev/null && npm install @xchonnect/dapp@next
```

Start a relay from the release image. It keeps everything in memory, makes a throwaway
OHTTP key on each start and asks for a cheap proof-of-work; none of that is a production
setting (see [operating a relay](../operating.md) for those):

```sh
docker run --rm -p 127.0.0.1:8787:80 \
  -e XCHONNECT_OHTTP=ephemeral -e XCHONNECT_POW_DIFFICULTY=12 \
  ghcr.io/xchonnect/xchonnect-relay:0.1.0-rc.3
curl http://127.0.0.1:8787/healthz     # ok
```

There is no wallet app to install: the package ships the wallet the SDK's own tests use,
under `@xchonnect/dapp/testing`. It runs the real protocol against the real relay, holds
no keys, and answers requests with the answers you give it. Put this in
`quickstart.mjs`:

```js
import { readFileSync } from "node:fs";
import { generateKeyPairSync, sign } from "node:crypto";
import { XchonnectClient, MemorySessionStore } from "@xchonnect/dapp";
import { FakeWallet } from "@xchonnect/dapp/testing";

const RELAY = "http://127.0.0.1:8787";
const DOMAIN = "localhost:5173"; // developer mode: a localhost domain, a plain-http relay

// The origin key. In production it lives in a KMS and the browser never sees it (step 2).
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const pk = publicKey.export({ type: "spki", format: "der" }).subarray(-32).toString("base64url");
const originDocument = JSON.stringify({
  v: 1,
  name: "Quickstart dApp",
  origin_keys: [{ kid: "k1", pk, not_after: "2030-01-01" }],
});

// The dApp.
const client = await XchonnectClient.create({
  relay: RELAY,
  domain: DOMAIN,
  kid: "k1",
  sign: async (sigInput) => sign(null, Buffer.from(sigInput, "base64url"), privateKey).toString("base64url"),
  developerMode: true,
  storage: new MemorySessionStore(),
  wasm: readFileSync(new URL(import.meta.resolve("@xchonnect/dapp/xchonnect_bg.wasm"))),
});

// The wallet: answers chainId, refuses everything else.
const wallet = new FakeWallet({
  relay: RELAY,
  originDocument,
  name: "Quickstart wallet",
  handle: (method) => {
    if (method === "chainId") return JSON.stringify("0x01");
    throw { code: 4001, message: `not allowed: ${method}` };
  },
});

// Pair: the dApp shows the URI, the wallet scans it, both show the SAS, both confirm.
const pairing = await client.pair();
await wallet.scan(pairing.uri);
const { sas, walletName } = await pairing.waitForWallet();
console.log(`dApp shows ${sas}; ${walletName} shows ${wallet.sas}`);
await wallet.confirm();
await pairing.confirm();
console.log(`session ${client.status}`);

// Request: the wallet answers in the background while the dApp waits.
const stop = wallet.run();
console.log("chainId:", await client.request("chainId"));
await client.request("signCoinSpends", { coinSpends: [] }).catch((e) => console.log("refused:", e.code, e.message));
stop();
await client.end();
```

```sh
node quickstart.mjs
```

```text
dApp shows 517 099; Quickstart wallet shows 517 099
session active
chainId: 0x01
refused: 4001 not allowed: signCoinSpends
```

What happened is the whole protocol: the wallet verified the pairing URI against the
origin document, created its own mailbox with a proof-of-work, both sides derived the
same six digits, the session became active only after both confirmed, and every
request and answer crossed the relay as padded ciphertext. The next sections take each
line of the script to production.

Two things in the script are development only and the SDK rejects them otherwise:
`developerMode` (it allows the plain-`http` loopback relay and the `localhost:<port>`
domain) and a private key in the same process as the client. `wasm` is needed in Node,
where the module cannot fetch its own `.wasm` file; in a browser or a bundler leave it out.

**In your tests**, replace the container with `MockRelay` from the same entry point: the
relay HTTP API in memory, as a `fetch` function. Pass `fetch: mock.fetch` to
`XchonnectClient.create` and `relay: new RelayClient(RELAY, { fetch: mock.fetch })` to the
wallet, and the script above runs with no server at all, in a few milliseconds. The
`testing` entry point is not covered by semantic versioning; it follows the SDK's tests.

### Or: the browser dApp and the CLI wallet from the repository

To see the same flow with a QR code in a browser and a wallet that prompts on the
command line, build it from a clone. Requirements: Rust (version pinned in
`rust-toolchain.toml`), Node.js ≥ 22 (`.nvmrc`), and `wasm-bindgen-cli` at the version
pinned in `bindings/wasm/Cargo.toml`:

```sh
cargo install wasm-bindgen-cli --version 0.2.129 --locked
./scripts/dev.sh
```

This builds the WASM core and the SDK, starts the reference relay on
`http://127.0.0.1:8787` with an ephemeral OHTTP key, and serves the example dApp on
<http://localhost:5173>. Click **Connect wallet**, then pair the CLI wallet with the URI
shown on the page:

```sh
./target/debug/xchonnect-wallet-cli pair '<URI from the page>' --dev
```

Compare the six-digit codes on both sides and confirm on both. The buttons on the page now
send real CHIP-0002 requests. See [`examples/README.md`](../../examples/README.md) for
`--dev-key`, which makes the CLI wallet produce real BLS signatures on testnet.

## 2. Publish your origin key

A wallet only pairs with a domain whose origin key signed the pairing URI
(spec 6.1). Publish an Ed25519 public key at
`https://<your-domain>/.well-known/xchonnect.json`:

```json
{
  "v": 1,
  "name": "Your dApp",
  "origin_keys": [
    { "kid": "2026-10", "pk": "<base64url Ed25519 public key>", "not_after": "2027-10-01" }
  ],
  "icon": "https://<your-domain>/icon.png"
}
```

The JSON Schema and the fetch rules wallets apply (HTTPS, exact domain, no redirects,
≤ 16 KiB, 10 s timeout) are in
[`docs/spec/wire/xchonnect.schema.json`](../spec/wire/xchonnect.schema.json). Rules you must
follow (spec 12):

- **The private key never reaches the browser.** Keep it in an HSM or cloud KMS; the
  frontend asks a backend endpoint for one signature per pairing.
- Rotate yearly with overlapping `kid`s and a `not_after` date. Remove a compromised key
  immediately — wallets re-fetch the document on every pairing, so removal revokes it.
- Serve the document with permissive CORS; wallets fetch it, and so does the SDK when you
  pass `originPublicKey`.

[`examples/dapp-web/vite.config.ts`](../../examples/dapp-web/vite.config.ts) is a complete
(development-only) backend: it publishes the document and exposes `POST /api/sign`.

## 3. Create the client

```ts
import { XchonnectClient } from "@xchonnect/dapp";

const client = await XchonnectClient.create({
  relay: "https://relay.example.org",
  domain: "your-dapp.example",            // must match the published document exactly
  kid: "2026-10",
  // Sign `uri_sig_input` with the origin key — a call to your backend, never a local key.
  sign: async (sigInput) => {
    const res = await fetch("/api/sign", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ sigInput }),
    });
    return ((await res.json()) as { signature: string }).signature;
  },
  // Hide the user's IP from the relay (spec 10). See step 6.
  ohttp: {
    relayUrl: "https://ohttp-relay.example/",
    keyConfig: "<base64url of the relay's /.well-known/ohttp-keys>",
  },
});
```

Everything else in [`ClientOptions`](../../sdk-ts/src/client.ts) is optional:
`originPublicKey` (verify your backend's signature before showing a QR), `apiKey`
(publishable relay API key), `storage` / `storageKey`, `poll`, `pairingLifetimeSeconds`
(≤ 300), `openUrl`, `now`, `fetch`, `wasm`, and `developerMode` — development only.

Session state is stored in IndexedDB, encrypted under a non-extractable WebCrypto key, and
shared across tabs with a Web Lock (spec 12.1). `XchonnectClient.create` restores a stored
session, so a page reload resumes an active session; check `client.status`
(`unpaired | pairing | awaiting-sas | active | ended`).

## 4. Pair

```ts
const pairing = await client.pair();

// Show pairing.uri as a QR code (desktop) and count down pairing.expiresAt.
// On a phone, pairing.openInWallet("https://wallet.example/pair") opens the wallet app.

const { sas, walletName } = await pairing.waitForWallet();
// Show `sas` as two groups of three digits and ask the user:
//   "Does <walletName> show 042 917?"  →  pairing.confirm()
//   "No"                               →  pairing.reject()
await pairing.confirm();                 // resolves when the session is active
```

Rules the SDK enforces for you, and which your UI must not undermine (spec 6.3):

- The pairing URI lives at most 5 minutes and is single-use: the first valid wallet reply
  wins and the pairing mailbox is deleted immediately.
- **You must ask the user to compare the SAS.** The session is not active until the user
  confirmed *and* `session.ready` arrived. Never auto-confirm, and never offer a way to
  skip the comparison — it is the only defence against a relayed pairing code.
- Show the QR only inside an authenticated page, to one logged-in user. Anyone who
  photographs it within its lifetime can pair in the user's place.
- On "codes do not match", `pairing.reject()` ends the session and deletes local state.

## 5. Send CHIP-0002 requests

```ts
const chainId = await client.request<string>("chainId");
const keys = await client.request<string[]>("getPublicKeys", { limit: 1 });

const signature = await client.request<string>("signCoinSpends", {
  coinSpends,            // CHIP-0002 CoinSpend[], snake_case fields, hex bytes
  partialSign: false,
});
```

- `request()` parses the JSON result. Use `requestRaw(method, paramsJson)` when a value
  exceeds 2^53 − 1 (mojo amounts) and must stay byte-exact.
- Errors arrive as `XchonnectRpcError` with the CHIP-0002 code (`4001` unauthorized/policy,
  `4002` user rejected, `4005` key not held, `4029` limit, `4100` request expired,
  `4101` undecodable spend). Relay transport failures are `RelayError`.
- Default request TTL is 600 s; pass `ttlSeconds` and an `AbortSignal` in
  [`RequestOptions`](../../sdk-ts/src/client.ts).
- `client.on("delivery", e => …)` reports `queued → delivered → completed | failed |
  expired` per request, so you can show "waiting for the wallet" honestly instead of a
  spinner that never resolves.
- For an existing CHIP-0002 integration, `createChip0002Provider(client)` wraps the client
  in the familiar provider shape — see the
  [WalletConnect comparison](walletconnect-comparison.md).
- Multi-party flows (`requestPartialSignature`, `aggregateSignatures`, `pushSpendBundle`)
  are in [`sdk-ts/src/multiparty.ts`](../../sdk-ts/src/multiparty.ts). Every party's spend
  must be **bound** to the payment it expects or wallets refuse it (`4001`,
  `unbound_partial`; spec 11.2).

Phones freeze a page while the user is in the wallet app, often with a long poll in
flight. The client gives every relay call a deadline (a long poll its wait plus 10 s, any
other call 15 s; `timeouts` in `ClientOptions`), and on `visibilitychange`, `pageshow`,
`focus` and `online` it aborts the poll in flight and polls again at once; call
`client.resume()` yourself where a native shell has its own resume event. In a browser it
keeps one long poll open while the page is visible, also with nothing pending, so a
`session.end` (`client.on("ended", …)`) or new permissions (`client.on("permissions",
…)`) arrive within seconds; `keepAlive: false` turns that off. Call `client.rotate()` at
least every 7 days of use (spec 12.1) and `client.end()` on logout, which sends
`session.end` and deletes the stored state. `client.close()` stops polling and detaches
listeners without ending the session.

## 6. OHTTP: do not let the relay see your users' IPs

Without OHTTP, the relay host and any TLS-terminating edge in front of it see every user's
IP address, the mailbox ids in the URLs and the request timing (spec 10.3). The relay
software stores none of it, but the network layer sees it.

With `ohttp` configured, each relay request is encrypted to the relay's gateway key and
sent through an **independent** OHTTP relay: that relay sees IPs but not content, and the
Xchonnect relay sees content metadata but not IPs. Ship the relay operator's published key
configuration with your app; the SDK pins it and learns rotations through the gateway
itself.

```ts
client.privacy;                                   // "ohttp" | "direct"
client.on("privacy", (e) => showBadge(e.state));  // "ohttp-failed" | "ohttp-restored"
client.on("ohttpKeyRotated", (keyId) => log(keyId));
```

**Surface `client.privacy` in your UI.** It is `"direct"` whenever no OHTTP is configured
or the opt-in fallback is active, and that is exactly when the relay sees the user's IP.
`allowDirectFallback` is **off by default**, so a failing OHTTP relay fails the request
rather than silently downgrading privacy; turn it on only if you show the state. A key
configuration mismatch (`OhttpKeyError`) never falls back.

Through OHTTP there is normally no long-poll (`max_wait_ohttp_s` defaults to 0), so the SDK
polls on the spec 10.1 schedule — every 2 s for 30 s after sending, then every 10 s, with
jitter, only while the page is visible. Responses can therefore be delayed by up to the
poll interval. See the [limitations](security-and-privacy.md#known-limitations).

## 7. Before you go live

- Strict CSP on signing pages, Subresource Integrity, no third-party scripts. The WASM
  core needs `script-src 'wasm-unsafe-eval'` and no `unsafe-eval`; a recommended policy is
  in [`bindings/wasm/README.md`](../../bindings/wasm/README.md).
- Never log or send wallet public keys to analytics.
- Never request `AGG_SIG_UNSAFE`; wallets refuse it by default.
- Build multi-party bundles with binding (spec 11.2).
- Read the [security and privacy page](security-and-privacy.md), including what Xchonnect
  does **not** protect against — an XSS on your own origin can use a live session.

## Reference

| What | Where |
|---|---|
| Generated API reference | [`api-reference.md`](api-reference.md) |
| Normative protocol | [`docs/spec/xchonnect-spec.md`](../spec/xchonnect-spec.md) |
| Relay HTTP API | [`docs/spec/wire/relay-api.md`](../spec/wire/relay-api.md) |
| Test vectors | [`docs/spec/vectors/`](../spec/vectors/) |
| Example dApp | [`examples/dapp-web/`](../../examples/dapp-web) |
