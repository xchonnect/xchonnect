# Xchonnect and WalletConnect

Most Chia dApps that already talk to a mobile wallet do so over WalletConnect v2 with
CHIP-0002 methods. This page explains what Xchonnect changes, what it deliberately does
not try to be, and how to run both side by side while you migrate.

Statements about WalletConnect describe its publicly documented v2 architecture as of
2026-10 ([docs.reown.com](https://docs.reown.com/)); check them yourself before quoting
them, and note that we are not a neutral party here.

## The short version

Xchonnect is **not** a competitor to WalletConnect's multi-chain wallet network. It is a
transport tuned for one situation that WalletConnect's architecture handles badly: a Chia
dApp that must reach a wallet app on a phone which is closed, backgrounded or asleep.

If your users sign on a desktop with the wallet in the foreground, WalletConnect works and
there is little to gain. If they sign on a phone, or if relay-visible metadata matters to
you, keep reading.

**The method layer does not change.** Both carry CHIP-0002
(`chainId`, `connect`, `getPublicKeys`, `signCoinSpends`, `signMessage`, …). Migration is a
transport and pairing-UI change, not a semantic one.

## What Xchonnect keeps from WalletConnect

Credit where it is due — the design borrows the parts that work:

- QR and deep-link pairing carrying an out-of-band shared secret.
- Symmetric end-to-end encryption of every payload, with the relay as a dumb pipe that
  holds no keys.
- A JSON-RPC-shaped method layer with per-session permissions.
- Mobile linking: a same-device round trip that returns the user to the dApp.

## What is different

| Area | WalletConnect v2 | Xchonnect |
|---|---|---|
| Transport | Persistent WebSocket to a relay | Store-and-forward mailboxes over plain HTTPS round trips |
| Delivery to a closed app | Requires the wallet to implement the optional push service; otherwise the request waits until the wallet is reopened | Push is part of the protocol: the relay sends a content-free wake-up, the wallet does one HTTPS round trip and sleeps again |
| Push credentials | Central push service | Each wallet vendor runs its own gateway with its own APNs/FCM credentials; the device token is sealed to the gateway's key and never visible to the relay |
| Access to the relay | Project ID from the hosted cloud | No accounts and no project ids. Capability tokens per mailbox: 128-bit ids, 256-bit read/write tokens stored hashed. Anyone can run a relay |
| Metadata at the relay | Topics, timing, client metadata and IP addresses at the network layer | Random, rotating mailboxes; hashed tokens; ciphertext padded to 1/4/16/64/256 KiB buckets; day-granular timestamps; no IP, User-Agent or Chia data stored or logged |
| IP privacy | Not addressed by the protocol | Oblivious HTTP (RFC 9458) through an independent relay, with the key configuration pinned by clients — when the OHTTP path is used ([limitations](security-and-privacy.md#ohttp-only-helps-when-it-is-actually-used)) |
| dApp authenticity | Hosted attestation service | Ed25519 origin key published at `https://<domain>/.well-known/xchonnect.json`, signing the pairing URI, plus a 6-digit SAS both sides must compare. No third party involved |
| Pairing crypto | X25519 with a symmetric key from the URI | HPKE PSK handshake (RFC 9180) with transcript-bound, direction-specific keys, an exported root key, and epoch rotation |
| Wire format | JSON-RPC over JSON | Canonical CBOR with a strict deterministic profile; 256 KiB maximum, sized for spend bundles |
| Replay and ordering | Relay-side message ids | `seq`, `exp` and a random `id` inside the AEAD, so the relay cannot replay or reorder |
| Chain model | CAIP namespaces, chain-agnostic | CHIP-0002 unchanged; Chia only |
| Multi-party spends | Not modelled | `partialSign` with **mandatory** binding verification in the wallet: a user spend that is not bound to the counterparty's settlement payment is refused |
| Reach | Hundreds of wallets, many chains | One reference wallet integration and a CLI test wallet today |

### What WalletConnect does better

- **Ecosystem.** Hundreds of integrated wallets across dozens of chains, mature SDKs,
  modal UIs, analytics and a brand users recognise. Xchonnect has none of that.
- **Multi-chain.** If your dApp is not Chia-only, Xchonnect does not help you.
- **Maturity.** WalletConnect is widely deployed and has been audited repeatedly.
  Xchonnect is pre-1.0 and **has not had an external security audit**
  ([limitations](security-and-privacy.md#the-project-has-not-been-audited)).
- **Instant round trips in the foreground.** A live WebSocket has lower latency than
  polling; through OHTTP, Xchonnect normally has no long-poll at all and a response can be
  delayed by up to one poll interval.

## What the user sees differently

| Moment | WalletConnect | Xchonnect |
|---|---|---|
| Pairing | QR, then a session-proposal dialog listing chains and methods | QR or one tap; the wallet shows the **verified domain** and a 6-digit code to compare; one approval |
| Request arrives while the phone is locked | Usually nothing until the wallet is reopened and reconnects | A generic notification ("New signing request"); tap, see the simulated effect, approve with biometrics |
| Same device, mobile browser | Manual app switching, requests often lost | App-link round trip with an automatic return to the dApp, push as fallback |
| "What am I signing?" | Wallet-dependent | The wallet simulates the spend locally and shows the net effect per asset, computed from conditions, never from dApp labels |
| A multi-party trade | Both parties online at once | Sign your part now; the counterparty signs later; whoever completes submits |
| Connection health | "Session expired", reconnect loops | There is no connection to drop; state is `queued → delivered → completed / failed / expired` |

## Migration overview

### If your dApp already uses CHIP-0002

The method calls stay the same. The adapter in
[`sdk-ts/src/chip0002.ts`](../../sdk-ts/src/chip0002.ts) gives you the familiar
`request({ method, params })` surface over an Xchonnect session:

```ts
import { XchonnectClient, createChip0002Provider } from "@xchonnect/dapp";

const client = await XchonnectClient.create({ /* see the dApp quickstart */ });
const provider = createChip0002Provider(client);

// Existing CHIP-0002 code paths work unchanged:
const sig = await provider.request<string>({ method: "signCoinSpends", params: { coinSpends } });
```

It accepts both bare (`signCoinSpends`) and prefixed (`chip0002_signCoinSpends`) method
names, and maps transport failures onto CHIP-0002 error codes, so a dApp that already
handles `4001`/`4002`/`4005` needs no new error handling. `provider.isXchonnect` lets code
that supports several providers tell them apart.

If you would rather not touch your call sites at all, the sign-client shim below keeps
them; either way the two items at the end of this section are **not optional**.

| WalletConnect concept | Xchonnect equivalent |
|---|---|
| `SignClient.connect()` → URI → `approval()` | `client.pair()` → `pairing.uri` → `pairing.waitForWallet()` → **user compares the SAS** → `pairing.confirm()` |
| Session proposal dialog with namespaces | Nothing to choose: the wallet grants permissions and reports them in `session.permissions` (specification 9.3), a message of its own that follows `session.ready` |
| `session.request({ topic, chainId, request })` | `client.request(method, params)` — no topic, no CAIP chain id; the session is already bound to one network |
| `session_event` / `session_update` subscriptions | `client.on("status" \| "delivery" \| "privacy" \| "ohttpKeyRotated", …)` |
| `SignClient.disconnect()` | `client.end(reason?)` |
| Project ID, cloud dashboard | Relay URL plus, optionally, a publishable relay API key |
| Verify API domain attestation | Your own Ed25519 origin key in `/.well-known/xchonnect.json` |

Two things have no WalletConnect analogue and are **not optional**:

1. **Publishing an origin key** and signing each pairing URI with it from a backend (the
   key must never reach the browser).
2. **The SAS comparison step** in your pairing UI. The session is not active until the
   user has confirmed that the wallet shows the same six digits. Skipping it removes the
   defence against a relayed pairing code.

## The sign-client shim

`XchonnectSignClient` ([`sdk-ts/src/walletconnect.ts`](../../sdk-ts/src/walletconnect.ts))
offers the `@walletconnect/sign-client` call shape — `connect()` → `approval()`, then
`request()`, `disconnect()` and `session.getAll()` — over an Xchonnect session, so your
existing call sites keep working.

**It is not a drop-in replacement, and it is not trying to be.** Two rules shape it:

1. **The SAS screen is mandatory.** `confirmSas` is a *required* option: the shim cannot be
   constructed without it. WalletConnect has no step where the user compares a code, so
   there is nothing to swap it for — this is the pairing-UI change, and it is the one part
   of a migration you cannot skip.
2. **Anything that cannot be honoured throws.** Not a silent no-op, not a quiet
   substitution. A façade that looks like WalletConnect and behaves differently is worse
   than no façade, so the shim fails loudly and names the Xchonnect equivalent in the
   error message.

It adds no dependency: `@xchonnect/dapp` has no runtime npm dependencies
([dependency policy](../dependency-policy.md) rule 7), and the handful of sign-client types
the shim needs are declared structurally in that file, so a proposal object you already
build for a real `SignClient` type-checks unchanged.

### What is supported, and what throws

| sign-client surface | In the shim |
|---|---|
| `SignClient.init({ … })` | `createSignClientShim({ client, confirmSas, chainId?, ttlSeconds?, topic? })` |
| `connect({ requiredNamespaces, optionalNamespaces })` | **Supported.** `uri` is always returned (nothing to reuse). Namespaces are checked, not negotiated |
| `approval()` | **Supported.** Resolves after the wallet replies **and** `confirmSas` returns `true`; rejects on a mismatch or when the code expires |
| `request({ topic, chainId, request })` | **Supported.** Bare and `chip0002_`-prefixed method names (spec 9.1); rejects with a CHIP-0002 error object `{ code, message, data? }` |
| `disconnect({ topic, reason })` | **Supported** → `client.end(reason?.message)` |
| `session.get` / `getAll` / `keys` / `length` | **Supported.** Zero or one session |
| `on("session_delete")` / `off` | **Supported** |
| `session.namespaces.chia.accounts` | **Always empty.** Pairing discloses no keys; call `getPublicKeys` (the wallet prompts) if you need an account |
| `session.expiry` | The *pairing URI's* expiry. Xchonnect sessions do not expire on a timer |
| `requiredNamespaces[…].methods` | Echoed back, not enforced: the wallet decides what it grants, and an ungranted method fails at request time with 4001 |
| A namespace other than `chia` | **Throws.** Keep WalletConnect for your other chains |
| More than one chain, or a chain that is not this client's | **Throws** |
| `request({ chainId })` that is not the session's chain | **Throws** before the request is posted |
| `pairingTopic`, `relays` | **Throws.** Pairing codes are single-use (spec 6.3); the relay is set on the client |
| `on("session_update" \| "session_event" \| "session_expire" \| "session_proposal" \| "session_request" \| "session_ping" \| "proposal_expire")` | **Throws.** None of these can ever fire, and a subscription that stays silent looks like one that works. Use `client.on("status" \| "delivery" \| "privacy" \| "ohttpKeyRotated", …)` |
| `ping`, `extend`, `update`, `pair`, `core` | **Throws.** There is no connection to ping, no expiry to extend, no namespace renegotiation, no pairing store |
| `approve`, `reject`, `respond`, `emit` | **Throws** — wallet-side API. Wallets use the native bindings ([wallet integration guide](../wallet-integration.md)) |
| `projectId`, Verify API, cloud dashboard | No analogue; see the table above |

One further difference worth planning for: **topics are random per shim instance** and are
not derived from session state. After a reload, read the current topic from
`session.getAll()`, or pass the topic you persisted as the `topic` option and call
`restore()` to re-wrap the session the client loaded from storage. A topic from a previous
page load that you did not pass in is rejected with `no matching key`.

### Sample migration

Before — a CHIP-0002 dApp on WalletConnect v2:

```ts
import SignClient from "@walletconnect/sign-client";

const signClient = await SignClient.init({ projectId, metadata });

const { uri, approval } = await signClient.connect({
  requiredNamespaces: { chia: { chains: ["chia:mainnet"], methods: ["chip0002_getPublicKeys", "chip0002_signCoinSpends"], events: [] } },
});
showQr(uri);
const session = await approval();

const keys = await signClient.request<string[]>({
  topic: session.topic,
  chainId: "chia:mainnet",
  request: { method: "chip0002_getPublicKeys", params: {} },
});

await signClient.disconnect({ topic: session.topic, reason: { code: 6000, message: "user disconnected" } });
```

After — the same flow over Xchonnect. The call sites are unchanged; what is new is
`XchonnectClient.create` (relay, domain, backend signing) and `confirmSas`:

```ts
import { XchonnectClient, createSignClientShim } from "@xchonnect/dapp";

const client = await XchonnectClient.create({
  relay: "https://relay.example.org",
  domain: "pengui.xyz",
  kid: "k1",
  sign: (sigInput) => fetch("/api/xchonnect/sign", { method: "POST", body: sigInput }).then((r) => r.text()),
});

const signClient = createSignClientShim({
  client,
  // The step WalletConnect has no equivalent for. Show the six digits next to the
  // wallet name and resolve true only when the user confirms they match.
  confirmSas: (sas, { walletName }) => showSasScreen(sas, walletName),
});

const { uri, approval } = await signClient.connect({
  requiredNamespaces: { chia: { chains: ["chia:mainnet"], methods: ["chip0002_getPublicKeys", "chip0002_signCoinSpends"], events: [] } },
});
showQr(uri);
const session = await approval();

const keys = await signClient.request<string[]>({
  topic: session.topic,
  chainId: "chia:mainnet",
  request: { method: "chip0002_getPublicKeys", params: {} },
});

await signClient.disconnect({ topic: session.topic, reason: { code: 6000, message: "user disconnected" } });
```

What changed beyond the two blocks above:

- **Add** `/.well-known/xchonnect.json` with your Ed25519 origin key, and the backend
  endpoint that signs `sigInput` — see the [dApp quickstart](dapp-quickstart.md).
- **Add** the SAS screen behind `confirmSas`, and a QR countdown driven by the `expiry`
  that `connect()` returns.
- **Replace** `signClient.on("session_update" | "session_event", …)` with
  `client.on("status" | "delivery" | …)`; `session_delete` keeps working.
- **Remove** `projectId` and the relay URL from your WalletConnect config.
- **Keep** your CHIP-0002 request and error handling exactly as it is.

The shim is exercised end to end against a real session (mock relay, real crypto) in
[`sdk-ts/src/walletconnect.test.ts`](../../sdk-ts/src/walletconnect.test.ts), including the
side-by-side case below.

### Suggested rollout

1. Add `@xchonnect/dapp` beside your existing WalletConnect client; both can be live at
   once. Publish `/.well-known/xchonnect.json` and wire up backend signing. Use
   [the sign-client shim](#the-sign-client-shim) if you want to keep your existing call
   sites, or `createChip0002Provider` if you would rather call Xchonnect directly.
2. Offer both in the connect dialog — "Connect with Xchonnect (recommended on mobile)" and
   "WalletConnect" — and route the same CHIP-0002 calls through whichever is active. Use
   `isLikelyMobile()` to pick the default.
3. Add the pairing-UI pieces: QR with a countdown, the SAS confirmation screen, and a
   transport indicator driven by `client.privacy`.
4. Measure completion rate of signing flows on iOS per transport. That is the number this
   whole exercise is about.
5. Keep WalletConnect for wallets that have not integrated Xchonnect. Change the default
   only once the wallets your users actually hold support it — today that is a short list.

### If you build a wallet

Both transports can coexist behind one request handler, because the method layer is
identical. The Xchonnect side is covered by the
[wallet integration guide](../wallet-integration.md): native bindings for Swift and
Kotlin, pairing and SAS screens, keychain session storage, your own push gateway, and
`handleWalletRequest` for simulation, policy and limits. Note that wallets must accept the
`chip0002_`-prefixed aliases as well as the bare names (spec 9.1), which is what
WalletConnect deployments send.

## Running both at once

Nothing in Xchonnect conflicts with WalletConnect: different transport, different relay,
same methods, separate sessions and separate permissions. A dApp may offer both
indefinitely, and a wallet may answer on both. Xchonnect does not deprecate WalletConnect.

Both clients are plain objects — the SDK touches no globals and does not define
`window.chia` — so a dApp holds one of each and routes the same CHIP-0002 call through
whichever the user picked:

```ts
const transports = {
  xchonnect: createSignClientShim({ client, confirmSas }),
  walletconnect: await SignClient.init({ projectId, metadata }),
};

function request<T>(which: keyof typeof transports, method: string, params: unknown): Promise<T> {
  const t = transports[which];
  const topic = t.session.getAll()[0]!.topic;
  return t.request<T>({ topic, chainId: "chia:mainnet", request: { method, params } });
}
```

Use `isLikelyMobile()` to pick the default. Note that the shim's `session.getAll()` is
empty until `approval()` has resolved (or `restore()` was called), exactly as
WalletConnect's is before a session exists.

## See also

- [dApp quickstart](dapp-quickstart.md)
- [Wallet integration guide](../wallet-integration.md)
- [Security and privacy](security-and-privacy.md), including the limitations
- [`docs/design/technical-stack.md`](../design/technical-stack.md) — the internal design
  note this page is derived from
