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

**There is no drop-in `@walletconnect/sign-client` replacement**, and none is planned in
this repository. The pieces that genuinely differ have to be rewritten:

| WalletConnect concept | Xchonnect equivalent |
|---|---|
| `SignClient.connect()` → URI → `approval()` | `client.pair()` → `pairing.uri` → `pairing.waitForWallet()` → **user compares the SAS** → `pairing.confirm()` |
| Session proposal dialog with namespaces | Nothing to choose: the wallet grants permissions and reports them in `session.ready` |
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

### Suggested rollout

1. Add `@xchonnect/dapp` beside your existing WalletConnect client; both can be live at
   once. Publish `/.well-known/xchonnect.json` and wire up backend signing.
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

## See also

- [dApp quickstart](dapp-quickstart.md)
- [Wallet integration guide](../wallet-integration.md)
- [Security and privacy](security-and-privacy.md), including the limitations
- [`docs/design/technical-stack.md`](../design/technical-stack.md) — the internal design
  note this page is derived from
