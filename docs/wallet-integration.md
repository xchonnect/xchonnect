# Integrating Xchonnect into a wallet

This guide is for iOS and Android wallet teams. It walks through pairing, session storage,
the relay, push wake-ups, the same-device universal-link flow, and answering CHIP-0002
requests safely, using the native
bindings in [`bindings/uniffi`](../bindings/uniffi) (Swift module `Xchonnect`, Kotlin
package `xchonnect.uniffi`). The Swift snippets are taken from
[`bindings/uniffi/tests/swift/guide_samples.swift`](../bindings/uniffi/tests/swift/guide_samples.swift),
which `scripts/test-swift.sh` compiles against the generated API; Kotlin uses the same names in
camelCase.

Normative behaviour is in the [specification](spec/xchonnect-spec.md); the
[MUST checklist](#must-checklist) at the end collects what a conforming wallet has to do.

## Building blocks

| You provide | Library provides |
|---|---|
| HTTP calls to the relay and the dApp's origin document | URI parsing, origin verification, pairing crypto, sessions, envelopes |
| Keychain / Keystore storage | Versioned session state (`Session.toBytes()` / `fromBytes`) |
| BLS keys in the Secure Enclave / StrongBox and biometric prompt (`WalletSigner`) | Spend simulation, signature policy, permissions and limits, CHIP-0002 handlers (`handleWalletRequest`) |
| Approval UI (`WalletApprover`), limit storage (`LimitStorage`) | The exact prompt content: simulated effect, signatures, bindings |
| APNs/FCM registration and a push gateway | Sealed push tokens (`sealPushToken`) |

Conventions: protocol values (mailbox ids, tokens, envelopes, keys) are base64url strings,
times are unix seconds you pass in, CHIP-0002 params/results are JSON text.

### Getting the library

- **Swift and Kotlin wallets** build the bindings from a checkout of a release tag:
  `./scripts/build-swift.sh` and `./scripts/build-kotlin.sh`
  ([`bindings/uniffi`](../bindings/uniffi)).
- **Rust wallets** depend on the crates from crates.io, not on a path into a checkout of
  this repository — a path dependency follows whatever is on `main` and breaks with it:

  ```toml
  [dependencies]
  xchonnect-wallet-kit = "=X.Y.Z-rc.N"
  # only when the wallet also calls the core directly; same version as the kit
  xchonnect-core = "=X.Y.Z-rc.N"
  ```

  Take the version from
  [crates.io](https://crates.io/crates/xchonnect-wallet-kit/versions). While the project
  is in pre-release the requirement has to be exact (`=`): Cargo never selects a
  pre-release for a plain requirement such as `"0.1"`, and one release candidate may
  break the API of the previous one. The kit requires `xchonnect-core` at exactly its own
  version, so the two always move together. How the crates are published and how to
  check a release: [`release.md`](release.md).

## 1. Pairing

1. **Scan** the QR code (`xchonnect:v1?…`) or receive the universal link
   (`https://<your-domain>/pair#…`, parameters in the fragment). Both forms parse the same
   way; [section 5](#5-same-device-flow-universal-links) covers claiming the link paths.
2. **Inspect** it: `inspectUri(uri:developerMode: false)` gives the relay, domain, origin
   document URL, expiry and an optional sponsorship ticket.
3. **Fetch the origin document** over HTTPS from `originDocumentUrl`: no redirects, no
   cookies, at most 16 KiB, 10 s timeout. Re-fetch on every pairing.
4. **Verify**: `VerifiedPairingUri(uri:originDocumentJson:now:developerMode:)` checks expiry
   and the origin signature. On any error abort; never offer "continue anyway".
5. **Show the verified domain** prominently: `domainDisplay().unicode`, the ASCII form if it
   differs, every `warnings` entry (non-ASCII, mixed scripts), and `dappName()`. Ask the user.
6. **Create your mailbox** on the dApp's relay with `generateMailboxTokens()` — the relay only
   ever sees the hashes. Use the URI's ticket if present, else solve the proof-of-work
   (`solvePow`, off the main thread).
7. **Reply**: `verified.reply(now:ownMailbox:meta:)` and post `outgoing` to the pairing
   mailbox. If the post returns `not_found`, the code was already used: tell the user another
   device may have paired with it.
8. **Show the SAS** (`pairing.sas()`), poll your mailbox for `session.confirm`
   (`pairing.onConfirm`), and give up after 5 minutes (`pairing.timedOut(now:)`) with the same
   warning.
9. **Confirm the SAS** with the user: matching → `session.confirmSas(now:meta:)` and post the
   returned `session.ready`; different → `session.rejectSas(now:)`, post it, delete everything.

```swift
let (pairing, sas, relay) = try await pair(scanned: uri, walletName: "My Wallet")
// show `sas`, wait for session.confirm on your mailbox, then:
// var session = try pairing.onConfirm(now: now, envelope: confirmEnvelope)
// if userConfirms { try await post(relay, try session.confirmSas(now: now, meta: nil)!) }
```

## 2. Session storage

- Store `session.toBytes()` in the Keychain (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`)
  or an Android Keystore-encrypted file, **separate from signing keys** (spec 11.3).
- Persist after **every** call that changes the session and **before** posting the
  resulting envelope. If you restore older state, the session must be re-paired (spec 5.3).
- Keep per-session: dApp domain, granted permissions, limit record, push registration.

## 3. Talking to the relay

Every call is plain HTTPS JSON (API: [`spec/wire/relay-api.md`](spec/wire/relay-api.md)):

- `GET /v1/mailboxes/{id}/messages?wait=N` with your read token; process messages in order,
  then `POST …/ack`.
- If `session.drainingMailbox()` returns a mailbox (after a key rotation), read it **before**
  your current one; when it is empty call `session.finishDrain()` and `DELETE` the returned
  mailbox.
- Post replies to the `Outgoing.mailbox` with `Outgoing.writeToken`.
- `not_found` means the mailbox is gone (session ended or expired).
- Route requests through an OHTTP relay when you use one (spec 10): wrap each request
  with `OhttpClient.encapsulate`, `POST` the bytes to the OHTTP relay, decapsulate the
  answer (bindings README, "Exported API"). Through OHTTP use `wait` ≤ `max_wait_ohttp_s`
  (default 0) and rely on push wake-ups plus foreground polling (spec 10.1). A key
  mismatch is a hard error: do not silently fall back to direct requests.

`session.open(now:mailboxId:envelope:)` returns an `IncomingMessage` whose `body` is a
typed `MessageBody`: requests, rotation offers (create a mailbox, then
`session.acceptRotation`), `session.end` (delete keys and mailbox), pings (answer with
`session.pong`).

## 4. Push wake-ups

Phones are never "connected": the relay sends a content-free wake-up through **your** push
gateway, and the app fetches its mailbox.

1. **Run the gateway** ([`crates/gateway`](../crates/gateway)). The compose file in
   [`deploy/`](../deploy) carries it behind a profile, so it stays off until you ask for it:

   ```sh
   cp deploy/example.env deploy/.env     # then fill in the XCHONNECT_GATEWAY_* values
   docker compose -f deploy/compose.yaml --env-file deploy/.env --profile gateway up -d
   curl http://127.0.0.1:8788/healthz    # "ok"
   ```

   Generate an X25519 key (`openssl rand -base64 32 | tr '+/' '-_' | tr -d '='`) and set
   `XCHONNECT_GATEWAY_KEYS` (newest first; keep the previous key during rotation) — the
   gateway refuses to start without it (started with no settings at all it waits for
   them, `operating.md` "Waiting for settings"). Point the APNs and FCM variables at credential
   **files** mounted read-only under `/secrets`; key material never belongs in the
   environment. Setting `XCHONNECT_GATEWAY_APNS_TEAM_ID` without the other APNs variables
   is fatal on purpose: a gateway that silently drops iOS wake-ups is worse than one that
   refuses to start. The full variable table is in
   [`operating.md`](operating.md#push-gateway-spec-73).
2. **Ship the gateway public key in the app** and rotate it yearly. The gateway logs its
   public keys at startup and serves them at `GET /v1/keys`; publish them from there so
   wallets (including older app versions) can seal to a current key.
3. **Register per session** with a fresh sealed token, so the relay cannot link sessions:

```swift
let reg = try await registerPush(relay: relay, mailbox: mailbox, readToken: readToken,
                                 apnsToken: deviceToken, gatewayKey: gatewayPublicKey)
// keep reg.hintKey with the session; re-register before reg.expiresAt
```

4. **Ask relay operators to allowlist your gateway URL** (`GET /v1/info` shows the relay's
   gateway policy). Self-hosted relays may run in `open` mode.
5. **On a notification**, fetch the mailbox; never act on push content. Show a generic
   alert ("New signing request"); no amounts or addresses on the lock screen. Use
   `interruption-level: time-sensitive` on iOS for signing requests.

### What the gateway owes (spec 7.3.2, T21)

The gateway is the one part of the stack a wallet vendor operates, and it is the lever an
attacker reaches for: `gateway_url` is chosen by anonymous clients, and a replayed sealed
token is free to produce. `crates/gateway` enforces all of the following; the list is here
because a vendor who writes their own, or wraps this one behind their own HTTP layer, still
owes every line of it.

- **Reject expired sealed tokens.** The token's `exp` is at most 90 days ahead; wallets
  re-register with `PUT /v1/mailboxes/{id}/push` before it passes.
- **Rate-limit per device token**, from **in-memory state only**: at most **one wake per
  10 seconds** and **60 per hour**. Excess wakes are dropped silently, so a replayed
  sealed token cannot flood a device. In-memory matters — persisting the counter would
  turn a transient key into a durable record of a device.
- **Answer every wake request identically.** The reference gateway returns the same
  `202 {}` whether the token opened, was rate-limited, or failed to deliver. A different
  status, body or timing for an invalid token makes the gateway an oracle for token
  validity.
- **Never fetch anything on behalf of a wake.** No URL in a wake request is ever
  followed. The gateway's only outbound traffic is to APNs and FCM.
- **Forget rejected devices.** When a platform reports a token invalid or unregistered
  (APNs `BadDeviceToken`, `DeviceTokenNotForTopic`, `Unregistered`; FCM `UNREGISTERED`,
  `SENDER_ID_MISMATCH`), discard every trace of it including its rate-limit state — and
  do not reveal that in the response, which stays uniform.
- **Never log device tokens** beyond delivery-failure handling. Expose aggregate counters
  only; `/metrics` on the reference gateway has `requests`, `invalid`, `limited`,
  `delivered`, `failed`, `invalid_device`, `forgotten` and `previews`, and no token ever
  appears in a log or a metric label.

### Notification previews (spec 7.3.3)

A wake-up carries no content, so the lock screen shows a generic alert by default. A peer
that knows the session's `mailbox_hint_key` — `PushRegistration.hintKey`, which you
generated at registration and may share over the **established session**, never with the
relay or the gateway — may attach a sealed preview. Every sealed preview is exactly 168
bytes, so no length leaks (T11); the gateway passes it through opaquely in the APNs `xcp`
key or the FCM `data.xcp` member, cannot read it, and drops a preview of any other size
while still sending the wake-up.

Decrypt it in an iOS Notification Service Extension or an Android FCM data handler. The
core API is [`crates/core/src/preview.rs`](../crates/core/src/preview.rs):

- `preview::open(hint_key, sealed, now, policy)` **never fails** — anything that does not
  authenticate, decode, parse or pass the policy yields `Outcome::Generic`, so the handler
  always has something to render, and the work is bounded enough for an extension's
  memory budget.
- `Policy::kind_only()` (the default) discards the sender's detail line. Use
  `Policy::with_detail()` only when the user has opted in to amounts or addresses on the
  lock screen (spec 7.3). A detail line containing control characters, line breaks or
  bidirectional overrides is refused outright (T12).
- `Outcome::loc_key()` returns the localisation key to look up (`xchonnect.preview.*`),
  so the user-visible strings ship in your app and never pass through the gateway or the
  push provider.
- The preview never drives a signing decision: still fetch the authenticated request from
  the mailbox and show what the simulation says (T12).

The UniFFI entry point for previews is landing separately; until it appears in the
generated API, call the core crate from your extension, or keep showing the generic alert
— a receiver must treat a missing preview exactly like an unauthenticated one.

## 5. Same-device flow (universal links)

When the dApp runs in a browser on the same phone, push is the wrong tool: the user is
right there and waiting. Spec 8.2 uses an app-link round trip instead, and push stays as
the fallback for when the user switches away.

```
dApp posts rpc.request → opens https://<your-domain>/req#mbx=<hint>
  → your app comes to the foreground, fetches its mailbox, signs, posts the response
  → your app opens the dApp's return_url → the browser tab regains visibility and fetches
```

### 5.1 Claim the two paths

Pairing URIs and request hints both put their parameters in the **fragment**, so they are
never sent to a web server and never appear in a server log (spec 6.2). That only holds if
the link opens your app instead of a web page, which means platform link verification:

- **iOS.** Add the Associated Domains entitlement `applinks:<your-domain>` and serve
  `https://<your-domain>/.well-known/apple-app-site-association` (content type
  `application/json`, no redirects) whose `applinks.details[].components` cover `/pair`
  and `/req` — and nothing else, so an unrelated path on your marketing site keeps opening
  in Safari.
- **Android.** Add an intent filter with `android:autoVerify="true"` for
  `https://<your-domain>` with `pathPrefix` `/pair` and `/req`, and serve
  `https://<your-domain>/.well-known/assetlinks.json` with your signing certificate
  fingerprint.
- Handle both paths with the app **closed, suspended and in the foreground**. A cold start
  must carry the fragment through to the pairing or request flow rather than dropping it on
  the launch screen.
- **Never log the fragment**, and never put it in a crash report or an analytics event: for
  `/pair` it contains the pairing secret `s`, which is the out-of-band secret that
  authenticates the whole handshake (spec 6.2).
- A malformed link shows an error and does nothing else. `inspectUri` and
  `VerifiedPairingUri` are total parsers; treat every failure as "not a pairing link".

### 5.2 What arrives on each path

| Path | Payload | What to do |
|---|---|---|
| `https://<your-domain>/pair#r=…&m=…&s=…` | the pairing URI's parameters | Pass the **whole URL** to `inspectUri` / `VerifiedPairingUri` — both the `xchonnect:v1?…` and the universal-link form parse — then continue with [section 1](#1-pairing) unchanged, SAS included |
| `https://<your-domain>/req#mbx=<mailbox id>` | a fetch **hint**, nothing more | Come to the foreground and fetch your session mailbox ([section 3](#3-talking-to-the-relay)). Everything you act on comes from the authenticated envelope |

The `mbx` value is an untrusted hint, not an instruction: anyone can open that link. If it
is not a mailbox of a session you hold, ignore it and sync your sessions as usual. A
request only exists once `session.open(now:mailboxId:envelope:)` has authenticated it.

### 5.3 Announce your link base at pairing

The dApp cannot guess your domain. Pass it as the `link` field of the wallet metadata in
the pairing reply:

- `verified.reply(now:ownMailbox:meta:)` takes a `WalletMetadata` with `name`, `icon` and
  `link`. Set `link` to the **base** only — `https://<your-domain>` — because the dApp
  appends `/req` itself; `https://wallet.example` becomes `https://wallet.example/req#mbx=…`.
- It must start with `https://` and stay within 256 bytes. The dApp SDK discards anything
  else, and then same-device requests fail with `no_wallet_link` instead of opening a
  wrong URL.
- The dApp keeps the base with the session, so it survives a page reload. If you change
  your link domain, existing sessions keep the old one until they re-pair.
- Pairing links are the other direction: the dApp builds `<your pairing base>#<params>`
  from a wallet it already knows about, so publish your `/pair` base in your integration
  notes.

### 5.4 Return the user to the dApp

The dApp's origin document may carry `return_url` (spec 8.2); it reaches you as
`verified.returnUrl()` on the verified pairing URI. Keep it with the session and open it
after you have posted the response, so the browser tab comes back to the foreground and
fetches the answer.

**The core has already checked it.** `return_url` must sit on the dApp's own domain, and
that rule is enforced where the document is bound to the claimed domain: a document whose
`return_url` has a different authority is rejected outright, so pairing fails rather than
handing you a URL you would have to police yourself. The comparison is byte-exact on the
whole authority, which refuses the cases a host-prefix check would wave through —
`evil-<domain>`, `<domain>.evil.com`, userinfo, a port, and a trailing dot. Without it, a
dApp whose origin key leaked (T18) could use your app as a one-tap redirect into a page the
user has every reason to trust (T3).

Two things this does **not** cover, so they are still yours:

- Take `return_url` from `verified.returnUrl()`, never from the free
  `parse_origin_document` helper — that one has no claimed domain to check against and so
  cannot apply the rule.
- `icon` is deliberately exempt, because icon CDNs are ordinary. Treat it as a URL to fetch
  an image from, never as somewhere to navigate the user.

If there is no `return_url`, leave the user in your app with a clear "you can go back now"
state rather than guessing a URL.

## 6. Answering requests safely

Pass every `rpc.request` to `handleWalletRequest`. For `signCoinSpends`, it:

1. runs every spend locally with the chain's CLVM interpreter (puzzle reveals checked);
2. derives the effect per asset from the conditions only — never from dApp labels;
3. computes the exact signing messages for your keys, refuses `AGG_SIG_UNSAFE` unless the
   user enabled it for this dApp (and always over a coin-bound or 32-byte message), signs
   an `AGG_SIG_ME` only over a quoted delegated puzzle so that the conditions shown are the
   only ones signed (4001 `unsigned_conditions`), refuses sessions for another network,
   never signs for other keys, and for `partialSign` requires every user spend to be
   **bound** to the counterparty's payment (spec 11.2);
4. applies per-dApp permissions and limits to the guaranteed loss;
5. calls your `WalletApprover` with a JSON prompt, then your `WalletSigner` for each
   planned signature (verifying what the platform returns), then records the spend.

```swift
try await answer(session: session, message: incoming, context: context, relay: relay)
```

Render the prompt honestly:

| Prompt field | Show as |
|---|---|
| `summary.assets[].net` | What the user gains or loses for sure |
| `summary.assets[].conditional_received` | "Only if the counterparty completes" — never as received |
| `binding.bound_payments` (partial requests) | What the signature depends on receiving |
| `binding.exercises` (option exercises) | What the exercise guarantees the user, per collateral asset |
| `summary.unknown_puzzles` | "Unknown contract" plus the puzzle hash (refused unless the user allows unknown contracts) |
| `plan.ours[].is_unsafe` | A red, scary warning |
| `summary.time_locks` | Expiry / not-before |
| `summary.implied_fee`, `reserve_fee` | Fees |
| `summary.options` | Option contracts: mint, transfer, exercise, clawback (below) |
| `summary.outputs[].option` | "Locked under option …" (collateral) or the option's launcher — never "paid to" |

Require one fresh biometric or passkey authentication per request, covering every
signature it needs (spec 11.1 item 4; no prompt per signature, no "remember for N
minutes" in v1): wallet-kit asks your signer for the whole batch at once (`Signer::sign_all`; the
native `WalletSigner` is called per signature inside that one batch), so unlock the keys
once, after the authentication, and sign the list. Default permissions: the required methods, `xchonnect_submitCoinSpends`
among them, and **one fresh key**; no auto-approval.

Tell the dApp what you granted with `session.permissions(now:methods:keys:limits:)` — a
message of its own, posted after the `session.ready` of step 9, and again whenever the
user changes the grant (spec 9.3). It saves the dApp from discovering your limits by being
refused, and it is a hint for its interface only: your refusal still decides every
request. Sending nothing is allowed; dApps must cope with never receiving one.

`WalletRequestContext` carries the session's domain, network and approved chain,
permissions, limits, your owned puzzle hashes and keys. `LimitStorage` persists daily
totals per dApp; a clock moving backwards never resets them.

### Methods that broadcast (spec 8.3)

A spend your wallet can complete alone is signed **and broadcast** by your wallet; the
dApp gets a transaction id, never a signature to push itself. Two kinds of request do
that, through one function, `xchonnect_wallet_kit::submit` (the `handle_with_host` entry
point calls it for `xchonnect_submitCoinSpends`; your own dispatcher calls it for the
`chia_*` methods you build):

| Request | Who builds the spend | What you pass to `submit` |
|---|---|---|
| `xchonnect_submitCoinSpends { coinSpends, aggregatedSignature?, intent? }` | the dApp | the parsed spends, the other party's signature if any, the dApp's `Intent`, `wallet_built: false`, `signatures_released: true` |
| `chia_send { address, amount, fee?, assetId?, memos? }` and the other `chia_*` methods you offer | your wallet, from its own coins | the spends you built, an `Intent` you derive from the request (the recipient, the amount, the fee), `wallet_built: true`, and `signatures_released: false` when you broadcast the bundle and return only `{ transactionId, status }` |

`submit` runs the checks of `signCoinSpends` — simulation, unknown contracts, signature
policy, permissions and limits — then verifies every claim of the intent against the
simulation (a mismatch is refused with 4001 `intent_mismatch` before any prompt), shows
**one** `Prompt::SubmitCoinSpends`, signs the whole plan in one batch after **one**
authentication, aggregates `aggregatedSignature` if the dApp brought one, checks that the
result satisfies every requirement of the bundle (4000 `signature_incomplete` otherwise),
hands the bundle to your `Broadcaster`, and only then records the loss against the
limits. With `aggregatedSignature` present it also requires binding (spec 11.2), exactly
like a partial request.

Your `Broadcaster` submits through peers your wallet already trusts — your own
light-wallet connections, or a node reached through OHTTP (spec 10.6) — never through a
third-party API that would see the user's address and IP together. Return the bundle
hash as the transaction id and a short status word; a refusal by the network becomes
4000 `broadcast_failed` with your message. Without a `Broadcaster` in `Host`, the
methods that broadcast answer 4004.

**Released or sealed signatures (spec 11.2).** Every request carries
`RequestContext::signed_coins`, your wallet's record of its own coins that have
signatures outside it (`SignedCoins { released, in_flight }`), and `submit` takes
`SubmitRequest::signatures_released`. Keep the record across sessions:

- `released`: every unspent coin of yours for which a signature covering a spend of it
  has left the wallet — each coin a `signCoinSpends` you answered spends, each coin of an
  offer you handed on (a loan request), each coin of any bundle you broadcast, including
  one the network refused. Drop a coin once it is spent on chain.
- `in_flight`: the coins of every bundle you broadcast with `signatures_released: false`,
  from the broadcast until any coin that bundle spends is spent on chain. The kit refuses
  every request that spends one (4001 `coin_in_flight`); rebroadcast the same bundle
  unchanged instead of building a new one.

Pass `signatures_released: false` only for a bundle your wallet built, that you broadcast
yourself, and of which nothing but `{ transactionId, status }` goes back to the dApp, and
then add its coins to both sets. The kit then treats the request as sealed when, in
addition, none of the user's coins is in `released` and you sign each user spend with
`AGG_SIG_ME` only: the user's spends are included together or not at all, so the links
Sage's builders make (`ASSERT_CONCURRENT_SPEND`) count, and Sage's mint, exercise and
take bundles pass unmodified. Everything else — `signCoinSpends`, every dApp-built
bundle, a signed offer you return — is released: only direct assertions bind (below).
`Prompt::SubmitCoinSpends::linking` and `binding.linking` say which rule applied
(`direct` or `sealed`). `true` is always safe; it only refuses more.

For a wallet-built spend, show both what your own wallet code says the spend does and
what wallet-kit's simulation says, and refuse the request if they disagree on what
leaves the wallet (the user's coins spent, amounts to others, the fee): two independent
calculations, and the user never approves a figure one of them contradicts.

Render the verified intent as facts, not as a description: each `IntentReport.verified`
entry is something the simulation proved (`recipient`, `fee`, `net`), and `kind` is the
website's own label, to be shown as such ("described by the website: option.buy").
`recipients_complete` tells you the dApp declared every payment to others, so there is
none it did not mention.

### Option contracts (spec 11.1.1)

wallet-kit recognises the spends of a Chia option (the Wallet SDK's option primitives)
when the request proves them, and otherwise leaves them unknown contracts. What it
recognises shows up in the prompt as typed facts, all computed from the spends:

- `summary.spends[].kind`: `singleton_launcher` (only the launcher of an option minted in
  this request), `option` (`action` `mint`, `transfer` or `exercise`, the `new_owner`,
  and the `terms` when the request proves them) and `option_underlying` (the collateral
  coin, `path` `exercise` or `clawback`).
- `summary.assets[]` with `asset.type == "option"`: the option itself, identified by its
  launcher id; its amounts are the singleton's mojos (normally 1), so show it as "1 option
  `<id>`", received or sent like an NFT.
- `summary.options[]`, one per option the request touches:

| `action` | Show as |
|---|---|
| `mint` | "Locks `terms.collateral` under option `<launcher_id>` until `terms.expiration_seconds`; the holder may buy it for `terms.strike` before then; after that `<creator>` can take it back", with *you* for `creator_is_user` / `owner_is_user`. `funded_by_user`: the collateral comes from the user's coins. `guaranteed: false`: the new option, or its collateral, is only conditional (always so when someone else funds the collateral) |
| `transfer` | "Option `<launcher_id>` from you to `<to>`" (or to you, `to_user`; "offered", `to_settlement`) |
| `exercise` | "Pay `terms.strike` to `<creator>`, receive `terms.collateral`"; the kit signs an exercise by the user only when `binding.co_required` and every `binding.exercises[].covered` hold (else 4001 `unbound_exercise`), so show `binding.exercises[].received` as what the user gets |
| `clawback` | "Take back `collateral` locked under option `<launcher_id>` (unknown if absent)"; the collateral returns to the balance (`net` +) |

A minted option's collateral leaves the user's balance (it is in `net` and in the
limits). When the user holds the new option and the launch is guaranteed, it is a lock,
not a payment: its output carries `option.role == "collateral"`,
`option.user_holds_option: true` and no `recipient`, and an intent's `recipients` does not
list it. The exception is a loan request (the creator, the lender, is someone else): the
collateral output names the creator as `recipient`, because the creator takes it after
`terms.expiration_seconds` unless the user repays (exercises) first, and `recipients`
must list it. Show the expiry prominently. The kit refuses (4001 `option_expires`) a
request that locks the user's collateral under another creator within an hour of the
option's expiry, using `RequestContext::now`: pass the device's current time. Otherwise it is a payment to the option's owner (`recipient`; the launcher's
mojo too), or, when the launch is not guaranteed, a payment to no one the wallet can name
(`recipient` absent) — show it as such. `outputs[].settlement` marks coins sent to the
offer settlement puzzle: whoever spends them chooses where they go, within the payments
the request asserts. An intent names an option with `assetId` `"option:<launcher id>"`.

A verified `kind` says that the request **contains** such an effect, not that the effect
is all it does: render the whole summary as for any request (spec 9.1).

**Linking the user's spends (spec 11.2).** In a sealed request (your wallet built it,
broadcasts it and keeps the signatures; see above) the kit counts the links your builder
makes between the user's spends: `ASSERT_CONCURRENT_SPEND` of another user spend's coin,
or a coin announcement another user spend makes in its signed conditions. Hand it the
Wallet SDK's action-system output as Sage builds it (`Relation::AssertConcurrent`):
`option_sage_tests.rs` in `crates/wallet-kit` runs Sage's mint (XCH and CAT collateral),
transfer, exercise (with a fee paid from absorbed XCH collateral) and offer takes (a CAT
for a CAT with fees on both sides, several CATs for one and one for several) through
`submit` and onto the simulator, unmodified.

When the signatures are released (`signCoinSpends`, a dApp-built bundle, an offer you
return to the dApp) no link between two spends counts, because a dApp holding the user's
signatures can put another signed spend of the linked coin in its place. Then:

- a partial request, or a take with `aggregatedSignature`, is bound only if **every**
  user spend asserts every settlement-payment announcement any user spend asserts;
- a mint is guaranteed only if the spend that creates the collateral also asserts the
  launcher's announcement;
- an exercise is co-required only if every user spend asserts the settlement payment of
  the collateral to the user (and the fee comes from the user's own coins).

**Loan requests.** A loan request's signed spends go to the lender as an offer, so call
`submit` with `signatures_released: true` (an `OfferOnly`-style broadcaster that does not
send) and build the request with direct links: every user spend asserts the settlement
announcement of the principal paid to the user, and the spend that creates the collateral
asserts the launcher's announcement. `crates/wallet-kit/src/final_audit_tests.rs`
(`a_loan_request_holds_only_with_direct_assertions`) is a working example; a request
linked by `ASSERT_CONCURRENT_SPEND` is refused (`loan.request` does not hold).

**Fees in an exercise.** In a sealed request the kit credits the fee the user's spends
reserve, up to the bundle's fee (you chose it, the user approved it), so Sage's exercise,
whose fee comes out of the released XCH collateral absorbed into your change, is
accepted. With the signatures released the fee is credited only up to the XCH the user's
own spends put into the bundle (spec 11.1.1). An exercise that loses value in the
collateral's own asset (strike above collateral) is refused, and in a request exercising
several options each counts its own strike, never more than its own collateral.

A mint looks like this
(one XCH-backed option of 1000 mojos, written and held by the user, strike 300 mojos,
fee 7):

```json
"options": [{
  "action": "mint", "launcher_id": "9c1f…", "owner": "4f45…", "owner_is_user": true,
  "creator_is_user": true, "funded_by_user": true, "guaranteed": true,
  "collateral_coin_id": "e2d0…",
  "terms": {
    "creator_puzzle_hash": "4f45…", "expiration_seconds": 1767225600,
    "collateral": { "asset": { "type": "xch" }, "amount": 1000 },
    "strike": { "asset": { "type": "xch" }, "amount": 300 }
  }
}]
```

with `assets` showing XCH `net: -1008` (collateral, the option's mojo, the fee) and
`{ "type": "option", "asset_id": "9c1f…" }` `received: 1`. An intent `kind` of
`option.mint`, `option.transfer`, `option.exercise`, `option.clawback`, `loan.request` or
`loan.take` is checked against these effects (`IntentReport.kind_verified`); show it as
verified only then. NFT and revocable-CAT strikes or collateral, a mint whose collateral
coin is created outside the request and the terms of a transfer are not recognised or
shown (`docs/guides/security-and-privacy.md`); keep track of the terms of options the user
minted or received in your own records.

### Cancellation and progress (spec 9.1)

While a request waits for the user, keep reading the session mailbox: an `rpc.cancel`
from the dApp withdraws the prompt, and you answer the request with 4102
(`Session.respond_error`). A request the user already approved stands; answer it
normally. When the user withdraws a request in your interface, send `rpc.cancel` and
then the 4102 response. `rpc.status` with `shown`, `approved` and `broadcast` (with the
transaction id) lets the dApp show honest progress; `rpc.received` on fetch says
"delivered". None of them replaces the `rpc.response`. The Rust core and the WASM
binding seal all of these (`Message::RpcCancel`, `Message::RpcStatus`,
`Message::RpcReceived` through the session's seal; `cancel`, `status`, `received` on the
WASM `Session`); the native bindings seal `received` only, so a Swift or Kotlin wallet built on them
cannot send `rpc.cancel` or `rpc.status` yet and must drop a cancelled request by
answering 4102 when it gets to it.

### Optional chain methods

The optional methods `getAssetCoins`, `getAssetBalance`, `filterUnlockedCoins` and
`sendTransaction` need your view of the chain. Rust wallets implement
`xchonnect_wallet_kit::ChainData` (any subset; the rest answer `4004`) and pass it as
`RequestContext::chain`; the kit validates the params, scopes every read to the keys
exposed to the dApp, and builds the CHIP-0002 result. Grant them per dApp
(`permissions::OPTIONAL_METHODS`); they are not in the default grant. The native bindings
do not bridge `ChainData` or a `Broadcaster` yet, so through them these methods and
`xchonnect_submitCoinSpends` answer `4004`; a wallet that uses the Rust crate directly
(Klimper does, through a Tauri plugin) has both.

## 7. Android notes

- Kotlin bindings: `./scripts/build-kotlin.sh`. The wallet-kit part includes C code (the BLS
  library), so building the `.so` libraries needs the Android NDK and `cargo-ndk`.
- Store session state in a file encrypted with a StrongBox-backed key; keep BLS keys
  hardware-wrapped and biometric-gated.
- Use FCM **data** messages so the app decides what to show.

## MUST checklist

From spec Sections 6, 9, 11 and 12.1:

- [ ] Verify the origin signature against the freshly fetched origin document; abort on failure, no "continue anyway".
- [ ] Show the verified domain with homograph warnings and get the user's approval before replying.
- [ ] Treat a `not_found` reply post or a missing `session.confirm` after 5 minutes as "code already used".
- [ ] Require the user to confirm the SAS; on mismatch send `session.end` and delete the session.
- [ ] Persist session state before posting; never reset `seq` (re-pair after state loss).
- [ ] Simulate every spend locally and show the net effect; ignore dApp-provided amounts and labels.
- [ ] Sign only coin-bound AGG_SIG variants for your keys; refuse `AGG_SIG_UNSAFE` by default, and always when its message ends with any network's AGG_SIG additional data or is 32 bytes long.
- [ ] Sign an `AGG_SIG_ME` only over a quoted program the spend reveals, one message per key and spend, so the conditions you showed are the only ones the signature allows (spec 11.1 item 2).
- [ ] Show unknown contracts with their puzzle hash and require extra confirmation (or refuse).
- [ ] Require one fresh biometric or passkey authentication per request, covering all its signatures; never one per signature, never remembered.
- [ ] Broadcast every spend you sign alone yourself, through your own peers or OHTTP, and return the transaction id; never hand a dApp a complete single-party signature to push.
- [ ] Verify every claim of a declared intent against your simulation and refuse on mismatch before showing anything; show `kind` as the website's description, never as a fact.
- [ ] Answer an `rpc.cancel` for an undecided request with 4102 and withdraw its prompt; a request already approved stands.
- [ ] Enforce user-configured per-dApp and per-day limits.
- [ ] Refuse requests for another network.
- [ ] Never produce a partial signature for an unbound multi-party spend.
- [ ] Keep the record of coins with signatures outside the wallet (`SignedCoins`), pass it with every request, and pass `signatures_released: false` only for a wallet-built bundle you broadcast yourself (spec 11.2).
- [ ] Keep BLS keys hardware-wrapped; keep Xchonnect session keys in the Keychain/Keystore, separate from signing keys.
- [ ] Never show amounts or addresses on the lock screen unless the user opts in.
- [ ] Use your own push credentials through your own gateway; register a fresh sealed token per session.
- [ ] Treat a notification preview that is missing, wrong-sized, unauthenticated, malformed or expired exactly like no preview, and never let one drive a signing decision.
- [ ] In your gateway: reject expired sealed tokens, rate-limit per device in memory (1 per 10 s, 60 per hour), answer every wake request uniformly, fetch nothing on behalf of a wake, and forget devices the platform rejects (spec 7.3.2).
- [ ] Keep universal-link parameters in the fragment and out of every log, crash report and analytics event.
- [ ] Treat `mbx` in a `/req` link as an untrusted hint; act only on what the mailbox envelope authenticates.
- [ ] Take `return_url` from the verified pairing URI, not from `parse_origin_document`, so the
      same-domain rule the core enforces actually applies; never navigate to `icon`.

## Effort

For a wallet already built on the Chia wallet SDK, the protocol and safety logic is in the
library; the work is mostly UI (pairing, SAS, approval screen), keychain storage, relay
HTTP calls and the push gateway deployment.
