# Integrating Xchonnect into a wallet

This guide is for iOS and Android wallet teams. It walks through pairing, session storage,
the relay, push wake-ups, and answering CHIP-0002 requests safely, using the native
bindings in [`bindings/uniffi`](../bindings/uniffi) (Swift module `Xchonnect`, Kotlin
package `xchonnect.uniffi`). The Swift snippets are taken from
[`bindings/uniffi/tests/swift/guide_samples.swift`](../bindings/uniffi/tests/swift/guide_samples.swift),
which is compiled in CI against the generated API; Kotlin uses the same names in
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

## 1. Pairing

1. **Scan** the QR code or receive the universal link (parameters are in the fragment).
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

1. **Run the gateway** ([`crates/gateway`](../crates/gateway), container image in
   [`deploy/`](../deploy)). Generate an X25519 key (`openssl rand 32 | basenc --base64url`),
   set `XCHONNECT_GATEWAY_KEYS` (newest first; keep the previous key during rotation), and
   configure your APNs/FCM credentials. The gateway logs its public keys at startup and
   serves them at `GET /v1/keys`.
2. **Ship the gateway public key in the app** and rotate it yearly.
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

Pending in the reference stack: the APNs and FCM senders in the gateway (TASK-46/47) and
encrypted notification previews decrypted in a Notification Service Extension / FCM handler
(TASK-48). Until then, use content-free alerts.

## 5. Answering requests safely

Pass every `rpc.request` to `handleWalletRequest`. For `signCoinSpends`, it:

1. runs every spend locally with the chain's CLVM interpreter (puzzle reveals checked);
2. derives the effect per asset from the conditions only — never from dApp labels;
3. computes the exact signing messages for your keys, refuses `AGG_SIG_UNSAFE` unless the
   user enabled it for this dApp, refuses sessions for another network, never signs for
   other keys, and for `partialSign` requires every user spend to be **bound** to the
   counterparty's payment (spec 11.2);
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
| `summary.unknown_puzzles` | "Unknown contract" plus the puzzle hash (refused unless the user allows unknown contracts) |
| `plan.ours[].is_unsafe` | A red, scary warning |
| `summary.time_locks` | Expiry / not-before |
| `summary.implied_fee`, `reserve_fee` | Fees |

Require biometrics for every signature (no "remember for N minutes" in v1). Default
permissions: the required methods and **one fresh key**; no auto-approval.

`WalletRequestContext` carries the session's domain, network and approved chain,
permissions, limits, your owned puzzle hashes and keys. `LimitStorage` persists daily
totals per dApp; a clock moving backwards never resets them.

## 6. Android notes

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
- [ ] Sign only coin-bound AGG_SIG variants for your keys; refuse `AGG_SIG_UNSAFE` by default.
- [ ] Show unknown contracts with their puzzle hash and require extra confirmation (or refuse).
- [ ] Require biometric approval for every signature.
- [ ] Enforce user-configured per-dApp and per-day limits.
- [ ] Refuse requests for another network.
- [ ] Never produce a partial signature for an unbound multi-party spend.
- [ ] Keep BLS keys hardware-wrapped; keep Xchonnect session keys in the Keychain/Keystore, separate from signing keys.
- [ ] Never show amounts or addresses on the lock screen unless the user opts in.
- [ ] Use your own push credentials through your own gateway; register a fresh sealed token per session.

## Effort

For a wallet already built on the Chia wallet SDK, the protocol and safety logic is in the
library; the work is mostly UI (pairing, SAS, approval screen), keychain storage, relay
HTTP calls and the push gateway deployment.
