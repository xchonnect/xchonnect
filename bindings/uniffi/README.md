# xchonnect-uniffi

Swift (iOS) and Kotlin (Android) bindings of `xchonnect-core` for **wallets**, generated
with [UniFFI](https://mozilla.github.io/uniffi-rs/) 0.32 (proc-macro mode). This crate is
FFI glue only; every protocol rule lives in `xchonnect-core`. Networking (relay HTTP,
origin-document fetch, push) stays in the wallet app.

## Conventions

| What | At the boundary |
| --- | --- |
| Mailbox ids, tokens, message ids, envelopes, PoW challenges/nonces, public keys | base64url strings without padding, exactly as the relay HTTP API carries them (`env`, path segments, bearer tokens) |
| Session persistence | raw bytes (`Data` / `ByteArray`) from `Session.toBytes()`; contains secrets, store in the Keychain / Android Keystore-encrypted storage |
| Time | unix seconds passed in as `now` (`UInt64` / `ULong`); the bindings never read the clock |
| CHIP-0002 `params` / `result` / error `data` | JSON text |
| Decoded messages | typed: `IncomingMessage { id, seq, iat, exp, body: MessageBody }` |
| Errors | `XchonnectError` (Swift) / `XchonnectException` (Kotlin) with one case per core error kind plus `InvalidInput` (bad argument; names the parameter, never its value) and `Other`. Messages never contain secrets. |

**Persist `session.toBytes()` after every mutating call and before posting the
returned envelope** (spec 12.1).

## Exported API

- Free functions: `protocolVersion`, `inspectUri` (relay, domain, origin document URL,
  expiry; unverified), `parseOriginDocument`, `displayDomain` (Unicode form +
  `DomainWarning`s), `generateToken`, `tokenHash`, `generateMailboxTokens`, `solvePow`
  (CPU-bound, call off the main thread), `canonicalMethod`, `rpcErrorCodeValue`,
  `sealPushToken` (fresh `PushRegistration` per session, spec 7.3).
- `VerifiedPairingUri(uri, originDocumentJson, now, developerMode)`: expiry + origin
  signature verified; `domain`, `domainDisplay`, `dappName`, `dappIcon`, `returnUrl`,
  `relay`, `ticket`, `expiresAt`, and `reply(now, ownMailbox, meta)` → `WalletReply
  { pairing, outgoing }`.
- `WalletPairing`: `sas`, `sasDigits`, `ownMailbox`, `timedOut(now)`,
  `onConfirm(now, envelope)` → `Session`.
- `Session`: `open`, `confirmSas`, `rejectSas`, `respond`, `respondError`, `received`,
  `ping`, `pong`, `end`, `beginRotation`, `acceptRotation`, `drainingMailbox`,
  `pendingRotationMailbox`, `finishDrain`, `needsRotation`, `isActive`, `isEnded`,
  `epoch`, `role`, `ownMailbox`, `toBytes`, `Session.fromBytes`.
- OHTTP (spec 10): `ohttpSelectKey(keyConfigs)` (pin from a published
  `application/ohttp-keys` list), `OhttpClient(keyConfig)`: `keyId`,
  `encapsulate(OhttpRequest)` → `OhttpEncapsulated { body, context }`;
  `context.decapsulate(responseBody)` → `OhttpResponse`. The app sends `body` with its
  own HTTP stack (`POST` to the OHTTP relay, `Content-Type: message/ohttp-req`). Ship the
  relay's key configuration with the app. Rotation: encapsulate
  `GET /.well-known/ohttp-keys` through the client (never fetch it directly) and call
  `context.decapsulateKeyRotation(responseBody)` → new pin (`Decrypt` unless answered
  under the pinned key, `OhttpKeyMismatch` when the list no longer contains it).

`developerMode` allows loopback `http` relays and `localhost:<port>` domains. Never
enable it in production builds.

## Swift: pairing

```swift
import Xchonnect

let now = { UInt64(Date().timeIntervalSince1970) }

// 1. QR code scanned: find out where the origin document lives.
let info = try inspectUri(uri: scanned, developerMode: false)
let originJson = try await fetchNoRedirects(info.originDocumentUrl) // HTTPS, <= 16 KiB

// 2. Verify and ask the user (show unicode + ascii domain and every warning).
let verified = try VerifiedPairingUri(
    uri: scanned, originDocumentJson: originJson, now: now(), developerMode: false)
let domain = verified.domainDisplay()
guard userApproves(verified.dappName(), domain.unicode, domain.ascii, domain.warnings) else { return }

// 3. Create mailbox W on the dApp's relay (PoW via solvePow if the relay asks for it).
let tokens = generateMailboxTokens()
let mailboxId = try await relay(verified.relay()).createMailbox(
    readTokenHash: tokens.readTokenHash, writeTokenHash: tokens.writeTokenHash,
    ticket: verified.ticket())
let w = NewMailbox(mailbox: mailboxId, readToken: tokens.readToken, writeToken: tokens.writeToken)

// 4. Reply, then poll W for session.confirm.
let reply = try verified.reply(now: now(), ownMailbox: w, meta: WalletMetadata(name: "My Wallet"))
try await relay.post(reply.outgoing) // mailbox, writeToken, envelope
var session: Session?
while session == nil {
    if reply.pairing.timedOut(now: now()) { throw PairingTimedOut() }
    for env in try await relay.fetch(w.mailbox, readToken: w.readToken) {
        session = session ?? (try? reply.pairing.onConfirm(now: now(), envelope: env))
    }
}

// 5. Show reply.pairing.sas() ("042 917"); the user compares it with the dApp.
let out = userSaysCodesMatch
    ? try session!.confirmSas(now: now(), meta: nil)!   // session.ready
    : try session!.rejectSas(now: now())                // session.end
keychain.store(try session!.toBytes())
try await relay.post(out)

// 6. Requests.
let own = session!.ownMailbox()
for env in try await relay.fetch(own.mailbox, readToken: own.readToken) {
    let msg = try session!.open(now: now(), fromMailbox: own.mailbox, envelope: env)
    switch msg.body {
    case let .rpcRequest(_, method, paramsJson):
        let out = try approve(method, paramsJson)
            ? session!.respond(now: now(), requestId: msg.id, resultJson: sign(method, paramsJson))
            : session!.respondError(now: now(), requestId: msg.id,
                                    code: rpcErrorCodeValue(code: .userRejected),
                                    message: "User rejected", dataJson: nil)
        keychain.store(try session!.toBytes())
        try await relay.post(out)
    case let .rotationOffered(offer):
        let w2 = try await createMailbox()  // NewMailbox
        let acc = try session!.acceptRotation(now: now(), offer: offer, newMailbox: w2)
        keychain.store(try session!.toBytes())
        try await relay.post(acc.outgoing)
    case .ping:
        try await relay.post(session!.pong(now: now()))
    case .sessionEnd:
        keychain.delete()
    default: break
    }
}
```

## Kotlin: pairing

```kotlin
import xchonnect.uniffi.*

fun now() = (System.currentTimeMillis() / 1000).toULong()

val info = inspectUri(scanned, false)
val originJson = httpGetNoRedirects(info.originDocumentUrl)          // HTTPS, <= 16 KiB
val verified = VerifiedPairingUri(scanned, originJson, now(), false)
val domain = verified.domainDisplay()
if (!userApproves(verified.dappName(), domain.unicode, domain.ascii, domain.warnings)) return

val tokens = generateMailboxTokens()
val mailboxId = relay.createMailbox(tokens.readTokenHash, tokens.writeTokenHash, verified.ticket())
val w = NewMailbox(mailboxId, tokens.readToken, tokens.writeToken)

val reply = verified.reply(now(), w, WalletMetadata(name = "My Wallet"))
relay.post(reply.outgoing)

var session: Session? = null
while (session == null) {
    check(!reply.pairing.timedOut(now())) { "pairing timed out" }
    for (env in relay.fetch(w.mailbox, w.readToken)) {
        if (session == null) session = try { reply.pairing.onConfirm(now(), env) } catch (e: XchonnectException) { null }
    }
}

val s = checkNotNull(session)
// Show reply.pairing.sas(); then:
val out = if (codesMatch) s.confirmSas(now(), null)!! else s.rejectSas(now())
secureStore.put(s.toBytes())
relay.post(out)

val own = s.ownMailbox()
for (env in relay.fetch(own.mailbox, own.readToken)) {
    val msg = s.open(now(), own.mailbox, env)
    when (val body = msg.body) {
        is MessageBody.RpcRequest -> {
            val resp = if (approve(body.canonicalMethod, body.paramsJson))
                s.respond(now(), msg.id, sign(body.canonicalMethod, body.paramsJson))
            else
                s.respondError(now(), msg.id, rpcErrorCodeValue(RpcErrorCode.USER_REJECTED), "User rejected", null)
            secureStore.put(s.toBytes())
            relay.post(resp)
        }
        is MessageBody.RotationOffered -> {
            val acc = s.acceptRotation(now(), body.offer, createMailbox())
            secureStore.put(s.toBytes())
            relay.post(acc.outgoing)
        }
        is MessageBody.Ping -> relay.post(s.pong(now()))
        is MessageBody.SessionEnd -> secureStore.delete()
        else -> {}
    }
}
```

After a rotation, read `drainingMailbox()` before `ownMailbox()`, and once it is empty
call `finishDrain()`; delete the returned mailbox on the relay.

## Building

| Script | Output | Needs |
| --- | --- | --- |
| `scripts/build-swift.sh` | `target/swift/`: `XchonnectFFI.xcframework` (iOS device + simulator static libs), `Sources/Xchonnect/Xchonnect.swift`, `Package.swift` | Rust targets `aarch64-apple-ios`, `aarch64-apple-ios-sim`; Xcode for the XCFramework step (without it the sources, headers and static libs are still produced) |
| `scripts/build-kotlin.sh` | `target/kotlin/src/main/kotlin/…/xchonnect.kt` and, with the NDK, `src/main/jniLibs/<abi>/libxchonnect_uniffi.so` (Android library module layout) | Android NDK + `cargo install cargo-ndk` + `ANDROID_NDK_HOME` for the `.so` files; otherwise only `cargo check --target aarch64-linux-android` runs |
| `scripts/test-swift.sh` | Swift round trip (pair, request/response, replay error, persist/restore, rotation, end) on the macOS host against the core's dApp side | Swift toolchain |
| `scripts/test-kotlin.sh` | the same round trip on the JVM | JDK, `kotlinc`, `JNA_JAR` |

Android apps depend on `net.java.dev.jna:jna:<version>@aar`. Bindings are generated by
the project-local `uniffi-bindgen` binary (`scripts/uniffi-bindgen.sh`, `bindgen`
feature), so the generator always matches the runtime crate. Generator settings
(Swift module `Xchonnect`, Kotlin package `xchonnect.uniffi`) are in `uniffi.toml`.

The `test-helpers` feature exports `TestDapp`, a dApp built from the core with a fixed,
public origin key, for the round-trip tests. Never enable it in wallet builds.

Rust tests (`cargo test -p xchonnect-uniffi`) pair the exported wallet API with the
core's `DappPairing` and cover requests, errors, persistence, both rotation directions,
SAS rejection, timeouts and end.

## Wallet-kit: answering CHIP-0002 requests safely

With the default `wallet-kit` feature, `handleWalletRequest` runs every request through
`xchonnect-wallet-kit`: local simulation of the spend, signature policy (no
`AGG_SIG_UNSAFE` without an explicit per-dApp override, network check, never signing for
foreign keys), permissions and spending limits, and an approval prompt showing the
simulated effect — then signs through your platform signer.

```swift
final class EnclaveSigner: WalletSigner {
    func sign(publicKey: String, message: Data) -> Data? {
        // Unwrap the BLS key with biometrics, sign (augmented scheme), zeroize. nil = cancelled.
    }
}
final class ApprovalUI: WalletApprover {
    func approve(promptJson: String) -> Bool { /* render the simulated net effect */ }
}
final class KeychainLimits: LimitStorage {
    func load() -> String? { /* per-dApp record */ }
    func save(json: String) -> Bool { /* persist */ }
}

let outcome = try handleWalletRequest(method: request.method, paramsJson: request.params,
                                      context: context, signer: EnclaveSigner(),
                                      approver: ApprovalUI(), limits: KeychainLimits())
switch outcome {
case .success(let result): try session.respond(now: now, requestId: id, resultJson: result)
case .failure(let code, let message, let data):
    try session.respondError(now: now, requestId: id, code: code, message: message, dataJson: data)
}
```

`promptJson` is the serialised `xchonnect_wallet_kit::Prompt`. Render amounts from
`summary.assets` (`net` is the guaranteed effect; `conditional_received` must be shown
as "only if the counterparty completes"), `summary.unknown_puzzles` as "Unknown
contract", and highlight `plan.ours[].is_unsafe`. The signer's output is verified
against the requested key before use.

Building for iOS uses `IPHONEOS_DEPLOYMENT_TARGET=15.0` (set in `.cargo/config.toml`)
for Rust and the C BLS library alike. Android builds of the `wallet-kit` feature need the
NDK (the BLS library is C).

## Licence and security

Apache-2.0 ([`LICENSE`](https://github.com/maximedogawa/xchonnect/blob/main/LICENSE)).

Report vulnerabilities privately - **not** as a public issue - per
[`SECURITY.md`](https://github.com/maximedogawa/xchonnect/blob/main/SECURITY.md).
Pre-audit software. Never enable the `test-helpers` feature in a wallet release build.
