// Pairing round trip through the generated Swift bindings against the core's dApp side
// (`TestDapp`, test-helpers feature). Run with scripts/test-swift.sh.
import Foundation

func check(_ cond: Bool, _ what: String, line: Int = #line) {
    if !cond {
        FileHandle.standardError.write("FAIL line \(line): \(what)\n".data(using: .utf8)!)
        exit(1)
    }
}

let now = UInt64(Date().timeIntervalSince1970)
let dapp = try TestDapp(now: now)

// 1. Scan: inspect, fetch origin document (here: from the test dApp), verify.
let uri = try dapp.pairingUri()
let info = try inspectUri(uri: uri, developerMode: false)
check(info.domain == "pengui.xyz", "domain")
check(info.originDocumentUrl == "https://pengui.xyz/.well-known/xchonnect.json", "origin url")
let verified = try VerifiedPairingUri(
    uri: uri, originDocumentJson: dapp.originDocumentJson(), now: now, developerMode: false)
check(verified.dappName() == "Pengui", "dapp name")
check(verified.domainDisplay().warnings.isEmpty, "no domain warnings")

// 2. Create mailbox W on the relay (simulated) and reply.
let tokens = generateMailboxTokens()
let w = NewMailbox(
    mailbox: dapp.fakeMailboxId(), readToken: tokens.readToken, writeToken: tokens.writeToken)
let reply = try verified.reply(now: now, ownMailbox: w, meta: WalletMetadata(name: "SwiftWallet"))

// 3. dApp accepts; both show the same SAS.
let dappSas = try dapp.onReply(now: now, envelope: reply.outgoing.envelope)
check(dappSas == reply.pairing.sas(), "SAS matches")

// 4. session.confirm arrives on W; user confirms the SAS on both sides.
let confirm = try dapp.confirm(now: now)
check(confirm.mailbox == w.mailbox, "confirm to W")
var session = try reply.pairing.onConfirm(now: now, envelope: confirm.envelope)
let ready = try session.confirmSas(now: now, meta: nil)!
_ = try dapp.open(now: now, mailboxId: ready.mailbox, envelope: ready.envelope)
try dapp.confirmSas(now: now)
check(try dapp.isActive() && session.isActive(), "both active")

// 5. Request / response.
let req = try dapp.request(now: now, method: "chip0002_chainId", paramsJson: "{}")
let msg = try session.open(now: now, fromMailbox: session.ownMailbox().mailbox, envelope: req.envelope)
guard case let .rpcRequest(method, canonicalMethod, paramsJson) = msg.body else {
    check(false, "expected rpc.request"); exit(1)
}
check(method == "chip0002_chainId" && canonicalMethod == "chainId" && paramsJson == "{}", "request body")
let resp = try session.respond(now: now, requestId: msg.id, resultJson: "\"mainnet\"")
let back = try dapp.open(now: now, mailboxId: resp.mailbox, envelope: resp.envelope)
guard case let .rpcResponse(requestId, .success(resultJson)) = back.body else {
    check(false, "expected rpc.response"); exit(1)
}
check(requestId == req.id && resultJson == "\"mainnet\"", "response body")

// Typed errors.
do {
    _ = try session.open(now: now, fromMailbox: session.ownMailbox().mailbox, envelope: req.envelope)
    check(false, "replay accepted")
} catch XchonnectError.Replay(let message) {
    check(!message.isEmpty, "replay message")
}

// 6. Persist and restore (keychain blob).
session = try Session.fromBytes(state: session.toBytes())

// 7. dApp-initiated rotation.
let offerOut = try dapp.beginRotation(now: now)
let offerMsg = try session.open(now: now, fromMailbox: session.ownMailbox().mailbox, envelope: offerOut.envelope)
guard case let .rotationOffered(offer) = offerMsg.body else { check(false, "expected offer"); exit(1) }
let t2 = generateMailboxTokens()
let w2 = NewMailbox(mailbox: dapp.fakeMailboxId(), readToken: t2.readToken, writeToken: t2.writeToken)
let accept = try session.acceptRotation(now: now, offer: offer, newMailbox: w2)
_ = try dapp.open(now: now, mailboxId: accept.outgoing.mailbox, envelope: accept.outgoing.envelope)
check(try dapp.epoch() == 1 && session.epoch() == 1, "epoch 1")
check(session.drainingMailbox()?.mailbox == w.mailbox, "draining W")
let req2 = try dapp.request(now: now, method: "getPublicKeys", paramsJson: "{}")
check(req2.mailbox == w2.mailbox, "request to W2")
let msg2 = try session.open(now: now, fromMailbox: w2.mailbox, envelope: req2.envelope)
_ = try session.respondError(
    now: now, requestId: msg2.id, code: rpcErrorCodeValue(code: .userRejected),
    message: "User rejected", dataJson: nil)
check(try session.finishDrain()?.mailbox == w.mailbox, "W retired")

// 8. End.
let end = try session.end(now: now, reason: "done")
let endMsg = try dapp.open(now: now, mailboxId: end.mailbox, envelope: end.envelope)
check(endMsg.body == .sessionEnd(reason: "done"), "session.end")
check(session.isEnded(), "ended")

// 9. OHTTP client surface (the gateway round trip runs in bindings/uniffi/tests/ohttp.rs).
let cfg: [UInt8] = [7, 0x00, 0x20] + [UInt8](repeating: 9, count: 32) + [0, 4, 0, 1, 0, 3]
let pin = try ohttpSelectKey(keyConfigs: Data([0, UInt8(cfg.count)] + cfg))
let ohttp = try OhttpClient(keyConfig: pin)
check(ohttp.keyId() == 7, "ohttp key id")
let enc = try ohttp.encapsulate(request: OhttpRequest(
    method: "GET", scheme: "https", authority: "relay.example", path: "/v1/info",
    headers: [HttpHeader(name: "accept", value: "application/json")], body: Data()))
check([UInt8](enc.body.prefix(7)) == [7, 0, 0x20, 0, 1, 0, 3], "ohttp header")
do {
    // Rotation only accepts an answer produced under the pinned key.
    _ = try enc.context.decapsulateKeyRotation(response: Data(repeating: 0, count: 64))
    check(false, "rotation from an unauthenticated response")
} catch XchonnectError.Decrypt {}

print("swift round trip OK (SAS \(dappSas))")
