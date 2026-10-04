// Pairing round trip through the generated Kotlin bindings against the core's dApp side
// (`TestDapp`, test-helpers feature). Run with scripts/test-kotlin.sh (needs a JDK,
// kotlinc and the JNA jar).
import xchonnect.uniffi.*

fun check(cond: Boolean, what: String) {
    if (!cond) {
        System.err.println("FAIL: $what")
        kotlin.system.exitProcess(1)
    }
}

fun main() {
    val now = (System.currentTimeMillis() / 1000).toULong()
    val dapp = TestDapp(now)

    // 1. Scan, fetch origin document (from the test dApp), verify.
    val uri = dapp.pairingUri()
    val info = inspectUri(uri, false)
    check(info.domain == "pengui.xyz", "domain")
    val verified = VerifiedPairingUri(uri, dapp.originDocumentJson(), now, false)
    check(verified.dappName() == "Pengui", "dapp name")
    check(verified.domainDisplay().warnings.isEmpty(), "no domain warnings")

    // 2. Mailbox W (relay simulated) and reply.
    val tokens = generateMailboxTokens()
    val w = NewMailbox(dapp.fakeMailboxId(), tokens.readToken, tokens.writeToken)
    val reply = verified.reply(now, w, WalletMetadata(name = "KotlinWallet"))

    // 3. Same SAS on both sides.
    val dappSas = dapp.onReply(now, reply.outgoing.envelope)
    check(dappSas == reply.pairing.sas(), "SAS matches")

    // 4. Confirm and activate.
    val confirm = dapp.confirm(now)
    check(confirm.mailbox == w.mailbox, "confirm to W")
    var session = reply.pairing.onConfirm(now, confirm.envelope)
    val ready = session.confirmSas(now, null)!!
    dapp.open(now, ready.mailbox, ready.envelope)
    dapp.confirmSas(now)
    check(session.isActive() && dapp.isActive(), "both active")

    // 5. Request / response.
    val req = dapp.request(now, "chip0002_chainId", "{}")
    val msg = session.open(now, session.ownMailbox().mailbox, req.envelope)
    val body = msg.body
    check(body is MessageBody.RpcRequest && body.canonicalMethod == "chainId", "request")
    val resp = session.respond(now, msg.id, "\"mainnet\"")
    val back = dapp.open(now, resp.mailbox, resp.envelope).body
    check(
        back is MessageBody.RpcResponse && back.requestId == req.id &&
            back.outcome == RpcOutcome.Success("\"mainnet\""),
        "response",
    )
    try {
        session.open(now, session.ownMailbox().mailbox, req.envelope)
        check(false, "replay accepted")
    } catch (e: XchonnectException.Replay) {
        // expected
    }

    // 6. Persist / restore.
    session = Session.fromBytes(session.toBytes())

    // 7. dApp-initiated rotation.
    val offerOut = dapp.beginRotation(now)
    val offer = session.open(now, session.ownMailbox().mailbox, offerOut.envelope).body
    check(offer is MessageBody.RotationOffered, "offer")
    val t2 = generateMailboxTokens()
    val w2 = NewMailbox(dapp.fakeMailboxId(), t2.readToken, t2.writeToken)
    val accept = session.acceptRotation(now, (offer as MessageBody.RotationOffered).offer, w2)
    dapp.open(now, accept.outgoing.mailbox, accept.outgoing.envelope)
    check(session.epoch() == 1UL && dapp.epoch() == 1UL, "epoch 1")
    val req2 = dapp.request(now, "getPublicKeys", "{}")
    val msg2 = session.open(now, w2.mailbox, req2.envelope)
    session.respondError(now, msg2.id, rpcErrorCodeValue(RpcErrorCode.USER_REJECTED), "User rejected", null)
    check(session.finishDrain()?.mailbox == w.mailbox, "W retired")

    // 8. End.
    val end = session.end(now, "done")
    check(dapp.open(now, end.mailbox, end.envelope).body == MessageBody.SessionEnd("done"), "end")
    check(session.isEnded(), "ended")
    println("kotlin round trip OK (SAS $dappSas)")
}
