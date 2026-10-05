// The published test vectors (docs/spec/vectors/) driven through the generated Swift
// bindings (TASK-33 AC3 + AC4). Run with scripts/test-bindings-native.sh.
//
// Two things are proved here: the Swift package reproduces every published vector byte
// for byte, and every negative vector surfaces as the *typed* `XchonnectError` case the
// vector names, with a message that carries no key material.
import CryptoKit
import Foundation

// --- tiny test harness ----------------------------------------------------------------

var checks = 0
func check(_ cond: Bool, _ what: String, line: Int = #line) {
    checks += 1
    if !cond {
        FileHandle.standardError.write("FAIL line \(line): \(what)\n".data(using: .utf8)!)
        exit(1)
    }
}

func same(_ got: String, _ want: String, _ what: String, line: Int = #line) {
    check(got == want, "\(what): got \(got), want \(want)", line: line)
}

func fail(_ what: String, line: Int = #line) -> Never {
    FileHandle.standardError.write("FAIL line \(line): \(what)\n".data(using: .utf8)!)
    exit(1)
}

// --- encodings ------------------------------------------------------------------------

func hexToData(_ hex: String, line: Int = #line) -> Data {
    var out = Data(capacity: hex.count / 2)
    var it = hex.startIndex
    while it < hex.endIndex {
        let next = hex.index(it, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
        guard next > it, let b = UInt8(hex[it..<next], radix: 16) else { fail("bad hex \(hex)", line: line) }
        out.append(b)
        it = next
    }
    return out
}

func toHex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

func b64url(_ d: Data) -> String {
    d.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

func fromB64url(_ s: String, line: Int = #line) -> Data {
    var t = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    while t.count % 4 != 0 { t += "=" }
    guard let d = Data(base64Encoded: t) else { fail("bad base64url \(s)", line: line) }
    return d
}

func hexOfB64url(_ s: String) -> String { toHex(fromB64url(s)) }
func b64urlOfHex(_ s: String) -> String { b64url(hexToData(s)) }
func sha256Hex(_ d: Data) -> String { toHex(Data(SHA256.hash(data: d))) }

// --- vector files ---------------------------------------------------------------------

typealias Obj = [String: Any]

let vectorDir: URL = {
    if let p = ProcessInfo.processInfo.environment["XCHONNECT_VECTORS"] {
        return URL(fileURLWithPath: p, isDirectory: true)
    }
    return URL(fileURLWithPath: "docs/spec/vectors", isDirectory: true)
}()

func load(_ name: String) -> Obj {
    let url = vectorDir.appendingPathComponent(name)
    guard let data = try? Data(contentsOf: url),
        let json = try? JSONSerialization.jsonObject(with: data) as? Obj
    else { fail("cannot read \(url.path)") }
    return json
}

func cases(_ file: Obj, _ name: String) -> [Obj] {
    guard let c = file["cases"] as? [Obj] else { fail("\(name) has no cases") }
    return c
}

func str(_ o: Obj, _ k: String, line: Int = #line) -> String {
    guard let v = o[k] as? String else { fail("field \(k) is not a string", line: line) }
    return v
}
func optStr(_ o: Obj, _ k: String) -> String? { o[k] as? String }
func num(_ o: Obj, _ k: String, line: Int = #line) -> UInt64 {
    guard let v = o[k] as? NSNumber else { fail("field \(k) is not a number", line: line) }
    return v.uint64Value
}
func obj(_ o: Obj, _ k: String, line: Int = #line) -> Obj {
    guard let v = o[k] as? Obj else { fail("field \(k) is not an object", line: line) }
    return v
}

/// `<base>_hex`, or `<base>_segments` (literal hex and `repeat`/`count` runs).
func bytesOf(_ o: Obj, _ base: String, line: Int = #line) -> Data {
    if let hex = o["\(base)_hex"] as? String { return hexToData(hex) }
    guard let segs = o["\(base)_segments"] as? [Obj] else {
        fail("no \(base)_hex or \(base)_segments", line: line)
    }
    var out = Data()
    for s in segs {
        if let hex = s["hex"] as? String {
            out.append(hexToData(hex))
        } else {
            let unit = hexToData(str(s, "repeat"))
            for _ in 0..<num(s, "count") { out.append(unit) }
        }
    }
    return out
}

func direction(_ o: Obj) -> UInt8 { str(o, "direction") == "dapp_to_wallet" ? 1 : 2 }

// --- typed errors ---------------------------------------------------------------------

/// The vector's `expected_error` kind for a thrown error, plus its message. Every case
/// of the generated `XchonnectError` enum is listed, so a new variant stops compiling.
func kindAndMessage(_ error: Error) -> (kind: String, message: String) {
    guard let e = error as? XchonnectError else {
        fail("not an XchonnectError: \(error)")
    }
    switch e {
    case .Cbor(let m): return ("cbor", m)
    case .Malformed(let m): return ("malformed", m)
    case .UnsupportedVersion(let m): return ("unsupported_version", m)
    case .Decrypt(let m): return ("decrypt", m)
    case .TooLarge(let m): return ("too_large", m)
    case .Replay(let m): return ("replay", m)
    case .Expired(let m): return ("expired", m)
    case .LifetimeTooLong(let m): return ("lifetime_too_long", m)
    case .ClockSkew(let m): return ("clock_skew", m)
    case .InvalidUri(let m): return ("invalid_uri", m)
    case .UriExpired(let m): return ("uri_expired", m)
    case .InvalidOrigin(let m): return ("invalid_origin", m)
    case .BadSignature(let m): return ("bad_signature", m)
    case .State(let m): return ("state", m)
    case .AlreadyPaired(let m): return ("already_paired", m)
    case .WeakKey(let m): return ("weak_key", m)
    case .PowInvalid(let m): return ("pow_invalid", m)
    case .Crypto(let m): return ("crypto", m)
    case .OhttpKeyMismatch(let m): return ("ohttp_key_mismatch", m)
    case .InvalidInput(let m): return ("invalid_input", m)
    case .Other(let m): return ("other", m)
    }
}

/// `body` must throw the typed error the vector expects; its message must not echo any
/// of `secrets`.
func expectError(_ expected: String, _ id: String, secrets: [String], _ body: () throws -> Void) {
    checks += 1
    do {
        try body()
        fail("\(id): expected \(expected), but it succeeded")
    } catch {
        let (kind, message) = kindAndMessage(error)
        if kind != expected { fail("\(id): expected \(expected), got \(kind) (\(message))") }
        if message.isEmpty { fail("\(id): typed error carries an empty message") }
        for s in secrets where !s.isEmpty && message.contains(s) {
            fail("\(id): error message leaked \(s): \(message)")
        }
    }
}

// --- pairing.json ---------------------------------------------------------------------

let pairingFile = load("pairing.json")
let pairingCases = cases(pairingFile, "pairing.json")

func pairingCase(_ name: String) -> Obj {
    guard let c = pairingCases.first(where: { str($0, "name") == name }) else {
        fail("no pairing case \(name)")
    }
    return c
}

/// The dApp of a pairing case, rebuilt from its explicit `dsk` and pairing secret.
func dappOf(_ c: Obj) throws -> TestDapp {
    let i = obj(c, "inputs")
    let o = obj(c, "outputs")
    return try TestDapp.fromVector(
        now: num(i, "created_at"),
        relay: str(i, "relay"),
        domain: str(i, "domain"),
        pairingMailbox: b64urlOfHex(str(i, "pairing_mailbox_hex")),
        pairingWriteToken: b64urlOfHex(str(i, "pairing_write_token_hex")),
        lifetimeS: num(i, "lifetime_s"),
        kid: str(i, "kid"),
        ticket: optStr(i, "ticket_hex").map(b64urlOfHex),
        dsk: b64urlOfHex(str(i, "dsk_hex")),
        pairingSecret: b64urlOfHex(str(i, "pairing_secret_hex")),
        signature: b64urlOfHex(str(o, "origin_signature_hex")),
        originPk: b64urlOfHex(str(o, "origin_pk_hex")))
}

for c in pairingCases {
    let name = str(c, "name")
    let i = obj(c, "inputs")
    let o = obj(c, "outputs")

    // The published URI parses to the published public fields.
    let info = try inspectUri(uri: str(o, "uri"), developerMode: false)
    same(info.relay, str(i, "relay"), "\(name) relay")
    same(info.domain, str(i, "domain"), "\(name) domain")
    check(info.expiresAt == num(o, "expires_at"), "\(name) expiresAt")
    same(info.kid, str(i, "kid"), "\(name) kid")

    // The origin signature verifies against the published origin document.
    let verified = try VerifiedPairingUri(
        uri: str(o, "uri"), originDocumentJson: str(o, "origin_document"),
        now: num(i, "reply_at"), developerMode: false)
    same(verified.relay(), str(i, "relay"), "\(name) verified relay")

    // The wallet's reply envelope is reproduced byte for byte, and both sides agree on
    // the SAS.
    let w = NewMailbox(
        mailbox: b64urlOfHex(str(i, "wallet_mailbox_hex")),
        readToken: generateToken(),
        writeToken: b64urlOfHex(str(i, "wallet_write_token_hex")))
    let reply = try vectorWalletReply(
        uri: str(o, "uri"), originDocumentJson: str(o, "origin_document"),
        now: num(i, "reply_at"), ownMailbox: w,
        meta: optStr(i, "wallet_name").map { WalletMetadata(name: $0) },
        ikmE: b64urlOfHex(str(i, "ikm_e_hex")))
    same(hexOfB64url(reply.outgoing.envelope), str(o, "envelope_hex"), "\(name) reply envelope")
    same(hexOfB64url(reply.outgoing.mailbox), str(i, "pairing_mailbox_hex"), "\(name) reply mailbox")
    same(reply.pairing.sas(), str(o, "sas_display"), "\(name) SAS display")
    same(reply.pairing.sasDigits(), str(o, "sas_digits"), "\(name) SAS digits")

    let dapp = try dappOf(c)
    same(try dapp.pairingUri(), str(o, "uri"), "\(name) rebuilt dApp URI")
    same(try dapp.onReply(now: num(i, "reply_at"), envelope: reply.outgoing.envelope),
         str(o, "sas_display"), "\(name) dApp SAS")

    // Epoch keys and the SAS derive from the published root key.
    let keys = try JSONSerialization.jsonObject(
        with: Data(try vectorEpochKeys(root: b64urlOfHex(str(o, "root_0_hex"))).utf8)) as! Obj
    same(hexOfB64url(str(keys, "d2w")), str(o, "k_d2w_hex"), "\(name) k_d2w")
    same(hexOfB64url(str(keys, "w2d")), str(o, "k_w2d_hex"), "\(name) k_w2d")
    same(hexOfB64url(str(keys, "ck")), str(o, "ck_0_hex"), "\(name) ck_0")
    same(str(keys, "sas"), str(o, "sas_digits"), "\(name) derived SAS digits")
}

// --- envelope.json --------------------------------------------------------------------

let envelopeCases = cases(load("envelope.json"), "envelope.json")
check(envelopeCases.count == 5, "one envelope case per padding bucket")
for c in envelopeCases {
    let name = str(c, "name")
    let inner = bytesOf(c, "inner_cbor")
    check(UInt64(inner.count) == num(c, "inner_cbor_len"), "\(name) inner length")
    same(sha256Hex(inner), str(c, "inner_cbor_sha256_hex"), "\(name) inner digest")

    let key = b64urlOfHex(str(c, "key_hex"))
    let mbx = b64urlOfHex(str(c, "recipient_mailbox_hex"))
    same(hexOfB64url(try vectorAad(dir: direction(c), recipientMailbox: mbx)),
         str(c, "aad_hex"), "\(name) AAD")

    let sealed = try vectorSealSession(
        key: key, nonce: b64urlOfHex(str(c, "nonce_hex")), dir: direction(c),
        recipientMailbox: mbx, inner: b64url(inner))
    let env = fromB64url(sealed)
    check(UInt64(env.count) == num(c, "envelope_len"), "\(name) envelope length")
    same(sha256Hex(env), str(c, "envelope_sha256_hex"), "\(name) envelope digest")
    if let want = optStr(c, "envelope_hex") { same(toHex(env), want, "\(name) envelope bytes") }
    same(toHex(env.suffix(16)), str(c, "tag_hex"), "\(name) tag")

    let opened = try vectorOpenSession(
        key: key, dir: direction(c), recipientMailbox: mbx, envelopeB64: sealed)
    same(hexOfB64url(opened), toHex(inner), "\(name) round trip")
}

// --- rotation.json --------------------------------------------------------------------

let rotationCases = cases(load("rotation.json"), "rotation.json")
same(str(obj(rotationCases[0], "inputs"), "ck_e_hex"),
     str(obj(pairingCase("basic"), "outputs"), "ck_0_hex"), "rotation chains from pairing")
for c in rotationCases {
    let name = str(c, "name")
    let i = obj(c, "inputs")
    let o = obj(c, "outputs")
    let r = try JSONSerialization.jsonObject(with: Data(try vectorRotate(
        ck: b64urlOfHex(str(i, "ck_e_hex")), a: b64urlOfHex(str(i, "a_hex")),
        b: b64urlOfHex(str(i, "b_hex")), newEpoch: num(o, "new_epoch")).utf8)) as! Obj
    same(hexOfB64url(str(r, "aPub")), str(o, "a_pub_hex"), "\(name) A")
    same(hexOfB64url(str(r, "bPub")), str(o, "b_pub_hex"), "\(name) B")
    same(hexOfB64url(str(r, "root")), str(o, "root_hex"), "\(name) root")
    let keys = try JSONSerialization.jsonObject(
        with: Data(try vectorEpochKeys(root: str(r, "root")).utf8)) as! Obj
    same(hexOfB64url(str(keys, "d2w")), str(o, "k_d2w_hex"), "\(name) k_d2w")
    same(hexOfB64url(str(keys, "w2d")), str(o, "k_w2d_hex"), "\(name) k_w2d")
    same(hexOfB64url(str(keys, "ck")), str(o, "ck_hex"), "\(name) ck")
}

// --- negative.json --------------------------------------------------------------------

// `session_receive` needs a restored session pinned to a given last-accepted seq; the
// wallet API has no deterministic constructor for that, so those cases are covered by
// the Rust suite (crates/core/src/vectors.rs) instead.
let negativeCases = cases(load("negative.json"), "negative.json")
var covered = 0
var skippedChecks = Set<String>()
for c in negativeCases {
    let id = str(c, "id")
    let expected = str(c, "expected_error")
    switch str(c, "check") {
    case "verify_uri":
        covered += 1
        expectError(expected, id, secrets: [str(c, "uri")]) {
            _ = try VerifiedPairingUri(
                uri: str(c, "uri"), originDocumentJson: str(c, "origin_document"),
                now: num(c, "now"), developerMode: false)
        }
    case "dapp_on_reply":
        covered += 1
        let dapp = try dappOf(pairingCase(str(c, "pairing_case")))
        expectError(expected, id, secrets: [str(c, "envelope_hex")]) {
            _ = try dapp.onReply(now: num(c, "now"), envelope: b64urlOfHex(str(c, "envelope_hex")))
        }
    case "decode_envelope":
        covered += 1
        let env = b64url(bytesOf(c, "envelope"))
        expectError(expected, id, secrets: []) { try vectorDecodeEnvelope(envelopeB64: env) }
    case "open_session":
        covered += 1
        expectError(expected, id, secrets: [str(c, "key_hex")]) {
            _ = try vectorOpenSession(
                key: b64urlOfHex(str(c, "key_hex")), dir: direction(c),
                recipientMailbox: b64urlOfHex(str(c, "recipient_mailbox_hex")),
                envelopeB64: b64urlOfHex(str(c, "envelope_hex")))
        }
    case "seal_session":
        covered += 1
        let inner = b64url(bytesOf(c, "inner_cbor"))
        expectError(expected, id, secrets: [str(c, "key_hex")]) {
            _ = try vectorSealSession(
                key: b64urlOfHex(str(c, "key_hex")), nonce: b64urlOfHex(str(c, "nonce_hex")),
                dir: direction(c),
                recipientMailbox: b64urlOfHex(str(c, "recipient_mailbox_hex")), inner: inner)
        }
    case let other:
        skippedChecks.insert(other)
    }
}
check(skippedChecks == ["session_receive"], "only session_receive is skipped, got \(skippedChecks)")
check(covered >= 20, "expected at least 20 negative cases, ran \(covered)")

// Boundary input errors are typed too, and never echo the rejected value.
expectError("invalid_input", "non-base64url token", secrets: ["not-a-token!!"]) {
    _ = try tokenHash(token: "not-a-token!!")
}
expectError("invalid_uri", "not a pairing URI", secrets: ["https://evil.example/secret"]) {
    _ = try inspectUri(uri: "https://evil.example/secret", developerMode: false)
}

// --- encrypted notification preview (spec 7.3.3, TASK-48 AC3/AC4/AC5) -----------------
//
// The two properties a Notification Service Extension depends on: a preview that does
// not authenticate falls back to the generic alert, and the sender's detail line is
// dropped unless the wallet opted in.

let previewHint = b64url(Data(repeating: 0x07, count: 32))
let previewNow: UInt64 = 1_790_000_000
let previewDetail = "1.25 XCH to xch1qq"
let sealedPreview = try vectorSealPreview(
    hintKey: previewHint, kind: 1, detail: previewDetail, now: previewNow, ttlS: 120,
    entropy: b64url(Data(repeating: 0x21, count: 64)))
check(fromB64url(sealedPreview).count == 168, "a sealed preview is 168 bytes")

// Opted in: the kind and the detail line.
switch openNotificationPreview(
    hintKey: previewHint, sealed: sealedPreview, now: previewNow, allowDetail: true) {
case let .decrypted(preview):
    check(preview.kind == .signingRequest, "preview kind: \(preview.kind)")
    same(preview.locKey, "xchonnect.preview.signing_request", "preview locKey")
    same(preview.detail ?? "", previewDetail, "opted-in detail line")
case let .generic(locKey):
    fail("an authentic preview fell back to the generic alert (\(locKey))")
}

// Not opted in: the kind survives, the amount never reaches the lock screen.
switch openNotificationPreview(
    hintKey: previewHint, sealed: sealedPreview, now: previewNow, allowDetail: false) {
case let .decrypted(preview):
    check(preview.kind == .signingRequest, "stripped preview keeps its kind")
    check(preview.detail == nil, "detail line was not stripped: \(preview.detail ?? "")")
    check(!"\(preview)".contains("XCH"), "the amount reached the host: \(preview)")
case let .generic(locKey):
    fail("an authentic preview fell back to the generic alert (\(locKey))")
}

// Anything untrusted is the generic alert, and the call never throws.
var tampered = fromB64url(sealedPreview)
tampered[tampered.count - 1] ^= 1
let fallbacks: [(String, String, String, UInt64)] = [
    ("tampered ciphertext", previewHint, b64url(tampered), previewNow),
    ("wrong hint key", b64url(Data(repeating: 0x08, count: 32)), sealedPreview, previewNow),
    ("truncated", previewHint, b64url(Data(fromB64url(sealedPreview).prefix(8))), previewNow),
    ("empty", previewHint, "", previewNow),
    ("hint key not base64url", "@@@", sealedPreview, previewNow),
    ("sealed not base64url", previewHint, "@@@", previewNow),
    ("replayed after the ttl", previewHint, sealedPreview, previewNow + 121),
]
for (what, hint, sealed, now) in fallbacks {
    switch openNotificationPreview(hintKey: hint, sealed: sealed, now: now, allowDetail: true) {
    case let .generic(locKey):
        same(locKey, "xchonnect.preview.generic", "\(what): generic locKey")
    case let .decrypted(preview):
        fail("\(what) was accepted: \(preview)")
    }
}

print("swift vectors OK (\(checks) checks, \(covered) negative cases)")
