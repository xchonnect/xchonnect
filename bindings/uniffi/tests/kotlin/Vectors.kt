// The published test vectors (docs/spec/vectors/) driven through the generated Kotlin
// bindings (TASK-33 AC3 + AC4). Run with scripts/test-bindings-native.sh.
//
// Mirrors bindings/uniffi/tests/swift/vectors/main.swift: the Kotlin package must
// reproduce every published vector byte for byte, and every negative vector must surface
// as the typed `XchonnectException` subclass the vector names, with a message that
// carries no key material.
import java.io.File
import java.security.MessageDigest
import kotlin.system.exitProcess
import xchonnect.uniffi.*

// --- tiny test harness ----------------------------------------------------------------

var checks = 0

fun fail(what: String): Nothing {
    System.err.println("FAIL: $what")
    exitProcess(1)
}

fun check(cond: Boolean, what: String) {
    checks++
    if (!cond) fail(what)
}

fun same(got: String, want: String, what: String) {
    checks++
    if (got != want) fail("$what: got $got, want $want")
}

// --- encodings ------------------------------------------------------------------------

fun hexToBytes(hex: String): ByteArray {
    if (hex.length % 2 != 0) fail("odd hex length: $hex")
    return ByteArray(hex.length / 2) {
        hex.substring(it * 2, it * 2 + 2).toInt(16).toByte()
    }
}

fun toHex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

private val B64 = java.util.Base64.getUrlEncoder().withoutPadding()
private val B64D = java.util.Base64.getUrlDecoder()

fun b64url(b: ByteArray): String = B64.encodeToString(b)
fun fromB64url(s: String): ByteArray = B64D.decode(s)
fun hexOfB64url(s: String): String = toHex(fromB64url(s))
fun b64urlOfHex(s: String): String = b64url(hexToBytes(s))
fun sha256Hex(b: ByteArray): String = toHex(MessageDigest.getInstance("SHA-256").digest(b))

// --- a minimal JSON reader ------------------------------------------------------------
// The vector files are plain JSON; pulling in a dependency for the test runner would
// only widen what has to be trusted.

sealed class Json {
    data class Str(val value: String) : Json()
    data class Num(val value: Double) : Json()
    data class Bool(val value: Boolean) : Json()
    object Null : Json()
    data class Arr(val items: List<Json>) : Json()
    data class Obj(val fields: Map<String, Json>) : Json()
}

class JsonParser(private val s: String) {
    private var i = 0

    fun parse(): Json {
        val v = value()
        ws()
        if (i != s.length) fail("trailing JSON at $i")
        return v
    }

    private fun ws() {
        while (i < s.length && s[i].isWhitespace()) i++
    }

    private fun value(): Json {
        ws()
        return when (s[i]) {
            '{' -> obj()
            '[' -> arr()
            '"' -> Json.Str(string())
            't' -> { expect("true"); Json.Bool(true) }
            'f' -> { expect("false"); Json.Bool(false) }
            'n' -> { expect("null"); Json.Null }
            else -> number()
        }
    }

    private fun expect(lit: String) {
        if (!s.startsWith(lit, i)) fail("expected $lit at $i")
        i += lit.length
    }

    private fun obj(): Json {
        i++ // {
        val out = LinkedHashMap<String, Json>()
        ws()
        if (s[i] == '}') { i++; return Json.Obj(out) }
        while (true) {
            ws()
            val k = string()
            ws()
            expect(":")
            out[k] = value()
            ws()
            when (s[i]) {
                ',' -> i++
                '}' -> { i++; return Json.Obj(out) }
                else -> fail("expected , or } at $i")
            }
        }
    }

    private fun arr(): Json {
        i++ // [
        val out = ArrayList<Json>()
        ws()
        if (s[i] == ']') { i++; return Json.Arr(out) }
        while (true) {
            out.add(value())
            ws()
            when (s[i]) {
                ',' -> i++
                ']' -> { i++; return Json.Arr(out) }
                else -> fail("expected , or ] at $i")
            }
        }
    }

    private fun string(): String {
        expect("\"")
        val sb = StringBuilder()
        while (s[i] != '"') {
            if (s[i] == '\\') {
                i++
                when (val c = s[i]) {
                    '"', '\\', '/' -> sb.append(c)
                    'b' -> sb.append('\b')
                    'f' -> sb.append('\u000C')
                    'n' -> sb.append('\n')
                    'r' -> sb.append('\r')
                    't' -> sb.append('\t')
                    'u' -> { sb.append(s.substring(i + 1, i + 5).toInt(16).toChar()); i += 4 }
                    else -> fail("bad escape \\$c")
                }
                i++
            } else {
                sb.append(s[i++])
            }
        }
        i++
        return sb.toString()
    }

    private fun number(): Json {
        val start = i
        while (i < s.length && (s[i].isDigit() || s[i] in "-+.eE")) i++
        return Json.Num(s.substring(start, i).toDouble())
    }
}

fun Json.obj(): Map<String, Json> = (this as? Json.Obj)?.fields ?: fail("not an object")
fun Json.arr(): List<Json> = (this as? Json.Arr)?.items ?: fail("not an array")
fun Map<String, Json>.str(k: String): String =
    (this[k] as? Json.Str)?.value ?: fail("field $k is not a string")
fun Map<String, Json>.optStr(k: String): String? = (this[k] as? Json.Str)?.value
fun Map<String, Json>.num(k: String): ULong =
    ((this[k] as? Json.Num)?.value ?: fail("field $k is not a number")).toLong().toULong()
fun Map<String, Json>.sub(k: String): Map<String, Json> =
    (this[k] as? Json.Obj)?.fields ?: fail("field $k is not an object")

val vectorDir: File =
    File(System.getenv("XCHONNECT_VECTORS") ?: "docs/spec/vectors")

fun load(name: String): Map<String, Json> {
    val f = File(vectorDir, name)
    if (!f.isFile) fail("cannot read ${f.path}")
    return JsonParser(f.readText()).parse().obj()
}

fun cases(file: Map<String, Json>): List<Map<String, Json>> =
    (file["cases"] ?: fail("no cases")).arr().map { it.obj() }

/** `<base>_hex`, or `<base>_segments` (literal hex and `repeat`/`count` runs). */
fun bytesOf(o: Map<String, Json>, base: String): ByteArray {
    o.optStr("${base}_hex")?.let { return hexToBytes(it) }
    val segs = (o["${base}_segments"] ?: fail("no ${base}_hex or ${base}_segments")).arr()
    val out = java.io.ByteArrayOutputStream()
    for (seg in segs) {
        val s = seg.obj()
        val hex = s.optStr("hex")
        if (hex != null) {
            out.write(hexToBytes(hex))
        } else {
            val unit = hexToBytes(s.str("repeat"))
            var n = s.num("count")
            while (n > 0UL) { out.write(unit); n-- }
        }
    }
    return out.toByteArray()
}

fun direction(o: Map<String, Json>): UByte =
    if (o.str("direction") == "dapp_to_wallet") 1u else 2u

// --- typed errors ---------------------------------------------------------------------

/**
 * The vector's `expected_error` kind for a thrown exception, plus its message. Every
 * generated `XchonnectException` subclass is listed; an unknown one is a failure rather
 * than a silent pass.
 */
fun kindAndMessage(e: Throwable): Pair<String, String> {
    val message = e.message ?: ""
    val kind = when (e) {
        is XchonnectException.Cbor -> "cbor"
        is XchonnectException.Malformed -> "malformed"
        is XchonnectException.UnsupportedVersion -> "unsupported_version"
        is XchonnectException.Decrypt -> "decrypt"
        is XchonnectException.TooLarge -> "too_large"
        is XchonnectException.Replay -> "replay"
        is XchonnectException.Expired -> "expired"
        is XchonnectException.LifetimeTooLong -> "lifetime_too_long"
        is XchonnectException.ClockSkew -> "clock_skew"
        is XchonnectException.InvalidUri -> "invalid_uri"
        is XchonnectException.UriExpired -> "uri_expired"
        is XchonnectException.InvalidOrigin -> "invalid_origin"
        is XchonnectException.BadSignature -> "bad_signature"
        is XchonnectException.State -> "state"
        is XchonnectException.AlreadyPaired -> "already_paired"
        is XchonnectException.WeakKey -> "weak_key"
        is XchonnectException.PowInvalid -> "pow_invalid"
        is XchonnectException.Crypto -> "crypto"
        is XchonnectException.OhttpKeyMismatch -> "ohttp_key_mismatch"
        is XchonnectException.InvalidInput -> "invalid_input"
        is XchonnectException.Other -> "other"
        else -> fail("not an XchonnectException: ${e::class.qualifiedName}: $message")
    }
    return Pair(kind, message)
}

fun expectError(expected: String, id: String, secrets: List<String>, body: () -> Unit) {
    checks++
    try {
        body()
        fail("$id: expected $expected, but it succeeded")
    } catch (e: Throwable) {
        val (kind, message) = kindAndMessage(e)
        if (kind != expected) fail("$id: expected $expected, got $kind ($message)")
        if (message.isEmpty()) fail("$id: typed error carries an empty message")
        for (s in secrets) {
            if (s.isNotEmpty() && message.contains(s)) fail("$id: error message leaked $s: $message")
        }
    }
}

// --- the run --------------------------------------------------------------------------

lateinit var pairingCases: List<Map<String, Json>>

fun pairingCase(name: String): Map<String, Json> =
    pairingCases.firstOrNull { it.str("name") == name } ?: fail("no pairing case $name")

/** The dApp of a pairing case, rebuilt from its explicit `dsk` and pairing secret. */
fun dappOf(c: Map<String, Json>): TestDapp {
    val i = c.sub("inputs")
    val o = c.sub("outputs")
    return TestDapp.fromVector(
        i.num("created_at"),
        i.str("relay"),
        i.str("domain"),
        b64urlOfHex(i.str("pairing_mailbox_hex")),
        b64urlOfHex(i.str("pairing_write_token_hex")),
        i.num("lifetime_s"),
        i.str("kid"),
        i.optStr("ticket_hex")?.let { b64urlOfHex(it) },
        b64urlOfHex(i.str("dsk_hex")),
        b64urlOfHex(i.str("pairing_secret_hex")),
        b64urlOfHex(o.str("origin_signature_hex")),
        b64urlOfHex(o.str("origin_pk_hex")),
    )
}

fun main() {
    pairingCases = cases(load("pairing.json"))

    // --- pairing.json ---------------------------------------------------------------
    for (c in pairingCases) {
        val name = c.str("name")
        val i = c.sub("inputs")
        val o = c.sub("outputs")

        val info = inspectUri(o.str("uri"), false)
        same(info.relay, i.str("relay"), "$name relay")
        same(info.domain, i.str("domain"), "$name domain")
        check(info.expiresAt == o.num("expires_at"), "$name expiresAt")
        same(info.kid, i.str("kid"), "$name kid")

        val verified =
            VerifiedPairingUri(o.str("uri"), o.str("origin_document"), i.num("reply_at"), false)
        same(verified.relay(), i.str("relay"), "$name verified relay")

        val w = NewMailbox(
            b64urlOfHex(i.str("wallet_mailbox_hex")),
            generateToken(),
            b64urlOfHex(i.str("wallet_write_token_hex")),
        )
        val reply = vectorWalletReply(
            o.str("uri"),
            o.str("origin_document"),
            i.num("reply_at"),
            w,
            i.optStr("wallet_name")?.let { WalletMetadata(name = it) },
            b64urlOfHex(i.str("ikm_e_hex")),
        )
        same(hexOfB64url(reply.outgoing.envelope), o.str("envelope_hex"), "$name reply envelope")
        same(hexOfB64url(reply.outgoing.mailbox), i.str("pairing_mailbox_hex"), "$name reply mailbox")
        same(reply.pairing.sas(), o.str("sas_display"), "$name SAS display")
        same(reply.pairing.sasDigits(), o.str("sas_digits"), "$name SAS digits")

        val dapp = dappOf(c)
        same(dapp.pairingUri(), o.str("uri"), "$name rebuilt dApp URI")
        same(dapp.onReply(i.num("reply_at"), reply.outgoing.envelope), o.str("sas_display"),
             "$name dApp SAS")

        val keys = JsonParser(vectorEpochKeys(b64urlOfHex(o.str("root_0_hex")))).parse().obj()
        same(hexOfB64url(keys.str("d2w")), o.str("k_d2w_hex"), "$name k_d2w")
        same(hexOfB64url(keys.str("w2d")), o.str("k_w2d_hex"), "$name k_w2d")
        same(hexOfB64url(keys.str("ck")), o.str("ck_0_hex"), "$name ck_0")
        same(keys.str("sas"), o.str("sas_digits"), "$name derived SAS digits")
    }

    // --- envelope.json --------------------------------------------------------------
    val envelopeCases = cases(load("envelope.json"))
    check(envelopeCases.size == 5, "one envelope case per padding bucket")
    for (c in envelopeCases) {
        val name = c.str("name")
        val inner = bytesOf(c, "inner_cbor")
        check(inner.size.toULong() == c.num("inner_cbor_len"), "$name inner length")
        same(sha256Hex(inner), c.str("inner_cbor_sha256_hex"), "$name inner digest")

        val key = b64urlOfHex(c.str("key_hex"))
        val mbx = b64urlOfHex(c.str("recipient_mailbox_hex"))
        same(hexOfB64url(vectorAad(direction(c), mbx)), c.str("aad_hex"), "$name AAD")

        val sealed = vectorSealSession(
            key, b64urlOfHex(c.str("nonce_hex")), direction(c), mbx, b64url(inner))
        val env = fromB64url(sealed)
        check(env.size.toULong() == c.num("envelope_len"), "$name envelope length")
        same(sha256Hex(env), c.str("envelope_sha256_hex"), "$name envelope digest")
        c.optStr("envelope_hex")?.let { same(toHex(env), it, "$name envelope bytes") }
        same(toHex(env.copyOfRange(env.size - 16, env.size)), c.str("tag_hex"), "$name tag")

        same(hexOfB64url(vectorOpenSession(key, direction(c), mbx, sealed)), toHex(inner),
             "$name round trip")
    }

    // --- rotation.json --------------------------------------------------------------
    val rotationCases = cases(load("rotation.json"))
    same(rotationCases[0].sub("inputs").str("ck_e_hex"),
         pairingCase("basic").sub("outputs").str("ck_0_hex"), "rotation chains from pairing")
    for (c in rotationCases) {
        val name = c.str("name")
        val i = c.sub("inputs")
        val o = c.sub("outputs")
        val r = JsonParser(vectorRotate(
            b64urlOfHex(i.str("ck_e_hex")), b64urlOfHex(i.str("a_hex")),
            b64urlOfHex(i.str("b_hex")), o.num("new_epoch"))).parse().obj()
        same(hexOfB64url(r.str("aPub")), o.str("a_pub_hex"), "$name A")
        same(hexOfB64url(r.str("bPub")), o.str("b_pub_hex"), "$name B")
        same(hexOfB64url(r.str("root")), o.str("root_hex"), "$name root")
        val keys = JsonParser(vectorEpochKeys(r.str("root"))).parse().obj()
        same(hexOfB64url(keys.str("d2w")), o.str("k_d2w_hex"), "$name k_d2w")
        same(hexOfB64url(keys.str("w2d")), o.str("k_w2d_hex"), "$name k_w2d")
        same(hexOfB64url(keys.str("ck")), o.str("ck_hex"), "$name ck")
    }

    // --- negative.json --------------------------------------------------------------
    // `session_receive` needs a restored session pinned to a given last-accepted seq;
    // the wallet API has no deterministic constructor for that, so those cases are
    // covered by the Rust suite (crates/core/src/vectors.rs) instead.
    var covered = 0
    val skipped = HashSet<String>()
    for (c in cases(load("negative.json"))) {
        val id = c.str("id")
        val expected = c.str("expected_error")
        when (c.str("check")) {
            "verify_uri" -> {
                covered++
                expectError(expected, id, listOf(c.str("uri"))) {
                    VerifiedPairingUri(
                        c.str("uri"), c.str("origin_document"), c.num("now"), false)
                }
            }
            "dapp_on_reply" -> {
                covered++
                val dapp = dappOf(pairingCase(c.str("pairing_case")))
                expectError(expected, id, listOf(c.str("envelope_hex"))) {
                    dapp.onReply(c.num("now"), b64urlOfHex(c.str("envelope_hex")))
                }
            }
            "decode_envelope" -> {
                covered++
                val env = b64url(bytesOf(c, "envelope"))
                expectError(expected, id, listOf()) { vectorDecodeEnvelope(env) }
            }
            "open_session" -> {
                covered++
                expectError(expected, id, listOf(c.str("key_hex"))) {
                    vectorOpenSession(
                        b64urlOfHex(c.str("key_hex")), direction(c),
                        b64urlOfHex(c.str("recipient_mailbox_hex")),
                        b64urlOfHex(c.str("envelope_hex")))
                }
            }
            "seal_session" -> {
                covered++
                val inner = b64url(bytesOf(c, "inner_cbor"))
                expectError(expected, id, listOf(c.str("key_hex"))) {
                    vectorSealSession(
                        b64urlOfHex(c.str("key_hex")), b64urlOfHex(c.str("nonce_hex")),
                        direction(c), b64urlOfHex(c.str("recipient_mailbox_hex")), inner)
                }
            }
            else -> skipped.add(c.str("check"))
        }
    }
    check(skipped == setOf("session_receive"), "only session_receive is skipped, got $skipped")
    check(covered >= 20, "expected at least 20 negative cases, ran $covered")

    // Boundary input errors are typed too, and never echo the rejected value.
    expectError("invalid_input", "non-base64url token", listOf("not-a-token!!")) {
        tokenHash("not-a-token!!")
    }
    expectError("invalid_uri", "not a pairing URI", listOf("https://evil.example/secret")) {
        inspectUri("https://evil.example/secret", false)
    }

    println("kotlin vectors OK ($checks checks, $covered negative cases)")
}
