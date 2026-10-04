//! Published test vectors (`docs/spec/vectors/*.json`, spec 5.2, 5.3, 6.2, 6.3, 9.2).
//!
//! Two independent halves:
//!
//! * **Generator** (`gen_*`): drives the real protocol APIs with [`TestEntropy`] and fixed
//!   inputs and renders the JSON files. [`vector_files_are_current`] regenerates them in
//!   memory and requires the committed files to be byte-identical, so any change to bytes
//!   on the wire fails CI until the vectors are regenerated deliberately with
//!
//!   ```text
//!   XCHONNECT_WRITE_VECTORS=1 cargo test -p xchonnect-core --lib vectors
//!   ```
//!
//! * **Checker** (`check_*`): reads the committed JSON, takes the explicit inputs and
//!   re-derives every output from low-level primitives following the spec formulas (not
//!   through the code paths the generator used), then replays the high-level APIs. Every
//!   negative case must fail with the recorded error kind.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use crate::cbor::{self, Value};
use crate::crypto::{
    self, ChainKey, DirectionKey, Ed25519Seed, Entropy, HpkeReceiver, HpkeSender, MailboxId, Psk,
    RootKey, TestEntropy, Token, X25519Secret,
};
use crate::envelope::{self, BUCKETS, Direction, Envelope, Kind, PAIRING_CT_LEN, TAG_LEN};
use crate::error::Error;
use crate::keys::{self, Sas};
use crate::message::{Inner, Message, PairingReply, WalletMeta};
use crate::origin::OriginDocument;
use crate::pairing::{DappPairing, DappPairingParams, UnsignedPairing, VerifiedUri, WalletPairing};
use crate::session::{NewSession, Role, Session};
use crate::uri::{LocalSigner, OriginSigner, PairingUri, ParseOptions};
use serde_json::Value as Json;
use std::path::PathBuf;

// --- Shared helpers ----------------------------------------------------------

/// Format version of the vector files (bump on incompatible layout changes).
const FORMAT: u64 = 1;
/// Runs of at least this many identical bytes are written as a `repeat` segment.
const RUN_MIN: usize = 64;
/// Envelopes up to this size are written out in full; larger ones only as SHA-256.
const ENVELOPE_HEX_MAX: usize = 4200;
const D2W: &str = "xchonnect v1 dapp->wallet";
const W2D: &str = "xchonnect v1 wallet->dapp";
const CHAIN: &str = "xchonnect v1 chain";

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/spec/vectors")
}

/// `start, start+1, …` (wrapping): readable fixed inputs.
fn pattern<const N: usize>(start: u8) -> [u8; N] {
    core::array::from_fn(|i| start.wrapping_add(i as u8))
}

fn draw<const N: usize>(seed: [u8; 32]) -> [u8; N] {
    crypto::random_array(&mut TestEntropy::new(seed))
}

/// Entropy that replays explicit bytes (then zeros). Lets the checker feed the
/// recorded secrets into the production APIs.
struct Replay(std::vec::IntoIter<u8>);

impl Replay {
    fn new(parts: &[&[u8]]) -> Self {
        Replay(parts.concat().into_iter())
    }
}

impl Entropy for Replay {
    fn fill(&mut self, dst: &mut [u8]) {
        dst.fill_with(|| self.0.next().unwrap_or(0));
    }
}

fn error_kind(e: &Error) -> &'static str {
    match e {
        Error::Cbor(_) => "cbor",
        Error::Malformed(_) => "malformed",
        Error::UnsupportedVersion => "unsupported_version",
        Error::Decrypt => "decrypt",
        Error::TooLarge => "too_large",
        Error::Replay => "replay",
        Error::Expired => "expired",
        Error::LifetimeTooLong => "lifetime_too_long",
        Error::ClockSkew => "clock_skew",
        Error::InvalidUri(_) => "invalid_uri",
        Error::UriExpired => "uri_expired",
        Error::InvalidOrigin(_) => "invalid_origin",
        Error::BadSignature => "bad_signature",
        Error::State(_) => "state",
        Error::AlreadyPaired => "already_paired",
        Error::WeakKey => "weak_key",
        Error::PowInvalid => "pow_invalid",
        Error::Crypto(_) => "crypto",
        Error::OhttpKeyMismatch => "ohttp_key_mismatch",
    }
}

const DIRECTIONS: [(Direction, &str); 2] = [
    (Direction::DappToWallet, "dapp_to_wallet"),
    (Direction::WalletToDapp, "wallet_to_dapp"),
];

fn direction_name(d: Direction) -> J {
    s(DIRECTIONS.iter().find(|(x, _)| *x == d).unwrap().1)
}

fn direction_of(v: &Json) -> Direction {
    let name = text(v, "direction");
    DIRECTIONS.iter().find(|(_, n)| *n == name).expect(name).0
}

// --- Ordered JSON with a fixed renderer (independent of serde_json's map ordering) ---

enum J {
    Null,
    Num(u64),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(&'static str, J)>),
}

fn s(v: impl Into<String>) -> J {
    J::Str(v.into())
}

fn h(bytes: &[u8]) -> J {
    J::Str(hex::encode(bytes))
}

fn n(v: usize) -> J {
    J::Num(v as u64)
}

fn render(j: &J, indent: usize, out: &mut String) {
    let (open, close, items): (char, char, Vec<(Option<&str>, &J)>) = match j {
        J::Null => return out.push_str("null"),
        J::Num(n) => return out.push_str(&n.to_string()),
        J::Str(v) => return out.push_str(&serde_json::to_string(v).unwrap()),
        J::Arr(items) if items.is_empty() => return out.push_str("[]"),
        J::Arr(items) => ('[', ']', items.iter().map(|v| (None, v)).collect()),
        J::Obj(fields) => (
            '{',
            '}',
            fields.iter().map(|(k, v)| (Some(*k), v)).collect(),
        ),
    };
    out.push(open);
    for (i, (key, v)) in items.iter().enumerate() {
        out.push_str(if i == 0 { "\n" } else { ",\n" });
        out.push_str(&"  ".repeat(indent + 1));
        if let Some(k) = key {
            out.push_str(&serde_json::to_string(k).unwrap());
            out.push_str(": ");
        }
        render(v, indent + 1, out);
    }
    out.push('\n');
    out.push_str(&"  ".repeat(indent));
    out.push(close);
}

/// A vector file: format header, description and cases.
fn file(description: &str, cases: Vec<J>) -> J {
    J::Obj(vec![
        ("format", J::Num(FORMAT)),
        ("protocol_version", J::Num(envelope::VERSION)),
        ("description", s(description)),
        ("cases", J::Arr(cases)),
    ])
}

/// Byte string as segments: `{"hex": …}` for literal bytes, `{"repeat": "aa",
/// "count": n}` for long runs of one byte.
fn segments(bytes: &[u8]) -> J {
    let mut segs = Vec::new();
    let mut lit_start = 0;
    let mut i = 0;
    while i < bytes.len() {
        let j = i + bytes[i..].iter().take_while(|b| **b == bytes[i]).count();
        if j - i >= RUN_MIN {
            if lit_start < i {
                segs.push(J::Obj(vec![("hex", h(&bytes[lit_start..i]))]));
            }
            segs.push(J::Obj(vec![
                ("repeat", h(&[bytes[i]])),
                ("count", n(j - i)),
            ]));
            lit_start = j;
        }
        i = j;
    }
    if lit_start < bytes.len() {
        segs.push(J::Obj(vec![("hex", h(&bytes[lit_start..]))]));
    }
    J::Arr(segs)
}

/// `(<name>_hex, hex)` without long runs, else `(<name>_segments, segments)`.
fn bytes_field(hex_key: &'static str, seg_key: &'static str, b: &[u8]) -> (&'static str, J) {
    if b.windows(RUN_MIN).any(|w| w.iter().all(|x| *x == w[0])) {
        (seg_key, segments(b))
    } else {
        (hex_key, h(b))
    }
}

// --- Reading JSON in the checker ---------------------------------------------

fn load(name: &str) -> Json {
    let path = vectors_dir().join(name);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap()
}

fn cases(v: &Json) -> &[Json] {
    get(v, "cases").as_array().unwrap()
}

fn get<'a>(v: &'a Json, key: &str) -> &'a Json {
    v.get(key).unwrap_or_else(|| panic!("missing field {key}"))
}

fn text<'a>(v: &'a Json, key: &str) -> &'a str {
    get(v, key)
        .as_str()
        .unwrap_or_else(|| panic!("{key} is not a string"))
}

fn num(v: &Json, key: &str) -> u64 {
    get(v, key)
        .as_u64()
        .unwrap_or_else(|| panic!("{key} is not a number"))
}

fn hx(v: &Json, key: &str) -> Vec<u8> {
    hex::decode(text(v, key)).unwrap_or_else(|_| panic!("{key} is not hex"))
}

fn hx_n<const N: usize>(v: &Json, key: &str) -> [u8; N] {
    hx(v, key)
        .try_into()
        .unwrap_or_else(|_| panic!("{key} must be {N} bytes"))
}

/// Assert that `actual` is byte-for-byte the hex string recorded under `key`.
fn eq_hex(v: &Json, key: &str, actual: impl AsRef<[u8]>, case: &str) {
    assert_eq!(hex::encode(actual), text(v, key), "{case}: {key}");
}

/// Read `<base>_hex` or `<base>_segments`.
fn bytes_of(v: &Json, base: &str) -> Vec<u8> {
    if let Some(Json::String(x)) = v.get(format!("{base}_hex")) {
        return hex::decode(x).unwrap();
    }
    let mut out = Vec::new();
    for seg in get(v, &format!("{base}_segments")).as_array().unwrap() {
        if let Some(Json::String(x)) = seg.get("hex") {
            out.extend(hex::decode(x).unwrap());
        } else {
            let b = hx(seg, "repeat");
            assert_eq!(b.len(), 1);
            out.extend(std::iter::repeat_n(b[0], num(seg, "count") as usize));
        }
    }
    out
}

fn opt_ticket(i: &Json) -> Option<[u8; 32]> {
    (!get(i, "ticket_hex").is_null()).then(|| hx_n(i, "ticket_hex"))
}

fn opt_meta(i: &Json) -> Option<WalletMeta> {
    get(i, "wallet_name").as_str().map(|n| WalletMeta {
        name: Some(n.to_owned()),
        ..Default::default()
    })
}

/// `DappPairing::prepare` fed with the explicit secrets of a pairing case.
fn prepare_from_inputs(i: &Json) -> UnsignedPairing {
    DappPairing::prepare(
        &mut Replay::new(&[&hx(i, "dsk_hex"), &hx(i, "pairing_secret_hex")]),
        num(i, "created_at"),
        text(i, "kid"),
        DappPairingParams {
            relay: text(i, "relay"),
            domain: text(i, "domain"),
            pairing_mailbox: MailboxId(hx_n(i, "pairing_mailbox_hex")),
            pairing_write: Token::from_bytes(hx_n(i, "pairing_write_token_hex")),
            lifetime_s: num(i, "lifetime_s"),
            ticket: opt_ticket(i),
            options: ParseOptions::default(),
        },
    )
    .unwrap()
}

// --- Pairing (spec 5.2, 6.2, 6.3) --------------------------------------------

const KID: &str = "2026-10";
const RELAY: &str = "https://relay.example";
const DOMAIN: &str = "dapp.example";
const CREATED_AT: u64 = 1_790_000_000;
const LIFETIME_S: u64 = 300;

struct PairingCase {
    name: &'static str,
    description: &'static str,
    dapp_seed: [u8; 32],
    wallet_seed: [u8; 32],
    origin_seed: [u8; 32],
    pairing_mailbox: [u8; 16],
    pairing_write: [u8; 32],
    ticket: Option<[u8; 32]>,
    wallet_mailbox: [u8; 16],
    wallet_read: [u8; 32],
    wallet_write: [u8; 32],
    wallet_name: Option<&'static str>,
    reply_at: u64,
}

fn pairing_cases() -> [PairingCase; 2] {
    [
        PairingCase {
            name: "basic",
            description: "Pairing with wallet metadata, no sponsorship ticket",
            dapp_seed: pattern(0x00),
            wallet_seed: pattern(0x20),
            origin_seed: pattern(0x40),
            pairing_mailbox: pattern(0xa0),
            pairing_write: pattern(0xb0),
            ticket: None,
            wallet_mailbox: pattern(0xd0),
            wallet_read: pattern(0xe0),
            wallet_write: pattern(0x60),
            wallet_name: Some("Example Wallet"),
            reply_at: CREATED_AT + 5,
        },
        PairingCase {
            name: "ticket-no-meta",
            description: "Pairing URI carrying a sponsorship ticket (t, not signed); reply without metadata",
            dapp_seed: [0x11; 32],
            wallet_seed: [0x22; 32],
            origin_seed: pattern(0x40),
            pairing_mailbox: [0x33; 16],
            pairing_write: [0x44; 32],
            ticket: Some([0x55; 32]),
            wallet_mailbox: [0x66; 16],
            wallet_read: [0x77; 32],
            wallet_write: [0x88; 32],
            wallet_name: None,
            reply_at: CREATED_AT + 299,
        },
    ]
}

fn origin_document(origin_pk: &[u8; 32]) -> String {
    format!(
        r#"{{"v":1,"name":"Example dApp","origin_keys":[{{"kid":"{KID}","pk":"{}","not_after":"2030-01-01"}}]}}"#,
        crate::b64::encode(origin_pk)
    )
}

fn hpke_info(h_uri: &[u8; 32]) -> Vec<u8> {
    [keys::LABEL_PAIRING_INFO, h_uri].concat()
}

/// Generator output reused by the rotation and negative vectors.
struct PairingOut {
    uri: PairingUri,
    origin_doc: String,
    envelope: Vec<u8>,
    origin_seed: [u8; 32],
    ck0: [u8; 32],
}

fn gen_pairing_case(c: &PairingCase) -> (J, PairingOut) {
    // dApp: DappPairing::prepare draws dsk (32 bytes) then s (32 bytes).
    let mut drng = TestEntropy::new(c.dapp_seed);
    let unsigned = DappPairing::prepare(
        &mut drng,
        CREATED_AT,
        KID,
        DappPairingParams {
            relay: RELAY,
            domain: DOMAIN,
            pairing_mailbox: MailboxId(c.pairing_mailbox),
            pairing_write: Token::from_bytes(c.pairing_write),
            lifetime_s: LIFETIME_S,
            ticket: c.ticket,
            options: ParseOptions::default(),
        },
    )
    .unwrap();
    let sig_input = unsigned.sig_input().unwrap();
    let signer = LocalSigner::new(Ed25519Seed::from_bytes(c.origin_seed), KID).unwrap();
    let origin_pk = signer.public_key();
    let signature = signer.sign(&sig_input).unwrap();
    let mut dapp = unsigned.finish(signature, Some(&origin_pk)).unwrap();
    let uri = dapp.uri().clone();
    let uri_text = uri.to_uri();
    let dsk_and_s: [u8; 64] = draw(c.dapp_seed);
    let (dsk, secret) = dsk_and_s.split_at(32);
    let dsk = X25519Secret::from_slice(dsk).unwrap();
    assert_eq!(dsk.public_key(), uri.dapp_pk);
    assert_eq!(uri.secret.expose().as_slice(), secret);
    let h_uri = uri.h_uri().unwrap();

    // Wallet: the HPKE sender draws ikmE (32 bytes) for DeriveKeyPair.
    let doc_json = origin_document(&origin_pk);
    let doc = OriginDocument::parse(doc_json.as_bytes()).unwrap();
    let parsed = PairingUri::parse(&uri_text, ParseOptions::default()).unwrap();
    let verified = VerifiedUri::new(parsed, &doc, c.reply_at).unwrap();
    let meta = c.wallet_name.map(|n| WalletMeta {
        name: Some(n.to_owned()),
        ..Default::default()
    });
    let reply_pt = PairingReply {
        mailbox: MailboxId(c.wallet_mailbox),
        write_token: Token::from_bytes(c.wallet_write),
        meta: meta.clone(),
    }
    .encode()
    .unwrap();
    let (wallet, out) = WalletPairing::reply(
        &mut TestEntropy::new(c.wallet_seed),
        c.reply_at,
        &verified,
        MailboxId(c.wallet_mailbox),
        Token::from_bytes(c.wallet_read),
        Token::from_bytes(c.wallet_write),
        meta,
    )
    .unwrap();
    let ikm_e: [u8; 32] = draw(c.wallet_seed);
    let env = Envelope::decode(&out.envelope).unwrap();
    let enc: [u8; 32] = env.n.as_slice().try_into().unwrap();
    let th = keys::pairing_transcript(&h_uri, &enc, &env.ct);
    let ctx = keys::root_export_context(&th);
    let psk = Psk {
        psk: secret,
        psk_id: keys::LABEL_PSK_ID,
    };
    let receiver = HpkeReceiver::setup(&dsk, &enc, &hpke_info(&h_uri), Some(psk)).unwrap();
    let root0 = RootKey::from_bytes(receiver.export(&ctx).unwrap());
    let k = keys::epoch_keys(&root0, 0).unwrap();
    let accepted = dapp.on_reply(c.reply_at + 1, &out.envelope).unwrap();
    let sas = accepted.sas();
    assert_eq!(sas, wallet.sas());
    assert_eq!(sas, Sas::derive(&root0).unwrap());

    let inputs = J::Obj(vec![
        ("dapp_entropy_seed_hex", h(&c.dapp_seed)),
        ("wallet_entropy_seed_hex", h(&c.wallet_seed)),
        ("dsk_hex", h(dsk.expose())),
        ("pairing_secret_hex", h(secret)),
        ("ikm_e_hex", h(&ikm_e)),
        ("origin_seed_hex", h(&c.origin_seed)),
        ("kid", s(KID)),
        ("relay", s(RELAY)),
        ("domain", s(DOMAIN)),
        ("pairing_mailbox_hex", h(&c.pairing_mailbox)),
        ("pairing_write_token_hex", h(&c.pairing_write)),
        ("ticket_hex", c.ticket.map_or(J::Null, |t| h(&t))),
        ("created_at", J::Num(CREATED_AT)),
        ("lifetime_s", J::Num(LIFETIME_S)),
        ("wallet_mailbox_hex", h(&c.wallet_mailbox)),
        ("wallet_write_token_hex", h(&c.wallet_write)),
        ("wallet_name", c.wallet_name.map_or(J::Null, s)),
        ("reply_at", J::Num(c.reply_at)),
    ]);
    let outputs = J::Obj(vec![
        ("dpk_hex", h(&uri.dapp_pk)),
        ("origin_pk_hex", h(&origin_pk)),
        ("origin_document", s(doc_json.clone())),
        ("expires_at", J::Num(uri.expires_at)),
        ("uri_sig_input_hex", h(&sig_input)),
        ("h_uri_hex", h(&h_uri)),
        ("origin_signature_hex", h(&signature)),
        ("uri", s(uri_text)),
        ("hpke_info_hex", h(&hpke_info(&h_uri))),
        ("hpke_psk_id_hex", h(keys::LABEL_PSK_ID)),
        (
            "aad_pair_hex",
            h(&[keys::LABEL_PAIRING_AAD, &c.pairing_mailbox].concat()),
        ),
        ("pairing_reply_plaintext_hex", h(&reply_pt)),
        ("pairing_reply_padded_len", n(PAIRING_CT_LEN - TAG_LEN)),
        ("enc_hex", h(&enc)),
        ("ct_pair_hex", h(&env.ct)),
        ("envelope_hex", h(&out.envelope)),
        ("th_hex", h(&th)),
        ("exporter_context_hex", h(&ctx)),
        ("root_0_hex", h(root0.expose())),
        ("k_d2w_hex", h(k.d2w.expose())),
        ("k_w2d_hex", h(k.w2d.expose())),
        ("ck_0_hex", h(k.chain.expose())),
        ("sas_value", J::Num(u64::from(sas.value()))),
        ("sas_digits", s(sas.digits())),
        ("sas_display", s(sas.to_string())),
    ]);
    let case = J::Obj(vec![
        ("name", s(c.name)),
        ("description", s(c.description)),
        ("inputs", inputs),
        ("outputs", outputs),
    ]);
    let out = PairingOut {
        uri,
        origin_doc: doc_json,
        envelope: out.envelope,
        origin_seed: c.origin_seed,
        ck0: *k.chain.expose(),
    };
    (case, out)
}

fn gen_pairing() -> (J, Vec<PairingOut>) {
    let (cases, outs): (Vec<J>, _) = pairing_cases().iter().map(gen_pairing_case).unzip();
    let description = "Pairing handshake (spec 5.2, 6.2, 6.3): pairing URI and origin signature, HPKE PSK pairing reply, transcript hash, root_0, epoch-0 keys and SAS. See README.md.";
    (file(description, cases), outs)
}

/// Percent-encode exactly as `wire/pairing-uri.md` requires (unreserved kept).
fn pct(v: &str) -> String {
    v.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn check_pairing_case(c: &Json) {
    let name = text(c, "name");
    let i = get(c, "inputs");
    let o = get(c, "outputs");
    let b64 = crate::b64::encode;

    // TestEntropy reproduces the explicit secrets (README formula, re-implemented here).
    let te = |seed: &[u8], n: usize| -> Vec<u8> {
        (0u64..)
            .flat_map(|ctr| {
                crypto::sha256_parts(&[b"xchonnect test entropy", seed, &ctr.to_be_bytes()])
            })
            .take(n)
            .collect()
    };
    let dsk_b = hx_n::<32>(i, "dsk_hex");
    let s_b = hx_n::<32>(i, "pairing_secret_hex");
    let ikm_e = hx_n::<32>(i, "ikm_e_hex");
    let dseed = hx_n::<32>(i, "dapp_entropy_seed_hex");
    assert_eq!(te(&dseed, 64), [dsk_b, s_b].concat(), "{name}: dsk||s");
    assert_eq!(
        te(&hx(i, "wallet_entropy_seed_hex"), 32),
        ikm_e,
        "{name}: ikm_e"
    );
    assert_eq!(draw::<64>(dseed).to_vec(), [dsk_b, s_b].concat());

    let dsk = X25519Secret::from_bytes(dsk_b);
    let dpk = dsk.public_key();
    eq_hex(o, "dpk_hex", dpk, name);
    let seed = Ed25519Seed::from_bytes(hx_n(i, "origin_seed_hex"));
    let origin_pk = seed.public_key();
    eq_hex(o, "origin_pk_hex", origin_pk, name);
    let doc_json = text(o, "origin_document");
    assert_eq!(doc_json, origin_document(&origin_pk));

    let (relay, domain, kid) = (text(i, "relay"), text(i, "domain"), text(i, "kid"));
    let mbx_p = hx(i, "pairing_mailbox_hex");
    let w_p = hx(i, "pairing_write_token_hex");
    let x = num(i, "created_at") + num(i, "lifetime_s");
    assert_eq!(x, num(o, "expires_at"));

    // uri_sig_input = canonical_cbor([label, r, mbx_P, wP, dpk, d, x, kid]).
    let sig_input = cbor::encode(&Value::Array(vec![
        Value::text("xchonnect pairing uri v1"),
        Value::text(relay),
        Value::bytes(&mbx_p),
        Value::bytes(&w_p),
        Value::bytes(&dpk),
        Value::text(domain),
        Value::Uint(x),
        Value::text(kid),
    ]))
    .unwrap();
    eq_hex(o, "uri_sig_input_hex", &sig_input, name);
    let h_uri = crypto::sha256_parts(&[&sig_input]);
    eq_hex(o, "h_uri_hex", h_uri, name);
    let sig = seed.sign(&sig_input);
    eq_hex(o, "origin_signature_hex", sig, name);
    crypto::ed25519_verify(&origin_pk, &sig_input, &sig).unwrap();

    let mut uri = format!(
        "xchonnect:v1?r={}&m={}&w={}&k={}&s={}&d={domain}&x={x}&i={kid}&o={}",
        pct(relay),
        b64(&mbx_p),
        b64(&w_p),
        b64(&dpk),
        b64(&s_b),
        b64(&sig)
    );
    if let Some(t) = opt_ticket(i) {
        uri.push_str(&format!("&t={}", b64(&t)));
    }
    assert_eq!(uri, text(o, "uri"), "{name}: uri");

    // HPKE mode_psk: sender with ikmE, receiver with dsk.
    let info = [b"xchonnect v1 pairing".as_slice(), &h_uri].concat();
    eq_hex(o, "hpke_info_hex", &info, name);
    eq_hex(o, "hpke_psk_id_hex", b"xchonnect v1 psk", name);
    let aad_pair = [b"xchonnect v1 pairing reply".as_slice(), &mbx_p].concat();
    eq_hex(o, "aad_pair_hex", &aad_pair, name);
    let psk = Psk {
        psk: &s_b,
        psk_id: b"xchonnect v1 psk",
    };
    let (_, pk_e) = <hpke::kem::X25519HkdfSha256 as hpke::Kem>::derive_keypair(&ikm_e);
    let enc = hx_n::<32>(o, "enc_hex");
    // enc = pk(DeriveKeyPair(ikmE))
    eq_hex(o, "enc_hex", hpke::Serializable::to_bytes(&pk_e), name);
    let (enc2, mut sender) =
        HpkeSender::setup(&mut Replay::new(&[&ikm_e]), &dpk, &info, Some(psk)).unwrap();
    assert_eq!(enc2, enc);

    let mut reply = vec![
        ("mbx", Value::bytes(&hx(i, "wallet_mailbox_hex"))),
        ("w", Value::bytes(&hx(i, "wallet_write_token_hex"))),
    ];
    if let Json::String(n) = get(i, "wallet_name") {
        reply.push(("meta", Value::text_map(vec![("name", Value::text(n))])));
    }
    let reply_pt = cbor::encode(&Value::text_map(reply)).unwrap();
    eq_hex(o, "pairing_reply_plaintext_hex", &reply_pt, name);
    let mut padded = reply_pt.clone();
    padded.resize(num(o, "pairing_reply_padded_len") as usize, 0);
    assert_eq!(padded.len() + 16, 1024);
    let ct = sender.seal(&aad_pair, &padded).unwrap();
    eq_hex(o, "ct_pair_hex", &ct, name);
    let mut receiver = HpkeReceiver::setup(&dsk, &enc, &info, Some(psk)).unwrap();
    assert_eq!(receiver.open(&aad_pair, &ct).unwrap(), padded);

    let env = cbor::encode(&Value::Map(vec![
        (Value::Uint(1), Value::Uint(1)),
        (Value::Uint(2), Value::Uint(2)),
        (Value::Uint(3), Value::bytes(&enc)),
        (Value::Uint(4), Value::bytes(&ct)),
    ]))
    .unwrap();
    eq_hex(o, "envelope_hex", &env, name);

    let th = crypto::sha256_parts(&[b"xchonnect v1 transcript", &h_uri, &enc, &ct]);
    eq_hex(o, "th_hex", th, name);
    let ctx = [b"xchonnect v1 root".as_slice(), &th].concat();
    eq_hex(o, "exporter_context_hex", &ctx, name);
    let root0 = receiver.export(&ctx).unwrap();
    assert_eq!(sender.export(&ctx).unwrap(), root0);
    eq_hex(o, "root_0_hex", root0, name);
    check_epoch_keys(o, &root0, 0, ["k_d2w_hex", "k_w2d_hex", "ck_0_hex"], name);
    let sas8: [u8; 8] = crypto::hkdf_expand(&root0, b"xchonnect v1 sas").unwrap();
    let code = u64::from_be_bytes(sas8) % 1_000_000;
    assert_eq!(code, num(o, "sas_value"), "{name}: SAS");
    assert_eq!(format!("{code:06}"), text(o, "sas_digits"));
    let display = format!("{:03} {:03}", code / 1000, code % 1000);
    assert_eq!(display, text(o, "sas_display"));

    // Production state machines fed with the explicit secrets.
    let unsigned = prepare_from_inputs(i);
    assert_eq!(unsigned.sig_input().unwrap(), sig_input);
    let mut dapp = unsigned.finish(sig, Some(&origin_pk)).unwrap();
    assert_eq!(dapp.uri().to_uri(), uri);
    let parsed = PairingUri::parse(&uri, ParseOptions::default()).unwrap();
    assert_eq!(&parsed, dapp.uri());
    let doc = OriginDocument::parse(doc_json.as_bytes()).unwrap();
    let reply_at = num(i, "reply_at");
    let verified = VerifiedUri::new(parsed, &doc, reply_at).unwrap();
    let (wallet, out) = WalletPairing::reply(
        &mut Replay::new(&[&ikm_e]),
        reply_at,
        &verified,
        MailboxId(hx_n(i, "wallet_mailbox_hex")),
        Token::from_bytes([0; 32]),
        Token::from_bytes(hx_n(i, "wallet_write_token_hex")),
        opt_meta(i),
    )
    .unwrap();
    assert_eq!(out.envelope, env, "{name}: WalletPairing::reply envelope");
    let accepted = dapp.on_reply(reply_at, &out.envelope).unwrap();
    assert_eq!(accepted.sas().digits(), text(o, "sas_digits"));
    assert_eq!(wallet.sas().digits(), text(o, "sas_digits"));
}

/// `k_d2w`, `k_w2d` and `ck` re-derived from `root` by the spec formula, checked against
/// the recorded values and against `keys::epoch_keys`.
fn check_epoch_keys(o: &Json, root: &[u8; 32], epoch: u64, names: [&str; 3], case: &str) {
    let api = keys::epoch_keys(&RootKey::from_bytes(*root), epoch).unwrap();
    let api = [api.d2w.expose(), api.w2d.expose(), api.chain.expose()];
    for ((label, key), via_api) in [D2W, W2D, CHAIN].into_iter().zip(names).zip(api) {
        let k = crypto::hkdf_expand32(root, &[label.as_bytes()]).unwrap();
        eq_hex(o, key, k, case);
        assert_eq!(via_api, &k, "{case}: {key} via epoch_keys");
    }
}

// --- Envelopes (spec 5.3) ----------------------------------------------------

struct EnvCase {
    name: &'static str,
    description: &'static str,
    direction: Direction,
    key: [u8; 32],
    nonce: [u8; 24],
    recipient: [u8; 16],
    inner: Vec<u8>,
}

const ENV_IAT: u64 = 1_790_000_100;

fn rpc_inner(seq: u64, method: &str, params: String) -> Vec<u8> {
    let message = Message::RpcRequest {
        method: method.to_owned(),
        params,
    };
    let (iat, exp, id) = (ENV_IAT, ENV_IAT + 600, pattern(0x01));
    Inner {
        seq,
        iat,
        exp,
        id,
        message,
    }
    .encode()
    .unwrap()
}

/// An `rpc.request` whose canonical encoding is exactly `target` bytes long.
fn inner_of_len(seq: u64, target: usize) -> Vec<u8> {
    let params = |n: usize| format!("{{\"message\":\"{}\"}}", "a".repeat(n));
    (target.saturating_sub(200)..)
        .map(|n| rpc_inner(seq, "signMessage", params(n)))
        .find(|enc| enc.len() >= target)
        .filter(|enc| enc.len() == target)
        .unwrap_or_else(|| panic!("length {target} unreachable"))
}

fn env_cases() -> Vec<EnvCase> {
    let case = |name, description, direction, nonce: u8, inner| {
        let (key, recipient) = match direction {
            Direction::DappToWallet => (pattern(0x80), pattern(0xc0)),
            Direction::WalletToDapp => (pattern(0xa0), pattern(0xd0)),
        };
        let nonce = pattern(nonce);
        EnvCase {
            name,
            description,
            direction,
            key,
            nonce,
            recipient,
            inner,
        }
    };
    let (d2w, w2d) = (Direction::DappToWallet, Direction::WalletToDapp);
    let typical = r#"{"message":"hello xchonnect","address":"xch1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0hn2a3"}"#;
    vec![
        case(
            "bucket-1k",
            "Typical rpc.request, dApp -> wallet; padded to the 1 KiB bucket",
            d2w,
            0x10,
            rpc_inner(1, "signMessageByAddress", typical.to_owned()),
        ),
        case(
            "bucket-4k",
            "Inner plaintext of 1009 bytes (one byte too large for 1 KiB), wallet -> dApp; 4 KiB bucket",
            w2d,
            0x30,
            inner_of_len(2, 1009),
        ),
        case(
            "bucket-16k",
            "Inner plaintext of exactly 16368 bytes (fills 16 KiB with no padding), dApp -> wallet",
            d2w,
            0x50,
            inner_of_len(3, 16368),
        ),
        case(
            "bucket-64k",
            "Inner plaintext of 40000 bytes, wallet -> dApp; 64 KiB bucket",
            w2d,
            0x70,
            inner_of_len(4, 40000),
        ),
        case(
            "bucket-256k",
            "Largest permitted inner plaintext (262128 bytes), dApp -> wallet; 256 KiB bucket",
            d2w,
            0x90,
            inner_of_len(5, 262_128),
        ),
    ]
}

impl EnvCase {
    fn seal(&self) -> Vec<u8> {
        let (key, mbx) = (
            DirectionKey::from_bytes(self.key),
            MailboxId(self.recipient),
        );
        envelope::seal_session_with_nonce(&self.nonce, &key, self.direction, &mbx, &self.inner)
            .unwrap()
    }

    /// Seal an arbitrary (possibly invalid) padded plaintext under this case's key.
    fn seal_padded(&self, nonce: &[u8; 24], padded: &[u8]) -> Vec<u8> {
        let aad = envelope::aad(Kind::Session, self.direction, &MailboxId(self.recipient));
        let key = DirectionKey::from_bytes(self.key);
        let ct = crypto::xchacha_seal(&key, nonce, &aad, padded).unwrap();
        let n = nonce.to_vec();
        let kind = Kind::Session;
        Envelope { kind, n, ct }.encode().unwrap()
    }
}

fn gen_envelope() -> J {
    let mut cases = Vec::new();
    for c in env_cases() {
        let env = c.seal();
        let ct = Envelope::decode(&env).unwrap().ct;
        let aad = envelope::aad(Kind::Session, c.direction, &MailboxId(c.recipient));
        let mut f = vec![
            ("name", s(c.name)),
            ("description", s(c.description)),
            ("direction", direction_name(c.direction)),
            ("key_hex", h(&c.key)),
            ("nonce_hex", h(&c.nonce)),
            ("recipient_mailbox_hex", h(&c.recipient)),
            bytes_field("inner_cbor_hex", "inner_cbor_segments", &c.inner),
            ("inner_cbor_len", n(c.inner.len())),
            (
                "inner_cbor_sha256_hex",
                h(&crypto::sha256_parts(&[&c.inner])),
            ),
            ("aad_hex", h(&aad)),
            ("padded_plaintext_len", n(ct.len() - TAG_LEN)),
            ("ct_len", n(ct.len())),
            ("tag_hex", h(&ct[ct.len() - TAG_LEN..])),
            ("envelope_len", n(env.len())),
            ("envelope_sha256_hex", h(&crypto::sha256_parts(&[&env]))),
        ];
        if env.len() <= ENVELOPE_HEX_MAX {
            f.push(("envelope_hex", h(&env)));
        }
        cases.push(J::Obj(f));
    }
    file(
        "Session envelopes (spec 5.3): XChaCha20-Poly1305 under a direction key with the 28-byte AAD, zero padding to the smallest bucket. One case per bucket. Large plaintexts use segments; envelopes above 4200 bytes are given by length, tag and SHA-256 only. See README.md.",
        cases,
    )
}

fn check_envelope_case(c: &Json) {
    let name = text(c, "name");
    let key = DirectionKey::from_bytes(hx_n(c, "key_hex"));
    let nonce = hx_n::<24>(c, "nonce_hex");
    let mbx = MailboxId(hx_n(c, "recipient_mailbox_hex"));
    let dir = direction_of(c);
    let inner = bytes_of(c, "inner_cbor");
    assert_eq!(inner.len() as u64, num(c, "inner_cbor_len"), "{name}");
    eq_hex(
        c,
        "inner_cbor_sha256_hex",
        crypto::sha256_parts(&[&inner]),
        name,
    );

    // AAD = "xchonnect" || v || kind || direction || recipient mailbox.
    let aad = [b"xchonnect".as_slice(), &[1, 1, dir as u8], &mbx.0].concat();
    eq_hex(c, "aad_hex", &aad, name);
    assert_eq!(envelope::aad(Kind::Session, dir, &mbx).as_slice(), aad);

    let bucket = BUCKETS
        .into_iter()
        .find(|b| inner.len() + 16 <= *b)
        .unwrap();
    assert_eq!(
        (bucket - 16) as u64,
        num(c, "padded_plaintext_len"),
        "{name}: padding"
    );
    assert_eq!(bucket as u64, num(c, "ct_len"));
    let mut padded = inner.clone();
    padded.resize(bucket - 16, 0);
    let ct = crypto::xchacha_seal(&key, &nonce, &aad, &padded).unwrap();
    eq_hex(c, "tag_hex", &ct[ct.len() - 16..], name);
    let env = cbor::encode(&Value::Map(vec![
        (Value::Uint(1), Value::Uint(1)),
        (Value::Uint(2), Value::Uint(1)),
        (Value::Uint(3), Value::bytes(&nonce)),
        (Value::Uint(4), Value::Bytes(ct)),
    ]))
    .unwrap();
    assert_eq!(env.len() as u64, num(c, "envelope_len"));
    eq_hex(
        c,
        "envelope_sha256_hex",
        crypto::sha256_parts(&[&env]),
        name,
    );
    if c.get("envelope_hex").is_some() {
        eq_hex(c, "envelope_hex", &env, name);
    }
    let sealed = envelope::seal_session_with_nonce(&nonce, &key, dir, &mbx, &inner).unwrap();
    assert_eq!(sealed, env);
    let back = envelope::open_session(&key, dir, &mbx, &Envelope::decode(&env).unwrap()).unwrap();
    assert_eq!(cbor::encode(&back).unwrap(), inner);
}

// --- Rotation (spec 5.2, 9.2) ------------------------------------------------

fn gen_rotation(ck0_basic: [u8; 32]) -> J {
    let rot_cases = [
        (
            "epoch-0-to-1",
            "First rotation of pairing case 'basic' (ck_e = its ck_0)",
            ck0_basic,
            0u64,
            [0xa1; 32],
            [0xb1; 32],
        ),
        (
            "epoch-41-to-42",
            "Rotation from an arbitrary chaining key at epoch 41",
            pattern(0x40),
            41,
            [0xa2; 32],
            [0xb2; 32],
        ),
    ];
    let mut cases = Vec::new();
    for (name, description, ck, epoch, a_seed, b_seed) in rot_cases {
        // Session::begin_rotation / accept_rotation draw the X25519 secret first.
        let a = X25519Secret::from_bytes(draw(a_seed));
        let b = X25519Secret::from_bytes(draw(b_seed));
        let (a_pub, b_pub) = (a.public_key(), b.public_key());
        let dh = a.diffie_hellman(&b_pub).unwrap();
        assert_eq!(dh, b.diffie_hellman(&a_pub).unwrap());
        let new_epoch = epoch + 1;
        let th_r =
            crypto::sha256_parts(&[keys::LABEL_ROTATE, &new_epoch.to_be_bytes(), &a_pub, &b_pub]);
        let prk = crypto::hkdf_extract(&ck, &dh);
        let root =
            keys::rotation_root(&ChainKey::from_bytes(ck), &dh, new_epoch, &a_pub, &b_pub).unwrap();
        let k = keys::epoch_keys(&root, new_epoch).unwrap();
        let inputs = J::Obj(vec![
            ("epoch", J::Num(epoch)),
            ("ck_e_hex", h(&ck)),
            ("a_entropy_seed_hex", h(&a_seed)),
            ("b_entropy_seed_hex", h(&b_seed)),
            ("a_hex", h(a.expose())),
            ("b_hex", h(b.expose())),
        ]);
        let outputs = J::Obj(vec![
            ("new_epoch", J::Num(new_epoch)),
            ("a_pub_hex", h(&a_pub)),
            ("b_pub_hex", h(&b_pub)),
            ("dh_hex", h(&dh)),
            ("th_r_hex", h(&th_r)),
            ("prk_hex", h(&prk)),
            ("root_hex", h(root.expose())),
            ("k_d2w_hex", h(k.d2w.expose())),
            ("k_w2d_hex", h(k.w2d.expose())),
            ("ck_hex", h(k.chain.expose())),
        ]);
        cases.push(J::Obj(vec![
            ("name", s(name)),
            ("description", s(description)),
            ("inputs", inputs),
            ("outputs", outputs),
        ]));
    }
    file(
        "Epoch rotation key schedule (spec 5.2 'Rotation', 9.2): A = X25519(a, 9), B = X25519(b, 9), dh, th_r, prk, root_{e+1} and the new epoch's keys. See README.md.",
        cases,
    )
}

fn check_rotation_case(c: &Json) {
    let name = text(c, "name");
    let i = get(c, "inputs");
    let o = get(c, "outputs");
    let a_b = hx_n::<32>(i, "a_hex");
    let b_b = hx_n::<32>(i, "b_hex");
    assert_eq!(draw::<32>(hx_n(i, "a_entropy_seed_hex")), a_b);
    assert_eq!(draw::<32>(hx_n(i, "b_entropy_seed_hex")), b_b);
    let (a, b) = (X25519Secret::from_bytes(a_b), X25519Secret::from_bytes(b_b));
    let (a_pub, b_pub) = (a.public_key(), b.public_key());
    eq_hex(o, "a_pub_hex", a_pub, name);
    eq_hex(o, "b_pub_hex", b_pub, name);
    let dh = a.diffie_hellman(&b_pub).unwrap();
    assert_eq!(dh, b.diffie_hellman(&a_pub).unwrap());
    eq_hex(o, "dh_hex", dh, name);
    let e1 = num(i, "epoch") + 1;
    assert_eq!(e1, num(o, "new_epoch"));
    let th_r = crypto::sha256_parts(&[b"xchonnect v1 rotate", &e1.to_be_bytes(), &a_pub, &b_pub]);
    eq_hex(o, "th_r_hex", th_r, name);
    let ck = hx_n::<32>(i, "ck_e_hex");
    let prk = crypto::hkdf_extract(&ck, &dh);
    eq_hex(o, "prk_hex", prk, name);
    let root = crypto::hkdf_expand32(&prk, &[b"xchonnect v1 root", &th_r]).unwrap();
    eq_hex(o, "root_hex", root, name);
    let via_api = keys::rotation_root(&ChainKey::from_bytes(ck), &dh, e1, &a_pub, &b_pub).unwrap();
    assert_eq!(via_api.expose(), &root);
    check_epoch_keys(o, &root, e1, ["k_d2w_hex", "k_w2d_hex", "ck_hex"], name);
}

// --- Negative cases ----------------------------------------------------------

const RECV_NOW: u64 = 1_790_001_000;

/// Encode an inner map with entries in the given (possibly non-canonical) order.
fn inner_raw(entries: &[(&str, Value)]) -> Vec<u8> {
    let mut out = vec![0xa0 | entries.len() as u8];
    for (k, v) in entries {
        out.extend(cbor::encode(&Value::text(k)).unwrap());
        out.extend(cbor::encode(v).unwrap());
    }
    out
}

fn neg(
    id: &str,
    description: &str,
    check: &str,
    fields: Vec<(&'static str, J)>,
    expected: &str,
) -> J {
    let head = [
        ("id", s(id)),
        ("description", s(description)),
        ("check", s(check)),
    ];
    let tail = ("expected_error", s(expected));
    J::Obj(head.into_iter().chain(fields).chain([tail]).collect())
}

fn gen_negative(pairing: &PairingOut) -> J {
    let mut cases = Vec::new();

    // --- Pairing URI
    let good = &pairing.uri;
    let x = good.expires_at;
    let resign = |u: &mut PairingUri, seed: [u8; 32]| {
        u.signature = Ed25519Seed::from_bytes(seed).sign(&u.sig_input().unwrap());
    };
    let mut wrong_key = good.clone();
    resign(&mut wrong_key, pattern(0x41));
    let mut tampered = good.clone();
    tampered.domain = "evil.example".into();
    let mut flipped = good.clone();
    flipped.signature[0] ^= 0x01;
    let mut other_kid = good.clone();
    other_kid.kid = "2025-01".into();
    resign(&mut other_kid, pairing.origin_seed);
    let t5 = CREATED_AT + 5;
    for (id, description, uri, now, expected) in [
        (
            "uri-signature-wrong-key",
            "Pairing case 'basic' URI with o replaced by a signature over the same uri_sig_input from a key not in the origin document",
            &wrong_key,
            t5,
            "bad_signature",
        ),
        (
            "uri-signature-domain-changed",
            "d changed to another domain after signing (d is covered by the signature)",
            &tampered,
            t5,
            "bad_signature",
        ),
        (
            "uri-signature-bit-flip",
            "One bit of the origin signature flipped",
            &flipped,
            t5,
            "bad_signature",
        ),
        (
            "uri-unknown-kid",
            "Validly signed by the origin key but naming a kid the origin document does not list",
            &other_kid,
            t5,
            "invalid_origin",
        ),
        (
            "uri-expired",
            "Valid URI checked one second after x",
            good,
            x + 1,
            "uri_expired",
        ),
        (
            "uri-lifetime-too-long",
            "Valid URI checked when x is more than 300 s + 60 s clock skew in the future",
            good,
            x - 361,
            "uri_expired",
        ),
    ] {
        let fields = vec![
            ("uri", s(uri.to_uri())),
            ("origin_document", s(pairing.origin_doc.clone())),
            ("now", J::Num(now)),
        ];
        cases.push(neg(id, description, "verify_uri", fields, expected));
    }

    // --- Pairing reply at the dApp
    let mut bad_ct = Envelope::decode(&pairing.envelope).unwrap();
    bad_ct.ct[0] ^= 0x01;
    for (id, description, now, env, expected) in [
        (
            "pairing-reply-tampered",
            "Pairing case 'basic' reply with one ciphertext bit flipped, processed by the dApp built from that case's inputs",
            CREATED_AT + 6,
            bad_ct.encode().unwrap(),
            "decrypt",
        ),
        (
            "pairing-reply-after-expiry",
            "Genuine pairing case 'basic' reply arriving after the URI expired",
            x + 1,
            pairing.envelope.clone(),
            "uri_expired",
        ),
    ] {
        let fields = vec![
            ("pairing_case", s("basic")),
            ("now", J::Num(now)),
            ("envelope_hex", h(&env)),
        ];
        cases.push(neg(id, description, "dapp_on_reply", fields, expected));
    }

    // --- Envelope decoding: raw bytes with hand-written CBOR heads. `env(head, tail)` is
    // `head || nonce(24) || ct head || ct(1024) || tail`.
    let (n24, ct_head, ct1k) = ([0x11; 24], [0x04, 0x59, 0x04, 0x00], [0; 1024]);
    let head = [0xa4, 0x01, 0x01, 0x02, 0x01, 0x03, 0x58, 0x18];
    let env = |head: &[u8], tail: &[u8]| [head, &n24, &ct_head, &ct1k, tail].concat();
    let raw = |parts: &[&[u8]]| [&head[..], &n24, &parts.concat()[..]].concat();
    // Control: the canonical form of the envelope used below decodes fine.
    assert!(Envelope::decode(&env(&head, &[])).is_ok());
    let mut big = raw(&[&[0x04, 0x5a, 0x00, 0x08, 0x00, 0x00]]);
    big.resize(big.len() + 524_288, 0);
    for (id, description, bytes, expected) in [
        (
            "envelope-version-2",
            "Well-formed session envelope with v = 2",
            env(&[0xa4, 0x01, 0x02, 0x02, 0x01, 0x03, 0x58, 0x18], &[]),
            "unsupported_version",
        ),
        (
            "envelope-version-0",
            "Well-formed session envelope with v = 0",
            env(&[0xa4, 0x01, 0x00, 0x02, 0x01, 0x03, 0x58, 0x18], &[]),
            "unsupported_version",
        ),
        (
            "envelope-oversized",
            "Session envelope with a 512 KiB ciphertext: the encoding exceeds the 262400-byte envelope limit",
            big,
            "too_large",
        ),
        (
            "envelope-ct-not-bucket",
            "Session ciphertext of 1000 bytes (not a bucket size)",
            raw(&[&[0x04, 0x59, 0x03, 0xe8], &[0; 1000]]),
            "malformed",
        ),
        (
            "envelope-nonce-length",
            "Session nonce of 12 bytes instead of 24",
            [
                &[0xa4, 0x01, 0x01, 0x02, 0x01, 0x03, 0x4c][..],
                &[0x11; 12],
                &ct_head,
                &ct1k,
            ]
            .concat(),
            "malformed",
        ),
        (
            "envelope-unknown-key",
            "Extra key 5 in the outer envelope",
            env(
                &[0xa5, 0x01, 0x01, 0x02, 0x01, 0x03, 0x58, 0x18],
                &[0x05, 0xf6],
            ),
            "malformed",
        ),
        (
            "cbor-non-shortest-int",
            "Non-canonical CBOR: v encoded as 0x18 0x01 instead of 0x01",
            env(&[0xa4, 0x01, 0x18, 0x01, 0x02, 0x01, 0x03, 0x58, 0x18], &[]),
            "cbor",
        ),
        (
            "cbor-non-shortest-length",
            "Non-canonical CBOR: nonce length encoded as 0x59 0x00 0x18 instead of 0x58 0x18",
            env(&[0xa4, 0x01, 0x01, 0x02, 0x01, 0x03, 0x59, 0x00, 0x18], &[]),
            "cbor",
        ),
        (
            "cbor-indefinite-map",
            "Non-canonical CBOR: indefinite-length outer map (0xbf ... 0xff)",
            env(&[0xbf, 0x01, 0x01, 0x02, 0x01, 0x03, 0x58, 0x18], &[0xff]),
            "cbor",
        ),
        (
            "cbor-indefinite-bstr",
            "Non-canonical CBOR: ciphertext as an indefinite-length byte string with one chunk",
            raw(&[&[0x04, 0x5f, 0x59, 0x04, 0x00], &ct1k, &[0xff]]),
            "cbor",
        ),
        (
            "cbor-unsorted-keys",
            "Non-canonical CBOR: outer map keys in the order 2, 1, 3, 4",
            env(&[0xa4, 0x02, 0x01, 0x01, 0x01, 0x03, 0x58, 0x18], &[]),
            "cbor",
        ),
        (
            "cbor-duplicate-key",
            "Non-canonical CBOR: key 1 appears twice",
            env(
                &[0xa5, 0x01, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03, 0x58, 0x18],
                &[],
            ),
            "cbor",
        ),
        (
            "cbor-trailing-bytes",
            "Canonical envelope followed by one extra 0x00 byte",
            env(&head, &[0x00]),
            "cbor",
        ),
        (
            "cbor-tag",
            "Forbidden CBOR tag: ciphertext wrapped in tag 24",
            raw(&[&[0x04, 0xd8, 0x18, 0x59, 0x04, 0x00], &ct1k]),
            "cbor",
        ),
        (
            "cbor-float",
            "Forbidden CBOR float: v encoded as half-precision 1.0 (0xf9 0x3c00)",
            env(
                &[0xa4, 0x01, 0xf9, 0x3c, 0x00, 0x02, 0x01, 0x03, 0x58, 0x18],
                &[],
            ),
            "cbor",
        ),
    ] {
        let fields = vec![bytes_field("envelope_hex", "envelope_segments", &bytes)];
        cases.push(neg(id, description, "decode_envelope", fields, expected));
    }

    // --- Session decryption (envelope case bucket-1k)
    let ec = env_cases().into_iter().next().unwrap();
    let env1k = ec.seal();
    let mut other_mbx = ec.recipient;
    other_mbx[15] ^= 0x01;
    let mut flipped_ct = Envelope::decode(&env1k).unwrap();
    flipped_ct.ct[1023] ^= 0x80;
    let mut pad_last = envelope::pad(&ec.inner).unwrap();
    *pad_last.last_mut().unwrap() = 0x01;
    let mut pad_first = envelope::pad(&ec.inner).unwrap();
    pad_first[ec.inner.len()] = 0xff;
    let canonical_entries = || -> Vec<(&'static str, Value)> {
        vec![
            ("id", Value::bytes(&pattern::<16>(0x01))),
            ("exp", Value::Uint(ENV_IAT + 600)),
            ("iat", Value::Uint(ENV_IAT)),
            ("seq", Value::Uint(1)),
            ("body", Value::Map(vec![])),
            ("type", Value::text("session.ping")),
        ]
    };
    let canon = inner_raw(&canonical_entries());
    let reencoded = cbor::encode(&cbor::decode(&canon).unwrap()).unwrap();
    assert_eq!(reencoded, canon, "control is canonical");
    let mut unsorted = canonical_entries();
    unsorted.rotate_left(3);
    let unsorted = envelope::pad(&inner_raw(&unsorted)).unwrap();
    let mut nonshort = canon;
    // Replace `seq: 1` (0x63 "seq" 0x01) with the two-byte form 0x18 0x01.
    let pos = nonshort.windows(4).position(|w| w == b"\x63seq").unwrap() + 4;
    nonshort.splice(pos..pos + 1, [0x18, 0x01]);
    let nonshort = envelope::pad(&nonshort).unwrap();
    let (dir, mbx) = (ec.direction, ec.recipient);
    for (id, description, dir, mbx, env, expected) in [
        (
            "aad-wrong-direction",
            "Envelope case 'bucket-1k' opened as wallet -> dApp (direction byte in the AAD differs)",
            Direction::WalletToDapp,
            mbx,
            env1k.clone(),
            "decrypt",
        ),
        (
            "aad-wrong-mailbox",
            "Envelope case 'bucket-1k' opened for a different recipient mailbox (last byte flipped)",
            dir,
            other_mbx,
            env1k,
            "decrypt",
        ),
        (
            "ciphertext-tampered",
            "Envelope case 'bucket-1k' with one tag bit flipped",
            dir,
            mbx,
            flipped_ct.encode().unwrap(),
            "decrypt",
        ),
        (
            "padding-non-zero-last",
            "Correctly encrypted envelope whose last padding byte is 0x01",
            dir,
            mbx,
            ec.seal_padded(&pattern(0x20), &pad_last),
            "malformed",
        ),
        (
            "padding-non-zero-first",
            "Correctly encrypted envelope with 0xff directly after the inner CBOR item",
            dir,
            mbx,
            ec.seal_padded(&pattern(0x21), &pad_first),
            "malformed",
        ),
        (
            "inner-cbor-unsorted-keys",
            "Correctly encrypted inner map with text keys out of canonical order (seq first)",
            dir,
            mbx,
            ec.seal_padded(&pattern(0x22), &unsorted),
            "cbor",
        ),
        (
            "inner-cbor-non-shortest-int",
            "Correctly encrypted inner map with seq encoded as 0x18 0x01",
            dir,
            mbx,
            ec.seal_padded(&pattern(0x23), &nonshort),
            "cbor",
        ),
    ] {
        let fields = vec![
            ("key_hex", h(&ec.key)),
            ("direction", direction_name(dir)),
            ("recipient_mailbox_hex", h(&mbx)),
            ("envelope_hex", h(&env)),
        ];
        cases.push(neg(id, description, "open_session", fields, expected));
    }

    // --- Sender-side size limit
    let too_big = cbor::encode(&Value::Bytes(vec![0xaa; 262_124])).unwrap();
    assert_eq!(too_big.len(), 262_129);
    let fields = vec![
        ("key_hex", h(&ec.key)),
        ("nonce_hex", h(&ec.nonce)),
        ("direction", direction_name(ec.direction)),
        ("recipient_mailbox_hex", h(&ec.recipient)),
        bytes_field("inner_cbor_hex", "inner_cbor_segments", &too_big),
    ];
    cases.push(neg(
        "seal-oversized",
        "Inner plaintext of 262129 bytes: plaintext + tag exceeds the largest bucket, so sealing must fail",
        "seal_session",
        fields,
        "too_large",
    ));

    // --- Receive rules (replay, times)
    let root = pattern::<32>(0x70);
    let k = keys::epoch_keys(&RootKey::from_bytes(root), 0).unwrap();
    let own = pattern::<16>(0x30);
    for (nonce, (name, description, seq, iat, exp, expected)) in (1u8..).zip([
        (
            "replay-equal-seq",
            "session.ping with seq 5 after seq 5 was accepted",
            5,
            RECV_NOW,
            RECV_NOW + 60,
            "replay",
        ),
        (
            "replay-lower-seq",
            "session.ping with seq 3 after seq 5 was accepted (reordered)",
            3,
            RECV_NOW,
            RECV_NOW + 60,
            "replay",
        ),
        (
            "message-expired",
            "seq 6 but exp one second before now",
            6,
            RECV_NOW - 61,
            RECV_NOW - 1,
            "expired",
        ),
        (
            "message-lifetime",
            "seq 6 with exp - iat = 7 days + 1 s",
            6,
            RECV_NOW,
            RECV_NOW + 604_801,
            "lifetime_too_long",
        ),
        (
            "message-clock-skew",
            "seq 6 with iat 301 s in the future",
            6,
            RECV_NOW + 301,
            RECV_NOW + 400,
            "clock_skew",
        ),
    ]) {
        let (id, message) = (pattern(nonce), Message::SessionPing);
        let inner = Inner {
            seq,
            iat,
            exp,
            id,
            message,
        };
        let inner = inner.encode().unwrap();
        let d2w = Direction::DappToWallet;
        let env = envelope::seal_session_with_nonce(
            &pattern(nonce),
            &k.d2w,
            d2w,
            &MailboxId(own),
            &inner,
        )
        .unwrap();
        let fields = vec![
            ("role", s("wallet")),
            ("root_0_hex", h(&root)),
            ("key_hex", h(k.d2w.expose())),
            ("direction", direction_name(d2w)),
            ("recipient_mailbox_hex", h(&own)),
            ("last_accepted_seq", J::Num(5)),
            ("now", J::Num(RECV_NOW)),
            ("inner_cbor_hex", h(&inner)),
            ("envelope_hex", h(&env)),
        ];
        cases.push(neg(name, description, "session_receive", fields, expected));
    }

    file(
        "Inputs every implementation MUST reject, with the expected error kind. The 'check' field names the operation; see README.md.",
        cases,
    )
}

fn run_negative(c: &Json, pairing: &Json) -> Result<(), Error> {
    let key = || DirectionKey::from_bytes(hx_n(c, "key_hex"));
    let mbx = || MailboxId(hx_n(c, "recipient_mailbox_hex"));
    match text(c, "check") {
        "verify_uri" => {
            let uri = PairingUri::parse(text(c, "uri"), ParseOptions::default())?;
            let doc = OriginDocument::parse(text(c, "origin_document").as_bytes())?;
            VerifiedUri::new(uri, &doc, num(c, "now")).map(|_| ())
        }
        "dapp_on_reply" => {
            let case = cases(pairing)
                .iter()
                .find(|p| text(p, "name") == text(c, "pairing_case"))
                .unwrap();
            let (i, o) = (get(case, "inputs"), get(case, "outputs"));
            let sig = hx_n(o, "origin_signature_hex");
            let mut dapp = prepare_from_inputs(i)
                .finish(sig, Some(&hx_n(o, "origin_pk_hex")))
                .unwrap();
            assert_eq!(dapp.uri().to_uri(), text(o, "uri"));
            dapp.on_reply(num(c, "now"), &hx(c, "envelope_hex"))
                .map(|_| ())
        }
        "decode_envelope" => Envelope::decode(&bytes_of(c, "envelope")).map(|_| ()),
        "open_session" => {
            let env = Envelope::decode(&hx(c, "envelope_hex"))?;
            envelope::open_session(&key(), direction_of(c), &mbx(), &env).map(|_| ())
        }
        "seal_session" => {
            let (nonce, inner) = (hx_n(c, "nonce_hex"), bytes_of(c, "inner_cbor"));
            envelope::seal_session_with_nonce(&nonce, &key(), direction_of(c), &mbx(), &inner)
                .map(|_| ())
        }
        "session_receive" => {
            assert_eq!(text(c, "role"), "wallet");
            let root = RootKey::from_bytes(hx_n(c, "root_0_hex"));
            let k = keys::epoch_keys(&root, 0).unwrap();
            assert_eq!(k.d2w, key());
            let own = mbx();
            let mut s = Session::new(NewSession {
                role: Role::Wallet,
                root0: root,
                own_mailbox: own,
                own_read: Token::from_bytes([0; 32]),
                peer_mailbox: MailboxId([0; 16]),
                peer_write: Token::from_bytes([0; 32]),
                now: num(c, "now"),
            })
            .unwrap();
            s.mark_received(num(c, "last_accepted_seq"));
            // The envelope itself decrypts: only the receive rule rejects it.
            let env = Envelope::decode(&hx(c, "envelope_hex")).unwrap();
            let v = envelope::open_session(&k.d2w, Direction::DappToWallet, &own, &env).unwrap();
            assert_eq!(cbor::encode(&v).unwrap(), hx(c, "inner_cbor_hex"));
            s.open(num(c, "now"), &own, &hx(c, "envelope_hex"))
                .map(|_| ())
        }
        other => panic!("unknown check {other}"),
    }
}

// --- Files and tests ---------------------------------------------------------

fn generate_all() -> Vec<(&'static str, String)> {
    let (pairing, outs) = gen_pairing();
    let files = [
        ("pairing.json", pairing),
        ("envelope.json", gen_envelope()),
        ("rotation.json", gen_rotation(outs[0].ck0)),
        ("negative.json", gen_negative(&outs[0])),
    ];
    files
        .into_iter()
        .map(|(name, j)| {
            let mut out = String::new();
            render(&j, 0, &mut out);
            out.push('\n');
            (name, out)
        })
        .collect()
}

/// The committed files are exactly what the generator produces today.
#[test]
fn vector_files_are_current() {
    let files = generate_all();
    assert_eq!(files, generate_all(), "generator is not deterministic");
    let write = std::env::var_os("XCHONNECT_WRITE_VECTORS").is_some();
    for (name, content) in files {
        let path = vectors_dir().join(name);
        if write {
            std::fs::create_dir_all(vectors_dir()).unwrap();
            std::fs::write(&path, &content).unwrap();
            continue;
        }
        let on_disk = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            on_disk == content,
            "{} is out of date: bytes on the wire changed. If intended, regenerate with \
             `XCHONNECT_WRITE_VECTORS=1 cargo test -p xchonnect-core --lib vectors` and \
             update the spec/CHANGELOG in the same change.",
            path.display()
        );
    }
}

#[test]
fn pairing_vectors_rederive() {
    let v = load("pairing.json");
    assert_eq!(cases(&v).len(), 2);
    cases(&v).iter().for_each(check_pairing_case);
}

#[test]
fn envelope_vectors_rederive() {
    let v = load("envelope.json");
    let buckets: Vec<u64> = cases(&v).iter().map(|c| num(c, "ct_len")).collect();
    assert_eq!(buckets, BUCKETS.map(|b| b as u64), "one case per bucket");
    cases(&v).iter().for_each(check_envelope_case);
}

#[test]
fn rotation_vectors_rederive() {
    let v = load("rotation.json");
    let p = load("pairing.json");
    assert_eq!(
        text(get(&cases(&v)[0], "inputs"), "ck_e_hex"),
        text(get(&cases(&p)[0], "outputs"), "ck_0_hex"),
        "first rotation chains from pairing case 'basic'"
    );
    cases(&v).iter().for_each(check_rotation_case);
}

#[test]
fn negative_vectors_fail_as_expected() {
    let v = load("negative.json");
    let p = load("pairing.json");
    for c in cases(&v) {
        let id = text(c, "id");
        match run_negative(c, &p) {
            Ok(()) => panic!("negative case {id} was accepted"),
            Err(e) => assert_eq!(error_kind(&e), text(c, "expected_error"), "case {id}: {e}"),
        }
    }
    let ids: std::collections::HashSet<&str> = cases(&v).iter().map(|c| text(c, "id")).collect();
    assert_eq!(ids.len(), cases(&v).len(), "unique ids");
}
