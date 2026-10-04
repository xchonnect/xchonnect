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
use crate::pairing::{DappPairing, DappPairingParams, VerifiedUri, WalletPairing};
use crate::session::{NewSession, Role, Session};
use crate::uri::{LocalSigner, OriginSigner, PairingUri, ParseOptions};
use serde_json::Value as Json;
use std::path::PathBuf;

// ===========================================================================
// Shared helpers
// ===========================================================================

/// Format version of the vector files (bump on incompatible layout changes).
const FORMAT: u64 = 1;
/// Runs of at least this many identical bytes are written as a `repeat` segment.
const RUN_MIN: usize = 64;
/// Envelopes up to this size are written out in full; larger ones only as SHA-256.
const ENVELOPE_HEX_MAX: usize = 4200;

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
struct Replay {
    bytes: Vec<u8>,
    pos: usize,
}

impl Replay {
    fn new(parts: &[&[u8]]) -> Self {
        Replay {
            bytes: parts.concat(),
            pos: 0,
        }
    }
}

impl Entropy for Replay {
    fn fill(&mut self, dst: &mut [u8]) {
        for b in dst {
            *b = self.bytes.get(self.pos).copied().unwrap_or(0);
            self.pos += 1;
        }
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

fn direction_name(d: Direction) -> &'static str {
    match d {
        Direction::DappToWallet => "dapp_to_wallet",
        Direction::WalletToDapp => "wallet_to_dapp",
    }
}

// ---------------------------------------------------------------------------
// Ordered JSON with a fixed renderer (independent of serde_json's map ordering)
// ---------------------------------------------------------------------------

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

fn render(j: &J, indent: usize, out: &mut String) {
    let pad = |n: usize| "  ".repeat(n);
    match j {
        J::Null => out.push_str("null"),
        J::Num(n) => out.push_str(&n.to_string()),
        J::Str(v) => out.push_str(&serde_json::to_string(v).unwrap()),
        J::Arr(items) if items.is_empty() => out.push_str("[]"),
        J::Arr(items) => {
            out.push_str("[\n");
            for (i, item) in items.iter().enumerate() {
                out.push_str(&pad(indent + 1));
                render(item, indent + 1, out);
                out.push_str(if i + 1 < items.len() { ",\n" } else { "\n" });
            }
            out.push_str(&pad(indent));
            out.push(']');
        }
        J::Obj(fields) => {
            out.push_str("{\n");
            for (i, (k, v)) in fields.iter().enumerate() {
                out.push_str(&pad(indent + 1));
                out.push_str(&serde_json::to_string(k).unwrap());
                out.push_str(": ");
                render(v, indent + 1, out);
                out.push_str(if i + 1 < fields.len() { ",\n" } else { "\n" });
            }
            out.push_str(&pad(indent));
            out.push('}');
        }
    }
}

fn render_file(j: &J) -> String {
    let mut out = String::new();
    render(j, 0, &mut out);
    out.push('\n');
    out
}

/// Byte string as segments: `{"hex": …}` for literal bytes, `{"repeat": "aa",
/// "count": n}` for long runs of one byte.
fn segments(bytes: &[u8]) -> J {
    let mut segs = Vec::new();
    let mut lit_start = 0;
    let mut i = 0;
    while i < bytes.len() {
        let mut j = i;
        while j < bytes.len() && bytes[j] == bytes[i] {
            j += 1;
        }
        if j - i >= RUN_MIN {
            if lit_start < i {
                segs.push(J::Obj(vec![("hex", h(&bytes[lit_start..i]))]));
            }
            segs.push(J::Obj(vec![
                ("repeat", h(&[bytes[i]])),
                ("count", J::Num((j - i) as u64)),
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

/// Push `<name>_hex` (no long runs) or `<name>_segments`.
fn push_bytes(
    fields: &mut Vec<(&'static str, J)>,
    hex_key: &'static str,
    seg_key: &'static str,
    b: &[u8],
) {
    let has_run = b.windows(RUN_MIN).any(|w| w.iter().all(|x| *x == w[0]));
    if has_run {
        fields.push((seg_key, segments(b)));
    } else {
        fields.push((hex_key, h(b)));
    }
}

// ---------------------------------------------------------------------------
// Reading JSON in the checker
// ---------------------------------------------------------------------------

fn load(name: &str) -> Json {
    let path = vectors_dir().join(name);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap()
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

/// Read `<base>_hex` or `<base>_segments`.
fn bytes_of(v: &Json, base: &str) -> Vec<u8> {
    if let Some(Json::String(x)) = v.get(format!("{base}_hex")) {
        return hex::decode(x).unwrap();
    }
    let segs = get(v, &format!("{base}_segments")).as_array().unwrap();
    let mut out = Vec::new();
    for seg in segs {
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

fn direction_of(v: &Json) -> Direction {
    match text(v, "direction") {
        "dapp_to_wallet" => Direction::DappToWallet,
        "wallet_to_dapp" => Direction::WalletToDapp,
        other => panic!("direction {other}"),
    }
}

// ===========================================================================
// Pairing (spec 5.2, 6.2, 6.3)
// ===========================================================================

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

fn pairing_cases() -> Vec<PairingCase> {
    vec![
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

fn pairing_aad(mbx: &[u8; 16]) -> Vec<u8> {
    [keys::LABEL_PAIRING_AAD, mbx].concat()
}

/// Generator output reused by the negative vectors.
struct PairingOut {
    uri: PairingUri,
    origin_doc: String,
    envelope: Vec<u8>,
    origin_seed: [u8; 32],
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
    assert_eq!(
        X25519Secret::from_slice(dsk).unwrap().public_key(),
        uri.dapp_pk
    );
    assert_eq!(uri.secret.expose().as_slice(), secret);
    let h_uri = uri.h_uri().unwrap();

    // Wallet: the HPKE sender draws ikmE (32 bytes) for DeriveKeyPair.
    let doc_json = origin_document(&origin_pk);
    let doc = OriginDocument::parse(doc_json.as_bytes()).unwrap();
    let verified = VerifiedUri::new(
        PairingUri::parse(&uri_text, ParseOptions::default()).unwrap(),
        &doc,
        c.reply_at,
    )
    .unwrap();
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
    let receiver = HpkeReceiver::setup(
        &X25519Secret::from_slice(dsk).unwrap(),
        &enc,
        &hpke_info(&h_uri),
        Some(Psk {
            psk: secret,
            psk_id: keys::LABEL_PSK_ID,
        }),
    )
    .unwrap();
    let root0 = RootKey::from_bytes(receiver.export(&ctx).unwrap());
    let k = keys::epoch_keys(&root0, 0).unwrap();
    let accepted = dapp.on_reply(c.reply_at + 1, &out.envelope).unwrap();
    let sas = accepted.sas();
    assert_eq!(sas, wallet.sas());
    assert_eq!(sas, Sas::derive(&root0).unwrap());

    let inputs = J::Obj(vec![
        ("dapp_entropy_seed_hex", h(&c.dapp_seed)),
        ("wallet_entropy_seed_hex", h(&c.wallet_seed)),
        ("dsk_hex", h(dsk)),
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
        ("aad_pair_hex", h(&pairing_aad(&c.pairing_mailbox))),
        ("pairing_reply_plaintext_hex", h(&reply_pt)),
        (
            "pairing_reply_padded_len",
            J::Num((PAIRING_CT_LEN - TAG_LEN) as u64),
        ),
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
    (
        case,
        PairingOut {
            uri,
            origin_doc: doc_json,
            envelope: out.envelope,
            origin_seed: c.origin_seed,
        },
    )
}

fn gen_pairing() -> (J, Vec<PairingOut>) {
    let mut cases = Vec::new();
    let mut outs = Vec::new();
    for c in pairing_cases() {
        let (j, o) = gen_pairing_case(&c);
        cases.push(j);
        outs.push(o);
    }
    let file = J::Obj(vec![
        ("format", J::Num(FORMAT)),
        ("protocol_version", J::Num(envelope::VERSION)),
        (
            "description",
            s(
                "Pairing handshake (spec 5.2, 6.2, 6.3): pairing URI and origin signature, HPKE PSK pairing reply, transcript hash, root_0, epoch-0 keys and SAS. See README.md.",
            ),
        ),
        ("cases", J::Arr(cases)),
    ]);
    (file, outs)
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
    let wseed = hx_n::<32>(i, "wallet_entropy_seed_hex");
    assert_eq!(te(&dseed, 64), [dsk_b, s_b].concat(), "{name}: dsk||s");
    assert_eq!(te(&wseed, 32), ikm_e, "{name}: ikm_e");
    assert_eq!(draw::<64>(dseed).to_vec(), [dsk_b, s_b].concat());

    let dsk = X25519Secret::from_bytes(dsk_b);
    let dpk = dsk.public_key();
    assert_eq!(dpk, hx_n::<32>(o, "dpk_hex"), "{name}: dpk");
    let seed = Ed25519Seed::from_bytes(hx_n(i, "origin_seed_hex"));
    let origin_pk = seed.public_key();
    assert_eq!(origin_pk, hx_n::<32>(o, "origin_pk_hex"));
    let doc_json = text(o, "origin_document");
    assert_eq!(doc_json, origin_document(&origin_pk));

    let relay = text(i, "relay");
    let domain = text(i, "domain");
    let kid = text(i, "kid");
    let mbx_p = hx_n::<16>(i, "pairing_mailbox_hex");
    let w_p = hx_n::<32>(i, "pairing_write_token_hex");
    let x = num(i, "created_at") + num(i, "lifetime_s");
    assert_eq!(x, num(o, "expires_at"));
    let ticket = match get(i, "ticket_hex") {
        Json::Null => None,
        _ => Some(hx_n::<32>(i, "ticket_hex")),
    };

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
    assert_eq!(
        sig_input,
        hx(o, "uri_sig_input_hex"),
        "{name}: uri_sig_input"
    );
    let h_uri = crypto::sha256_parts(&[&sig_input]);
    assert_eq!(h_uri, hx_n::<32>(o, "h_uri_hex"));
    let sig = seed.sign(&sig_input);
    assert_eq!(
        sig,
        hx_n::<64>(o, "origin_signature_hex"),
        "{name}: signature"
    );
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
    if let Some(t) = ticket {
        uri.push_str(&format!("&t={}", b64(&t)));
    }
    assert_eq!(uri, text(o, "uri"), "{name}: uri");

    // HPKE mode_psk: sender with ikmE, receiver with dsk.
    let info = [keys::LABEL_PAIRING_INFO, &h_uri].concat();
    assert_eq!(info, hx(o, "hpke_info_hex"));
    assert_eq!(b"xchonnect v1 psk".as_slice(), hx(o, "hpke_psk_id_hex"));
    let aad_pair = [b"xchonnect v1 pairing reply".as_slice(), &mbx_p].concat();
    assert_eq!(aad_pair, hx(o, "aad_pair_hex"));
    let psk = Psk {
        psk: &s_b,
        psk_id: b"xchonnect v1 psk",
    };
    let (_, pk_e) = <hpke::kem::X25519HkdfSha256 as hpke::Kem>::derive_keypair(&ikm_e);
    let enc = hx_n::<32>(o, "enc_hex");
    assert_eq!(
        hpke::Serializable::to_bytes(&pk_e).as_slice(),
        enc,
        "{name}: enc = pk(DeriveKeyPair(ikmE))"
    );
    let (enc2, mut sender) =
        HpkeSender::setup(&mut Replay::new(&[&ikm_e]), &dpk, &info, Some(psk)).unwrap();
    assert_eq!(enc2, enc);

    let mut meta_entries = vec![];
    if let Json::String(n) = get(i, "wallet_name") {
        meta_entries.push(("name", Value::text(n)));
    }
    let mut reply = vec![
        ("mbx", Value::bytes(&hx(i, "wallet_mailbox_hex"))),
        ("w", Value::bytes(&hx(i, "wallet_write_token_hex"))),
    ];
    if !meta_entries.is_empty() {
        reply.push(("meta", Value::text_map(meta_entries)));
    }
    let reply_pt = cbor::encode(&Value::text_map(reply)).unwrap();
    assert_eq!(
        reply_pt,
        hx(o, "pairing_reply_plaintext_hex"),
        "{name}: reply plaintext"
    );
    let mut padded = reply_pt.clone();
    padded.resize(num(o, "pairing_reply_padded_len") as usize, 0);
    assert_eq!(padded.len() + 16, 1024);
    let ct = sender.seal(&aad_pair, &padded).unwrap();
    assert_eq!(ct, hx(o, "ct_pair_hex"), "{name}: ct_pair");
    let mut receiver = HpkeReceiver::setup(&dsk, &enc, &info, Some(psk)).unwrap();
    assert_eq!(receiver.open(&aad_pair, &ct).unwrap(), padded);

    let env = cbor::encode(&Value::Map(vec![
        (Value::Uint(1), Value::Uint(1)),
        (Value::Uint(2), Value::Uint(2)),
        (Value::Uint(3), Value::bytes(&enc)),
        (Value::Uint(4), Value::bytes(&ct)),
    ]))
    .unwrap();
    assert_eq!(env, hx(o, "envelope_hex"), "{name}: envelope");

    let th = crypto::sha256_parts(&[b"xchonnect v1 transcript", &h_uri, &enc, &ct]);
    assert_eq!(th, hx_n::<32>(o, "th_hex"), "{name}: th");
    let ctx = [b"xchonnect v1 root".as_slice(), &th].concat();
    assert_eq!(ctx, hx(o, "exporter_context_hex"));
    let root0 = receiver.export(&ctx).unwrap();
    assert_eq!(sender.export(&ctx).unwrap(), root0);
    assert_eq!(root0, hx_n::<32>(o, "root_0_hex"), "{name}: root_0");
    let exp = |label: &[u8]| crypto::hkdf_expand32(&root0, &[label]).unwrap();
    assert_eq!(
        exp(b"xchonnect v1 dapp->wallet"),
        hx_n::<32>(o, "k_d2w_hex"),
        "{name}: k_d2w"
    );
    assert_eq!(
        exp(b"xchonnect v1 wallet->dapp"),
        hx_n::<32>(o, "k_w2d_hex"),
        "{name}: k_w2d"
    );
    assert_eq!(
        exp(b"xchonnect v1 chain"),
        hx_n::<32>(o, "ck_0_hex"),
        "{name}: ck_0"
    );
    let api = keys::epoch_keys(&RootKey::from_bytes(root0), 0).unwrap();
    assert_eq!(api.d2w.expose(), &exp(b"xchonnect v1 dapp->wallet"));
    assert_eq!(api.w2d.expose(), &exp(b"xchonnect v1 wallet->dapp"));
    assert_eq!(api.chain.expose(), &exp(b"xchonnect v1 chain"));
    let sas8: [u8; 8] = crypto::hkdf_expand(&root0, b"xchonnect v1 sas").unwrap();
    let code = u64::from_be_bytes(sas8) % 1_000_000;
    assert_eq!(code, num(o, "sas_value"), "{name}: SAS");
    assert_eq!(format!("{code:06}"), text(o, "sas_digits"));
    assert_eq!(
        format!("{:03} {:03}", code / 1000, code % 1000),
        text(o, "sas_display")
    );

    // Production state machines fed with the explicit secrets.
    let unsigned = DappPairing::prepare(
        &mut Replay::new(&[&dsk_b, &s_b]),
        num(i, "created_at"),
        kid,
        DappPairingParams {
            relay,
            domain,
            pairing_mailbox: MailboxId(mbx_p),
            pairing_write: Token::from_bytes(w_p),
            lifetime_s: num(i, "lifetime_s"),
            ticket,
            options: ParseOptions::default(),
        },
    )
    .unwrap();
    assert_eq!(unsigned.sig_input().unwrap(), sig_input);
    let mut dapp = unsigned.finish(sig, Some(&origin_pk)).unwrap();
    assert_eq!(dapp.uri().to_uri(), uri);
    let parsed = PairingUri::parse(&uri, ParseOptions::default()).unwrap();
    assert_eq!(&parsed, dapp.uri());
    let doc = OriginDocument::parse(doc_json.as_bytes()).unwrap();
    let reply_at = num(i, "reply_at");
    let verified = VerifiedUri::new(parsed, &doc, reply_at).unwrap();
    let meta = match get(i, "wallet_name") {
        Json::String(n) => Some(WalletMeta {
            name: Some(n.clone()),
            ..Default::default()
        }),
        _ => None,
    };
    let (wallet, out) = WalletPairing::reply(
        &mut Replay::new(&[&ikm_e]),
        reply_at,
        &verified,
        MailboxId(hx_n(i, "wallet_mailbox_hex")),
        Token::from_bytes([0; 32]),
        Token::from_bytes(hx_n(i, "wallet_write_token_hex")),
        meta,
    )
    .unwrap();
    assert_eq!(out.envelope, env, "{name}: WalletPairing::reply envelope");
    let accepted = dapp.on_reply(reply_at, &out.envelope).unwrap();
    assert_eq!(accepted.sas().digits(), text(o, "sas_digits"));
    assert_eq!(wallet.sas().digits(), text(o, "sas_digits"));
}

// ===========================================================================
// Envelopes (spec 5.3)
// ===========================================================================

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

fn rpc_inner(seq: u64, id: [u8; 16], method: &str, params: String) -> Vec<u8> {
    Inner {
        seq,
        iat: ENV_IAT,
        exp: ENV_IAT + 600,
        id,
        message: Message::RpcRequest {
            method: method.to_owned(),
            params,
        },
    }
    .encode()
    .unwrap()
}

/// An `rpc.request` whose canonical encoding is exactly `target` bytes long.
fn inner_of_len(seq: u64, target: usize) -> Vec<u8> {
    let params = |n: usize| format!("{{\"message\":\"{}\"}}", "a".repeat(n));
    let mut n = target.saturating_sub(200);
    loop {
        let enc = rpc_inner(seq, pattern(0x01), "signMessage", params(n));
        match enc.len().cmp(&target) {
            core::cmp::Ordering::Equal => return enc,
            core::cmp::Ordering::Less => n += 1,
            core::cmp::Ordering::Greater => panic!("length {target} unreachable"),
        }
    }
}

fn env_cases() -> Vec<EnvCase> {
    let d2w_key = pattern(0x80);
    let w2d_key = pattern(0xa0);
    let wallet_mbx = pattern(0xc0);
    let dapp_mbx = pattern(0xd0);
    vec![
        EnvCase {
            name: "bucket-1k",
            description: "Typical rpc.request, dApp -> wallet; padded to the 1 KiB bucket",
            direction: Direction::DappToWallet,
            key: d2w_key,
            nonce: pattern(0x10),
            recipient: wallet_mbx,
            inner: rpc_inner(
                1,
                pattern(0x01),
                "signMessageByAddress",
                r#"{"message":"hello xchonnect","address":"xch1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0hn2a3"}"#.to_owned(),
            ),
        },
        EnvCase {
            name: "bucket-4k",
            description: "Inner plaintext of 1009 bytes (one byte too large for 1 KiB), wallet -> dApp; 4 KiB bucket",
            direction: Direction::WalletToDapp,
            key: w2d_key,
            nonce: pattern(0x30),
            recipient: dapp_mbx,
            inner: inner_of_len(2, 1009),
        },
        EnvCase {
            name: "bucket-16k",
            description: "Inner plaintext of exactly 16368 bytes (fills 16 KiB with no padding), dApp -> wallet",
            direction: Direction::DappToWallet,
            key: d2w_key,
            nonce: pattern(0x50),
            recipient: wallet_mbx,
            inner: inner_of_len(3, 16368),
        },
        EnvCase {
            name: "bucket-64k",
            description: "Inner plaintext of 40000 bytes, wallet -> dApp; 64 KiB bucket",
            direction: Direction::WalletToDapp,
            key: w2d_key,
            nonce: pattern(0x70),
            recipient: dapp_mbx,
            inner: inner_of_len(4, 40000),
        },
        EnvCase {
            name: "bucket-256k",
            description: "Largest permitted inner plaintext (262128 bytes), dApp -> wallet; 256 KiB bucket",
            direction: Direction::DappToWallet,
            key: d2w_key,
            nonce: pattern(0x90),
            recipient: wallet_mbx,
            inner: inner_of_len(5, 262_128),
        },
    ]
}

fn seal(c: &EnvCase) -> Vec<u8> {
    envelope::seal_session_with_nonce(
        &c.nonce,
        &DirectionKey::from_bytes(c.key),
        c.direction,
        &MailboxId(c.recipient),
        &c.inner,
    )
    .unwrap()
}

fn gen_envelope() -> J {
    let mut cases = Vec::new();
    for c in env_cases() {
        let env = seal(&c);
        let decoded = Envelope::decode(&env).unwrap();
        let mut f = vec![
            ("name", s(c.name)),
            ("description", s(c.description)),
            ("direction", s(direction_name(c.direction))),
            ("key_hex", h(&c.key)),
            ("nonce_hex", h(&c.nonce)),
            ("recipient_mailbox_hex", h(&c.recipient)),
        ];
        push_bytes(&mut f, "inner_cbor_hex", "inner_cbor_segments", &c.inner);
        f.push(("inner_cbor_len", J::Num(c.inner.len() as u64)));
        f.push((
            "inner_cbor_sha256_hex",
            h(&crypto::sha256_parts(&[&c.inner])),
        ));
        f.push((
            "aad_hex",
            h(&envelope::aad(
                Kind::Session,
                c.direction,
                &MailboxId(c.recipient),
            )),
        ));
        f.push((
            "padded_plaintext_len",
            J::Num((decoded.ct.len() - TAG_LEN) as u64),
        ));
        f.push(("ct_len", J::Num(decoded.ct.len() as u64)));
        f.push(("tag_hex", h(&decoded.ct[decoded.ct.len() - TAG_LEN..])));
        f.push(("envelope_len", J::Num(env.len() as u64)));
        f.push(("envelope_sha256_hex", h(&crypto::sha256_parts(&[&env]))));
        if env.len() <= ENVELOPE_HEX_MAX {
            f.push(("envelope_hex", h(&env)));
        }
        cases.push(J::Obj(f));
    }
    J::Obj(vec![
        ("format", J::Num(FORMAT)),
        ("protocol_version", J::Num(envelope::VERSION)),
        (
            "description",
            s(
                "Session envelopes (spec 5.3): XChaCha20-Poly1305 under a direction key with the 28-byte AAD, zero padding to the smallest bucket. One case per bucket. Large plaintexts use segments; envelopes above 4200 bytes are given by length, tag and SHA-256 only. See README.md.",
            ),
        ),
        ("cases", J::Arr(cases)),
    ])
}

fn check_envelope_case(c: &Json) {
    let name = text(c, "name");
    let key = hx_n::<32>(c, "key_hex");
    let nonce = hx_n::<24>(c, "nonce_hex");
    let mbx = hx_n::<16>(c, "recipient_mailbox_hex");
    let dir = direction_of(c);
    let inner = bytes_of(c, "inner_cbor");
    assert_eq!(inner.len() as u64, num(c, "inner_cbor_len"), "{name}");
    assert_eq!(
        crypto::sha256_parts(&[&inner]),
        hx_n::<32>(c, "inner_cbor_sha256_hex")
    );

    // AAD = "xchonnect" || v || kind || direction || recipient mailbox.
    let aad = [b"xchonnect".as_slice(), &[1, 1, dir as u8], &mbx].concat();
    assert_eq!(aad, hx(c, "aad_hex"), "{name}: aad");
    assert_eq!(
        envelope::aad(Kind::Session, dir, &MailboxId(mbx)).as_slice(),
        aad
    );

    let bucket = BUCKETS
        .iter()
        .copied()
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
    let ct = crypto::xchacha_seal(&DirectionKey::from_bytes(key), &nonce, &aad, &padded).unwrap();
    assert_eq!(
        &ct[ct.len() - 16..],
        hx(c, "tag_hex").as_slice(),
        "{name}: tag"
    );
    let env = cbor::encode(&Value::Map(vec![
        (Value::Uint(1), Value::Uint(1)),
        (Value::Uint(2), Value::Uint(1)),
        (Value::Uint(3), Value::bytes(&nonce)),
        (Value::Uint(4), Value::Bytes(ct)),
    ]))
    .unwrap();
    assert_eq!(env.len() as u64, num(c, "envelope_len"));
    assert_eq!(
        crypto::sha256_parts(&[&env]),
        hx_n::<32>(c, "envelope_sha256_hex"),
        "{name}: envelope"
    );
    if c.get("envelope_hex").is_some() {
        assert_eq!(env, hx(c, "envelope_hex"));
    }
    let k = DirectionKey::from_bytes(key);
    assert_eq!(
        envelope::seal_session_with_nonce(&nonce, &k, dir, &MailboxId(mbx), &inner).unwrap(),
        env
    );
    let back =
        envelope::open_session(&k, dir, &MailboxId(mbx), &Envelope::decode(&env).unwrap()).unwrap();
    assert_eq!(cbor::encode(&back).unwrap(), inner);
}

// ===========================================================================
// Rotation (spec 5.2, 9.2)
// ===========================================================================

struct RotCase {
    name: &'static str,
    description: &'static str,
    ck: [u8; 32],
    epoch: u64,
    a_seed: [u8; 32],
    b_seed: [u8; 32],
}

fn gen_rotation(ck0_basic: [u8; 32]) -> J {
    let rot_cases = [
        RotCase {
            name: "epoch-0-to-1",
            description: "First rotation of pairing case 'basic' (ck_e = its ck_0)",
            ck: ck0_basic,
            epoch: 0,
            a_seed: [0xa1; 32],
            b_seed: [0xb1; 32],
        },
        RotCase {
            name: "epoch-41-to-42",
            description: "Rotation from an arbitrary chaining key at epoch 41",
            ck: pattern(0x40),
            epoch: 41,
            a_seed: [0xa2; 32],
            b_seed: [0xb2; 32],
        },
    ];
    let mut cases = Vec::new();
    for c in rot_cases {
        // Session::begin_rotation / accept_rotation draw the X25519 secret first.
        let a = X25519Secret::from_bytes(draw(c.a_seed));
        let b = X25519Secret::from_bytes(draw(c.b_seed));
        let (a_pub, b_pub) = (a.public_key(), b.public_key());
        let dh = a.diffie_hellman(&b_pub).unwrap();
        assert_eq!(dh, b.diffie_hellman(&a_pub).unwrap());
        let new_epoch = c.epoch + 1;
        let th_r =
            crypto::sha256_parts(&[keys::LABEL_ROTATE, &new_epoch.to_be_bytes(), &a_pub, &b_pub]);
        let prk = crypto::hkdf_extract(&c.ck, &dh);
        let root = keys::rotation_root(&ChainKey::from_bytes(c.ck), &dh, new_epoch, &a_pub, &b_pub)
            .unwrap();
        let k = keys::epoch_keys(&root, new_epoch).unwrap();
        cases.push(J::Obj(vec![
            ("name", s(c.name)),
            ("description", s(c.description)),
            (
                "inputs",
                J::Obj(vec![
                    ("epoch", J::Num(c.epoch)),
                    ("ck_e_hex", h(&c.ck)),
                    ("a_entropy_seed_hex", h(&c.a_seed)),
                    ("b_entropy_seed_hex", h(&c.b_seed)),
                    ("a_hex", h(a.expose())),
                    ("b_hex", h(b.expose())),
                ]),
            ),
            (
                "outputs",
                J::Obj(vec![
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
                ]),
            ),
        ]));
    }
    J::Obj(vec![
        ("format", J::Num(FORMAT)),
        ("protocol_version", J::Num(envelope::VERSION)),
        (
            "description",
            s(
                "Epoch rotation key schedule (spec 5.2 'Rotation', 9.2): A = X25519(a, 9), B = X25519(b, 9), dh, th_r, prk, root_{e+1} and the new epoch's keys. See README.md.",
            ),
        ),
        ("cases", J::Arr(cases)),
    ])
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
    let a_pub = a.public_key();
    let b_pub = b.public_key();
    assert_eq!(a_pub, hx_n::<32>(o, "a_pub_hex"), "{name}: A");
    assert_eq!(b_pub, hx_n::<32>(o, "b_pub_hex"), "{name}: B");
    let dh = a.diffie_hellman(&b_pub).unwrap();
    assert_eq!(dh, b.diffie_hellman(&a_pub).unwrap());
    assert_eq!(dh, hx_n::<32>(o, "dh_hex"), "{name}: dh");
    let e1 = num(i, "epoch") + 1;
    assert_eq!(e1, num(o, "new_epoch"));
    let th_r = crypto::sha256_parts(&[b"xchonnect v1 rotate", &e1.to_be_bytes(), &a_pub, &b_pub]);
    assert_eq!(th_r, hx_n::<32>(o, "th_r_hex"), "{name}: th_r");
    let ck = hx_n::<32>(i, "ck_e_hex");
    let prk = crypto::hkdf_extract(&ck, &dh);
    assert_eq!(prk, hx_n::<32>(o, "prk_hex"), "{name}: prk");
    let root = crypto::hkdf_expand32(&prk, &[b"xchonnect v1 root", &th_r]).unwrap();
    assert_eq!(root, hx_n::<32>(o, "root_hex"), "{name}: root");
    let via_api = keys::rotation_root(&ChainKey::from_bytes(ck), &dh, e1, &a_pub, &b_pub).unwrap();
    assert_eq!(via_api.expose(), &root);
    let exp = |label: &[u8]| crypto::hkdf_expand32(&root, &[label]).unwrap();
    assert_eq!(
        exp(b"xchonnect v1 dapp->wallet"),
        hx_n::<32>(o, "k_d2w_hex")
    );
    assert_eq!(
        exp(b"xchonnect v1 wallet->dapp"),
        hx_n::<32>(o, "k_w2d_hex")
    );
    assert_eq!(exp(b"xchonnect v1 chain"), hx_n::<32>(o, "ck_hex"));
    let api = keys::epoch_keys(&via_api, e1).unwrap();
    assert_eq!(api.d2w.expose(), &exp(b"xchonnect v1 dapp->wallet"));
    assert_eq!(api.w2d.expose(), &exp(b"xchonnect v1 wallet->dapp"));
    assert_eq!(api.chain.expose(), &exp(b"xchonnect v1 chain"));
}

// ===========================================================================
// Negative cases
// ===========================================================================

const RECV_NOW: u64 = 1_790_001_000;

/// Raw session envelope bytes with hand-written CBOR heads.
fn raw_env(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

const N24: [u8; 24] = [0x11; 24];

fn zeros(n: usize) -> Vec<u8> {
    vec![0; n]
}

/// Encode an inner map with entries in the given (possibly non-canonical) order.
fn inner_raw(entries: &[(&str, Value)]) -> Vec<u8> {
    let mut out = vec![0xa0 | entries.len() as u8];
    for (k, v) in entries {
        out.extend(cbor::encode(&Value::text(k)).unwrap());
        out.extend(cbor::encode(v).unwrap());
    }
    out
}

fn seal_padded(
    key: &[u8; 32],
    nonce: &[u8; 24],
    dir: Direction,
    mbx: &[u8; 16],
    padded: &[u8],
) -> Vec<u8> {
    let ct = crypto::xchacha_seal(
        &DirectionKey::from_bytes(*key),
        nonce,
        &envelope::aad(Kind::Session, dir, &MailboxId(*mbx)),
        padded,
    )
    .unwrap();
    Envelope {
        kind: Kind::Session,
        n: nonce.to_vec(),
        ct,
    }
    .encode()
    .unwrap()
}

struct Neg {
    id: &'static str,
    description: &'static str,
    check: &'static str,
    fields: Vec<(&'static str, J)>,
    expected: &'static str,
}

fn neg_case(n: Neg) -> J {
    let mut f = vec![
        ("id", s(n.id)),
        ("description", s(n.description)),
        ("check", s(n.check)),
    ];
    f.extend(n.fields);
    f.push(("expected_error", s(n.expected)));
    J::Obj(f)
}

fn gen_negative(pairing: &PairingOut) -> J {
    let mut cases = Vec::new();
    let mut add = |n: Neg| cases.push(neg_case(n));

    // --- Pairing URI -------------------------------------------------------
    let uri_fields = |uri: String, now: u64| {
        vec![
            ("uri", s(uri)),
            ("origin_document", s(pairing.origin_doc.clone())),
            ("now", J::Num(now)),
        ]
    };
    let good = &pairing.uri;
    let x = good.expires_at;
    let mut wrong_key = good.clone();
    wrong_key.signature = Ed25519Seed::from_bytes(pattern(0x41)).sign(&good.sig_input().unwrap());
    add(Neg {
        id: "uri-signature-wrong-key",
        description: "Pairing case 'basic' URI with o replaced by a signature over the same uri_sig_input from a key not in the origin document",
        check: "verify_uri",
        fields: uri_fields(wrong_key.to_uri(), CREATED_AT + 5),
        expected: "bad_signature",
    });
    let mut tampered = good.clone();
    tampered.domain = "evil.example".into();
    add(Neg {
        id: "uri-signature-domain-changed",
        description: "d changed to another domain after signing (d is covered by the signature)",
        check: "verify_uri",
        fields: uri_fields(tampered.to_uri(), CREATED_AT + 5),
        expected: "bad_signature",
    });
    let mut flipped = good.clone();
    flipped.signature[0] ^= 0x01;
    add(Neg {
        id: "uri-signature-bit-flip",
        description: "One bit of the origin signature flipped",
        check: "verify_uri",
        fields: uri_fields(flipped.to_uri(), CREATED_AT + 5),
        expected: "bad_signature",
    });
    let mut other_kid = good.clone();
    other_kid.kid = "2025-01".into();
    other_kid.signature =
        Ed25519Seed::from_bytes(pairing.origin_seed).sign(&other_kid.sig_input().unwrap());
    add(Neg {
        id: "uri-unknown-kid",
        description: "Validly signed by the origin key but naming a kid the origin document does not list",
        check: "verify_uri",
        fields: uri_fields(other_kid.to_uri(), CREATED_AT + 5),
        expected: "invalid_origin",
    });
    add(Neg {
        id: "uri-expired",
        description: "Valid URI checked one second after x",
        check: "verify_uri",
        fields: uri_fields(good.to_uri(), x + 1),
        expected: "uri_expired",
    });
    add(Neg {
        id: "uri-lifetime-too-long",
        description: "Valid URI checked when x is more than 300 s + 60 s clock skew in the future",
        check: "verify_uri",
        fields: uri_fields(good.to_uri(), x - 361),
        expected: "uri_expired",
    });

    // --- Pairing reply at the dApp ----------------------------------------
    let mut bad_ct = Envelope::decode(&pairing.envelope).unwrap();
    bad_ct.ct[0] ^= 0x01;
    add(Neg {
        id: "pairing-reply-tampered",
        description: "Pairing case 'basic' reply with one ciphertext bit flipped, processed by the dApp built from that case's inputs",
        check: "dapp_on_reply",
        fields: vec![
            ("pairing_case", s("basic")),
            ("now", J::Num(CREATED_AT + 6)),
            ("envelope_hex", h(&bad_ct.encode().unwrap())),
        ],
        expected: "decrypt",
    });
    add(Neg {
        id: "pairing-reply-after-expiry",
        description: "Genuine pairing case 'basic' reply arriving after the URI expired",
        check: "dapp_on_reply",
        fields: vec![
            ("pairing_case", s("basic")),
            ("now", J::Num(x + 1)),
            ("envelope_hex", h(&pairing.envelope)),
        ],
        expected: "uri_expired",
    });

    // --- Envelope decoding --------------------------------------------------
    let ct1k = zeros(1024);
    let dec = |id, description, bytes: Vec<u8>, expected| {
        let mut f = Vec::new();
        push_bytes(&mut f, "envelope_hex", "envelope_segments", &bytes);
        Neg {
            id,
            description,
            check: "decode_envelope",
            fields: f,
            expected,
        }
    };
    let head = [0xa4, 0x01, 0x01, 0x02, 0x01, 0x03, 0x58, 0x18];
    let ct_head = [0x04, 0x59, 0x04, 0x00];
    // Control: the canonical form of the envelope used below decodes fine.
    assert!(Envelope::decode(&raw_env(&[&head, &N24, &ct_head, &ct1k])).is_ok());
    add(dec(
        "envelope-version-2",
        "Well-formed session envelope with v = 2",
        raw_env(&[
            &[0xa4, 0x01, 0x02, 0x02, 0x01, 0x03, 0x58, 0x18],
            &N24,
            &ct_head,
            &ct1k,
        ]),
        "unsupported_version",
    ));
    add(dec(
        "envelope-version-0",
        "Well-formed session envelope with v = 0",
        raw_env(&[
            &[0xa4, 0x01, 0x00, 0x02, 0x01, 0x03, 0x58, 0x18],
            &N24,
            &ct_head,
            &ct1k,
        ]),
        "unsupported_version",
    ));
    let mut big = raw_env(&[&head, &N24, &[0x04, 0x5a, 0x00, 0x08, 0x00, 0x00]]);
    big.extend(zeros(524_288));
    add(dec(
        "envelope-oversized",
        "Session envelope with a 512 KiB ciphertext: the encoding exceeds the 262400-byte envelope limit",
        big,
        "too_large",
    ));
    add(dec(
        "envelope-ct-not-bucket",
        "Session ciphertext of 1000 bytes (not a bucket size)",
        raw_env(&[&head, &N24, &[0x04, 0x59, 0x03, 0xe8], &zeros(1000)]),
        "malformed",
    ));
    add(dec(
        "envelope-nonce-length",
        "Session nonce of 12 bytes instead of 24",
        raw_env(&[
            &[0xa4, 0x01, 0x01, 0x02, 0x01, 0x03, 0x4c],
            &[0x11; 12],
            &ct_head,
            &ct1k,
        ]),
        "malformed",
    ));
    add(dec(
        "envelope-unknown-key",
        "Extra key 5 in the outer envelope",
        raw_env(&[
            &[0xa5, 0x01, 0x01, 0x02, 0x01, 0x03, 0x58, 0x18],
            &N24,
            &ct_head,
            &ct1k,
            &[0x05, 0xf6],
        ]),
        "malformed",
    ));
    add(dec(
        "cbor-non-shortest-int",
        "Non-canonical CBOR: v encoded as 0x18 0x01 instead of 0x01",
        raw_env(&[
            &[0xa4, 0x01, 0x18, 0x01, 0x02, 0x01, 0x03, 0x58, 0x18],
            &N24,
            &ct_head,
            &ct1k,
        ]),
        "cbor",
    ));
    add(dec(
        "cbor-non-shortest-length",
        "Non-canonical CBOR: nonce length encoded as 0x59 0x00 0x18 instead of 0x58 0x18",
        raw_env(&[
            &[0xa4, 0x01, 0x01, 0x02, 0x01, 0x03, 0x59, 0x00, 0x18],
            &N24,
            &ct_head,
            &ct1k,
        ]),
        "cbor",
    ));
    add(dec(
        "cbor-indefinite-map",
        "Non-canonical CBOR: indefinite-length outer map (0xbf ... 0xff)",
        raw_env(&[
            &[0xbf, 0x01, 0x01, 0x02, 0x01, 0x03, 0x58, 0x18],
            &N24,
            &ct_head,
            &ct1k,
            &[0xff],
        ]),
        "cbor",
    ));
    add(dec(
        "cbor-indefinite-bstr",
        "Non-canonical CBOR: ciphertext as an indefinite-length byte string with one chunk",
        raw_env(&[&head, &N24, &[0x04, 0x5f, 0x59, 0x04, 0x00], &ct1k, &[0xff]]),
        "cbor",
    ));
    add(dec(
        "cbor-unsorted-keys",
        "Non-canonical CBOR: outer map keys in the order 2, 1, 3, 4",
        raw_env(&[
            &[0xa4, 0x02, 0x01, 0x01, 0x01, 0x03, 0x58, 0x18],
            &N24,
            &ct_head,
            &ct1k,
        ]),
        "cbor",
    ));
    add(dec(
        "cbor-duplicate-key",
        "Non-canonical CBOR: key 1 appears twice",
        raw_env(&[
            &[0xa5, 0x01, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03, 0x58, 0x18],
            &N24,
            &ct_head,
            &ct1k,
        ]),
        "cbor",
    ));
    add(dec(
        "cbor-trailing-bytes",
        "Canonical envelope followed by one extra 0x00 byte",
        raw_env(&[&head, &N24, &ct_head, &ct1k, &[0x00]]),
        "cbor",
    ));
    add(dec(
        "cbor-tag",
        "Forbidden CBOR tag: ciphertext wrapped in tag 24",
        raw_env(&[&head, &N24, &[0x04, 0xd8, 0x18, 0x59, 0x04, 0x00], &ct1k]),
        "cbor",
    ));
    add(dec(
        "cbor-float",
        "Forbidden CBOR float: v encoded as half-precision 1.0 (0xf9 0x3c00)",
        raw_env(&[
            &[0xa4, 0x01, 0xf9, 0x3c, 0x00, 0x02, 0x01, 0x03, 0x58, 0x18],
            &N24,
            &ct_head,
            &ct1k,
        ]),
        "cbor",
    ));

    // --- Session decryption (envelope case bucket-1k) ----------------------
    let ec = env_cases().into_iter().next().unwrap();
    let env1k = seal(&ec);
    let open_fields = |dir: Direction, mbx: &[u8; 16], key: &[u8; 32], env: &[u8]| {
        vec![
            ("key_hex", h(key)),
            ("direction", s(direction_name(dir))),
            ("recipient_mailbox_hex", h(mbx)),
            ("envelope_hex", h(env)),
        ]
    };
    add(Neg {
        id: "aad-wrong-direction",
        description: "Envelope case 'bucket-1k' opened as wallet -> dApp (direction byte in the AAD differs)",
        check: "open_session",
        fields: open_fields(Direction::WalletToDapp, &ec.recipient, &ec.key, &env1k),
        expected: "decrypt",
    });
    let mut other_mbx = ec.recipient;
    other_mbx[15] ^= 0x01;
    add(Neg {
        id: "aad-wrong-mailbox",
        description: "Envelope case 'bucket-1k' opened for a different recipient mailbox (last byte flipped)",
        check: "open_session",
        fields: open_fields(ec.direction, &other_mbx, &ec.key, &env1k),
        expected: "decrypt",
    });
    let mut flipped_ct = Envelope::decode(&env1k).unwrap();
    flipped_ct.ct[1023] ^= 0x80;
    add(Neg {
        id: "ciphertext-tampered",
        description: "Envelope case 'bucket-1k' with one tag bit flipped",
        check: "open_session",
        fields: open_fields(
            ec.direction,
            &ec.recipient,
            &ec.key,
            &flipped_ct.encode().unwrap(),
        ),
        expected: "decrypt",
    });
    let mut padded = envelope::pad(&ec.inner).unwrap();
    let last = padded.len() - 1;
    padded[last] = 0x01;
    add(Neg {
        id: "padding-non-zero-last",
        description: "Correctly encrypted envelope whose last padding byte is 0x01",
        check: "open_session",
        fields: open_fields(
            ec.direction,
            &ec.recipient,
            &ec.key,
            &seal_padded(
                &ec.key,
                &pattern(0x20),
                ec.direction,
                &ec.recipient,
                &padded,
            ),
        ),
        expected: "malformed",
    });
    let mut padded = envelope::pad(&ec.inner).unwrap();
    padded[ec.inner.len()] = 0xff;
    add(Neg {
        id: "padding-non-zero-first",
        description: "Correctly encrypted envelope with 0xff directly after the inner CBOR item",
        check: "open_session",
        fields: open_fields(
            ec.direction,
            &ec.recipient,
            &ec.key,
            &seal_padded(
                &ec.key,
                &pattern(0x21),
                ec.direction,
                &ec.recipient,
                &padded,
            ),
        ),
        expected: "malformed",
    });
    let canonical_entries = |seq: Value| -> Vec<(&'static str, Value)> {
        vec![
            ("id", Value::bytes(&pattern::<16>(0x01))),
            ("exp", Value::Uint(ENV_IAT + 600)),
            ("iat", Value::Uint(ENV_IAT)),
            ("seq", seq),
            ("body", Value::Map(vec![])),
            ("type", Value::text("session.ping")),
        ]
    };
    let canon = inner_raw(&canonical_entries(Value::Uint(1)));
    assert_eq!(
        cbor::encode(&cbor::decode(&canon).unwrap()).unwrap(),
        canon,
        "control is canonical"
    );
    let mut unsorted = canonical_entries(Value::Uint(1));
    unsorted.rotate_left(3);
    let unsorted = inner_raw(&unsorted);
    add(Neg {
        id: "inner-cbor-unsorted-keys",
        description: "Correctly encrypted inner map with text keys out of canonical order (seq first)",
        check: "open_session",
        fields: open_fields(
            ec.direction,
            &ec.recipient,
            &ec.key,
            &seal_padded(
                &ec.key,
                &pattern(0x22),
                ec.direction,
                &ec.recipient,
                &envelope::pad(&unsorted).unwrap(),
            ),
        ),
        expected: "cbor",
    });
    let mut nonshort = inner_raw(&canonical_entries(Value::Uint(1)));
    // Replace `seq: 1` (0x63 "seq" 0x01) with the two-byte form 0x18 0x01.
    let pos = nonshort.windows(4).position(|w| w == b"\x63seq").unwrap() + 4;
    nonshort.splice(pos..pos + 1, [0x18, 0x01]);
    add(Neg {
        id: "inner-cbor-non-shortest-int",
        description: "Correctly encrypted inner map with seq encoded as 0x18 0x01",
        check: "open_session",
        fields: open_fields(
            ec.direction,
            &ec.recipient,
            &ec.key,
            &seal_padded(
                &ec.key,
                &pattern(0x23),
                ec.direction,
                &ec.recipient,
                &envelope::pad(&nonshort).unwrap(),
            ),
        ),
        expected: "cbor",
    });

    // --- Sender-side size limit -------------------------------------------
    let too_big = cbor::encode(&Value::Bytes(vec![0xaa; 262_124])).unwrap();
    assert_eq!(too_big.len(), 262_129);
    let mut f = vec![
        ("key_hex", h(&ec.key)),
        ("nonce_hex", h(&ec.nonce)),
        ("direction", s(direction_name(ec.direction))),
        ("recipient_mailbox_hex", h(&ec.recipient)),
    ];
    push_bytes(&mut f, "inner_cbor_hex", "inner_cbor_segments", &too_big);
    add(Neg {
        id: "seal-oversized",
        description: "Inner plaintext of 262129 bytes: plaintext + tag exceeds the largest bucket, so sealing must fail",
        check: "seal_session",
        fields: f,
        expected: "too_large",
    });

    // --- Receive rules (replay, times) ---------------------------------------
    let root = pattern::<32>(0x70);
    let k = keys::epoch_keys(&RootKey::from_bytes(root), 0).unwrap();
    let own = pattern::<16>(0x30);
    let mut recv = |id, description, seq: u64, iat: u64, exp: u64, nonce: u8, expected| {
        let inner = Inner {
            seq,
            iat,
            exp,
            id: pattern(nonce),
            message: Message::SessionPing,
        }
        .encode()
        .unwrap();
        let env = envelope::seal_session_with_nonce(
            &pattern(nonce),
            &k.d2w,
            Direction::DappToWallet,
            &MailboxId(own),
            &inner,
        )
        .unwrap();
        add(Neg {
            id,
            description,
            check: "session_receive",
            fields: vec![
                ("role", s("wallet")),
                ("root_0_hex", h(&root)),
                ("key_hex", h(k.d2w.expose())),
                ("direction", s(direction_name(Direction::DappToWallet))),
                ("recipient_mailbox_hex", h(&own)),
                ("last_accepted_seq", J::Num(5)),
                ("now", J::Num(RECV_NOW)),
                ("inner_cbor_hex", h(&inner)),
                ("envelope_hex", h(&env)),
            ],
            expected,
        });
    };
    recv(
        "replay-equal-seq",
        "session.ping with seq 5 after seq 5 was accepted",
        5,
        RECV_NOW,
        RECV_NOW + 60,
        0x01,
        "replay",
    );
    recv(
        "replay-lower-seq",
        "session.ping with seq 3 after seq 5 was accepted (reordered)",
        3,
        RECV_NOW,
        RECV_NOW + 60,
        0x02,
        "replay",
    );
    recv(
        "message-expired",
        "seq 6 but exp one second before now",
        6,
        RECV_NOW - 61,
        RECV_NOW - 1,
        0x03,
        "expired",
    );
    recv(
        "message-lifetime",
        "seq 6 with exp - iat = 7 days + 1 s",
        6,
        RECV_NOW,
        RECV_NOW + 604_801,
        0x04,
        "lifetime_too_long",
    );
    recv(
        "message-clock-skew",
        "seq 6 with iat 301 s in the future",
        6,
        RECV_NOW + 301,
        RECV_NOW + 400,
        0x05,
        "clock_skew",
    );

    J::Obj(vec![
        ("format", J::Num(FORMAT)),
        ("protocol_version", J::Num(envelope::VERSION)),
        (
            "description",
            s(
                "Inputs every implementation MUST reject, with the expected error kind. The 'check' field names the operation; see README.md.",
            ),
        ),
        ("cases", J::Arr(cases)),
    ])
}

fn run_negative(c: &Json, pairing: &Json) -> Result<(), Error> {
    match text(c, "check") {
        "verify_uri" => {
            let uri = PairingUri::parse(text(c, "uri"), ParseOptions::default())?;
            let doc = OriginDocument::parse(text(c, "origin_document").as_bytes())?;
            VerifiedUri::new(uri, &doc, num(c, "now")).map(|_| ())
        }
        "dapp_on_reply" => {
            let case = get(pairing, "cases")
                .as_array()
                .unwrap()
                .iter()
                .find(|p| text(p, "name") == text(c, "pairing_case"))
                .unwrap();
            let (i, o) = (get(case, "inputs"), get(case, "outputs"));
            let unsigned = DappPairing::prepare(
                &mut Replay::new(&[&hx(i, "dsk_hex"), &hx(i, "pairing_secret_hex")]),
                num(i, "created_at"),
                text(i, "kid"),
                DappPairingParams {
                    relay: text(i, "relay"),
                    domain: text(i, "domain"),
                    pairing_mailbox: MailboxId(hx_n(i, "pairing_mailbox_hex")),
                    pairing_write: Token::from_bytes(hx_n(i, "pairing_write_token_hex")),
                    lifetime_s: num(i, "lifetime_s"),
                    ticket: match get(i, "ticket_hex") {
                        Json::Null => None,
                        _ => Some(hx_n(i, "ticket_hex")),
                    },
                    options: ParseOptions::default(),
                },
            )
            .unwrap();
            let mut dapp = unsigned
                .finish(
                    hx_n(o, "origin_signature_hex"),
                    Some(&hx_n(o, "origin_pk_hex")),
                )
                .unwrap();
            assert_eq!(dapp.uri().to_uri(), text(o, "uri"));
            dapp.on_reply(num(c, "now"), &hx(c, "envelope_hex"))
                .map(|_| ())
        }
        "decode_envelope" => Envelope::decode(&bytes_of(c, "envelope")).map(|_| ()),
        "open_session" => {
            let env = Envelope::decode(&hx(c, "envelope_hex"))?;
            envelope::open_session(
                &DirectionKey::from_bytes(hx_n(c, "key_hex")),
                direction_of(c),
                &MailboxId(hx_n(c, "recipient_mailbox_hex")),
                &env,
            )
            .map(|_| ())
        }
        "seal_session" => envelope::seal_session_with_nonce(
            &hx_n(c, "nonce_hex"),
            &DirectionKey::from_bytes(hx_n(c, "key_hex")),
            direction_of(c),
            &MailboxId(hx_n(c, "recipient_mailbox_hex")),
            &bytes_of(c, "inner_cbor"),
        )
        .map(|_| ()),
        "session_receive" => {
            assert_eq!(text(c, "role"), "wallet");
            let root = RootKey::from_bytes(hx_n(c, "root_0_hex"));
            let k = keys::epoch_keys(&root, 0).unwrap();
            assert_eq!(k.d2w.expose(), &hx_n::<32>(c, "key_hex"));
            let own = MailboxId(hx_n(c, "recipient_mailbox_hex"));
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

// ===========================================================================
// Files and tests
// ===========================================================================

fn generate_all() -> Vec<(&'static str, String)> {
    let (pairing, outs) = gen_pairing();
    let basic_ck0 = {
        let J::Obj(f) = &pairing else { unreachable!() };
        let J::Arr(cases) = &f.iter().find(|(k, _)| *k == "cases").unwrap().1 else {
            unreachable!()
        };
        let J::Obj(c) = &cases[0] else { unreachable!() };
        let J::Obj(o) = &c.iter().find(|(k, _)| *k == "outputs").unwrap().1 else {
            unreachable!()
        };
        let J::Str(ck) = &o.iter().find(|(k, _)| *k == "ck_0_hex").unwrap().1 else {
            unreachable!()
        };
        hex::decode(ck).unwrap().try_into().unwrap()
    };
    vec![
        ("pairing.json", render_file(&pairing)),
        ("envelope.json", render_file(&gen_envelope())),
        ("rotation.json", render_file(&gen_rotation(basic_ck0))),
        ("negative.json", render_file(&gen_negative(&outs[0]))),
    ]
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
    let cases = get(&v, "cases").as_array().unwrap();
    assert_eq!(cases.len(), 2);
    for c in cases {
        check_pairing_case(c);
    }
}

#[test]
fn envelope_vectors_rederive() {
    let v = load("envelope.json");
    let cases = get(&v, "cases").as_array().unwrap();
    let buckets: Vec<u64> = cases.iter().map(|c| num(c, "ct_len")).collect();
    assert_eq!(
        buckets,
        BUCKETS.map(|b| b as u64).to_vec(),
        "one case per bucket"
    );
    for c in cases {
        check_envelope_case(c);
    }
}

#[test]
fn rotation_vectors_rederive() {
    let v = load("rotation.json");
    let p = load("pairing.json");
    let cases = get(&v, "cases").as_array().unwrap();
    assert_eq!(
        text(get(&cases[0], "inputs"), "ck_e_hex"),
        text(get(&get(&p, "cases")[0], "outputs"), "ck_0_hex"),
        "first rotation chains from pairing case 'basic'"
    );
    for c in cases {
        check_rotation_case(c);
    }
}

#[test]
fn negative_vectors_fail_as_expected() {
    let v = load("negative.json");
    let p = load("pairing.json");
    let cases = get(&v, "cases").as_array().unwrap();
    for c in cases {
        let id = text(c, "id");
        let got = run_negative(c, &p);
        match got {
            Ok(()) => panic!("negative case {id} was accepted"),
            Err(e) => assert_eq!(error_kind(&e), text(c, "expected_error"), "case {id}: {e}"),
        }
    }
    let ids: std::collections::HashSet<&str> = cases.iter().map(|c| text(c, "id")).collect();
    assert_eq!(ids.len(), cases.len(), "unique ids");
}
