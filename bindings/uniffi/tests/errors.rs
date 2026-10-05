//! Every error crossing the UniFFI boundary is typed, and no secret material reaches
//! its message or any `Debug` output (TASK-33 AC3; spec threats T13 "operational
//! leakage" and T5 "stolen device / local attacker").
//!
//! Two independent checks:
//!
//! 1. **Exact message set.** Every boundary call is driven into every reachable failure
//!    with inputs stuffed full of recognisable secret material, and the set of messages
//!    produced is compared against a literal list of constants. A message built from
//!    attacker- or caller-supplied data cannot be in that list, so any new formatting of
//!    a value into an error fails this test.
//! 2. **Marker scan.** Every message, every `Display`, and the `Debug` of every exported
//!    object is scanned for each piece of secret material in its raw, base64url and hex
//!    forms.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::collections::BTreeSet;
use std::sync::Arc;

use xchonnect_core::b64;
use xchonnect_core::crypto::{Ed25519Seed, MailboxId, OsEntropy, Token, X25519Secret};
use xchonnect_core::pairing::{DappPairing, DappPairingParams};
use xchonnect_core::session::Session as DappSession;
use xchonnect_core::uri::{LocalSigner, ParseOptions};
use xchonnect_uniffi::*;

const NOW: u64 = 1_790_000_000;

/// 32 recognisable bytes: the tag, padded with `.`. Used wherever a real deployment
/// would hold a secret, so that any leak is a literal substring match.
fn marked(tag: &str) -> [u8; 32] {
    let mut a = [b'.'; 32];
    for (i, b) in tag.bytes().take(32).enumerate() {
        a[i] = b;
    }
    a
}

fn marked16(tag: &str) -> [u8; 16] {
    let mut a = [b'.'; 16];
    for (i, b) in tag.bytes().take(16).enumerate() {
        a[i] = b;
    }
    a
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Every form a 32-byte secret could plausibly be printed in.
fn forms(tag: &str) -> Vec<String> {
    let raw = marked(tag);
    vec![tag.to_owned(), b64::encode(&raw), hex(&raw)]
}

/// Collects error messages and asserts that none of them carries secret material.
#[derive(Default)]
struct Collector {
    messages: BTreeSet<String>,
    /// Strings that must never appear anywhere.
    markers: Vec<String>,
}

impl Collector {
    fn secret(&mut self, tag: &str) {
        self.markers.extend(forms(tag));
    }

    /// Record the message of an expected failure and check the value is `Err`.
    #[track_caller]
    fn err<T: std::fmt::Debug>(&mut self, what: &str, r: core::result::Result<T, XchonnectError>) {
        let e = match r {
            Err(e) => e,
            Ok(v) => panic!("{what} unexpectedly succeeded: {v:?}"),
        };
        // `Display` and the variant payload must agree: Swift and Kotlin only ever see
        // this one string.
        self.scan(what, &e.to_string());
        self.messages.insert(e.to_string());
        // The `Debug` of the error itself must also be clean.
        self.scan(what, &format!("{e:?}"));
    }

    #[track_caller]
    fn scan(&self, what: &str, text: &str) {
        for m in &self.markers {
            assert!(
                !text.contains(m.as_str()),
                "{what}: secret material {m:?} leaked into {text:?}"
            );
        }
    }
}

/// A dApp whose pairing mailbox, write token and origin key are all marked.
struct Dapp {
    pairing: DappPairing,
    origin_json: String,
    uri: String,
}

/// An origin document naming the key derived from `seed` as `k1`.
fn origin_json(seed: [u8; 32]) -> String {
    let signer = LocalSigner::new(Ed25519Seed::from_bytes(seed), "k1").unwrap();
    format!(
        r#"{{"v":1,"name":"Pengui","origin_keys":[{{"kid":"k1","pk":"{}","not_after":"2030-01-01"}}]}}"#,
        b64::encode(&signer.public_key())
    )
}

fn dapp() -> Dapp {
    let signer = LocalSigner::new(Ed25519Seed::from_bytes(marked("ORIGIN-SEED")), "k1").unwrap();
    let origin_json = origin_json(marked("ORIGIN-SEED"));
    let pairing = DappPairing::new(
        &mut OsEntropy,
        NOW,
        &signer,
        DappPairingParams {
            relay: "https://relay.example",
            domain: "pengui.xyz",
            pairing_mailbox: MailboxId(marked16("PAIRING-MAILBOX")),
            pairing_write: Token::from_bytes(marked("PAIRING-WRITE-TOKEN")),
            lifetime_s: 300,
            ticket: None,
            options: ParseOptions::default(),
        },
    )
    .unwrap();
    let uri = pairing.uri().to_uri();
    Dapp {
        pairing,
        origin_json,
        uri,
    }
}

fn wallet_mailbox() -> NewMailbox {
    NewMailbox {
        mailbox: MailboxId(marked16("WALLET-MAILBOX")).to_b64(),
        read_token: b64::encode(&marked("WALLET-READ-TOKEN")),
        write_token: b64::encode(&marked("WALLET-WRITE-TOKEN")),
    }
}

/// Pair through the bindings with marked material on both sides.
fn paired(c: &mut Collector) -> (DappSession, MailboxId, Arc<Session>, String) {
    let mut d = dapp();
    let verified = VerifiedPairingUri::new(d.uri.clone(), d.origin_json.clone(), NOW, false)
        .unwrap_or_else(|e| panic!("verify: {e}"));
    let w = wallet_mailbox();
    let reply = verified.reply(NOW, w.clone(), None).unwrap();
    let accepted = d
        .pairing
        .on_reply(NOW + 1, &b64::decode(&reply.outgoing.envelope).unwrap())
        .unwrap();
    let d_mbx = MailboxId(marked16("DAPP-MAILBOX"));
    let (mut ds, confirm) = accepted
        .confirm(
            &mut OsEntropy,
            NOW + 2,
            d_mbx,
            Token::from_bytes(marked("DAPP-READ-TOKEN")),
            Token::from_bytes(marked("DAPP-WRITE-TOKEN")),
        )
        .unwrap();
    let ws = reply
        .pairing
        .on_confirm(NOW + 3, b64::encode(&confirm.envelope))
        .unwrap();
    let ready = ws.confirm_sas(NOW + 4, None).unwrap().unwrap();
    ds.open(NOW + 4, &d_mbx, &b64::decode(&ready.envelope).unwrap())
        .unwrap();
    ds.confirm_sas(&mut OsEntropy, NOW + 4, None).unwrap();
    c.scan("session Debug", &format!("{ws:?}"));
    c.scan("pairing Debug", &format!("{:?}", reply.pairing));
    c.scan("verified-uri Debug", &format!("{verified:?}"));
    (ds, d_mbx, ws, w.mailbox)
}

/// Exactly the messages the boundary may produce. Each is a compile-time constant in
/// `xchonnect-core` (whose `Error` carries only `&'static str`) or an
/// `XchonnectError::input` parameter *name*. Nothing here is derived from a value.
const EXPECTED_MESSAGES: &[&str] = &[
    "OHTTP response already decapsulated",
    "decryption failed",
    "invalid CBOR: too many items",
    "invalid CBOR: trailing bytes",
    "invalid challenge",
    "invalid envelope",
    "invalid from_mailbox",
    "invalid gateway_public_key",
    "invalid limit",
    "invalid mailbox",
    "invalid network",
    "invalid offer.epk",
    "invalid origin document: not valid JSON for schema",
    "invalid pairing URI: unknown scheme or version",
    "invalid public key",
    "invalid puzzle hash",
    "invalid read_token",
    "invalid request_id",
    "invalid state: pairing timed out",
    "invalid state: session ended",
    "invalid token",
    "malformed message: not valid JSON",
    "malformed message: ohttp key config: unsupported suite",
    "message expired",
    "origin signature invalid",
    "pairing URI expired",
    "replayed or reordered message",
];

#[test]
fn boundary_errors_are_typed_and_carry_no_secrets() {
    let mut c = Collector::default();
    for tag in [
        "ORIGIN-SEED",
        "PAIRING-MAILBOX",
        "PAIRING-WRITE-TOKEN",
        "WALLET-MAILBOX",
        "WALLET-READ-TOKEN",
        "WALLET-WRITE-TOKEN",
        "DAPP-MAILBOX",
        "DAPP-READ-TOKEN",
        "DAPP-WRITE-TOKEN",
        "PLAINTEXT-PARAMS",
    ] {
        c.secret(tag);
    }
    // The pairing URI carries the pairing secret `s`: it must never be echoed either.
    let d = dapp();
    c.markers.push(d.uri.clone());

    // --- free functions -------------------------------------------------------------
    c.err(
        "token_hash",
        token_hash(b64::encode(&marked("LEAK-TOKEN"))[..20].into()),
    );
    c.err("solve_pow", solve_pow("@@@".into()));
    c.err(
        "inspect_uri non-uri",
        inspect_uri(d.uri.replace("xchonnect:", "http:"), false),
    );
    c.err(
        "inspect_uri wrong version",
        inspect_uri(d.uri.replace("v1?", "v9?"), false),
    );
    c.err(
        "seal_push_token",
        seal_push_token(
            "https://push.example".into(),
            b64::encode(&marked("GATEWAY-KEY"))[..10].into(),
            PushPlatform::Apns,
            "device".into(),
            NOW,
            3600,
        ),
    );
    c.err("parse_origin_document", parse_origin_document("{}".into()));

    // --- pairing --------------------------------------------------------------------
    c.err(
        "verify with a foreign origin key",
        VerifiedPairingUri::new(
            d.uri.clone(),
            origin_json(marked("EVIL-ORIGIN-SEED")),
            NOW,
            false,
        ),
    );
    c.err(
        "verify after expiry",
        VerifiedPairingUri::new(d.uri.clone(), d.origin_json.clone(), NOW + 400, false),
    );
    let verified =
        VerifiedPairingUri::new(d.uri.clone(), d.origin_json.clone(), NOW, false).unwrap();
    let mut bad = wallet_mailbox();
    bad.mailbox = b64::encode(&marked("WALLET-MAILBOX"));
    c.err(
        "reply with a wrong-length mailbox",
        verified.reply(NOW, bad, None),
    );
    let mut bad = wallet_mailbox();
    bad.read_token = format!("!{}", bad.read_token);
    c.err(
        "reply with a non-base64url read token",
        verified.reply(NOW, bad, None),
    );
    let reply = verified.reply(NOW, wallet_mailbox(), None).unwrap();
    c.err(
        "on_confirm with a foreign envelope",
        reply
            .pairing
            .on_confirm(NOW, b64::encode(&marked("NOT-AN-ENVELOPE"))),
    );
    c.err(
        "on_confirm with a non-base64url envelope",
        reply.pairing.on_confirm(NOW, "!!!".into()),
    );
    c.err(
        "on_confirm after the timeout",
        reply
            .pairing
            .on_confirm(NOW + 400, b64::encode(&marked("NOT-AN-ENVELOPE"))),
    );

    // --- sessions -------------------------------------------------------------------
    let (mut ds, d_mbx, ws, w_mbx) = paired(&mut c);
    let plaintext = format!(r#"{{"message":"{}"}}"#, "PLAINTEXT-PARAMS");
    let req: Outgoing = ds
        .seal(
            &mut OsEntropy,
            NOW + 10,
            xchonnect_core::rpc::request("chip0002_signMessage", &plaintext).unwrap(),
            600,
        )
        .unwrap()
        .into();
    let got = ws
        .open(NOW + 10, w_mbx.clone(), req.envelope.clone())
        .unwrap();
    c.err(
        "replayed envelope",
        ws.open(NOW + 10, w_mbx.clone(), req.envelope.clone()),
    );
    c.err(
        "envelope from an unknown mailbox",
        ws.open(
            NOW + 11,
            b64::encode(&marked("WALLET-MAILBOX")),
            req.envelope.clone(),
        ),
    );
    c.err(
        "non-base64url envelope",
        ws.open(NOW + 11, w_mbx.clone(), format!("!{}", req.envelope)),
    );
    c.err(
        "foreign envelope",
        ws.open(NOW + 11, w_mbx.clone(), b64::encode(&[0u8; 300])),
    );
    c.err(
        "respond with a bad request id",
        ws.respond(NOW + 11, b64::encode(&marked("REQUEST-ID")), "{}".into()),
    );
    c.err(
        "respond with non-JSON",
        ws.respond(NOW + 11, got.id.clone(), "PLAINTEXT-PARAMS".into()),
    );
    c.err(
        "accept a rotation with a malformed epk",
        ws.accept_rotation(
            NOW + 11,
            RotationOffer {
                epoch: 1,
                epk: "!".into(),
                mailbox: w_mbx.clone(),
                write_token: b64::encode(&marked("PEER-WRITE-TOKEN")),
            },
            wallet_mailbox(),
        ),
    );
    // An envelope whose own `exp` has passed.
    let short: Outgoing = ds
        .seal(
            &mut OsEntropy,
            NOW + 11,
            xchonnect_core::rpc::request("chainId", &plaintext).unwrap(),
            1,
        )
        .unwrap()
        .into();
    c.err(
        "expired envelope",
        ws.open(NOW + 100, w_mbx.clone(), short.envelope),
    );

    // The persisted blob holds every session secret; nothing may echo it.
    let state = ws.to_bytes().unwrap();
    c.markers.push(b64::encode(&state));
    c.markers.push(hex(&state));
    c.err(
        "from_bytes with a truncated blob",
        Session::from_bytes(state[..8].to_vec()),
    );
    c.err(
        "from_bytes with foreign bytes",
        Session::from_bytes(marked("PERSISTED-STATE").to_vec()),
    );
    let ended = ws.end(NOW + 12, None).unwrap();
    ds.open(NOW + 12, &d_mbx, &b64::decode(&ended.envelope).unwrap())
        .unwrap();
    c.err("ping after end", ws.ping(NOW + 13));
    c.err(
        "open after end",
        ws.open(NOW + 13, w_mbx, req.envelope.clone()),
    );

    // --- OHTTP ----------------------------------------------------------------------
    c.err(
        "ohttp client with a malformed config",
        OhttpClient::new(vec![0, 1, 2]),
    );
    let cfg = ohttp_select_key(key_config_list()).unwrap();
    let client = OhttpClient::new(cfg).unwrap();
    c.scan("ohttp client Debug", &format!("{client:?}"));
    let enc = client
        .encapsulate(OhttpRequest {
            method: "GET".into(),
            scheme: "https".into(),
            authority: "relay.example".into(),
            path: "/v1/info".into(),
            headers: vec![HttpHeader {
                name: "authorization".into(),
                value: format!("Bearer {}", b64::encode(&marked("WALLET-READ-TOKEN"))),
            }],
            body: Vec::new(),
        })
        .unwrap();
    c.scan("ohttp context Debug", &format!("{:?}", enc.context));
    c.err(
        "decapsulate a forged response",
        enc.context.decapsulate(vec![0; 64]),
    );
    c.err("decapsulate twice", enc.context.decapsulate(vec![0; 64]));
    let enc = client
        .encapsulate(OhttpRequest {
            method: "GET".into(),
            scheme: "https".into(),
            authority: "relay.example".into(),
            path: "/.well-known/ohttp-keys".into(),
            headers: Vec::new(),
            body: Vec::new(),
        })
        .unwrap();
    c.err(
        "key rotation from a forged response",
        enc.context.decapsulate_key_rotation(vec![0; 64]),
    );

    // --- wallet-kit -----------------------------------------------------------------
    #[cfg(feature = "wallet-kit")]
    wallet_kit_errors(&mut c);

    // The set of messages the boundary produced must be exactly the reviewed list of
    // constants: a message built from a value cannot be in it, and an entry that stops
    // being reachable has to be removed deliberately.
    let expected: BTreeSet<String> = EXPECTED_MESSAGES.iter().map(|s| (*s).to_owned()).collect();
    assert_eq!(
        c.messages, expected,
        "the boundary's error messages are no longer exactly the reviewed constants \
         (a value may have been formatted into an error)"
    );
}

/// A one-entry `application/ohttp-keys` list for key id 7 (X25519/HKDF-SHA256,
/// ChaCha20-Poly1305).
fn key_config_list() -> Vec<u8> {
    let pk = X25519Secret::from_bytes([9; 32]).public_key();
    let mut cfg = vec![7, 0x00, 0x20];
    cfg.extend_from_slice(&pk);
    cfg.extend_from_slice(&[0, 4, 0, 1, 0, 3]);
    let mut list = vec![0, cfg.len() as u8];
    list.extend_from_slice(&cfg);
    list
}

#[cfg(feature = "wallet-kit")]
fn wallet_kit_errors(c: &mut Collector) {
    struct NoSigner;
    impl WalletSigner for NoSigner {
        fn sign(&self, _public_key: String, _message: Vec<u8>) -> Option<Vec<u8>> {
            None
        }
    }
    struct NoApprover;
    impl WalletApprover for NoApprover {
        fn approve(&self, _prompt_json: String) -> bool {
            false
        }
    }
    struct NoLimits;
    impl LimitStorage for NoLimits {
        fn load(&self) -> Option<String> {
            None
        }
        fn save(&self, _json: String) -> bool {
            true
        }
    }
    let ctx = |f: &dyn Fn(&mut WalletRequestContext)| {
        let mut ctx = WalletRequestContext {
            dapp: "pengui.xyz".into(),
            network: "mainnet".into(),
            session_chain_id: "mainnet".into(),
            methods: vec!["chainId".into()],
            exposed_keys: vec![],
            xch_per_request: None,
            xch_per_day: None,
            allow_agg_sig_unsafe: false,
            allow_unknown_contracts: false,
            owned_puzzle_hashes: vec![],
            keys: vec![],
            now: NOW,
        };
        f(&mut ctx);
        ctx
    };
    let run = |ctx: WalletRequestContext| {
        handle_wallet_request(
            "chainId".into(),
            "{}".into(),
            ctx,
            Arc::new(NoSigner),
            Arc::new(NoApprover),
            Arc::new(NoLimits),
        )
    };
    c.err(
        "unknown network",
        run(ctx(&|x| x.network = hex(&marked("NETWORK")))),
    );
    c.err(
        "malformed exposed key",
        run(ctx(&|x| x.exposed_keys = vec![hex(&marked("EXPOSED-KEY"))])),
    );
    c.err(
        "malformed signing key",
        run(ctx(&|x| x.keys = vec![hex(&marked("SIGNING-KEY"))])),
    );
    c.err(
        "malformed puzzle hash",
        run(ctx(&|x| {
            x.owned_puzzle_hashes = vec![hex(&marked("PUZZLE-HASH"))[..10].into()]
        })),
    );
    c.err(
        "malformed limit",
        run(ctx(&|x| x.xch_per_day = Some("not a number".into()))),
    );
}

/// Compile-time proof that every variant is enumerated, and that `Display` is exactly
/// the variant payload (Swift gets `XchonnectError.<Variant>(message:)`, Kotlin
/// `XchonnectException.<Variant>`). Adding a variant breaks this match.
#[test]
fn every_variant_is_enumerated_and_displays_its_payload() {
    let all = [
        XchonnectError::Cbor("m".into()),
        XchonnectError::Malformed("m".into()),
        XchonnectError::UnsupportedVersion("m".into()),
        XchonnectError::Decrypt("m".into()),
        XchonnectError::TooLarge("m".into()),
        XchonnectError::Replay("m".into()),
        XchonnectError::Expired("m".into()),
        XchonnectError::LifetimeTooLong("m".into()),
        XchonnectError::ClockSkew("m".into()),
        XchonnectError::InvalidUri("m".into()),
        XchonnectError::UriExpired("m".into()),
        XchonnectError::InvalidOrigin("m".into()),
        XchonnectError::BadSignature("m".into()),
        XchonnectError::State("m".into()),
        XchonnectError::AlreadyPaired("m".into()),
        XchonnectError::WeakKey("m".into()),
        XchonnectError::PowInvalid("m".into()),
        XchonnectError::Crypto("m".into()),
        XchonnectError::OhttpKeyMismatch("m".into()),
        XchonnectError::InvalidInput("m".into()),
        XchonnectError::Other("m".into()),
    ];
    for e in &all {
        assert_eq!(e.to_string(), "m", "Display must be the payload: {e:?}");
        // Exhaustive: a new variant makes this match fail to compile.
        let name = match e {
            XchonnectError::Cbor(_) => "Cbor",
            XchonnectError::Malformed(_) => "Malformed",
            XchonnectError::UnsupportedVersion(_) => "UnsupportedVersion",
            XchonnectError::Decrypt(_) => "Decrypt",
            XchonnectError::TooLarge(_) => "TooLarge",
            XchonnectError::Replay(_) => "Replay",
            XchonnectError::Expired(_) => "Expired",
            XchonnectError::LifetimeTooLong(_) => "LifetimeTooLong",
            XchonnectError::ClockSkew(_) => "ClockSkew",
            XchonnectError::InvalidUri(_) => "InvalidUri",
            XchonnectError::UriExpired(_) => "UriExpired",
            XchonnectError::InvalidOrigin(_) => "InvalidOrigin",
            XchonnectError::BadSignature(_) => "BadSignature",
            XchonnectError::State(_) => "State",
            XchonnectError::AlreadyPaired(_) => "AlreadyPaired",
            XchonnectError::WeakKey(_) => "WeakKey",
            XchonnectError::PowInvalid(_) => "PowInvalid",
            XchonnectError::Crypto(_) => "Crypto",
            XchonnectError::OhttpKeyMismatch(_) => "OhttpKeyMismatch",
            XchonnectError::InvalidInput(_) => "InvalidInput",
            XchonnectError::Other(_) => "Other",
        };
        assert!(format!("{e:?}").starts_with(name));
    }
    assert_eq!(all.len(), 21, "variant count changed: review the mapping");
}

/// Every core error kind maps to its own variant, never to the catch-all `Other`.
#[test]
fn core_error_kinds_map_to_dedicated_variants() {
    use xchonnect_core::Error as E;
    let cases: Vec<(E, &str)> = vec![
        (E::Cbor("x"), "Cbor"),
        (E::Malformed("x"), "Malformed"),
        (E::UnsupportedVersion, "UnsupportedVersion"),
        (E::Decrypt, "Decrypt"),
        (E::TooLarge, "TooLarge"),
        (E::Replay, "Replay"),
        (E::Expired, "Expired"),
        (E::LifetimeTooLong, "LifetimeTooLong"),
        (E::ClockSkew, "ClockSkew"),
        (E::InvalidUri("x"), "InvalidUri"),
        (E::UriExpired, "UriExpired"),
        (E::InvalidOrigin("x"), "InvalidOrigin"),
        (E::BadSignature, "BadSignature"),
        (E::State("x"), "State"),
        (E::AlreadyPaired, "AlreadyPaired"),
        (E::WeakKey, "WeakKey"),
        (E::PowInvalid, "PowInvalid"),
        (E::Crypto("x"), "Crypto"),
        (E::OhttpKeyMismatch, "OhttpKeyMismatch"),
    ];
    for (core, variant) in cases {
        let display = core.to_string();
        let mapped = XchonnectError::from(core);
        assert!(
            format!("{mapped:?}").starts_with(variant),
            "expected {variant}, got {mapped:?}"
        );
        assert_eq!(mapped.to_string(), display);
    }
}
