//! Seed corpus for the cargo-fuzz targets in `fuzz/`, generated from the real encoders.
//!
//! The test always builds the seeds and checks that each one is accepted by the parser
//! its target exercises. With `XCHONNECT_FUZZ_SEEDS=<repo>/fuzz/corpus` set it also
//! writes them to `<dir>/<target>/seed-<name>`:
//!
//! ```text
//! XCHONNECT_FUZZ_SEEDS=$PWD/fuzz/corpus cargo test -p xchonnect-core fuzz_seeds
//! ```

#![allow(clippy::unwrap_used, clippy::panic)]

use crate::cbor;
use crate::crypto::{MailboxId, PairingSecret, Token, X25519Secret};
use crate::envelope::{self, Envelope, Kind};
use crate::message::{
    Inner, Limits, Message, PairingReply, Permissions, Rotate, RotatePhase, RpcError, RpcOutcome,
    WalletMeta,
};
use crate::origin::OriginDocument;
use crate::pairing::tests::{fixture, paired, ping, rotate_of};
use crate::push::{Platform, PushToken};
use crate::rpc::PendingRequests;
use crate::session::Session;
use crate::uri::{PairingUri, ParseOptions, UriParams};

const NOW: u64 = 1_790_000_100;

fn inner(seq: u64, message: Message) -> Vec<u8> {
    Inner {
        seq,
        iat: NOW,
        exp: NOW + 3600,
        id: [seq as u8; 16],
        message,
    }
    .encode()
    .unwrap()
}

fn messages() -> Vec<(&'static str, Message)> {
    vec![
        ("ping", Message::SessionPing),
        ("pong", Message::SessionPong),
        (
            "rpc-request",
            Message::RpcRequest {
                method: "signCoinSpends".into(),
                params: r#"{"coinSpends":[],"partialSign":true}"#.into(),
            },
        ),
        (
            "rpc-result",
            Message::RpcResponse {
                request_id: [9; 16],
                outcome: RpcOutcome::Result("\"mainnet\"".into()),
            },
        ),
        (
            "rpc-error",
            Message::RpcResponse {
                request_id: [9; 16],
                outcome: RpcOutcome::Error(RpcError {
                    code: 4001,
                    message: "user rejected request".into(),
                    data: Some("{}".into()),
                }),
            },
        ),
        (
            "rpc-received",
            Message::RpcReceived {
                request_id: [9; 16],
            },
        ),
        (
            "confirm",
            Message::SessionConfirm {
                mailbox: MailboxId([4; 16]),
                write_token: Token::from_bytes([5; 32]),
            },
        ),
        (
            "ready",
            Message::SessionReady {
                meta: Some(WalletMeta {
                    name: Some("Klimper".into()),
                    icon: Some("https://klimper.app/icon.png".into()),
                    link: Some("https://klimper.app/pair".into()),
                }),
            },
        ),
        (
            "rotate-offer",
            Message::SessionRotate(Rotate {
                phase: RotatePhase::Offer,
                epoch: 1,
                epk: [9; 32],
                mailbox: MailboxId([6; 16]),
                write_token: Token::from_bytes([7; 32]),
            }),
        ),
        (
            "permissions",
            Message::SessionPermissions(Permissions {
                methods: vec!["signCoinSpends".into(), "getPublicKeys".into()],
                keys: vec!["0xaa".into()],
                limits: Some(Limits {
                    per_request_mojos: Some("1000".into()),
                    per_day_mojos: Some("1000000".into()),
                }),
            }),
        ),
        (
            "end",
            Message::SessionEnd {
                reason: Some("logout".into()),
            },
        ),
    ]
}

fn seeds() -> Vec<(&'static str, &'static str, Vec<u8>)> {
    let mut out = Vec::new();
    let mut add = |target, name, bytes| out.push((target, name, bytes));
    let mut f = fixture();
    let (mut ds, mut ws) = paired(&mut f);

    // envelope_decode: real session envelope, a pairing-kind envelope, padded plaintext.
    add(
        "envelope_decode",
        "session",
        ping(&mut ds, &mut f, NOW).envelope,
    );
    let pairing = Envelope {
        kind: Kind::Pairing,
        n: vec![3; 32],
        ct: vec![0x5a; envelope::PAIRING_CT_LEN],
    };
    add("envelope_decode", "pairing", pairing.encode().unwrap());
    let padded = envelope::pad(&inner(1, Message::SessionPing)).unwrap();
    add("envelope_decode", "padded-inner", padded);

    // inner_decode: every message type, plus a pairing reply.
    let all: Vec<(&str, Vec<u8>)> = (1..)
        .zip(messages())
        .map(|(seq, (name, m))| (name, inner(seq, m)))
        .collect();
    for (name, m) in &all {
        add("inner_decode", *name, m.clone());
    }
    let meta = WalletMeta {
        name: Some("Klimper".into()),
        icon: None,
        link: None,
    };
    let reply = PairingReply {
        mailbox: MailboxId([8; 16]),
        write_token: Token::from_bytes([8; 32]),
        meta: Some(meta),
    };
    add("inner_decode", "pairing-reply", reply.encode().unwrap());

    // session_open: flags byte, then u16be-length-prefixed inner plaintexts.
    let frame = |flags: u8| {
        let mut b = vec![flags];
        for (_, m) in &all {
            b.extend_from_slice(&(m.len() as u16).to_be_bytes());
            b.extend_from_slice(m);
        }
        b
    };
    add("session_open", "wallet-active-all", frame(0b010));
    add("session_open", "dapp-active-all", frame(0b111));
    add("session_open", "wallet-inactive", frame(0b000));

    // uri_parse: both forms, with and without a ticket, and developer-mode loopback.
    let build = |relay, domain, ticket, developer_mode| {
        let p = UriParams {
            relay,
            mailbox: MailboxId([1; 16]),
            write_token: Token::from_bytes([2; 32]),
            dapp_pk: [3; 32],
            secret: PairingSecret::from_bytes([4; 32]),
            domain,
            expires_at: NOW + 300,
            ticket,
        };
        let opts = ParseOptions { developer_mode };
        PairingUri::build(&f.signer, NOW, p, opts).unwrap()
    };
    let normal = build("https://relay.example/v1", "pengui.xyz", None, false);
    add("uri_parse", "qr", normal.to_uri().into_bytes());
    let link = normal.to_universal_link("https://klimper.app/pair");
    add("uri_parse", "universal-link", link.into_bytes());
    let ticketed = build(
        "https://relay.example",
        "app.pengui.xyz",
        Some([5; 32]),
        false,
    );
    add("uri_parse", "ticket", ticketed.to_uri().into_bytes());
    let local = build("http://127.0.0.1:8080", "localhost:3000", None, true);
    add("uri_parse", "dev-localhost", local.to_uri().into_bytes());

    // origin_parse.
    let pk = crate::b64::encode(&f.signer.public_key());
    let minimal = format!(
        r#"{{"v":1,"name":"Pengui","origin_keys":[{{"kid":"k1","pk":"{pk}","not_after":"2030-01-01"}}]}}"#
    );
    add("origin_parse", "minimal", minimal.into_bytes());
    let full = format!(
        r#"{{"v":1,"name":"Pengui","icon":"https://pengui.xyz/i.png","return_url":"https://pengui.xyz/back","origin_keys":[{{"kid":"k1","pk":"{pk}","not_after":"2030-01-01"}},{{"kid":"k2.next","pk":"{pk}","not_after":"2028-02-29"}}]}}"#
    );
    add("origin_parse", "full", full.into_bytes());

    // session_state: fresh sessions, a pending rotation, and a draining one.
    add("session_state", "dapp", ds.to_bytes().unwrap());
    add("session_state", "wallet", ws.to_bytes().unwrap());
    let (m, r, w) = (MailboxId([0x60; 16]), [0x61; 32], [0x62; 32]);
    let (r, w) = (Token::from_bytes(r), Token::from_bytes(w));
    let offer = ds.begin_rotation(&mut f.rng, NOW, m, r, w).unwrap();
    add("session_state", "dapp-rotating", ds.to_bytes().unwrap());
    let offer = rotate_of(ws.open(NOW, &ws.own_mailbox(), &offer.envelope).unwrap());
    let (m, r, w) = (MailboxId([0x70; 16]), [0x71; 32], [0x72; 32]);
    let (r, w) = (Token::from_bytes(r), Token::from_bytes(w));
    ws.accept_rotation(&mut f.rng, NOW, &offer, m, r, w)
        .unwrap();
    add("session_state", "wallet-draining", ws.to_bytes().unwrap());

    // pending_requests.
    let mut p = PendingRequests::default();
    add("pending_requests", "empty", p.to_bytes().unwrap());
    p.insert([1; 16], "chainId", NOW + 60).unwrap();
    p.insert([2; 16], "signCoinSpends", NOW + 600).unwrap();
    let received = Message::RpcReceived {
        request_id: [2; 16],
    };
    p.resolve(&received).unwrap();
    add("pending_requests", "two", p.to_bytes().unwrap());

    // push_reg: sealed tokens for the fuzz target's fixed gateway key [9; 32].
    let gw = X25519Secret::from_bytes([9; 32]).public_key();
    for (name, platform) in [("apns", Platform::Apns), ("fcm", Platform::Fcm)] {
        let t = PushToken {
            platform,
            device_token: "0123456789abcdef".repeat(4),
            hint_key: [3; 32],
            exp: NOW + 86_400,
        };
        add("push_reg", name, t.seal(&mut f.rng, &gw, NOW).unwrap());
    }

    out
}

/// The `session_open` input format: a flags byte (bits 0-2), then frames
/// `u16be length || inner plaintext` covering the rest exactly, each an inner message.
fn session_frames_ok(bytes: &[u8]) -> bool {
    let Some((&flags, mut rest)) = bytes.split_first() else {
        return false;
    };
    let mut frames = 0;
    while let [hi, lo, tail @ ..] = rest {
        let len = usize::from(u16::from_be_bytes([*hi, *lo]));
        let Some((inner, next)) = (len <= tail.len()).then(|| tail.split_at(len)) else {
            return false;
        };
        if !cbor::decode(inner).is_ok_and(|v| Inner::from_value(&v).is_ok()) {
            return false;
        }
        frames += 1;
        rest = next;
    }
    flags <= 0b111 && rest.is_empty() && frames > 0
}

#[test]
fn fuzz_seeds_parse_and_dump() {
    let seeds = seeds();
    let dev = ParseOptions {
        developer_mode: true,
    };
    let gw = X25519Secret::from_bytes([9; 32]);
    for (target, name, bytes) in &seeds {
        let ok = match *target {
            "envelope_decode" => Envelope::decode(bytes).is_ok() || envelope::unpad(bytes).is_ok(),
            "inner_decode" => {
                let v = cbor::decode(bytes).unwrap();
                Inner::from_value(&v).is_ok() || PairingReply::from_value(&v).is_ok()
            }
            "session_open" => session_frames_ok(bytes),
            "uri_parse" => PairingUri::parse(core::str::from_utf8(bytes).unwrap(), dev).is_ok(),
            "origin_parse" => OriginDocument::parse(bytes).is_ok(),
            "session_state" => Session::from_bytes(bytes).is_ok(),
            "pending_requests" => PendingRequests::from_bytes(bytes).is_ok(),
            "push_reg" => PushToken::open(&gw, bytes, NOW).is_ok(),
            other => panic!("unknown target {other}"),
        };
        assert!(ok, "seed {target}/{name} is not accepted");
    }
    // The frame check itself rejects malformed inputs.
    for bad in [&[][..], &[0], &[8, 0, 1, 0xa0], &[0, 0, 5, 0xa0]] {
        assert!(!session_frames_ok(bad));
    }
    if let Some(dir) = std::env::var_os("XCHONNECT_FUZZ_SEEDS") {
        for (target, name, bytes) in &seeds {
            let d = std::path::Path::new(&dir).join(target);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join(format!("seed-{name}")), bytes).unwrap();
        }
    }
}
