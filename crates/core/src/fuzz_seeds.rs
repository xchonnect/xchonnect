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
use crate::crypto::{MailboxId, PairingSecret, Token};
use crate::envelope::{self, Envelope, Kind};
use crate::message::{
    Inner, Limits, Message, PairingReply, Permissions, Rotate, RotatePhase, RpcError, RpcOutcome,
    WalletMeta,
};
use crate::origin::OriginDocument;
use crate::pairing::tests::{fixture, paired};
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

fn seeds() -> Vec<(&'static str, String, Vec<u8>)> {
    let mut out: Vec<(&'static str, String, Vec<u8>)> = Vec::new();
    let mut f = fixture();
    let (mut ds, mut ws) = paired(&mut f);

    // envelope_decode: real session envelope, a pairing-kind envelope, padded plaintext.
    let ping = ds.seal(&mut f.rng, NOW, Message::SessionPing, 60).unwrap();
    out.push(("envelope_decode", "session".into(), ping.envelope.clone()));
    let pairing = Envelope {
        kind: Kind::Pairing,
        n: vec![3; 32],
        ct: vec![0x5a; envelope::PAIRING_CT_LEN],
    };
    out.push((
        "envelope_decode",
        "pairing".into(),
        pairing.encode().unwrap(),
    ));
    out.push((
        "envelope_decode",
        "padded-inner".into(),
        envelope::pad(&inner(1, Message::SessionPing)).unwrap(),
    ));

    // inner_decode: every message type, plus a pairing reply.
    for (i, (name, m)) in messages().into_iter().enumerate() {
        out.push(("inner_decode", name.into(), inner(i as u64 + 1, m)));
    }
    let reply = PairingReply {
        mailbox: MailboxId([8; 16]),
        write_token: Token::from_bytes([8; 32]),
        meta: Some(WalletMeta {
            name: Some("Klimper".into()),
            icon: None,
            link: None,
        }),
    };
    out.push((
        "inner_decode",
        "pairing-reply".into(),
        reply.encode().unwrap(),
    ));

    // session_open: flags byte, then u16be-length-prefixed inner plaintexts.
    let frame = |flags: u8, msgs: &[Vec<u8>]| {
        let mut b = vec![flags];
        for m in msgs {
            b.extend_from_slice(&(m.len() as u16).to_be_bytes());
            b.extend_from_slice(m);
        }
        b
    };
    let all: Vec<Vec<u8>> = messages()
        .into_iter()
        .enumerate()
        .map(|(i, (_, m))| inner(i as u64 + 1, m))
        .collect();
    out.push((
        "session_open",
        "wallet-active-all".into(),
        frame(0b010, &all),
    ));
    out.push(("session_open", "dapp-active-all".into(), frame(0b111, &all)));
    out.push(("session_open", "wallet-inactive".into(), frame(0b000, &all)));

    // uri_parse: both forms, with and without a ticket, and developer-mode loopback.
    let build = |relay: &str, domain: &str, ticket, opts| {
        PairingUri::build(
            &f.signer,
            NOW,
            UriParams {
                relay,
                mailbox: MailboxId([1; 16]),
                write_token: Token::from_bytes([2; 32]),
                dapp_pk: [3; 32],
                secret: PairingSecret::from_bytes([4; 32]),
                domain,
                expires_at: NOW + 300,
                ticket,
            },
            opts,
        )
        .unwrap()
    };
    let normal = build(
        "https://relay.example/v1",
        "pengui.xyz",
        None,
        ParseOptions::default(),
    );
    out.push(("uri_parse", "qr".into(), normal.to_uri().into_bytes()));
    out.push((
        "uri_parse",
        "universal-link".into(),
        normal
            .to_universal_link("https://klimper.app/pair")
            .into_bytes(),
    ));
    let ticketed = build(
        "https://relay.example",
        "app.pengui.xyz",
        Some([5; 32]),
        ParseOptions::default(),
    );
    out.push(("uri_parse", "ticket".into(), ticketed.to_uri().into_bytes()));
    let dev = ParseOptions {
        developer_mode: true,
    };
    let local = build("http://127.0.0.1:8080", "localhost:3000", None, dev);
    out.push((
        "uri_parse",
        "dev-localhost".into(),
        local.to_uri().into_bytes(),
    ));

    // origin_parse.
    let pk = crate::b64::encode(&f.signer.public_key());
    out.push((
        "origin_parse",
        "minimal".into(),
        format!(
            r#"{{"v":1,"name":"Pengui","origin_keys":[{{"kid":"k1","pk":"{pk}","not_after":"2030-01-01"}}]}}"#
        )
        .into_bytes(),
    ));
    out.push((
        "origin_parse",
        "full".into(),
        format!(
            r#"{{"v":1,"name":"Pengui","icon":"https://pengui.xyz/i.png","return_url":"https://pengui.xyz/back","origin_keys":[{{"kid":"k1","pk":"{pk}","not_after":"2030-01-01"}},{{"kid":"k2.next","pk":"{pk}","not_after":"2028-02-29"}}]}}"#
        )
        .into_bytes(),
    ));

    // session_state: fresh sessions, a pending rotation, and a draining one.
    out.push(("session_state", "dapp".into(), ds.to_bytes().unwrap()));
    out.push(("session_state", "wallet".into(), ws.to_bytes().unwrap()));
    let offer = ds
        .begin_rotation(
            &mut f.rng,
            NOW,
            MailboxId([0x60; 16]),
            Token::from_bytes([0x61; 32]),
            Token::from_bytes([0x62; 32]),
        )
        .unwrap();
    out.push((
        "session_state",
        "dapp-rotating".into(),
        ds.to_bytes().unwrap(),
    ));
    let got = ws.open(NOW, &ws.own_mailbox(), &offer.envelope).unwrap();
    let Message::SessionRotate(r) = got.message else {
        panic!("expected rotate")
    };
    ws.accept_rotation(
        &mut f.rng,
        NOW,
        &r,
        MailboxId([0x70; 16]),
        Token::from_bytes([0x71; 32]),
        Token::from_bytes([0x72; 32]),
    )
    .unwrap();
    out.push((
        "session_state",
        "wallet-draining".into(),
        ws.to_bytes().unwrap(),
    ));

    // pending_requests.
    let mut p = PendingRequests::default();
    out.push(("pending_requests", "empty".into(), p.to_bytes().unwrap()));
    p.insert([1; 16], "chainId", NOW + 60).unwrap();
    p.insert([2; 16], "signCoinSpends", NOW + 600).unwrap();
    p.resolve(&Message::RpcReceived {
        request_id: [2; 16],
    })
    .unwrap();
    out.push(("pending_requests", "two".into(), p.to_bytes().unwrap()));

    // push_reg: sealed tokens for the fuzz target's fixed gateway key [9; 32].
    let gw = crate::crypto::X25519Secret::from_bytes([9; 32]);
    for (name, platform) in [
        ("apns", crate::push::Platform::Apns),
        ("fcm", crate::push::Platform::Fcm),
    ] {
        let t = crate::push::PushToken {
            platform,
            device_token: "0123456789abcdef".repeat(4),
            hint_key: [3; 32],
            exp: NOW + 86_400,
        };
        out.push((
            "push_reg",
            name.into(),
            t.seal(&mut f.rng, &gw.public_key(), NOW).unwrap(),
        ));
    }

    out
}

#[test]
fn fuzz_seeds_parse_and_dump() {
    let seeds = seeds();
    for (target, name, bytes) in &seeds {
        let ok = match *target {
            "envelope_decode" => Envelope::decode(bytes).is_ok() || envelope::unpad(bytes).is_ok(),
            "inner_decode" => {
                let v = cbor::decode(bytes).unwrap();
                Inner::from_value(&v).is_ok() || PairingReply::from_value(&v).is_ok()
            }
            "session_open" => true,
            "uri_parse" => PairingUri::parse(
                core::str::from_utf8(bytes).unwrap(),
                ParseOptions {
                    developer_mode: true,
                },
            )
            .is_ok(),
            "origin_parse" => OriginDocument::parse(bytes).is_ok(),
            "session_state" => Session::from_bytes(bytes).is_ok(),
            "pending_requests" => PendingRequests::from_bytes(bytes).is_ok(),
            "push_reg" => crate::push::PushToken::open(
                &crate::crypto::X25519Secret::from_bytes([9; 32]),
                bytes,
                NOW,
            )
            .is_ok(),
            other => panic!("unknown target {other}"),
        };
        assert!(ok, "seed {target}/{name} is not accepted");
    }
    if let Some(dir) = std::env::var_os("XCHONNECT_FUZZ_SEEDS") {
        let dir = std::path::PathBuf::from(dir);
        for (target, name, bytes) in &seeds {
            let d = dir.join(target);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join(format!("seed-{name}")), bytes).unwrap();
        }
    }
}
