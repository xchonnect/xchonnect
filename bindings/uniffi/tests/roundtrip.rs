//! End-to-end: the exported wallet API against the core's dApp side.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use xchonnect_core::b64;
use xchonnect_core::crypto::{Ed25519Seed, MailboxId, OsEntropy, Token, random_array};
use xchonnect_core::message::{Message, Rotate, RotatePhase};
use xchonnect_core::pairing::{DappPairing, DappPairingParams};
use xchonnect_core::session::Session as DappSession;
use xchonnect_core::uri::{LocalSigner, ParseOptions};
use xchonnect_uniffi::*;

const NOW: u64 = 1_790_000_000;

struct Dapp {
    pairing: DappPairing,
    origin_json: String,
}

fn dapp() -> Dapp {
    let signer = LocalSigner::new(Ed25519Seed::from_bytes([1; 32]), "k1").unwrap();
    let origin_json = format!(
        r#"{{"v":1,"name":"Pengui","icon":"https://pengui.xyz/i.png","origin_keys":[{{"kid":"k1","pk":"{}","not_after":"2030-01-01"}}]}}"#,
        b64::encode(&signer.public_key())
    );
    let pairing = DappPairing::new(
        &mut OsEntropy,
        NOW,
        &signer,
        DappPairingParams {
            relay: "https://relay.example",
            domain: "pengui.xyz",
            pairing_mailbox: MailboxId([1; 16]),
            pairing_write: Token::from_bytes([2; 32]),
            lifetime_s: 300,
            ticket: None,
            options: ParseOptions::default(),
        },
    )
    .unwrap();
    Dapp {
        pairing,
        origin_json,
    }
}

fn new_mailbox() -> NewMailbox {
    NewMailbox {
        mailbox: MailboxId(random_array(&mut OsEntropy)).to_b64(),
        read_token: generate_token(),
        write_token: generate_token(),
    }
}

fn mbx(s: &str) -> MailboxId {
    MailboxId::from_b64(s).unwrap()
}

fn env(o: &Outgoing) -> Vec<u8> {
    b64::decode(&o.envelope).unwrap()
}

fn core_out(o: xchonnect_core::session::Outgoing) -> Outgoing {
    Outgoing {
        mailbox: o.mailbox.to_b64(),
        write_token: b64::encode(o.write_token.expose()),
        envelope: b64::encode(&o.envelope),
        id: b64::encode(&o.id),
    }
}

/// Pair through the bindings; returns (dApp session, dApp mailbox D, wallet session).
fn paired() -> (DappSession, MailboxId, std::sync::Arc<Session>) {
    let mut d = dapp();
    let uri = d.pairing.uri().to_uri();

    let info = inspect_uri(uri.clone(), false).unwrap();
    assert_eq!(info.domain, "pengui.xyz");
    assert_eq!(info.relay, "https://relay.example");
    assert_eq!(
        info.origin_document_url,
        "https://pengui.xyz/.well-known/xchonnect.json"
    );
    assert_eq!(info.expires_at, NOW + 300);

    let verified = VerifiedPairingUri::new(uri, d.origin_json.clone(), NOW + 1, false).unwrap();
    assert_eq!(verified.dapp_name(), "Pengui");
    assert_eq!(
        verified.dapp_icon().as_deref(),
        Some("https://pengui.xyz/i.png")
    );
    assert!(verified.domain_display().warnings.is_empty());

    let w = new_mailbox();
    let reply = verified
        .reply(
            NOW + 2,
            w.clone(),
            Some(WalletMetadata {
                name: Some("Klimper".into()),
                ..Default::default()
            }),
        )
        .unwrap();
    assert_eq!(reply.outgoing.mailbox, MailboxId([1; 16]).to_b64());
    assert_eq!(reply.pairing.own_mailbox().mailbox, w.mailbox);

    let accepted = d.pairing.on_reply(NOW + 3, &env(&reply.outgoing)).unwrap();
    assert_eq!(accepted.sas().to_string(), reply.pairing.sas());
    assert_eq!(
        accepted.wallet_meta().unwrap().name.as_deref(),
        Some("Klimper")
    );

    let d_mbx = MailboxId([20; 16]);
    let (mut ds, confirm) = accepted
        .confirm(
            &mut OsEntropy,
            NOW + 4,
            d_mbx,
            Token::from_bytes([21; 32]),
            Token::from_bytes([22; 32]),
        )
        .unwrap();
    let confirm = core_out(confirm);
    assert_eq!(confirm.mailbox, w.mailbox);
    let ws = reply.pairing.on_confirm(NOW + 5, confirm.envelope).unwrap();
    assert!(!ws.is_active());
    assert_eq!(ws.role(), SessionRole::Wallet);

    let ready = ws.confirm_sas(NOW + 6, None).unwrap().unwrap();
    assert!(ws.is_active());
    assert_eq!(mbx(&ready.mailbox), d_mbx);
    ds.open(NOW + 7, &d_mbx, &env(&ready)).unwrap();
    assert!(
        ds.confirm_sas(&mut OsEntropy, NOW + 7, None)
            .unwrap()
            .is_none()
    );
    assert!(ds.is_active());
    (ds, d_mbx, ws)
}

fn request(ds: &mut DappSession, now: u64, method: &str) -> Outgoing {
    core_out(
        ds.seal(
            &mut OsEntropy,
            now,
            xchonnect_core::rpc::request(method, r#"{"message":"hi"}"#).unwrap(),
            600,
        )
        .unwrap(),
    )
}

#[test]
fn pairing_request_response_rotation_end() {
    let (mut ds, mut d_mbx, ws) = paired();

    // Request / receipt / response.
    let req = request(&mut ds, NOW + 10, "chip0002_signMessage");
    let own = ws.own_mailbox();
    assert_eq!(req.mailbox, own.mailbox);
    let got = ws
        .open(NOW + 11, own.mailbox.clone(), req.envelope.clone())
        .unwrap();
    assert_eq!(got.id, req.id);
    let MessageBody::RpcRequest {
        method,
        canonical_method,
        params_json,
    } = &got.body
    else {
        panic!("expected request, got {got:?}")
    };
    assert_eq!(method, "chip0002_signMessage");
    assert_eq!(canonical_method, "signMessage");
    assert_eq!(params_json, r#"{"message":"hi"}"#);
    // Replays are rejected with a typed error.
    assert!(matches!(
        ws.open(NOW + 11, own.mailbox.clone(), req.envelope.clone()),
        Err(XchonnectError::Replay(_))
    ));

    let rcpt = ws.received(NOW + 12, got.id.clone()).unwrap();
    let m = ds.open(NOW + 12, &d_mbx, &env(&rcpt)).unwrap();
    assert!(matches!(m.message, Message::RpcReceived { .. }));

    let resp = ws
        .respond(NOW + 13, got.id.clone(), r#""sig""#.into())
        .unwrap();
    let m = ds.open(NOW + 13, &d_mbx, &env(&resp)).unwrap();
    assert!(
        matches!(m.message, Message::RpcResponse { request_id, .. } if b64::encode(&request_id) == req.id)
    );

    // Error response.
    let req2 = request(&mut ds, NOW + 14, "signCoinSpends");
    let got2 = ws
        .open(NOW + 14, own.mailbox.clone(), req2.envelope)
        .unwrap();
    let rej = ws
        .respond_error(
            NOW + 15,
            got2.id,
            rpc_error_code_value(RpcErrorCode::UserRejected),
            "User rejected".into(),
            None,
        )
        .unwrap();
    let m = ds.open(NOW + 15, &d_mbx, &env(&rej)).unwrap();
    let Message::RpcResponse {
        outcome: xchonnect_core::message::RpcOutcome::Error(e),
        ..
    } = m.message
    else {
        panic!("expected error response")
    };
    assert_eq!(e.code, 4002);
    assert!(matches!(
        ws.respond(NOW + 15, "x".into(), "{}".into()),
        Err(XchonnectError::InvalidInput(_))
    ));
    assert!(matches!(
        ws.respond(NOW + 15, b64::encode(&[0; 16]), "not json".into()),
        Err(XchonnectError::Malformed(_))
    ));

    // Persistence round trip mid-session.
    let ws = Session::from_bytes(ws.to_bytes().unwrap()).unwrap();
    assert!(ws.is_active());

    // Ping / pong.
    let ping = core_out(
        ds.seal(&mut OsEntropy, NOW + 16, Message::SessionPing, 300)
            .unwrap(),
    );
    let got = ws
        .open(NOW + 16, own.mailbox.clone(), ping.envelope)
        .unwrap();
    assert_eq!(got.body, MessageBody::Ping);
    let pong = ws.pong(NOW + 16).unwrap();
    assert!(matches!(
        ds.open(NOW + 16, &d_mbx, &env(&pong)).unwrap().message,
        Message::SessionPong
    ));

    // dApp-initiated rotation.
    assert!(!ws.needs_rotation(NOW + 17));
    assert!(ws.needs_rotation(NOW + 31 * 24 * 3600));
    let d2 = MailboxId([30; 16]);
    let offer = core_out(
        ds.begin_rotation(
            &mut OsEntropy,
            NOW + 20,
            d2,
            Token::from_bytes([31; 32]),
            Token::from_bytes([32; 32]),
        )
        .unwrap(),
    );
    let got = ws
        .open(NOW + 21, own.mailbox.clone(), offer.envelope)
        .unwrap();
    let MessageBody::RotationOffered { offer } = got.body else {
        panic!("expected rotation offer")
    };
    assert_eq!(offer.epoch, 1);
    let w2 = new_mailbox();
    let acc = ws.accept_rotation(NOW + 22, offer, w2.clone()).unwrap();
    assert!(acc.abandoned.is_none());
    assert_eq!(
        mbx(&acc.outgoing.mailbox),
        d_mbx,
        "accept goes to the old mailbox"
    );
    assert_eq!(ws.epoch(), 1);
    assert_eq!(ws.own_mailbox().mailbox, w2.mailbox);
    assert_eq!(ws.draining_mailbox().unwrap().mailbox, own.mailbox);
    assert!(
        ws.finish_drain().unwrap().is_none(),
        "responder waits for the peer"
    );
    ds.open(NOW + 23, &d_mbx, &env(&acc.outgoing)).unwrap();
    assert_eq!(ds.epoch(), 1);
    d_mbx = d2;
    let req3 = request(&mut ds, NOW + 24, "chainId");
    assert_eq!(req3.mailbox, w2.mailbox);
    let got3 = ws
        .open(NOW + 24, w2.mailbox.clone(), req3.envelope)
        .unwrap();
    let resp3 = ws
        .respond(NOW + 25, got3.id, r#""mainnet""#.into())
        .unwrap();
    assert_eq!(mbx(&resp3.mailbox), d_mbx);
    ds.open(NOW + 25, &d_mbx, &env(&resp3)).unwrap();
    let retired = ws.finish_drain().unwrap().unwrap();
    assert_eq!(retired.mailbox, own.mailbox);
    assert_eq!(retired.read_token, own.read_token);
    assert!(
        ds.finish_drain().is_some(),
        "initiator retires after the accept"
    );

    // Wallet-initiated rotation.
    let w3 = new_mailbox();
    let offer = ws.begin_rotation(NOW + 30, w3.clone()).unwrap();
    assert_eq!(ws.pending_rotation_mailbox().unwrap().mailbox, w3.mailbox);
    let m = ds.open(NOW + 30, &d_mbx, &env(&offer)).unwrap();
    let Message::SessionRotate(r) = m.message else {
        panic!("expected rotate")
    };
    let d3 = MailboxId([40; 16]);
    let (acc, _) = ds
        .accept_rotation(
            &mut OsEntropy,
            NOW + 31,
            &Rotate {
                phase: RotatePhase::Offer,
                ..r
            },
            d3,
            Token::from_bytes([41; 32]),
            Token::from_bytes([42; 32]),
        )
        .unwrap();
    let acc = core_out(acc);
    assert_eq!(acc.mailbox, w2.mailbox);
    let got = ws.open(NOW + 32, w2.mailbox.clone(), acc.envelope).unwrap();
    assert_eq!(got.body, MessageBody::RotationAccepted { epoch: 2 });
    assert_eq!(ws.epoch(), 2);
    assert_eq!(ws.own_mailbox().mailbox, w3.mailbox);
    assert_eq!(
        ws.finish_drain().unwrap().unwrap().mailbox,
        w2.mailbox,
        "initiator may retire right away"
    );
    d_mbx = d3;

    // End from the wallet.
    let end = ws.end(NOW + 40, Some("user disconnected".into())).unwrap();
    assert!(ws.is_ended());
    assert!(matches!(ws.ping(NOW + 40), Err(XchonnectError::State(_))));
    let m = ds.open(NOW + 41, &d_mbx, &env(&end)).unwrap();
    assert!(
        matches!(m.message, Message::SessionEnd { reason: Some(r) } if r == "user disconnected")
    );
    assert!(ds.is_ended());
}

#[test]
fn dapp_end_reaches_wallet() {
    let (mut ds, _d, ws) = paired();
    let end = core_out(
        ds.end(&mut OsEntropy, NOW + 10, Some("bye".into()))
            .unwrap(),
    );
    let got = ws
        .open(NOW + 11, ws.own_mailbox().mailbox, end.envelope)
        .unwrap();
    assert_eq!(
        got.body,
        MessageBody::SessionEnd {
            reason: Some("bye".into())
        }
    );
    assert!(ws.is_ended());
}

#[test]
fn sas_rejection_and_timeout() {
    let mut d = dapp();
    let uri = d.pairing.uri().to_uri();
    let verified = VerifiedPairingUri::new(uri, d.origin_json.clone(), NOW, false).unwrap();
    let reply = verified.reply(NOW, new_mailbox(), None).unwrap();
    assert!(!reply.pairing.timed_out(NOW + 300));
    assert!(reply.pairing.timed_out(NOW + 301));
    assert_eq!(reply.pairing.sas_digits().len(), 6);
    let accepted = d.pairing.on_reply(NOW + 1, &env(&reply.outgoing)).unwrap();
    let (mut ds, confirm) = accepted
        .confirm(
            &mut OsEntropy,
            NOW + 2,
            MailboxId([20; 16]),
            Token::from_bytes([21; 32]),
            Token::from_bytes([22; 32]),
        )
        .unwrap();
    let confirm = core_out(confirm);
    // After the timeout the confirm is refused.
    assert!(matches!(
        reply
            .pairing
            .on_confirm(NOW + 400, confirm.envelope.clone()),
        Err(XchonnectError::State(_))
    ));
    let ws = reply.pairing.on_confirm(NOW + 3, confirm.envelope).unwrap();
    let end = ws.reject_sas(NOW + 4).unwrap();
    assert!(ws.is_ended());
    let m = ds.open(NOW + 5, &MailboxId([20; 16]), &env(&end)).unwrap();
    assert!(matches!(m.message, Message::SessionEnd { .. }));
}

#[test]
fn verification_failures_are_typed() {
    let d = dapp();
    let uri = d.pairing.uri().to_uri();
    // Origin document with a different key.
    let other = LocalSigner::new(Ed25519Seed::from_bytes([9; 32]), "k1").unwrap();
    let wrong = format!(
        r#"{{"v":1,"name":"Evil","origin_keys":[{{"kid":"k1","pk":"{}","not_after":"2030-01-01"}}]}}"#,
        b64::encode(&other.public_key())
    );
    assert!(matches!(
        VerifiedPairingUri::new(uri.clone(), wrong, NOW, false),
        Err(XchonnectError::BadSignature(_))
    ));
    assert!(matches!(
        VerifiedPairingUri::new(uri.clone(), d.origin_json.clone(), NOW + 301, false),
        Err(XchonnectError::UriExpired(_))
    ));
    assert!(matches!(
        VerifiedPairingUri::new(uri.clone(), "{}".into(), NOW, false),
        Err(XchonnectError::InvalidOrigin(_))
    ));
    assert!(matches!(
        inspect_uri("https://example.com".into(), false),
        Err(XchonnectError::InvalidUri(_))
    ));
    let info = parse_origin_document(d.origin_json.clone()).unwrap();
    assert_eq!(info.name, "Pengui");
    assert_eq!(info.keys.len(), 1);
    assert_eq!(info.keys[0].kid, "k1");
    // Bad mailbox credentials are rejected before any crypto, without echoing input.
    let verified = VerifiedPairingUri::new(uri, d.origin_json, NOW, false).unwrap();
    let bad = NewMailbox {
        mailbox: "secret-ish".into(),
        read_token: generate_token(),
        write_token: generate_token(),
    };
    let e = verified.reply(NOW, bad, None).unwrap_err();
    assert_eq!(e, XchonnectError::InvalidInput("invalid mailbox".into()));
    assert!(!e.to_string().contains("secret-ish"));
    assert!(Session::from_bytes(vec![1, 2, 3]).is_err());
}
