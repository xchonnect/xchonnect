//! End-to-end: the exported wallet API against the core's dApp side.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use xchonnect_core::b64;
use xchonnect_core::crypto::{Ed25519Seed, MailboxId, OsEntropy, Token, random_array};
use xchonnect_core::message::{Message, Rotate, RotatePhase};
use xchonnect_core::pairing::{AcceptedPairing, DappPairing, DappPairingParams};
use xchonnect_core::session::Session as DappSession;
use xchonnect_core::uri::{LocalSigner, ParseOptions};
use xchonnect_uniffi::*;

const NOW: u64 = 1_790_000_000;

struct Dapp {
    pairing: DappPairing,
    origin_json: String,
}

/// Origin document with key `k1` from `seed`; `fields` go before `origin_keys`.
fn origin_doc(seed: u8, fields: &str) -> (LocalSigner, String) {
    let signer = LocalSigner::new(Ed25519Seed::from_bytes([seed; 32]), "k1").unwrap();
    let json = format!(
        r#"{{"v":1,{fields},"origin_keys":[{{"kid":"k1","pk":"{}","not_after":"2030-01-01"}}]}}"#,
        b64::encode(&signer.public_key())
    );
    (signer, json)
}

fn dapp() -> Dapp {
    let (signer, origin_json) =
        origin_doc(1, r#""name":"Pengui","icon":"https://dapp.example/i.png""#);
    let pairing = DappPairing::new(
        &mut OsEntropy,
        NOW,
        &signer,
        DappPairingParams {
            relay: "https://relay.example",
            domain: "dapp.example",
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

/// The dApp confirms on mailbox D `[20; 16]`; returns its session and `session.confirm`.
fn confirm(accepted: AcceptedPairing, now: u64) -> (DappSession, Outgoing) {
    let (ds, out) = accepted
        .confirm(
            &mut OsEntropy,
            now,
            MailboxId([20; 16]),
            Token::from_bytes([21; 32]),
            Token::from_bytes([22; 32]),
        )
        .unwrap();
    (ds, out.into())
}

/// Pair through the bindings; returns (dApp session, dApp mailbox D, wallet session).
fn paired() -> (DappSession, MailboxId, std::sync::Arc<Session>) {
    let mut d = dapp();
    let uri = d.pairing.uri().to_uri();

    let info = inspect_uri(uri.clone(), false).unwrap();
    assert_eq!(info.domain, "dapp.example");
    assert_eq!(info.relay, "https://relay.example");
    assert_eq!(
        info.origin_document_url,
        "https://dapp.example/.well-known/xchonnect.json"
    );
    assert_eq!(info.expires_at, NOW + 300);

    let verified = VerifiedPairingUri::new(uri, d.origin_json.clone(), NOW + 1, false).unwrap();
    assert_eq!(verified.dapp_name(), "Pengui");
    assert_eq!(
        verified.dapp_icon().as_deref(),
        Some("https://dapp.example/i.png")
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
    let (mut ds, confirm) = confirm(accepted, NOW + 4);
    assert_eq!(confirm.mailbox, w.mailbox);
    let ws = reply.pairing.on_confirm(NOW + 5, confirm.envelope).unwrap();
    assert!(!ws.is_active());
    assert_eq!(ws.role(), SessionRole::Wallet);

    let ready = ws.confirm_sas(NOW + 6, None).unwrap().unwrap();
    assert!(ws.is_active());
    assert_eq!(mbx(&ready.mailbox), d_mbx);
    dopen(&mut ds, NOW + 7, &d_mbx, &ready);
    assert!(
        ds.confirm_sas(&mut OsEntropy, NOW + 7, None)
            .unwrap()
            .is_none()
    );
    assert!(ds.is_active());
    (ds, d_mbx, ws)
}

fn seal(ds: &mut DappSession, now: u64, msg: Message, ttl_s: u64) -> Outgoing {
    ds.seal(&mut OsEntropy, now, msg, ttl_s).unwrap().into()
}

fn request(ds: &mut DappSession, now: u64, method: &str) -> Outgoing {
    let msg = xchonnect_core::rpc::request(method, r#"{"message":"hi"}"#).unwrap();
    seal(ds, now, msg, 600)
}

/// The wallet opens `o` from `mailbox`.
fn wopen(ws: &Session, now: u64, mailbox: &str, o: &Outgoing) -> IncomingMessage {
    ws.open(now, mailbox.into(), o.envelope.clone()).unwrap()
}

/// The dApp opens `o` from its mailbox `d`.
fn dopen(ds: &mut DappSession, now: u64, d: &MailboxId, o: &Outgoing) -> Message {
    ds.open(now, d, &env(o)).unwrap().message
}

#[test]
fn pairing_request_response_rotation_end() {
    let (mut ds, mut d_mbx, ws) = paired();

    // Request / receipt / response.
    let req = request(&mut ds, NOW + 10, "chip0002_signMessage");
    let own = ws.own_mailbox();
    assert_eq!(req.mailbox, own.mailbox);
    let got = wopen(&ws, NOW + 11, &own.mailbox, &req);
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
    let m = dopen(&mut ds, NOW + 12, &d_mbx, &rcpt);
    assert!(matches!(m, Message::RpcReceived { .. }));

    let resp = ws
        .respond(NOW + 13, got.id.clone(), r#""sig""#.into())
        .unwrap();
    let m = dopen(&mut ds, NOW + 13, &d_mbx, &resp);
    assert!(
        matches!(m, Message::RpcResponse { request_id, .. } if b64::encode(&request_id) == req.id)
    );

    // Error response.
    let req2 = request(&mut ds, NOW + 14, "signCoinSpends");
    let got2 = wopen(&ws, NOW + 14, &own.mailbox, &req2);
    let rej = ws
        .respond_error(
            NOW + 15,
            got2.id,
            rpc_error_code_value(RpcErrorCode::UserRejected),
            "User rejected".into(),
            None,
        )
        .unwrap();
    let Message::RpcResponse {
        outcome: xchonnect_core::message::RpcOutcome::Error(e),
        ..
    } = dopen(&mut ds, NOW + 15, &d_mbx, &rej)
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
    let ping = seal(&mut ds, NOW + 16, Message::SessionPing, 300);
    let got = wopen(&ws, NOW + 16, &own.mailbox, &ping);
    assert_eq!(got.body, MessageBody::Ping);
    let pong = ws.pong(NOW + 16).unwrap();
    assert!(matches!(
        dopen(&mut ds, NOW + 16, &d_mbx, &pong),
        Message::SessionPong
    ));

    // The wallet declares what it granted (spec 9.3): its own message, not a field of
    // `session.ready`, and the dApp decodes the body the grammar defines.
    let decl = ws
        .permissions(
            NOW + 17,
            vec!["signMessage".into(), "getPublicKeys".into()],
            vec!["0xb0b0".into()],
            Some(Limits {
                per_request_mojos: Some("1000000000000".into()),
                per_day_mojos: None,
            }),
        )
        .unwrap();
    let Message::SessionPermissions(p) = dopen(&mut ds, NOW + 17, &d_mbx, &decl) else {
        panic!("expected session.permissions")
    };
    assert_eq!(p.methods, ["signMessage", "getPublicKeys"]);
    assert_eq!(p.keys, ["0xb0b0"]);
    assert_eq!(
        p.limits,
        Some(xchonnect_core::message::Limits {
            per_request_mojos: Some("1000000000000".into()),
            per_day_mojos: None,
        })
    );
    // No limits at all is the common case (spec 9.3 default) and omits `limits`.
    let decl = ws
        .permissions(NOW + 18, vec!["chainId".into()], vec![], None)
        .unwrap();
    assert_eq!(
        dopen(&mut ds, NOW + 18, &d_mbx, &decl),
        Message::SessionPermissions(xchonnect_core::message::Permissions {
            methods: vec!["chainId".into()],
            keys: vec![],
            limits: None,
        })
    );

    // dApp-initiated rotation.
    assert!(!ws.needs_rotation(NOW + 17));
    assert!(ws.needs_rotation(NOW + 31 * 24 * 3600));
    let d2 = MailboxId([30; 16]);
    let offer = Outgoing::from(
        ds.begin_rotation(
            &mut OsEntropy,
            NOW + 20,
            d2,
            Token::from_bytes([31; 32]),
            Token::from_bytes([32; 32]),
        )
        .unwrap(),
    );
    let got = wopen(&ws, NOW + 21, &own.mailbox, &offer);
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
    dopen(&mut ds, NOW + 23, &d_mbx, &acc.outgoing);
    assert_eq!(ds.epoch(), 1);
    d_mbx = d2;
    let req3 = request(&mut ds, NOW + 24, "chainId");
    assert_eq!(req3.mailbox, w2.mailbox);
    let got3 = wopen(&ws, NOW + 24, &w2.mailbox, &req3);
    let resp3 = ws
        .respond(NOW + 25, got3.id, r#""mainnet""#.into())
        .unwrap();
    assert_eq!(mbx(&resp3.mailbox), d_mbx);
    dopen(&mut ds, NOW + 25, &d_mbx, &resp3);
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
    let Message::SessionRotate(r) = dopen(&mut ds, NOW + 30, &d_mbx, &offer) else {
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
    let acc: Outgoing = acc.into();
    assert_eq!(acc.mailbox, w2.mailbox);
    let got = wopen(&ws, NOW + 32, &w2.mailbox, &acc);
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
    let m = dopen(&mut ds, NOW + 41, &d_mbx, &end);
    assert!(matches!(m, Message::SessionEnd { reason: Some(r) } if r == "user disconnected"));
    assert!(ds.is_ended());
}

#[test]
fn dapp_end_reaches_wallet() {
    let (mut ds, _d, ws) = paired();
    let end = Outgoing::from(
        ds.end(&mut OsEntropy, NOW + 10, Some("bye".into()))
            .unwrap(),
    );
    let got = wopen(&ws, NOW + 11, &ws.own_mailbox().mailbox, &end);
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
    let (mut ds, confirm) = confirm(accepted, NOW + 2);
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
    let m = dopen(&mut ds, NOW + 5, &MailboxId([20; 16]), &end);
    assert!(matches!(m, Message::SessionEnd { .. }));
}

#[test]
fn verification_failures_are_typed() {
    let d = dapp();
    let uri = d.pairing.uri().to_uri();
    // Origin document with a different key.
    let (_, wrong) = origin_doc(9, r#""name":"Evil""#);
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

#[test]
fn sealed_push_tokens_open_at_the_gateway_and_are_unlinkable() {
    use xchonnect_core::crypto::X25519Secret;
    let gw = X25519Secret::from_bytes([4; 32]);
    let seal_push = |pk: String, platform| {
        seal_push_token(
            "https://push.example/v1/wake".into(),
            pk,
            platform,
            "device".into(),
            NOW,
            86_400,
        )
    };
    let pk = b64::encode(&gw.public_key());
    let a = seal_push(pk.clone(), PushPlatform::Apns).unwrap();
    let b = seal_push(pk, PushPlatform::Apns).unwrap();
    assert_ne!(a.sealed_token, b.sealed_token);
    let opened =
        xchonnect_core::push::PushToken::open(&gw, &b64::decode(&a.sealed_token).unwrap(), NOW)
            .unwrap();
    assert_eq!(opened.device_token, "device");
    assert_eq!(opened.exp, a.expires_at);
    assert!(seal_push("bad".into(), PushPlatform::Fcm).is_err());
}
