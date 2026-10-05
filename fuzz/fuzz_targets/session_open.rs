//! The session receive path on authenticated but otherwise arbitrary plaintexts.
//!
//! Decryption normally stops fuzzers at the AEAD. This target knows the session keys,
//! so it seals fuzzer-chosen inner plaintexts correctly and drives `Session::open` (and
//! the rotation handling behind it) with a sequence of them.
//!
//! Input: `flags` byte, then frames of `u16be length || inner plaintext`.
//! `flags` bit 0: receiver is the dApp (else the wallet); bit 1: SAS confirmed;
//! bit 2: peer ready (dApp).
#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use libfuzzer_sys::fuzz_target;
use xchonnect_core::cbor::{self, Value};
use xchonnect_core::crypto::{DirectionKey, MailboxId, TestEntropy, Token};
use xchonnect_core::envelope::{self, Direction};
use xchonnect_core::error::Error;
use xchonnect_core::message::Message;
use xchonnect_core::session::Session;

const NOW: u64 = 1_790_000_000;
const D2W: [u8; 32] = [0x11; 32];
const W2D: [u8; 32] = [0x22; 32];
const DAPP_MBX: [u8; 16] = [0x0d; 16];
const WALLET_MBX: [u8; 16] = [0x0a; 16];

fn session(dapp: bool, sas_ok: bool, peer_ready: bool) -> Session {
    let (own, peer) = if dapp {
        (DAPP_MBX, WALLET_MBX)
    } else {
        (WALLET_MBX, DAPP_MBX)
    };
    let state = Value::text_map(vec![
        ("v", Value::Uint(1)),
        ("role", Value::text(if dapp { "dapp" } else { "wallet" })),
        (
            "keys",
            Value::text_map(vec![
                ("e", Value::Uint(0)),
                ("d2w", Value::bytes(&D2W)),
                ("w2d", Value::bytes(&W2D)),
                ("ck", Value::bytes(&[0x33; 32])),
            ]),
        ),
        ("own_mbx", Value::bytes(&own)),
        ("own_r", Value::bytes(&[0x44; 32])),
        ("peer_mbx", Value::bytes(&peer)),
        ("peer_w", Value::bytes(&[0x55; 32])),
        ("send_seq", Value::Uint(0)),
        ("recv_seq", Value::Uint(0)),
        ("sas_ok", Value::Bool(sas_ok)),
        ("peer_ready", Value::Bool(peer_ready)),
        ("ended", Value::Bool(false)),
        ("epoch_started", Value::Uint(NOW)),
        ("epoch_sent", Value::Uint(0)),
    ]);
    Session::from_bytes(&cbor::encode(&state).unwrap()).unwrap()
}

fuzz_target!(|data: &[u8]| {
    let Some((&flags, mut rest)) = data.split_first() else {
        return;
    };
    let dapp = flags & 1 != 0;
    let mut s = session(dapp, flags & 2 != 0, flags & 4 != 0);
    let (key, dir) = if dapp {
        (DirectionKey::from_bytes(W2D), Direction::WalletToDapp)
    } else {
        (DirectionKey::from_bytes(D2W), Direction::DappToWallet)
    };
    let mut rng = TestEntropy::new([9; 32]);
    let mut last_seq = 0u64;
    let mut frame = 0u8;

    while rest.len() >= 2 {
        let len = usize::from(u16::from_be_bytes([rest[0], rest[1]])).min(rest.len() - 2);
        let (pt, tail) = rest[2..].split_at(len);
        rest = tail;
        frame = frame.wrapping_add(1);

        let own = s.own_mailbox();
        let draining = s.draining_mailbox().map(|(m, _)| m);
        // Messages are sealed to the mailbox the peer believes we read: the original one.
        let target = MailboxId(if dapp { DAPP_MBX } else { WALLET_MBX });
        let Ok(env) = envelope::seal_session_with_nonce(&[frame; 24], &key, dir, &target, pt)
        else {
            continue;
        };
        let was_ended = s.is_ended();
        let Ok(inner) = s.open(NOW, &target, &env) else {
            continue;
        };
        // Only mailboxes we own are ever accepted.
        assert!(
            target == own || Some(target) == draining,
            "foreign mailbox accepted"
        );
        assert!(!was_ended, "ended session accepted a message");
        assert!(inner.seq > last_seq, "seq did not increase");
        last_seq = inner.seq;
        // Exactly the same envelope is a replay now.
        let again = s.open(NOW, &target, &env);
        assert!(
            matches!(again, Err(Error::Replay | Error::State(_))),
            "replay accepted: {again:?}"
        );

        match &inner.message {
            Message::SessionRotate(offer) => {
                let epoch = s.epoch();
                if let Ok((out, _)) = s.accept_rotation(
                    &mut rng,
                    NOW,
                    offer,
                    MailboxId([frame; 16]),
                    Token::from_bytes([frame; 32]),
                    Token::from_bytes([frame ^ 0xff; 32]),
                ) {
                    assert_eq!(s.epoch(), epoch + 1);
                    assert_eq!(s.draining_mailbox().map(|(m, _)| m), Some(own));
                    assert!(envelope::Envelope::decode(&out.envelope).is_ok());
                }
            }
            Message::SessionEnd { .. } => assert!(s.is_ended()),
            Message::SessionReady { .. } => assert!(dapp && s.peer_ready()),
            Message::RpcRequest { .. } => assert!(!dapp && s.is_active()),
            _ => {}
        }
        // The state always survives persistence.
        let bytes = s.to_bytes().unwrap();
        assert_eq!(
            Session::from_bytes(&bytes).unwrap().to_bytes().unwrap(),
            bytes
        );
    }
});
