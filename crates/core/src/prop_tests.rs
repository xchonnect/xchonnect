//! Property tests across modules: envelope seal/open round trips, rejection of
//! mutated ciphertexts, and a stateful model of a paired dApp/wallet session pair
//! driven through an adversarial relay (spec 5.3, 9.2.1).

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::collections::HashSet;

use proptest::prelude::*;

use crate::cbor::{self, Value};
use crate::crypto::{DirectionKey, MailboxId, TestEntropy, Token};
use crate::envelope::{self, BUCKETS, Direction, Envelope};
use crate::error::Error;
use crate::message::{Message, Permissions, RotatePhase, RpcError, RpcOutcome};
use crate::pairing::tests::{Fixture, fixture, paired};
use crate::session::{Outgoing, Session};

const NOW: u64 = 1_790_000_100;

fn arb_direction() -> impl Strategy<Value = Direction> {
    prop_oneof![Just(Direction::DappToWallet), Just(Direction::WalletToDapp)]
}

fn other(d: Direction) -> Direction {
    match d {
        Direction::DappToWallet => Direction::WalletToDapp,
        Direction::WalletToDapp => Direction::DappToWallet,
    }
}

/// Messages a dApp may send once the session is active.
fn arb_dapp_message() -> impl Strategy<Value = Message> {
    prop_oneof![
        Just(Message::SessionPing),
        Just(Message::SessionPong),
        ("[a-zA-Z0-9_]{1,40}", ".{0,300}")
            .prop_map(|(method, params)| Message::RpcRequest { method, params }),
        proptest::option::of(".{0,40}").prop_map(|reason| Message::SessionEnd { reason }),
    ]
}

/// Messages a wallet may send once the session is active.
fn arb_wallet_message() -> impl Strategy<Value = Message> {
    let outcome = prop_oneof![
        ".{0,300}".prop_map(RpcOutcome::Result),
        (any::<i64>(), ".{0,60}", proptest::option::of(".{0,60}")).prop_map(
            |(code, message, data)| RpcOutcome::Error(RpcError {
                code,
                message,
                data
            })
        ),
    ];
    prop_oneof![
        Just(Message::SessionPong),
        (any::<[u8; 16]>(), outcome).prop_map(|(request_id, outcome)| Message::RpcResponse {
            request_id,
            outcome
        }),
        any::<[u8; 16]>().prop_map(|request_id| Message::RpcReceived { request_id }),
        (
            proptest::collection::vec("[a-zA-Z]{1,20}", 0..4),
            proptest::collection::vec("[0-9a-f]{2,20}", 0..4)
        )
            .prop_map(|(methods, keys)| Message::SessionPermissions(Permissions {
                methods,
                keys,
                limits: None
            })),
    ]
}

/// Seal `m` the way a host must: `session.end` goes through [`Session::end`].
fn send(s: &mut Session, rng: &mut TestEntropy, m: Message, ttl: u64) -> Outgoing {
    match m {
        Message::SessionEnd { reason } => s.end(rng, NOW, reason).unwrap(),
        m => s.seal(rng, NOW, m, ttl).unwrap(),
    }
}

// ---------------------------------------------------------------------------
// Envelope-level properties
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    /// Anything sealed opens again with the same key, direction and mailbox, and with
    /// no other direction or mailbox.
    #[test]
    fn envelope_seal_open_roundtrip(
        key in any::<[u8; 32]>(),
        nonce in any::<[u8; 24]>(),
        mbx in any::<[u8; 16]>(),
        dir in arb_direction(),
        payload in proptest::collection::vec(any::<u8>(), 0..5000),
        other_mbx in any::<[u8; 16]>(),
    ) {
        let key = DirectionKey::from_bytes(key);
        let mbx = MailboxId(mbx);
        let inner = cbor::encode(&Value::Bytes(payload)).unwrap();
        let bytes = envelope::seal_session_with_nonce(&nonce, &key, dir, &mbx, &inner).unwrap();
        let env = Envelope::decode(&bytes).unwrap();
        prop_assert!(BUCKETS.contains(&env.ct.len()));
        prop_assert_eq!(env.encode().unwrap(), bytes.clone());
        let back = envelope::open_session(&key, dir, &mbx, &env).unwrap();
        prop_assert_eq!(cbor::encode(&back).unwrap(), inner);
        prop_assert_eq!(
            envelope::open_session(&key, other(dir), &mbx, &env),
            Err(Error::Decrypt)
        );
        if other_mbx != mbx.0 {
            prop_assert_eq!(
                envelope::open_session(&key, dir, &MailboxId(other_mbx), &env),
                Err(Error::Decrypt)
            );
        }
    }

    /// Flipping any bits of any byte of an encoded envelope makes decoding or opening
    /// fail without panicking.
    #[test]
    fn mutated_envelope_never_opens(
        key in any::<[u8; 32]>(),
        nonce in any::<[u8; 24]>(),
        payload in proptest::collection::vec(any::<u8>(), 0..2000),
        pos in any::<prop::sample::Index>(),
        mask in 1u8..=255,
    ) {
        let key = DirectionKey::from_bytes(key);
        let mbx = MailboxId([3; 16]);
        let dir = Direction::DappToWallet;
        let inner = cbor::encode(&Value::Bytes(payload)).unwrap();
        let mut bytes = envelope::seal_session_with_nonce(&nonce, &key, dir, &mbx, &inner).unwrap();
        let i = pos.index(bytes.len());
        bytes[i] ^= mask;
        let opened = Envelope::decode(&bytes)
            .and_then(|env| envelope::open_session(&key, dir, &mbx, &env));
        prop_assert!(opened.is_err(), "mutation at byte {} accepted", i);
    }
}

// ---------------------------------------------------------------------------
// Session-level properties
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// Session messages round-trip in both directions with increasing `seq`.
    #[test]
    fn session_seal_open_roundtrip(
        d_msgs in proptest::collection::vec(arb_dapp_message(), 1..6),
        w_msgs in proptest::collection::vec(arb_wallet_message(), 1..6),
        ttl in 1u64..=7 * 24 * 3600,
    ) {
        let mut f = fixture();
        let (mut ds, mut ws) = paired(&mut f);
        let mut last = 0;
        for m in w_msgs {
            let out = ws.seal(&mut f.rng, NOW, m.clone(), ttl).unwrap();
            prop_assert_eq!(out.mailbox, ds.own_mailbox());
            let got = ds.open(NOW, &out.mailbox, &out.envelope).unwrap();
            prop_assert_eq!(got.message, m);
            prop_assert_eq!(got.id, out.id);
            prop_assert!(got.seq > last);
            last = got.seq;
        }
        let mut last = 0;
        for m in d_msgs {
            if ds.is_ended() {
                break;
            }
            let out = send(&mut ds, &mut f.rng, m.clone(), ttl);
            let got = ws.open(NOW, &out.mailbox, &out.envelope).unwrap();
            prop_assert_eq!(&got.message, &m);
            if !matches!(m, Message::SessionEnd { .. }) {
                prop_assert_eq!(got.exp - got.iat, ttl);
            }
            prop_assert!(got.seq > last);
            last = got.seq;
            if matches!(m, Message::SessionEnd { .. }) {
                prop_assert!(ws.is_ended());
            }
        }
    }

    /// Flipping any byte of a real session envelope makes `Session::open` fail, leaves
    /// the receiver unchanged, and the untouched envelope still opens afterwards.
    #[test]
    fn session_rejects_mutated_envelope(
        m in arb_dapp_message(),
        pos in any::<prop::sample::Index>(),
        mask in 1u8..=255,
    ) {
        let mut f = fixture();
        let (mut ds, mut ws) = paired(&mut f);
        let out = send(&mut ds, &mut f.rng, m, 3600);
        let mut bad = out.envelope.clone();
        let i = pos.index(bad.len());
        bad[i] ^= mask;
        let before = ws.to_bytes().unwrap();
        prop_assert!(ws.open(NOW, &out.mailbox, &bad).is_err(), "mutation at byte {} accepted", i);
        prop_assert_eq!(ws.to_bytes().unwrap(), before);
        prop_assert!(ws.open(NOW, &out.mailbox, &out.envelope).is_ok());
    }
}

// ---------------------------------------------------------------------------
// Stateful model: two sessions talking through an adversarial relay
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    Dapp,
    Wallet,
}

impl Side {
    fn peer(self) -> Side {
        match self {
            Side::Dapp => Side::Wallet,
            Side::Wallet => Side::Dapp,
        }
    }
}

fn arb_side() -> impl Strategy<Value = Side> {
    prop_oneof![Just(Side::Dapp), Just(Side::Wallet)]
}

#[derive(Debug, Clone)]
enum Op {
    /// The side sends a data message (kind selects which).
    Send(Side, u8),
    /// Deliver an in-flight message addressed to the side (any order: reordering).
    Deliver(Side, prop::sample::Index),
    /// Deliver an in-flight message but keep it queued (relay duplicates it).
    Duplicate(Side, prop::sample::Index),
    /// The relay loses an in-flight data message.
    Drop(Side, prop::sample::Index),
    /// Re-inject a message the side already accepted.
    Replay(Side, prop::sample::Index),
    /// Present an in-flight message as coming from a mailbox the side does not own.
    WrongMailbox(Side, prop::sample::Index, u8),
    /// Hand a message addressed to the side to its peer instead.
    CrossDeliver(Side, prop::sample::Index),
    /// The side offers a rotation.
    Rotate(Side),
    /// The host finishes draining the previous mailbox if it is empty.
    FinishDrain(Side),
    /// The host persists and restores the session.
    Persist(Side),
}

fn arb_op() -> impl Strategy<Value = Op> {
    let idx = any::<prop::sample::Index>;
    prop_oneof![
        6 => (arb_side(), any::<u8>()).prop_map(|(s, k)| Op::Send(s, k)),
        8 => (arb_side(), idx()).prop_map(|(s, i)| Op::Deliver(s, i)),
        2 => (arb_side(), idx()).prop_map(|(s, i)| Op::Duplicate(s, i)),
        2 => (arb_side(), idx()).prop_map(|(s, i)| Op::Drop(s, i)),
        2 => (arb_side(), idx()).prop_map(|(s, i)| Op::Replay(s, i)),
        2 => (arb_side(), idx(), any::<u8>()).prop_map(|(s, i, w)| Op::WrongMailbox(s, i, w)),
        2 => (arb_side(), idx()).prop_map(|(s, i)| Op::CrossDeliver(s, i)),
        2 => arb_side().prop_map(Op::Rotate),
        2 => arb_side().prop_map(Op::FinishDrain),
        1 => arb_side().prop_map(Op::Persist),
    ]
}

#[derive(Debug, Clone)]
struct InFlight {
    mailbox: MailboxId,
    envelope: Vec<u8>,
    /// Rotation messages model durable control traffic: delayed, duplicated or
    /// reordered, but never silently lost by the relay.
    control: bool,
}

struct Peer {
    s: Session,
    /// Messages addressed to this side, in send order.
    inbox: Vec<InFlight>,
    /// Envelopes this side accepted (for replays).
    accepted: Vec<InFlight>,
    accepted_ids: HashSet<[u8; 16]>,
    last_seq: u64,
}

struct World {
    f: Fixture,
    dapp: Peer,
    wallet: Peer,
    next_mbx: u16,
}

impl World {
    fn new() -> World {
        let mut f = fixture();
        let (ds, ws) = paired(&mut f);
        let peer = |s| Peer {
            s,
            inbox: Vec::new(),
            accepted: Vec::new(),
            accepted_ids: HashSet::new(),
            last_seq: 0,
        };
        World {
            f,
            dapp: peer(ds),
            wallet: peer(ws),
            next_mbx: 0,
        }
    }

    fn peer(&mut self, side: Side) -> &mut Peer {
        match side {
            Side::Dapp => &mut self.dapp,
            Side::Wallet => &mut self.wallet,
        }
    }

    /// Fresh mailbox and tokens, as the host would create on the relay.
    fn new_mailbox(&mut self) -> (MailboxId, Token, Token) {
        self.next_mbx += 1;
        let [a, b] = self.next_mbx.to_be_bytes();
        let mut id = [0xf0; 16];
        id[0] = a;
        id[1] = b;
        (
            MailboxId(id),
            Token::from_bytes([a ^ 0x5a; 32]),
            Token::from_bytes([b ^ 0xa5; 32]),
        )
    }

    fn post(&mut self, to: Side, mailbox: MailboxId, envelope: Vec<u8>, control: bool) {
        self.peer(to).inbox.push(InFlight {
            mailbox,
            envelope,
            control,
        });
    }

    fn owned(&mut self, side: Side) -> Vec<MailboxId> {
        let s = &self.peer(side).s;
        std::iter::once(s.own_mailbox())
            .chain(s.draining_mailbox().map(|(m, _)| m))
            .collect()
    }

    fn send(&mut self, side: Side, kind: u8) {
        let msg = match (side, kind % 3) {
            (_, 0) => Message::SessionPing,
            (Side::Dapp, _) => Message::RpcRequest {
                method: "chainId".into(),
                params: "{}".into(),
            },
            (Side::Wallet, 1) => Message::RpcReceived {
                request_id: [kind; 16],
            },
            (Side::Wallet, _) => Message::SessionPong,
        };
        let mut rng = self.f.rng.clone();
        let res = self.peer(side).s.seal(&mut rng, NOW, msg, 3600);
        self.f.rng = rng;
        let out = res.expect("an active, never-ended session can always send");
        self.post(side.peer(), out.mailbox, out.envelope, false);
    }

    /// Open `m` at `side` as the host would. Checks the safety invariants on success
    /// and runs the host's reaction to rotation offers.
    fn open(&mut self, side: Side, m: &InFlight) -> Result<(), Error> {
        let owned = self.owned(side);
        let p = self.peer(side);
        let inner = p.s.open(NOW, &m.mailbox, &m.envelope)?;
        assert!(
            owned.contains(&m.mailbox),
            "{side:?} accepted a message on a mailbox it does not own"
        );
        assert!(
            p.accepted_ids.insert(inner.id),
            "{side:?} accepted the same message twice"
        );
        assert!(
            inner.seq > p.last_seq,
            "{side:?} accepted a non-increasing seq"
        );
        p.last_seq = inner.seq;
        p.accepted.push(m.clone());
        if let Message::SessionRotate(offer) = &inner.message {
            if offer.phase == RotatePhase::Offer {
                self.accept_offer(side, offer);
            }
        }
        Ok(())
    }

    fn accept_offer(&mut self, side: Side, offer: &crate::message::Rotate) {
        // Spec 9.2.1 step 4: the previous mailbox must be drained before a new rotation.
        if let Some((prev, _)) = self.peer(side).s.draining_mailbox() {
            let p = self.peer(side);
            if !p.inbox.iter().any(|m| m.mailbox == prev) {
                p.s.finish_drain();
            }
        }
        let (mbx, r, w) = self.new_mailbox();
        let mut rng = self.f.rng.clone();
        let res = self
            .peer(side)
            .s
            .accept_rotation(&mut rng, NOW, offer, mbx, r, w);
        self.f.rng = rng;
        if let Ok((out, _abandoned)) = res {
            self.post(side.peer(), out.mailbox, out.envelope, true);
        }
    }

    fn deliver(&mut self, side: Side, idx: prop::sample::Index, keep: bool) {
        let inbox_len = self.peer(side).inbox.len();
        if inbox_len == 0 {
            return;
        }
        let i = idx.index(inbox_len);
        let m = self.peer(side).inbox[i].clone();
        let res = self.open(side, &m);
        let retry = matches!(res, Err(Error::State(s)) if s.starts_with("rotation pending"));
        if !keep && !retry {
            self.peer(side).inbox.remove(i);
        }
    }

    fn apply(&mut self, op: &Op) {
        match op {
            Op::Send(side, kind) => self.send(*side, *kind),
            Op::Deliver(side, i) => self.deliver(*side, *i, false),
            Op::Duplicate(side, i) => self.deliver(*side, *i, true),
            Op::Drop(side, i) => {
                let p = self.peer(*side);
                if !p.inbox.is_empty() {
                    let i = i.index(p.inbox.len());
                    if !p.inbox[i].control {
                        p.inbox.remove(i);
                    }
                }
            }
            Op::Replay(side, i) => {
                let p = self.peer(*side);
                if !p.accepted.is_empty() {
                    let m = p.accepted[i.index(p.accepted.len())].clone();
                    let res = p.s.open(NOW, &m.mailbox, &m.envelope);
                    assert!(res.is_err(), "{side:?} accepted a replayed message");
                }
            }
            Op::WrongMailbox(side, i, which) => {
                let peer_own = self.peer(side.peer()).s.own_mailbox();
                let p = self.peer(*side);
                if p.inbox.is_empty() {
                    return;
                }
                let m = p.inbox[i.index(p.inbox.len())].clone();
                let wrong = match which % 3 {
                    0 => MailboxId([0xee; 16]),
                    1 => peer_own,
                    _ => {
                        p.s.pending_rotation_mailbox()
                            .map_or(MailboxId([0xed; 16]), |(m, _)| m)
                    }
                };
                let before = p.s.to_bytes().unwrap();
                assert!(
                    p.s.open(NOW, &wrong, &m.envelope).is_err(),
                    "{side:?} accepted a message on a foreign mailbox"
                );
                assert_eq!(
                    p.s.to_bytes().unwrap(),
                    before,
                    "rejected open mutated state"
                );
            }
            Op::CrossDeliver(side, i) => {
                let p = self.peer(*side);
                if p.inbox.is_empty() {
                    return;
                }
                let m = p.inbox[i.index(p.inbox.len())].clone();
                let q = self.peer(side.peer());
                let own = q.s.own_mailbox();
                assert!(
                    q.s.open(NOW, &own, &m.envelope).is_err(),
                    "reflected message accepted"
                );
                assert!(
                    q.s.open(NOW, &m.mailbox, &m.envelope).is_err(),
                    "foreign mailbox accepted"
                );
            }
            Op::Rotate(side) => {
                let (mbx, r, w) = self.new_mailbox();
                let mut rng = self.f.rng.clone();
                let res = self.peer(*side).s.begin_rotation(&mut rng, NOW, mbx, r, w);
                self.f.rng = rng;
                if let Ok(out) = res {
                    self.post(side.peer(), out.mailbox, out.envelope, true);
                }
            }
            Op::FinishDrain(side) => {
                let p = self.peer(*side);
                if let Some((prev, _)) = p.s.draining_mailbox() {
                    if !p.inbox.iter().any(|m| m.mailbox == prev) {
                        p.s.finish_drain();
                    }
                }
            }
            Op::Persist(side) => {
                let p = self.peer(*side);
                let bytes = p.s.to_bytes().unwrap();
                p.s = Session::from_bytes(&bytes).unwrap();
                assert_eq!(p.s.to_bytes().unwrap(), bytes);
            }
        }
    }

    /// Deliver everything still queued the way a well-behaved host does: previous
    /// mailbox first, then the current one, retrying messages for a pending rotation.
    fn settle(&mut self) {
        for _ in 0..64 {
            let mut progress = false;
            for side in [Side::Dapp, Side::Wallet] {
                let order = self.owned(side);
                let pending = self.peer(side).s.pending_rotation_mailbox().map(|(m, _)| m);
                // Draining mailbox first (spec 9.2.1 step 4), then current, then pending.
                let mut boxes: Vec<MailboxId> = order.iter().rev().copied().collect();
                boxes.extend(pending);
                for mbx in boxes {
                    while let Some(pos) =
                        self.peer(side).inbox.iter().position(|m| m.mailbox == mbx)
                    {
                        let m = self.peer(side).inbox[pos].clone();
                        let res = self.open(side, &m);
                        if matches!(res, Err(Error::State(s)) if s.starts_with("rotation pending"))
                        {
                            break;
                        }
                        self.peer(side).inbox.remove(pos);
                        progress = true;
                    }
                }
                // Messages to mailboxes this side no longer reads are gone for good.
                let keep: Vec<MailboxId> = self.owned(side).into_iter().chain(pending).collect();
                self.peer(side).inbox.retain(|m| keep.contains(&m.mailbox));
            }
            if !progress {
                break;
            }
        }
    }

    /// Both directions still work.
    fn assert_live(&mut self) {
        for side in [Side::Dapp, Side::Wallet] {
            self.send(side, 0);
            self.settle();
            let peer = self.peer(side.peer());
            assert!(
                peer.inbox.is_empty(),
                "{:?} could not deliver to {:?}: {} message(s) stuck; epochs d={} w={}",
                side,
                side.peer(),
                peer.inbox.len(),
                self.dapp.s.epoch(),
                self.wallet.s.epoch(),
            );
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 96, ..ProptestConfig::default() })]

    /// Arbitrary interleavings of sends, deliveries, drops, duplicates, reorderings,
    /// replays, misdirected deliveries, rotations and restores never panic, never
    /// accept a replay or a message on a foreign mailbox, and never break the session.
    #[test]
    fn session_pair_state_machine(ops in proptest::collection::vec(arb_op(), 1..80)) {
        let mut w = World::new();
        for op in &ops {
            w.apply(op);
        }
        w.settle();
        w.assert_live();
        // And once more after any rotation completed during settling.
        w.assert_live();
        prop_assert!(w.dapp.s.is_active() && w.wallet.s.is_active());
    }
}
