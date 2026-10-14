//! Regression tests for the final audit of the rc.5 option rules (TASK-78): F1, binding
//! through a link between two of the user's spends, which a dApp holding the user's
//! signatures can defeat by putting another signed spend of the linked coin in place of the
//! one in the request. Only direct binding counts when the signatures are released (spec
//! 11.2); the sealed wallet-built case is in `option_reaudit_tests` (N2) and
//! `option_sage_tests`.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use crate::handlers::{
    Approver, Broadcast, BroadcastRecord, Broadcaster, Host, Prompt, RequestContext, RpcError,
    SUBMIT_COIN_SPENDS, SignedCoins, Signer, SignerError, SubmitRequest, Submitted, handle,
    handle_with_host, submit,
};
use crate::permissions::DappPermissions;
use crate::policy::Network;
use crate::simulate::Ownership;
use crate::swap_fixture::{Mem, params};
use chia_bls::{PublicKey, SecretKey, Signature};
use chia_protocol::{Bytes32, Coin, CoinSpend, SpendBundle};
use chia_puzzle_types::Memos;
use chia_puzzle_types::offer::{NotarizedPayment, Payment, SettlementPaymentsSolution};
use chia_puzzles::SETTLEMENT_PAYMENT_HASH;
use chia_sdk_driver::{Layer, SettlementLayer, SpendContext, StandardLayer};
use chia_sdk_test::{BlsPair, Simulator};
use chia_sdk_types::Conditions;
use std::cell::Cell;
use std::cell::RefCell;
use std::collections::HashSet;
use xchonnect_core::crypto::sha256_parts;

const SETTLEMENT: Bytes32 = Bytes32::new(SETTLEMENT_PAYMENT_HASH);

struct Key(SecretKey);
impl Signer for Key {
    fn sign(&self, _pk: &PublicKey, msg: &[u8]) -> Result<Signature, SignerError> {
        Ok(chia_bls::sign(&self.0, msg))
    }
}

struct Yes;
impl Approver for Yes {
    fn approve(&self, _p: &Prompt<'_>) -> bool {
        true
    }
}

fn spend(user: &BlsPair, coin: Coin, conds: Conditions) -> CoinSpend {
    let mut ctx = SpendContext::new();
    StandardLayer::new(user.pk)
        .spend(&mut ctx, coin, conds)
        .unwrap();
    ctx.take().remove(0)
}

fn signature(out: &str) -> Signature {
    let h: String = serde_json::from_str(out).unwrap();
    let bytes: [u8; 96] = hex::decode(h.trim_start_matches("0x"))
        .unwrap()
        .try_into()
        .unwrap();
    Signature::from_bytes(&bytes).unwrap()
}

/// `signCoinSpends` as the user's wallet, every prompt approved.
fn sign(user: &BlsPair, spends: &[CoinSpend], partial: bool) -> Result<Signature, RpcError> {
    sign_with(user, spends, partial, &SignedCoins::default())
}

fn sign_with(
    user: &BlsPair,
    spends: &[CoinSpend],
    partial: bool,
    signed: &SignedCoins,
) -> Result<Signature, RpcError> {
    let perms = DappPermissions::new_default(user.pk);
    let own = Ownership {
        p2_puzzle_hashes: [user.puzzle_hash].into_iter().collect(),
    };
    let keys: HashSet<PublicKey> = [user.pk].into_iter().collect();
    let limits = Mem::default();
    let ctx = RequestContext {
        dapp: "dapp.example",
        network: Network::Testnet11,
        session_chain_id: "testnet11",
        permissions: &perms,
        allow_agg_sig_unsafe: false,
        allow_unknown_contracts: false,
        ownership: &own,
        keys: &keys,
        limits: &limits,
        now: 1_790_000_000,
        chain: None,
        signed_coins: signed,
    };
    handle(
        "signCoinSpends",
        &params(spends, partial),
        &ctx,
        &Key(user.sk.clone()),
        &Yes,
    )
    .map(|out| signature(&out))
}

/// The requested payment of 900 to the user, through the settlement puzzle, and the id of
/// its announcement.
fn requested(user: &BlsPair) -> (CoinSpend, Bytes32) {
    let mut ctx = SpendContext::new();
    let np = NotarizedPayment::new(
        Bytes32::new([7; 32]),
        vec![Payment::new(user.puzzle_hash, 900, Memos::None)],
    );
    let node = ctx.alloc(&np).unwrap();
    let id = Bytes32::from(sha256_parts(&[
        SETTLEMENT_PAYMENT_HASH.as_slice(),
        &ctx.tree_hash(node).to_bytes(),
    ]));
    let cs = SettlementLayer
        .construct_coin_spend(
            &mut ctx,
            Coin::new(Bytes32::default(), SETTLEMENT, 0),
            SettlementPaymentsSolution::new(vec![np]),
        )
        .unwrap();
    (cs, id)
}

/// F1: the user's coin `d` goes to the settlement puzzle, bound only through a coin
/// announcement of the user's coin `c`, whose spend asserts the requested payment. The dApp
/// first has the user sign a harmless spend of `c` making the same announcement (R1) and the
/// request's own spend of `c` on its own (R0, which asserts a payment that never comes).
/// Then the partial request R2. Subtracting R0's signature from R2's leaves the signature of
/// `d`'s spend, which with R1's spend of `c` makes a valid bundle without the payment.
/// Refused now: `d`'s spend does not assert the payment itself. Built with direct binding
/// (`d`'s spend asserts the payment), the same request is signed and the same swap is
/// invalid on chain.
#[test]
fn f1_a_link_through_another_spend_does_not_bind_when_signatures_are_released() {
    let user = BlsPair::new(1);
    let mut sim = Simulator::new();
    let c = sim.new_coin(user.puzzle_hash, 1000);
    let d = sim.new_coin(user.puzzle_hash, 1000);
    let (settle, pay_id) = requested(&user);
    let message = b"link".to_vec();
    let ann_c = Bytes32::from(sha256_parts(&[c.coin_id().as_ref(), &message]));
    let back_to_user = || {
        Conditions::new()
            .create_coin(user.puzzle_hash, 1000, Memos::None)
            .create_coin_announcement(message.clone().into())
    };
    let c_old = spend(&user, c, back_to_user());
    let c_new = spend(&user, c, back_to_user().assert_puzzle_announcement(pay_id));
    let d_linked = spend(
        &user,
        d,
        Conditions::new()
            .create_coin(SETTLEMENT, 1000, Memos::None)
            .assert_coin_announcement(ann_c),
    );

    let sig_r1 = sign(&user, std::slice::from_ref(&c_old), false).unwrap();
    let sig_r0 = sign(&user, &[c_new.clone(), settle.clone()], false).unwrap();
    let r2 = [c_new.clone(), d_linked.clone(), settle.clone()];
    let e = sign(&user, &r2, true).unwrap_err();
    assert_eq!(e.data.as_deref(), Some(r#"{"reason":"unbound_partial"}"#));

    // What the wallet used to return for R2 (both of its signatures), and the attack it
    // allowed: the chain takes R1's spend of `c` with R2's spend of `d`, paying nothing.
    let agg_r2 = crate::option_sage_tests::signature_of(&r2, &user.sk);
    let sig_d = agg_r2 + &(-&sig_r0);
    let attack = SpendBundle::new(vec![c_old.clone(), d_linked], sig_r1.clone() + &sig_d);
    assert!(
        sim.clone().new_transaction(attack).is_ok(),
        "the attack is real"
    );

    // Direct binding: `d`'s spend asserts the payment itself. Signed; the same swap fails.
    let d_direct = spend(
        &user,
        d,
        Conditions::new()
            .create_coin(SETTLEMENT, 1000, Memos::None)
            .assert_puzzle_announcement(pay_id),
    );
    let agg = sign(&user, &[c_new, d_direct.clone(), settle], true).unwrap();
    let sig_d = agg + &(-&sig_r0);
    let attack = SpendBundle::new(vec![c_old, d_direct], sig_r1 + &sig_d);
    assert!(sim.new_transaction(attack).is_err());
}

/// A loan request is a wallet-built mint whose signed spends go to the lender as an offer:
/// its signatures are released, so only direct links count (spec 11.1.1 item 1). Built as
/// spec 11.2 asks (every user spend asserts the requested principal; the spend that creates
/// the collateral asserts the launch), `loan.request` holds. Built as Klimper built it at
/// f25f044 (the launch asserted by the launcher's parent, the collateral tied to it by
/// ASSERT_CONCURRENT_SPEND), the launch is not guaranteed and `loan.request` is refused.
#[test]
fn a_loan_request_holds_only_with_direct_assertions() {
    use crate::option_fixture::{issue_cat, launch_assertion};
    use crate::option_sage_tests::{Mode, reason, run_as};
    use chia_sdk_driver::{Cat, CatSpend, OptionLauncher, OptionLauncherInfo, OptionType};
    use std::cell::RefCell;

    for direct in [true, false] {
        let (user, lender) = (BlsPair::new(1), BlsPair::new(2));
        let mut sim = Simulator::new();
        let seconds = sim.next_timestamp() + 100_000;
        let cat = issue_cat(&mut sim, &user, 400);
        let mut ctx = SpendContext::new();
        let p2 = StandardLayer::new(user.pk);
        let parent = sim.new_coin(user.puzzle_hash, 10);
        let launcher = OptionLauncher::new(
            &mut ctx,
            parent.coin_id(),
            OptionLauncherInfo::new(
                lender.puzzle_hash,
                user.puzzle_hash,
                seconds,
                400,
                OptionType::Xch { amount: 5000 },
            ),
            1,
        )
        .unwrap();
        let p2_option = launcher.p2_puzzle_hash();
        let collateral = cat.child(p2_option, 400);
        let launcher = launcher.with_underlying(collateral.coin.coin_id());
        let (mint, _) = launcher.mint(&mut ctx).unwrap();
        let launch = launch_assertion(&mint);
        // The principal the request asks of the lender (paid to the borrower on take).
        let (_, principal) = requested(&user);
        let mut lock = Conditions::new().create_coin(p2_option, 400, ctx.hint(p2_option).unwrap());
        let mut parent_conds = mint.reserve_fee(9).assert_puzzle_announcement(principal);
        if direct {
            lock = lock
                .assert_coin_announcement(launch)
                .assert_puzzle_announcement(principal);
        } else {
            lock = lock.assert_concurrent_spend(parent.coin_id());
            parent_conds = parent_conds.assert_concurrent_spend(cat.coin.coin_id());
        }
        let inner =
            chia_sdk_driver::SpendWithConditions::spend_with_conditions(&p2, &mut ctx, lock)
                .unwrap();
        Cat::spend_all(&mut ctx, &[CatSpend::new(cat, inner)]).unwrap();
        p2.spend(&mut ctx, parent, parent_conds).unwrap();
        let spends = ctx.take();
        let intent = serde_json::json!({ "kind": "loan.request" });
        let offer = Mode {
            offer: true,
            ..Mode::released()
        };
        let result = run_as(&RefCell::new(sim), &user, spends, Some(intent), &offer);
        if direct {
            let p = result.unwrap();
            assert_eq!(p["intent"]["kind_verified"], true);
            assert_eq!(p["summary"]["options"][0]["guaranteed"], true);
        } else {
            let e = result.unwrap_err();
            assert!(reason(&e).contains("intent_mismatch"), "{e:?}");
        }
    }
}

/// Records what the kit reports and accepts nothing on chain: the bundle is public (the
/// aggregate is what a node relays) but never included.
struct Recorder(RefCell<Vec<BroadcastRecord>>, RefCell<Option<SpendBundle>>);
impl Broadcaster for Recorder {
    fn record(&self, r: &BroadcastRecord) -> Result<(), String> {
        self.0.borrow_mut().push(r.clone());
        Ok(())
    }
    fn submit(&self, b: &SpendBundle) -> Result<Broadcast, String> {
        *self.1.borrow_mut() = Some(b.clone());
        Err("not included".to_owned())
    }
}

/// A sealed wallet-built bundle as the wallet broadcasts it; `Err` from the network.
fn submit_sealed(
    user: &BlsPair,
    spends: Vec<CoinSpend>,
    signed: &SignedCoins,
    to: &Recorder,
) -> Result<Submitted, RpcError> {
    let perms = DappPermissions::new_default(user.pk);
    let own = Ownership {
        p2_puzzle_hashes: [user.puzzle_hash].into_iter().collect(),
    };
    let keys: HashSet<PublicKey> = [user.pk].into_iter().collect();
    let limits = Mem::default();
    let ctx = RequestContext {
        dapp: "wallet",
        network: Network::Testnet11,
        session_chain_id: "testnet11",
        permissions: &perms,
        allow_agg_sig_unsafe: false,
        allow_unknown_contracts: false,
        ownership: &own,
        keys: &keys,
        limits: &limits,
        now: 1_790_000_000,
        chain: None,
        signed_coins: signed,
    };
    submit(
        SubmitRequest {
            method: SUBMIT_COIN_SPENDS,
            spends,
            other_signature: None,
            intent: None,
            wallet_built: true,
            signatures_released: false,
        },
        &ctx,
        &Key(user.sk.clone()),
        &Yes,
        to,
    )
}

/// F-S1 (round 4): a sealed bundle that can no longer be included because a coin in it
/// that is not the user's was spent elsewhere (here a settlement coin anyone can spend).
/// The user's coins `c` and `d` stay unspent and the broadcast aggregate is public. The
/// dApp then asks `signCoinSpends` for the bundle's spend of `c` alone (it looks like a
/// self-send): with that signature, `d`'s sealed spend could be split out of the aggregate
/// and combined with any spend of `c` making the same announcement. The wallet never makes
/// a sealed signature again, so the request is refused, whatever happened to the other
/// coins; a different spend of `c` (another message) is signed, and the split stays out of
/// reach (F-S2: no coin is locked by a dead bundle).
#[test]
fn a_sealed_signature_is_never_made_again() {
    let user = BlsPair::new(1);
    let mut sim = Simulator::new();
    let c = sim.new_coin(user.puzzle_hash, 1000);
    let d = sim.new_coin(user.puzzle_hash, 1000);
    // The counterparty's settlement coin of 900 that pays the user.
    let sc = sim.new_coin(SETTLEMENT, 900);
    let settle = |nonce: u8, to: Bytes32| {
        let mut ctx = SpendContext::new();
        let np = NotarizedPayment::new(
            Bytes32::new([nonce; 32]),
            vec![Payment::new(to, 900, Memos::None)],
        );
        let node = ctx.alloc(&np).unwrap();
        let id = Bytes32::from(sha256_parts(&[
            SETTLEMENT_PAYMENT_HASH.as_slice(),
            &ctx.tree_hash(node).to_bytes(),
        ]));
        let cs = SettlementLayer
            .construct_coin_spend(&mut ctx, sc, SettlementPaymentsSolution::new(vec![np]))
            .unwrap();
        (cs, id)
    };
    let (pay, pay_id) = settle(7, user.puzzle_hash);
    let message = b"link".to_vec();
    let ann_c = Bytes32::from(sha256_parts(&[c.coin_id().as_ref(), &message]));
    let s1 = spend(
        &user,
        c,
        Conditions::new()
            .create_coin(user.puzzle_hash, 1000, Memos::None)
            .create_coin_announcement(message.clone().into())
            .assert_puzzle_announcement(pay_id),
    );
    let s2 = spend(
        &user,
        d,
        Conditions::new()
            .create_coin(SETTLEMENT, 1000, Memos::None)
            .assert_coin_announcement(ann_c),
    );
    let s1_alt = spend(
        &user,
        c,
        Conditions::new()
            .create_coin(user.puzzle_hash, 999, Memos::None)
            .create_coin_announcement(message.into()),
    );

    // 1. The sealed bundle; the network refuses it, the host records it all the same.
    let mut signed = SignedCoins::default();
    let to = Recorder(RefCell::default(), RefCell::default());
    let bundle = vec![s1.clone(), s2.clone(), pay];
    let e = submit_sealed(&user, bundle.clone(), &signed, &to).unwrap_err();
    assert_eq!(e.data.as_deref(), Some(r#"{"reason":"broadcast_failed"}"#));
    let agg = to.1.borrow().clone().unwrap().aggregated_signature;
    let record = to.0.borrow()[0].clone();
    assert_eq!(record.coins, [c.coin_id(), d.coin_id(), sc.coin_id()]);
    let sealed_coins: HashSet<Bytes32> = record.sealed.iter().map(|(coin, _)| *coin).collect();
    assert_eq!(
        sealed_coins,
        [c.coin_id(), d.coin_id()].into_iter().collect()
    );
    signed.add(&record);

    // 2. Anyone spends the settlement coin elsewhere; the bundle is dead. Only that coin
    //    leaves the record.
    let (kill, _) = settle(9, Bytes32::new([0xaa; 32]));
    sim.new_transaction(SpendBundle::new(vec![kill], Signature::default()))
        .unwrap();
    signed.spent(&sc.coin_id());

    // 3. The bundle's spends are not signed again: alone, or as the same bundle.
    for spends in [vec![s1.clone()], vec![s2.clone()]] {
        let e = sign_with(&user, &spends, false, &signed).unwrap_err();
        assert_eq!(e.data.as_deref(), Some(r#"{"reason":"sealed_signature"}"#));
    }
    let again = Recorder(RefCell::default(), RefCell::default());
    let e = submit_sealed(&user, bundle, &signed, &again).unwrap_err();
    assert_eq!(e.data.as_deref(), Some(r#"{"reason":"sealed_signature"}"#));
    assert!(again.0.borrow().is_empty() && again.1.borrow().is_none());

    // Before the fix the dApp got S1's signature here: the split is real.
    let sig_s1 = crate::option_sage_tests::signature_of(std::slice::from_ref(&s1), &user.sk);
    let sig_alt = sign_with(&user, std::slice::from_ref(&s1_alt), false, &signed).unwrap();
    let split = |sig_s2: Signature| {
        sim.clone()
            .new_transaction(SpendBundle::new(
                vec![s1_alt.clone(), s2.clone()],
                sig_alt.clone() + &sig_s2,
            ))
            .is_ok()
    };
    assert!(split(agg.clone() + &(-&sig_s1)), "the attack is real");
    // What the dApp holds now does not split the aggregate.
    assert!(!split(agg.clone()));
    assert!(!split(agg + &(-&sig_alt)));

    // F-S2: neither coin is locked; a different spend of each lands on chain.
    let d_home = spend(
        &user,
        d,
        Conditions::new().create_coin(user.puzzle_hash, 1000, Memos::None),
    );
    let sig_d = sign_with(&user, std::slice::from_ref(&d_home), false, &signed).unwrap();
    sim.new_transaction(SpendBundle::new(vec![s1_alt, d_home], sig_alt + &sig_d))
        .unwrap();
    signed.spent(&c.coin_id());
    signed.spent(&d.coin_id());
    assert_eq!(signed, SignedCoins::default());
}

/// `signMessage` never returns a signature the wallet made in a sealed bundle.
#[test]
fn sign_message_checks_the_sealed_record() {
    let user = BlsPair::new(1);
    let msg = b"hello".to_vec();
    let mut signed = SignedCoins::default();
    signed.add(&BroadcastRecord {
        coins: vec![Bytes32::new([1; 32])],
        sealed: vec![(
            Bytes32::new([1; 32]),
            crate::handlers::sealed_digest(&user.pk, &crate::handlers::signed_message_hash(&msg)),
        )],
    });
    let perms = DappPermissions::new_default(user.pk);
    let own = Ownership {
        p2_puzzle_hashes: [user.puzzle_hash].into_iter().collect(),
    };
    let keys: HashSet<PublicKey> = [user.pk].into_iter().collect();
    let limits = Mem::default();
    let params = serde_json::json!({
        "message": hex::encode(&msg),
        "publicKey": hex::encode(user.pk.to_bytes()),
    })
    .to_string();
    for (record, refused) in [(signed, true), (SignedCoins::default(), false)] {
        let ctx = RequestContext {
            dapp: "dapp.example",
            network: Network::Testnet11,
            session_chain_id: "testnet11",
            permissions: &perms,
            allow_agg_sig_unsafe: false,
            allow_unknown_contracts: false,
            ownership: &own,
            keys: &keys,
            limits: &limits,
            now: 1_790_000_000,
            chain: None,
            signed_coins: &record,
        };
        let out = handle("signMessage", &params, &ctx, &Key(user.sk.clone()), &Yes);
        assert_eq!(out.is_err(), refused, "{out:?}");
    }
}

/// Records into a `SignedCoins` (or fails to), and notes whether the user had already
/// signed when it was asked: the record is made after signing, before the answer.
struct Store<'a> {
    signed: RefCell<SignedCoins>,
    fail: bool,
    signs: &'a Cell<usize>,
    signs_at_record: Cell<Option<usize>>,
}
impl Broadcaster for Store<'_> {
    fn record(&self, r: &BroadcastRecord) -> Result<(), String> {
        self.signs_at_record.set(Some(self.signs.get()));
        if self.fail {
            return Err("disk full".to_owned());
        }
        self.signed.borrow_mut().add(r);
        Ok(())
    }
    fn submit(&self, _b: &SpendBundle) -> Result<Broadcast, String> {
        Err("not used".to_owned())
    }
}

struct Counting<'a>(SecretKey, &'a Cell<usize>);
impl Signer for Counting<'_> {
    fn sign(&self, _pk: &PublicKey, msg: &[u8]) -> Result<Signature, SignerError> {
        self.1.set(self.1.get() + 1);
        Ok(chia_bls::sign(&self.0, msg))
    }
}

/// `signCoinSpends` (and its `chip0002_` alias) through a host with a broadcaster: the kit
/// records every coin of the request as released before it returns the signature, and
/// returns no signature when the host cannot store the record (spec 11.2).
#[test]
fn sign_coin_spends_records_released_coins_before_answering() {
    let user = BlsPair::new(1);
    let mut sim = Simulator::new();
    let c = sim.new_coin(user.puzzle_hash, 1000);
    let d = sim.new_coin(user.puzzle_hash, 500);
    let spends = vec![
        spend(
            &user,
            c,
            Conditions::new().create_coin(user.puzzle_hash, 1000, Memos::None),
        ),
        spend(
            &user,
            d,
            Conditions::new().create_coin(user.puzzle_hash, 500, Memos::None),
        ),
    ];
    let perms = DappPermissions::new_default(user.pk);
    let own = Ownership {
        p2_puzzle_hashes: [user.puzzle_hash].into_iter().collect(),
    };
    let keys: HashSet<PublicKey> = [user.pk].into_iter().collect();
    let empty = SignedCoins::default();
    for method in ["signCoinSpends", "chip0002_signCoinSpends"] {
        for fail in [false, true] {
            let limits = Mem::default();
            let ctx = RequestContext {
                dapp: "dapp.example",
                network: Network::Testnet11,
                session_chain_id: "testnet11",
                permissions: &perms,
                allow_agg_sig_unsafe: false,
                allow_unknown_contracts: false,
                ownership: &own,
                keys: &keys,
                limits: &limits,
                now: 1_790_000_000,
                chain: None,
                signed_coins: &empty,
            };
            let signs = Cell::new(0);
            let store = Store {
                signed: RefCell::default(),
                fail,
                signs: &signs,
                signs_at_record: Cell::new(None),
            };
            let out = handle_with_host(
                method,
                &params(&spends, false),
                &ctx,
                &Host {
                    signer: &Counting(user.sk.clone(), &signs),
                    approver: &Yes,
                    broadcaster: Some(&store),
                },
            );
            // Asked once, after the signatures were made.
            assert_eq!(store.signs_at_record.get(), Some(2), "{method}");
            if fail {
                let e = out.unwrap_err();
                assert_eq!(e.code, 4000);
                assert_eq!(e.data.as_deref(), Some(r#"{"reason":"record_failed"}"#));
                assert_eq!(*store.signed.borrow(), SignedCoins::default());
            } else {
                signature(&out.unwrap());
                let rec = store.signed.borrow();
                assert_eq!(
                    rec.released,
                    [c.coin_id(), d.coin_id()].into_iter().collect()
                );
                assert!(rec.sealed.is_empty());
            }
        }
    }
}

/// `SignedCoins::sealed` is keyed by digest: one lookup, and a digest held for two coins
/// stays refused until both are spent.
#[test]
fn sealed_lookup_is_by_digest_and_kept_until_every_coin_is_spent() {
    let user = BlsPair::new(1);
    let (a, b) = (Bytes32::new([1; 32]), Bytes32::new([2; 32]));
    let digest = crate::handlers::sealed_digest(&user.pk, b"m");
    let mut signed = SignedCoins::default();
    signed.add(&BroadcastRecord {
        coins: vec![a, b],
        sealed: vec![(a, digest), (b, digest)],
    });
    assert!(signed.is_sealed(&user.pk, b"m"));
    assert!(!signed.is_sealed(&user.pk, b"n"));
    signed.spent(&a);
    assert!(signed.is_sealed(&user.pk, b"m"));
    signed.spent(&b);
    assert!(!signed.is_sealed(&user.pk, b"m"));
    assert_eq!(signed, SignedCoins::default());
}
