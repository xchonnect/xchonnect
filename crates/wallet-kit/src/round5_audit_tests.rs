//! Regression tests for the fifth audit round of rc.5 (TASK-78): S1 (a sealed bundle whose
//! user spends are bound but not tied to one another), U1 (a spend the wallet signs but does
//! not recognise as the user's), N-b (a request with another party's spends and no partial
//! signature). H1, N-a and the option limit are in `option_sage_tests`, `binding` and
//! `permissions`. Each attack ends refused or harmless.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use crate::handlers::{
    Approver, Broadcast, BroadcastRecord, Broadcaster, Prompt, RequestContext, RpcError,
    SUBMIT_COIN_SPENDS, SignedCoins, Signer, SignerError, SubmitRequest, handle, submit,
};
use crate::permissions::DappPermissions;
use crate::policy::Network;
use crate::simulate::Ownership;
use crate::swap_fixture::{Mem, params};
use chia_bls::{PublicKey, SecretKey, Signature};
use chia_protocol::{Bytes32, Coin, CoinSpend, Program, SpendBundle};
use chia_puzzle_types::Memos;
use chia_puzzle_types::offer::{NotarizedPayment, Payment, SettlementPaymentsSolution};
use chia_puzzles::SETTLEMENT_PAYMENT_HASH;
use chia_sdk_driver::{Layer, SettlementLayer, SpendContext, StandardLayer};
use chia_sdk_test::{BlsPair, Simulator};
use chia_sdk_types::Conditions;
use clvm_traits::{FromClvm, ToClvm};
use clvmr::Allocator;
use serde_json::Value;
use std::cell::RefCell;
use std::collections::HashSet;
use xchonnect_core::crypto::sha256_parts;
use xchonnect_core::rpc::codes;

const SETTLEMENT: Bytes32 = Bytes32::new(SETTLEMENT_PAYMENT_HASH);

struct Key(SecretKey);
impl Signer for Key {
    fn sign(&self, _pk: &PublicKey, msg: &[u8]) -> Result<Signature, SignerError> {
        Ok(chia_bls::sign(&self.0, msg))
    }
}

/// Approves everything and keeps the prompts as hosts receive them.
#[derive(Default)]
struct Ui(RefCell<Vec<Value>>);
impl Approver for Ui {
    fn approve(&self, p: &Prompt<'_>) -> bool {
        self.0.borrow_mut().push(serde_json::to_value(p).unwrap());
        true
    }
}

/// Records what the kit reports and hands the bundle to `chain` (`None`: never included).
struct Net<'a>(
    RefCell<Vec<BroadcastRecord>>,
    RefCell<Option<SpendBundle>>,
    Option<&'a RefCell<Simulator>>,
);
impl Broadcaster for Net<'_> {
    fn record(&self, r: &BroadcastRecord) -> Result<(), String> {
        self.0.borrow_mut().push(r.clone());
        Ok(())
    }
    fn submit(&self, b: &SpendBundle) -> Result<Broadcast, String> {
        *self.1.borrow_mut() = Some(b.clone());
        match self.2 {
            Some(sim) => sim
                .borrow_mut()
                .new_transaction(b.clone())
                .map_err(|e| e.to_string())?,
            None => return Err("not included".to_owned()),
        };
        Ok(Broadcast {
            transaction_id: hex::encode(b.name()),
            status: "ok".to_owned(),
        })
    }
}

/// The user's wallet.
struct Wallet {
    user: BlsPair,
    perms: DappPermissions,
    own: Ownership,
    keys: HashSet<PublicKey>,
    limits: Mem,
}

impl Wallet {
    fn new(user: BlsPair) -> Self {
        Wallet {
            perms: DappPermissions::new_default(user.pk),
            own: Ownership {
                p2_puzzle_hashes: [user.puzzle_hash].into_iter().collect(),
            },
            keys: [user.pk].into_iter().collect(),
            limits: Mem::default(),
            user,
        }
    }

    fn ctx<'a>(&'a self, signed: &'a SignedCoins, unknown: bool) -> RequestContext<'a> {
        RequestContext {
            dapp: "dapp.example",
            network: Network::Testnet11,
            session_chain_id: "testnet11",
            permissions: &self.perms,
            allow_agg_sig_unsafe: false,
            allow_unknown_contracts: unknown,
            ownership: &self.own,
            keys: &self.keys,
            limits: &self.limits,
            now: 1_790_000_000,
            chain: None,
            signed_coins: signed,
        }
    }

    /// `signCoinSpends`: the signature, and the prompt shown.
    fn sign(
        &self,
        spends: &[CoinSpend],
        partial: bool,
        signed: &SignedCoins,
        unknown: bool,
    ) -> (Result<Signature, RpcError>, Option<Value>) {
        let ui = Ui::default();
        let out = handle(
            "signCoinSpends",
            &params(spends, partial),
            &self.ctx(signed, unknown),
            &Key(self.user.sk.clone()),
            &ui,
        )
        .map(|out| {
            let h: String = serde_json::from_str(&out).unwrap();
            let bytes: [u8; 96] = hex::decode(h.trim_start_matches("0x"))
                .unwrap()
                .try_into()
                .unwrap();
            Signature::from_bytes(&bytes).unwrap()
        });
        let prompt = ui.0.borrow().first().cloned();
        (out, prompt)
    }

    /// A wallet-built request the wallet broadcasts itself (sealed when eligible).
    fn submit_built(
        &self,
        spends: Vec<CoinSpend>,
        other: Option<Signature>,
        signed: &SignedCoins,
        net: &Net<'_>,
    ) -> (Result<(), RpcError>, Option<Value>) {
        let ui = Ui::default();
        let out = submit(
            SubmitRequest {
                method: SUBMIT_COIN_SPENDS,
                spends,
                other_signature: other,
                intent: None,
                wallet_built: true,
                wallet_fee: 0,
                signatures_released: false,
            },
            &self.ctx(signed, false),
            &Key(self.user.sk.clone()),
            &ui,
            net,
        )
        .map(|_| ());
        let prompt = ui.0.borrow().first().cloned();
        (out, prompt)
    }
}

fn spend(who: &BlsPair, coin: Coin, conds: Conditions) -> CoinSpend {
    let mut ctx = SpendContext::new();
    StandardLayer::new(who.pk)
        .spend(&mut ctx, coin, conds)
        .unwrap();
    ctx.take().remove(0)
}

/// A settlement coin paying `amount` to `to` under nonce `nonce`, and its announcement.
fn settle(coin: Coin, nonce: u8, to: Bytes32, amount: u64) -> (CoinSpend, Bytes32) {
    let mut ctx = SpendContext::new();
    let np = NotarizedPayment::new(
        Bytes32::new([nonce; 32]),
        vec![Payment::new(to, amount, Memos::None)],
    );
    let node = ctx.alloc(&np).unwrap();
    let id = Bytes32::from(sha256_parts(&[
        SETTLEMENT_PAYMENT_HASH.as_slice(),
        &ctx.tree_hash(node).to_bytes(),
    ]));
    let cs = SettlementLayer
        .construct_coin_spend(&mut ctx, coin, SettlementPaymentsSolution::new(vec![np]))
        .unwrap();
    (cs, id)
}

fn reason(e: &RpcError) -> String {
    e.data.clone().unwrap_or_default()
}

/// S1. A wallet-built take: the user's `u1` (coin `c1`, 10 mojos back to the user) asserts
/// the maker's payment of 1000; `u2` (coin `c2`) pays the maker 1000 and asserts only a
/// 1-mojo payment. Each is bound, but neither requires the other. If the bundle were sealed,
/// the maker could double-spend her coin (the bundle fails), wait until the user spends
/// `c1` and the host prunes it, have the user re-sign `u1` (its coin is spent, it looks
/// harmless), subtract, and send `u2` alone with a fresh 1-mojo payment: ~999 lost.
///
/// (a) Such a bundle is never sealed: with more than one user spend, every user spend must
/// require every other. It is read with the signatures released, where `u2` does not assert
/// every payment, so it is refused before any prompt. (b) Tied together, it is sealed, and
/// its signatures stay refused until both coins are spent, whatever was pruned; `u2` alone
/// can never be valid again once `c1` is spent.
#[test]
fn s1_a_sealed_bundle_cannot_be_split_after_pruning() {
    let w = Wallet::new(BlsPair::new(1));
    let mallory = BlsPair::new(9);
    for tied in [false, true] {
        let sim = RefCell::new(Simulator::new());
        let (c1, c2, mc) = {
            let mut s = sim.borrow_mut();
            (
                s.new_coin(w.user.puzzle_hash, 10),
                s.new_coin(w.user.puzzle_hash, 1000),
                s.new_coin(mallory.puzzle_hash, 1001),
            )
        };
        let mc_spend = spend(
            &mallory,
            mc,
            Conditions::new()
                .create_coin(SETTLEMENT, 1000, Memos::None)
                .create_coin(SETTLEMENT, 1, Memos::None),
        );
        let maker_sig =
            crate::option_sage_tests::signature_of(std::slice::from_ref(&mc_spend), &mallory.sk);
        let (p1, id1) = settle(
            Coin::new(mc.coin_id(), SETTLEMENT, 1000),
            1,
            w.user.puzzle_hash,
            1000,
        );
        let (p2, id2) = settle(
            Coin::new(mc.coin_id(), SETTLEMENT, 1),
            2,
            w.user.puzzle_hash,
            1,
        );
        let mut c1_conds = Conditions::new()
            .create_coin(w.user.puzzle_hash, 10, Memos::None)
            .assert_puzzle_announcement(id1);
        let mut c2_conds = Conditions::new()
            .create_coin(mallory.puzzle_hash, 1000, Memos::None)
            .assert_puzzle_announcement(id2);
        if tied {
            c1_conds = c1_conds.assert_concurrent_spend(c2.coin_id());
            c2_conds = c2_conds.assert_concurrent_spend(c1.coin_id());
        }
        let u1 = spend(&w.user, c1, c1_conds);
        let u2 = spend(&w.user, c2, c2_conds);

        // B: the maker double-spends first, so the network refuses it.
        let kill = spend(
            &mallory,
            mc,
            Conditions::new().create_coin(mallory.puzzle_hash, 1001, Memos::None),
        );
        let kill_sig =
            crate::option_sage_tests::signature_of(std::slice::from_ref(&kill), &mallory.sk);
        sim.borrow_mut()
            .new_transaction(SpendBundle::new(vec![kill], kill_sig))
            .unwrap();
        let mut store = SignedCoins::default();
        let net = Net(RefCell::default(), RefCell::default(), Some(&sim));
        let bundle = vec![
            u1.clone(),
            u2.clone(),
            mc_spend.clone(),
            p1.clone(),
            p2.clone(),
        ];
        let (out, prompt) = w.submit_built(bundle, Some(maker_sig.clone()), &store, &net);
        if !tied {
            // (a) Not sealed: read as released, refused, nothing signed or recorded.
            let e = out.unwrap_err();
            assert!(reason(&e).contains("unbound_partial"), "{e:?}");
            assert!(prompt.is_none() && net.0.borrow().is_empty());
            continue;
        }
        let e = out.unwrap_err();
        assert!(reason(&e).contains("broadcast_failed"), "{e:?}");
        let prompt = prompt.unwrap();
        assert_eq!(prompt["linking"], "sealed");
        assert_eq!(prompt["binding"]["co_required"], true);
        for r in net.0.borrow().iter() {
            store.add(r);
        }
        let agg = net.1.borrow().clone().unwrap().aggregated_signature;

        // The user later spends c1 in an ordinary send; it confirms deeply and the host
        // prunes it, as spec 11.2 allows.
        let send = spend(
            &w.user,
            c1,
            Conditions::new().create_coin(w.user.puzzle_hash, 10, Memos::None),
        );
        let (sig, _) = w.sign(std::slice::from_ref(&send), false, &store, false);
        sim.borrow_mut()
            .new_transaction(SpendBundle::new(vec![send], sig.unwrap()))
            .unwrap();
        store.spent(&c1.coin_id());

        // (b) u1 again: refused while c2, a coin of the same bundle, is unspent.
        let (out, prompt) = w.sign(&[u1.clone(), p1.clone()], true, &store, false);
        let e = out.unwrap_err();
        assert!(reason(&e).contains("sealed_signature"), "{e:?}");
        assert!(prompt.is_none());

        // Even with u1's signature (what the pruned record would have let out), u2 alone
        // requires c1's spend, which can never happen again.
        let sig_u1 = crate::option_sage_tests::signature_of(std::slice::from_ref(&u1), &w.user.sk);
        let sig_u2 = agg + &(-&sig_u1) + &(-&maker_sig);
        let k2b = sim.borrow_mut().new_coin(SETTLEMENT, 1);
        let (p2b, _) = settle(k2b, 2, w.user.puzzle_hash, 1);
        assert!(
            sim.borrow_mut()
                .new_transaction(SpendBundle::new(vec![u2.clone(), p2b], sig_u2))
                .is_err()
        );
        assert_eq!(
            sim.borrow()
                .unspent_coins(w.user.puzzle_hash, false)
                .iter()
                .map(|c| c.amount)
                .sum::<u64>(),
            1010,
            "the user keeps everything"
        );
        // c2 spent too: the bundle, and its signatures, leave the record.
        store.spent(&c2.coin_id());
        assert!(store.sealed.is_empty() && store.sealed_bundles.is_empty());
    }
}

/// `(a (q . PUZZLE) 1)`: runs `cs`'s puzzle unchanged, but the wallet does not recognise it
/// (as an NFT, a vault or any other contract around the user's key).
fn wrapped(cs: &CoinSpend, sim: &mut Simulator) -> CoinSpend {
    let mut a = Allocator::new();
    let inner = cs.puzzle_reveal.to_clvm(&mut a).unwrap();
    let q = a.new_pair(a.one(), inner).unwrap();
    let two = a.new_small_number(2).unwrap();
    let nil = a.nil();
    let one = a.one();
    let args = a.new_pair(one, nil).unwrap();
    let args = a.new_pair(q, args).unwrap();
    let program = a.new_pair(two, args).unwrap();
    let ph = Bytes32::from(clvm_utils::tree_hash(&a, program));
    let coin = sim.new_coin(ph, cs.coin.amount);
    CoinSpend::new(
        coin,
        Program::from_clvm(&a, program).unwrap(),
        cs.solution.clone(),
    )
}

/// U1. A decoy of the user's (pays 1000 into the offer and asserts a payment of 900), plus
/// 1 XCH of the user's under a contract the wallet does not recognise that pays Mallory and
/// asserts nothing, plus the settlement payment. The wallet signs the unrecognised spend:
/// it is a user spend, so the request is never bound by the decoy alone. It is refused
/// outright in any multi-party request (`unknown_partial`), with or without
/// `partialSign`. On its own, allowed by the user, it is shown as 1 XCH leaving the user,
/// its outputs unaccounted, nothing received.
#[test]
fn u1_a_spend_the_wallet_signs_is_a_user_spend() {
    let w = Wallet::new(BlsPair::new(1));
    let mallory = BlsPair::new(9);
    let mut sim = Simulator::new();
    let c = sim.new_coin(w.user.puzzle_hash, 1000);
    let sc = sim.new_coin(SETTLEMENT, 900);
    let (pay, pay_id) = settle(sc, 7, w.user.puzzle_hash, 900);
    let decoy = spend(
        &w.user,
        c,
        Conditions::new()
            .create_coin(SETTLEMENT, 1000, Memos::None)
            .assert_puzzle_announcement(pay_id),
    );
    let template = spend(
        &w.user,
        Coin::new(Bytes32::new([3; 32]), w.user.puzzle_hash, 1_000_000),
        Conditions::new().create_coin(mallory.puzzle_hash, 1_000_000, Memos::None),
    );
    let unknown = wrapped(&template, &mut sim);
    let none = SignedCoins::default();
    let request = [decoy.clone(), unknown.clone(), pay.clone()];

    for partial in [true, false] {
        // Not allowed: an unknown contract.
        let (out, prompt) = w.sign(&request, partial, &none, false);
        assert_eq!(out.unwrap_err().code, codes::UNSUPPORTED_CONTENT);
        assert!(prompt.is_none());
        // Allowed by the user: still refused in a request with another party's spends.
        let (out, prompt) = w.sign(&request, partial, &none, true);
        let e = out.unwrap_err();
        assert!(reason(&e).contains("unknown_partial"), "{partial}: {e:?}");
        assert!(prompt.is_none());
    }
    // The binding check sees it as a user spend that is not bound.
    let report = crate::binding::verify_binding_signed(
        &request,
        &w.own,
        &w.keys,
        crate::simulate::DEFAULT_MAX_COST,
        crate::binding::Linking::Direct,
    )
    .unwrap();
    assert!(
        !report.all_bound && report.unbound_user_spends == vec![1],
        "{report:?}"
    );

    // On its own, allowed: shown as a loss, its outputs unaccounted, never received.
    let (out, prompt) = w.sign(std::slice::from_ref(&unknown), false, &none, true);
    out.unwrap();
    let summary = &prompt.unwrap()["summary"];
    let coin_id = hex::encode(unknown.coin.coin_id());
    assert_eq!(summary["unaccounted_spends"], serde_json::json!([coin_id]));
    assert_eq!(
        summary["unknown_puzzles"],
        serde_json::json!([hex::encode(unknown.coin.puzzle_hash)])
    );
    assert_eq!(summary["outputs"][0]["unaccounted"], true);
    assert_eq!(summary["assets"][0]["sent"], "1000000");
    assert_eq!(summary["assets"][0]["received"], "0");
    // What it sends back to the user's own puzzle is not received either.
    let back = spend(
        &w.user,
        Coin::new(Bytes32::new([4; 32]), w.user.puzzle_hash, 500),
        Conditions::new().create_coin(w.user.puzzle_hash, 500, Memos::None),
    );
    let back = wrapped(&back, &mut sim);
    let (out, prompt) = w.sign(std::slice::from_ref(&back), false, &none, true);
    out.unwrap();
    let summary = &prompt.unwrap()["summary"];
    assert_eq!(summary["assets"][0]["received"], "0");
    assert_eq!(summary["assets"][0]["conditional_received"], "500");
    assert_eq!(summary["assets"][0]["net"], "-500");
}

/// N-b. A request without `partialSign` that spends another party's coin (here a
/// settlement coin paying the user 900) is checked for binding all the same: the dApp could
/// drop that spend and use the user's signature alone. The user's spend that does not
/// assert the payment is refused; one that does is signed.
#[test]
fn n_b_another_partys_spend_needs_binding_without_partial_sign() {
    let w = Wallet::new(BlsPair::new(1));
    let mut sim = Simulator::new();
    let c = sim.new_coin(w.user.puzzle_hash, 1000);
    let sc = sim.new_coin(SETTLEMENT, 900);
    let (pay, pay_id) = settle(sc, 7, w.user.puzzle_hash, 900);
    let none = SignedCoins::default();
    let loose = spend(
        &w.user,
        c,
        Conditions::new().create_coin(SETTLEMENT, 1000, Memos::None),
    );
    let (out, prompt) = w.sign(&[loose, pay.clone()], false, &none, false);
    let e = out.unwrap_err();
    assert!(reason(&e).contains("unbound_partial"), "{e:?}");
    assert!(prompt.is_none());
    let bound = spend(
        &w.user,
        c,
        Conditions::new()
            .create_coin(SETTLEMENT, 1000, Memos::None)
            .assert_puzzle_announcement(pay_id),
    );
    let (out, prompt) = w.sign(&[bound, pay], false, &none, false);
    out.unwrap();
    assert_eq!(prompt.unwrap()["binding"]["all_bound"], true);
}

/// 0.1.0 release audit, found by fuzzing (`option_spends`): amounts reach the host as exact
/// decimal strings. Two outputs of `u64::MAX` to the user sum to more than `u64::MAX`, which
/// `serde_json` cannot write as a number, and anything above 2^53 is not exact in a JSON
/// double; the prompt used to fail to serialise, or round in the host.
#[test]
fn prompt_amounts_are_exact_decimal_strings() {
    let w = Wallet::new(BlsPair::new(7));
    let none = SignedCoins::default();
    let big = spend(
        &w.user,
        Coin::new(Bytes32::new([5; 32]), w.user.puzzle_hash, 1),
        Conditions::new()
            .create_coin(w.user.puzzle_hash, u64::MAX, Memos::None)
            .create_coin(w.user.puzzle_hash, u64::MAX, Memos::None),
    );
    let (_, prompt) = w.sign(std::slice::from_ref(&big), false, &none, false);
    let prompt = prompt.expect("the request reaches the prompt");
    let xch = &prompt["summary"]["assets"][0];
    let twice = (u128::from(u64::MAX) * 2).to_string();
    assert_eq!(xch["received"], twice.as_str());
    assert_eq!(xch["sent"], "1");
    assert_eq!(xch["net"], (u128::from(u64::MAX) * 2 - 1).to_string());
    assert_eq!(
        prompt["summary"]["outputs"][0]["amount"],
        u64::MAX.to_string()
    );
    assert_eq!(prompt["summary"]["spends"][0]["amount"], "1");
    assert!(prompt["summary"]["implied_fee"].is_null());
    assert_eq!(prompt["summary"]["reserve_fee"], "0");
}
