//! Regression tests for the final audit of the rc.5 option rules (TASK-78): F1, binding
//! through a link between two of the user's spends, which a dApp holding the user's
//! signatures can defeat by putting another signed spend of the linked coin in place of the
//! one in the request. Only direct binding counts when the signatures are released (spec
//! 11.2); the sealed wallet-built case is in `option_reaudit_tests` (N2) and
//! `option_sage_tests`.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use crate::handlers::{
    Approver, Prompt, RequestContext, RpcError, SignedCoins, Signer, SignerError, handle,
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

/// `signCoinSpends` never signs a spend of a coin in flight in a sealed bundle (spec 11.2):
/// that signature would let the dApp split the bundle's aggregate.
#[test]
fn a_coin_in_flight_is_not_signed_again() {
    let user = BlsPair::new(1);
    let coin = Coin::new(Bytes32::new([4; 32]), user.puzzle_hash, 1000);
    let back = spend(
        &user,
        coin,
        Conditions::new().create_coin(user.puzzle_hash, 1000, Memos::None),
    );
    let mut signed = SignedCoins::default();
    signed.in_flight.insert(coin.coin_id());
    let e = sign_with(&user, std::slice::from_ref(&back), false, &signed).unwrap_err();
    assert_eq!(e.data.as_deref(), Some(r#"{"reason":"coin_in_flight"}"#));
    sign(&user, &[back], false).unwrap();
}
