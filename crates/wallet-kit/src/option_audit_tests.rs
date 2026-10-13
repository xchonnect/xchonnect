//! Regression tests for the rc.5 option audit and review (TASK-78): the security audit's
//! proofs of concept (SA-H1 scenarios A and A2, SA-H2 scenario B, SA-H3 scenario C) and the
//! review's findings, each turned into a test that the wallet now refuses what it must and
//! states what the request does.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use crate::binding::verify_binding;
use crate::intent::{Intent, IntentError};
use crate::option::OptionEffect;
use crate::option_fixture::{self as fx, Collateral, MintSpec};
use crate::option_sage_tests::{reason, run};
use crate::permissions::guaranteed_loss;
use crate::simulate::{AssetId, DEFAULT_MAX_COST, Ownership, Summary, simulate};
use crate::swap_fixture::owned;
use chia_protocol::{Bytes32, Coin, CoinSpend};
use chia_puzzle_types::Memos;
use chia_puzzle_types::offer::{NotarizedPayment, Payment, SettlementPaymentsSolution};
use chia_puzzles::SETTLEMENT_PAYMENT_HASH;
use chia_sdk_driver::{
    Layer, OptionContract, OptionLauncher, OptionLauncherInfo, OptionType, OptionUnderlying,
    SettlementLayer, SingletonInfo, SpendContext, StandardLayer,
};
use chia_sdk_test::{BlsPair, Simulator};
use chia_sdk_types::Conditions;
use proptest::prelude::*;
use serde_json::json;
use std::cell::RefCell;
use xchonnect_core::crypto::sha256_parts;

const EXPIRY: u64 = 1_900_000_000;
const SETTLEMENT: Bytes32 = Bytes32::new(SETTLEMENT_PAYMENT_HASH);

fn sim_of(spends: &[CoinSpend], who: &BlsPair) -> Summary {
    simulate(spends, &owned(who.puzzle_hash), DEFAULT_MAX_COST).unwrap()
}

fn mints(s: &Summary) -> Vec<&OptionEffect> {
    s.options
        .iter()
        .filter(|e| matches!(e, OptionEffect::Mint { .. }))
        .collect()
}

fn guaranteed(s: &Summary) -> bool {
    matches!(
        mints(s).as_slice(),
        [OptionEffect::Mint {
            guaranteed: true,
            ..
        }]
    )
}

fn verify(
    s: &Summary,
    intent: serde_json::Value,
) -> Result<crate::intent::IntentReport, IntentError> {
    Intent::from_json(&intent).unwrap().verify(s)
}

/// The audit's mint builder: `launcher_payer` creates the launcher (and asserts it),
/// `collateral_payer` funds the collateral. `link`: the two spends require each other.
struct Built {
    spends: Vec<CoinSpend>,
    option: OptionContract,
    underlying: OptionUnderlying,
    collateral: Coin,
    funding: Coin,
    parent: Coin,
}

#[allow(clippy::too_many_arguments)]
fn build_mint(
    sim: &mut Simulator,
    launcher_payer: &BlsPair,
    collateral_payer: &BlsPair,
    creator: Bytes32,
    owner: Bytes32,
    amount: u64,
    strike: OptionType,
    launcher_amount: u64,
    premium_to: Option<(Bytes32, u64)>,
    link: bool,
) -> Built {
    let mut ctx = SpendContext::new();
    let premium = premium_to.map_or(0, |p| p.1);
    let parent = sim.new_coin(launcher_payer.puzzle_hash, launcher_amount + premium);
    let launcher = OptionLauncher::with_amount(
        &mut ctx,
        parent.coin_id(),
        launcher_amount,
        OptionLauncherInfo::new(creator, owner, EXPIRY, amount, strike),
        launcher_amount,
    )
    .unwrap();
    let underlying = launcher.underlying();
    let p2_option = launcher.p2_puzzle_hash();
    let funding = sim.new_coin(collateral_payer.puzzle_hash, amount);
    let tie = |c: Conditions, other: Coin| {
        if link {
            c.assert_concurrent_spend(other.coin_id())
        } else {
            c
        }
    };
    StandardLayer::new(collateral_payer.pk)
        .spend(
            &mut ctx,
            funding,
            tie(Conditions::new(), parent).create_coin(p2_option, amount, Memos::None),
        )
        .unwrap();
    let collateral = Coin::new(funding.coin_id(), p2_option, amount);
    let launcher = launcher.with_underlying(collateral.coin_id());
    let (mut conds, option) = launcher.mint(&mut ctx).unwrap();
    if let Some((to, amt)) = premium_to {
        conds = conds.create_coin(to, amt, Memos::None);
    }
    StandardLayer::new(launcher_payer.pk)
        .spend(&mut ctx, parent, tie(conds, funding))
        .unwrap();
    Built {
        spends: ctx.take(),
        option,
        underlying,
        collateral,
        funding,
        parent,
    }
}

// --- SA-H1: value to a stranger hidden in option outputs ---

/// PoC A: the user funds the collateral and a 500,001-mojo launcher of an option Mallory
/// creates and owns. The intent says "no payments". Now: the oversized launcher makes the
/// mint unrecognised, and the outputs are payments, so the empty `recipients` is refused.
#[test]
fn poc_a_a_large_launcher_is_not_an_option_and_its_value_is_a_payment() {
    let (user, mallory) = (BlsPair::new(1), BlsPair::new(2));
    let mut sim = Simulator::new();
    let b = build_mint(
        &mut sim,
        &user,
        &user,
        mallory.puzzle_hash,
        mallory.puzzle_hash,
        1_000_000,
        OptionType::Xch { amount: 1 },
        500_001,
        None,
        true,
    );
    let s = sim_of(&b.spends, &user);
    assert!(mints(&s).is_empty(), "{:?}", s.options);
    assert!(!s.unknown_puzzles.is_empty());
    assert!(s.outputs.iter().all(|o| o.option.is_none()));
    assert_eq!(
        verify(&s, json!({ "kind": "option.buy", "recipients": [] })),
        Err(IntentError::Mismatch("recipients"))
    );
    assert_eq!(guaranteed_loss(&s).get(&AssetId::Xch), Some(&1_500_001));
    sim.spend_coins(b.spends, &[user.sk]).unwrap();
}

/// PoC A with a regular one-mojo launcher: a recognised mint for Mallory. The collateral and
/// the launcher are payments to Mallory, the owner; `recipients` must list them.
#[test]
fn poc_a_an_option_for_a_stranger_is_a_payment_to_its_owner() {
    let (user, mallory) = (BlsPair::new(1), BlsPair::new(2));
    for link in [true, false] {
        let mut sim = Simulator::new();
        let b = build_mint(
            &mut sim,
            &user,
            &user,
            mallory.puzzle_hash,
            mallory.puzzle_hash,
            1_000_000,
            OptionType::Xch { amount: 1 },
            1,
            None,
            link,
        );
        let s = sim_of(&b.spends, &user);
        assert_eq!(guaranteed(&s), link, "link={link}");
        let marked: Vec<_> = s.outputs.iter().filter(|o| o.option.is_some()).collect();
        assert_eq!(marked.len(), 2);
        assert!(marked.iter().all(|o| !o.option.unwrap().user_holds_option));
        let none = json!({ "kind": "option.buy", "recipients": [] });
        let declared = json!({ "recipients": [
            { "puzzleHash": hex::encode(mallory.puzzle_hash), "amount": "1000000" },
            { "puzzleHash": hex::encode(mallory.puzzle_hash), "amount": 1 },
        ] });
        if link {
            // Guaranteed: the owner is named, and only a declaration that lists them holds.
            assert!(
                marked
                    .iter()
                    .all(|o| o.recipient == Some(hex::encode(mallory.puzzle_hash)))
            );
            assert_eq!(verify(&s, none), Err(IntentError::Mismatch("recipients")));
            let report = verify(&s, declared).unwrap();
            assert!(report.recipients_complete && report.verified.len() == 1);
        } else {
            // Not guaranteed: no one the wallet can name receives it; nothing is complete.
            assert!(marked.iter().all(|o| o.recipient.is_none()));
            assert_eq!(
                verify(&s, none),
                Err(IntentError::Mismatch("unnamed_recipient"))
            );
            assert_eq!(
                verify(&s, declared),
                Err(IntentError::Mismatch("unnamed_recipient"))
            );
        }
    }
}

/// PoC A2: the user creates an option that Mallory owns. `option.mint` is true (and says
/// only that the request contains such a mint), but `recipients: []` is not.
#[test]
fn poc_a2_writing_an_option_for_a_stranger_must_declare_them() {
    let (user, mallory) = (BlsPair::new(1), BlsPair::new(2));
    let mut sim = Simulator::new();
    let b = build_mint(
        &mut sim,
        &user,
        &user,
        user.puzzle_hash,
        mallory.puzzle_hash,
        1_000_000,
        OptionType::Xch { amount: 1 },
        1,
        None,
        true,
    );
    let s = sim_of(&b.spends, &user);
    assert_eq!(
        verify(&s, json!({ "kind": "option.mint", "recipients": [] })),
        Err(IntentError::Mismatch("recipients"))
    );
    let report = verify(&s, json!({ "kind": "option.mint" })).unwrap();
    assert!(report.kind_verified && !report.recipients_complete);
    let sim = RefCell::new(sim);
    let err = run(
        &sim,
        &user,
        b.spends,
        Some(json!({ "kind": "option.mint", "recipients": [] })),
    )
    .unwrap_err();
    assert!(reason(&err).contains("intent_mismatch"), "{err:?}");
}

// --- SA-H2: a launch whose collateral the counterparty can drop ---

/// PoC B: the user buys an option: their coin creates the launcher, asserts it, and pays
/// Mallory a premium; Mallory funds the collateral. Mallory can swap her funding spend
/// (the user's signature stays valid): the mint is never shown as guaranteed.
#[test]
fn poc_b_collateral_funded_by_the_counterparty_is_not_guaranteed() {
    let (user, mallory) = (BlsPair::new(1), BlsPair::new(2));
    let mut sim = Simulator::new();
    let b = build_mint(
        &mut sim,
        &user,
        &mallory,
        mallory.puzzle_hash,
        user.puzzle_hash,
        1_000_000,
        OptionType::Xch { amount: 10 },
        1,
        Some((mallory.puzzle_hash, 50_000)),
        true,
    );
    let s = sim_of(&b.spends, &user);
    let [
        OptionEffect::Mint {
            guaranteed,
            funded_by_user,
            owner_is_user,
            ..
        },
    ] = mints(&s).as_slice()
    else {
        panic!("{:?}", s.options)
    };
    assert!(!guaranteed && !funded_by_user && *owner_is_user);
    // The swap the audit found: the chain accepts it, the collateral never exists.
    let mut ctx = SpendContext::new();
    StandardLayer::new(mallory.pk)
        .spend(
            &mut ctx,
            b.funding,
            Conditions::new().create_coin(mallory.puzzle_hash, 1_000_000, Memos::None),
        )
        .unwrap();
    let swapped = ctx.take().remove(0);
    let attack: Vec<CoinSpend> = b
        .spends
        .iter()
        .map(|cs| {
            if cs.coin == b.funding {
                swapped.clone()
            } else {
                cs.clone()
            }
        })
        .collect();
    assert!(b.spends.iter().any(|cs| cs.coin == b.parent));
    sim.spend_coins(attack, &[user.sk, mallory.sk]).unwrap();
    assert!(sim.coin_state(b.collateral.coin_id()).is_none());
    assert!(sim.coin_state(b.option.coin.coin_id()).is_some());
    let _ = b.underlying;
}

/// `loan.take` (the user lends; the borrower's coins fund the collateral) cannot be
/// guaranteed for the same reason, so it never holds and is refused before any prompt.
#[test]
fn loan_take_is_refused_while_the_borrowers_collateral_can_be_dropped() {
    let (lender, borrower) = (BlsPair::new(1), BlsPair::new(2));
    let mut sim = Simulator::new();
    // The lender's coin launches and asserts the option and pays the principal.
    let b = build_mint(
        &mut sim,
        &lender,
        &borrower,
        lender.puzzle_hash,
        borrower.puzzle_hash,
        1_000_000,
        OptionType::Xch { amount: 600_000 },
        1,
        Some((borrower.puzzle_hash, 500_000)),
        true,
    );
    let s = sim_of(&b.spends, &lender);
    assert!(matches!(
        mints(&s).as_slice(),
        [OptionEffect::Mint {
            creator_is_user: true,
            funded_by_user: false,
            owner_is_user: false,
            guaranteed: false,
            ..
        }]
    ));
    assert_eq!(
        verify(&s, json!({ "kind": "loan.take" })),
        Err(IntentError::Mismatch("kind"))
    );
}

// --- SA-H3: an exercise "covered" by a refund of the user's own money ---

/// PoC C: the user funds strike + 1,000,000 into a settlement coin that pays the strike
/// and refunds 1,000,000 to the user (asserted); the released collateral pays Mallory.
fn poc_c(link: bool) -> (Simulator, BlsPair, Vec<CoinSpend>, Coin, Bytes32) {
    let (user, mallory) = (BlsPair::new(1), BlsPair::new(2));
    let mut sim = Simulator::new();
    let (c_amt, strike) = (1_000_000u64, 10_000u64);
    let b = build_mint(
        &mut sim,
        &mallory,
        &mallory,
        mallory.puzzle_hash,
        user.puzzle_hash,
        c_amt,
        OptionType::Xch { amount: strike },
        1,
        None,
        true,
    );
    sim.spend_coins(b.spends.clone(), std::slice::from_ref(&mallory.sk))
        .unwrap();

    let mut ctx = SpendContext::new();
    let p2 = StandardLayer::new(user.pk);
    let refund = NotarizedPayment::new(
        Bytes32::new([0x43; 32]),
        vec![Payment::new(user.puzzle_hash, c_amt, Memos::None)],
    );
    let ptr = ctx.alloc(&refund).unwrap();
    let refund_id = Bytes32::from(sha256_parts(&[
        &SETTLEMENT_PAYMENT_HASH,
        &ctx.tree_hash(ptr).to_bytes(),
    ]));
    let funding = sim.new_coin(user.puzzle_hash, strike + c_amt);
    let tie = |c: Conditions, other: Bytes32| {
        if link {
            c.assert_concurrent_spend(other)
        } else {
            c
        }
    };
    b.option
        .exercise(
            &mut ctx,
            &p2,
            tie(Conditions::new(), funding.coin_id()).assert_puzzle_announcement(refund_id),
        )
        .unwrap();
    b.underlying
        .exercise_coin_spend(
            &mut ctx,
            b.collateral,
            b.option.info.inner_puzzle_hash().into(),
            b.option.coin.amount,
        )
        .unwrap();
    let released = Coin::new(b.collateral.coin_id(), SETTLEMENT, c_amt);
    let claim = NotarizedPayment::new(
        Bytes32::new([0x42; 32]),
        vec![Payment::new(mallory.puzzle_hash, c_amt, Memos::None)],
    );
    let cs = SettlementLayer
        .construct_coin_spend(
            &mut ctx,
            released,
            SettlementPaymentsSolution::new(vec![claim]),
        )
        .unwrap();
    ctx.insert(cs);
    p2.spend(
        &mut ctx,
        funding,
        tie(Conditions::new(), b.option.coin.coin_id())
            .create_coin(SETTLEMENT, strike + c_amt, Memos::None)
            .assert_puzzle_announcement(refund_id),
    )
    .unwrap();
    let sc = Coin::new(funding.coin_id(), SETTLEMENT, strike + c_amt);
    let payment = b.underlying.requested_payment(&mut *ctx).unwrap();
    let cs = SettlementLayer
        .construct_coin_spend(
            &mut ctx,
            sc,
            SettlementPaymentsSolution::new(vec![payment, refund]),
        )
        .unwrap();
    ctx.insert(cs);
    let to_mallory = Coin::new(released.coin_id(), mallory.puzzle_hash, c_amt).coin_id();
    (sim, user, ctx.take(), released, to_mallory)
}

#[test]
fn poc_c_a_refund_of_the_users_own_money_does_not_cover_the_collateral() {
    for link in [false, true] {
        let (sim, user, spends, _, to_mallory) = poc_c(link);
        let own = owned(user.puzzle_hash);
        let report = verify_binding(&spends, &own, DEFAULT_MAX_COST).unwrap();
        // The old rule's numbers: every spend bound, bound receipts >= collateral.
        assert!(report.all_bound && report.received(AssetId::Xch) >= 1_000_000);
        assert_eq!(report.co_required, link);
        let cover = report.exercises[0];
        assert_eq!(
            (cover.collateral, cover.covered),
            (1_000_000, false),
            "link={link}"
        );
        assert!(!report.exercises_covered());
        // The handler refuses before any prompt.
        let chain = RefCell::new(sim.clone());
        let err = run(&chain, &user, spends.clone(), None).unwrap_err();
        assert!(reason(&err).contains("unbound_exercise"), "{err:?}");
        // What the audit showed: the chain takes it and Mallory gets the collateral.
        let mut sim = sim;
        sim.spend_coins(spends, &[user.sk]).unwrap();
        assert!(sim.coin_state(to_mallory).is_some());
    }
}

/// The exercise fixture with the claim asserted by both of the holder's spends but the
/// spends not linked: each could be included without the other, so it is refused.
#[test]
fn an_exercise_whose_spends_do_not_require_each_other_is_refused() {
    let mut sim = Simulator::new();
    let (alice, bob) = (BlsPair::new(1), BlsPair::new(2));
    let spec = MintSpec {
        creator: bob.puzzle_hash,
        owner: alice.puzzle_hash,
        ..MintSpec::simple(&bob)
    };
    let m = fx::minted(&mut sim, &bob, spec);
    let loose = fx::exercise_with(&mut sim, &alice, &m, true, false, true);
    let report = verify_binding(&loose, &owned(alice.puzzle_hash), DEFAULT_MAX_COST).unwrap();
    assert!(report.all_bound && !report.co_required && report.exercises[0].covered);
    assert!(!report.exercises_covered());
    let linked = fx::exercise(&mut sim, &alice, &m, true, true);
    let report = verify_binding(&linked, &owned(alice.puzzle_hash), DEFAULT_MAX_COST).unwrap();
    assert!(report.co_required && report.exercises_covered());
}

// --- SA-L1: an option singleton paying out XCH ---

#[test]
fn xch_an_option_singleton_pays_out_counts_as_xch_sent() {
    let (alice, mallory) = (BlsPair::new(1), BlsPair::new(2));
    let mut sim = Simulator::new();
    // A 1,000,001-mojo option (minted outside any wallet rule) held by Alice.
    let mut ctx = SpendContext::new();
    let parent = sim.new_coin(alice.puzzle_hash, 1_000_001);
    let launcher = OptionLauncher::with_amount(
        &mut ctx,
        parent.coin_id(),
        1_000_001,
        OptionLauncherInfo::new(
            alice.puzzle_hash,
            alice.puzzle_hash,
            EXPIRY,
            1,
            OptionType::Xch { amount: 1 },
        ),
        1_000_001,
    )
    .unwrap();
    let launcher = launcher.with_underlying(Bytes32::new([1; 32]));
    let (conds, option) = launcher.mint(&mut ctx).unwrap();
    StandardLayer::new(alice.pk)
        .spend(&mut ctx, parent, conds)
        .unwrap();
    sim.spend_coins(ctx.take(), std::slice::from_ref(&alice.sk))
        .unwrap();
    // Alice "moves the option to herself" while its even output pays Mallory.
    let mut ctx = SpendContext::new();
    option
        .spend_with(
            &mut ctx,
            &StandardLayer::new(alice.pk),
            Conditions::new()
                .create_coin(alice.puzzle_hash, 1, Memos::None)
                .create_coin(mallory.puzzle_hash, 1_000_000, Memos::None),
        )
        .unwrap();
    let spends = ctx.take();
    let s = sim_of(&spends, &alice);
    let xch = s.asset(AssetId::Xch).unwrap();
    assert_eq!(
        (xch.sent, xch.received, xch.net),
        (1_000_000, 0, -1_000_000)
    );
    assert_eq!(guaranteed_loss(&s).get(&AssetId::Xch), Some(&1_000_000));
    sim.spend_coins(spends, &[alice.sk]).unwrap();
}

// --- CR-M5: taking an offer that gives the user an option ---

#[test]
fn taking_an_offer_for_an_option_is_bound_to_receiving_it() {
    let mut sim = Simulator::new();
    let (alice, bob) = (BlsPair::new(1), BlsPair::new(2));
    let m = fx::minted(&mut sim, &alice, MintSpec::simple(&alice));
    // Alice offers the option: she moves it to the settlement puzzle.
    let offer = fx::transfer(&alice, &m, SETTLEMENT);
    let s = sim_of(&offer, &alice);
    assert!(matches!(
        s.options.as_slice(),
        [OptionEffect::Transfer {
            to_settlement: true,
            ..
        }]
    ));
    assert!(s.outputs[0].settlement);
    sim.spend_coins(offer, std::slice::from_ref(&alice.sk))
        .unwrap();
    let offered = m.option.child(SETTLEMENT, m.option.coin.amount);

    for assert in [true, false] {
        // Bob takes it: the settlement-held option pays Bob, Bob pays Alice 500.
        let mut ctx = SpendContext::new();
        let np = NotarizedPayment::new(
            Bytes32::new([7; 32]),
            vec![Payment::new(bob.puzzle_hash, 1, Memos::None)],
        );
        let ptr = ctx.alloc(&np).unwrap();
        let id = Bytes32::from(sha256_parts(&[
            offered.coin.puzzle_hash.as_ref(),
            &ctx.tree_hash(ptr).to_bytes(),
        ]));
        let inner = SettlementLayer
            .construct_spend(&mut ctx, SettlementPaymentsSolution::new(vec![np]))
            .unwrap();
        offered.spend(&mut ctx, inner).unwrap();
        let coin = sim.new_coin(bob.puzzle_hash, 500);
        let conds = Conditions::new().create_coin(alice.puzzle_hash, 500, Memos::None);
        let conds = if assert {
            conds.assert_puzzle_announcement(id)
        } else {
            conds
        };
        StandardLayer::new(bob.pk)
            .spend(&mut ctx, coin, conds)
            .unwrap();
        let spends = ctx.take();
        let report = verify_binding(&spends, &owned(bob.puzzle_hash), DEFAULT_MAX_COST).unwrap();
        assert_eq!(report.all_bound, assert);
        if assert {
            assert_eq!(report.received(AssetId::Option(m.launcher_id)), 1);
            let s = sim_of(&spends, &bob);
            assert!(matches!(
                s.options.as_slice(),
                [OptionEffect::Transfer {
                    to_user: true,
                    from_user: false,
                    ..
                }]
            ));
            sim.spend_coins(spends, std::slice::from_ref(&bob.sk))
                .unwrap();
        }
    }
}

// --- an option minted and moved on in one bundle ---

#[test]
fn a_mint_whose_option_moves_on_in_the_same_bundle_is_not_a_lock_of_the_users() {
    let mut sim = Simulator::new();
    let (alice, bob) = (BlsPair::new(1), BlsPair::new(2));
    let mut ctx = SpendContext::new();
    let p2 = StandardLayer::new(alice.pk);
    let parent = sim.new_coin(alice.puzzle_hash, 1);
    let launcher = OptionLauncher::new(
        &mut ctx,
        parent.coin_id(),
        OptionLauncherInfo::new(
            alice.puzzle_hash,
            alice.puzzle_hash,
            EXPIRY,
            1000,
            OptionType::Xch { amount: 300 },
        ),
        1,
    )
    .unwrap();
    let p2_option = launcher.p2_puzzle_hash();
    let funding = sim.new_coin(alice.puzzle_hash, 1000);
    p2.spend(
        &mut ctx,
        funding,
        Conditions::new()
            .create_coin(p2_option, 1000, Memos::None)
            .assert_concurrent_spend(parent.coin_id()),
    )
    .unwrap();
    let launcher =
        launcher.with_underlying(Coin::new(funding.coin_id(), p2_option, 1000).coin_id());
    // The eve is Alice's own puzzle (as Sage mints); it moves the option to Alice, and the
    // child then goes to Bob in the same bundle.
    let (conds, eve) = launcher.mint_eve(&mut ctx, alice.puzzle_hash).unwrap();
    p2.spend(
        &mut ctx,
        parent,
        conds.assert_concurrent_spend(funding.coin_id()),
    )
    .unwrap();
    let child = eve
        .transfer(&mut ctx, &p2, alice.puzzle_hash, Conditions::new())
        .unwrap();
    let _to_bob = child
        .transfer(&mut ctx, &p2, bob.puzzle_hash, Conditions::new())
        .unwrap();
    let spends = ctx.take();
    let s = sim_of(&spends, &alice);
    assert!(s.unknown_puzzles.is_empty());
    assert!(guaranteed(&s), "{:?}", s.options);
    assert!(s.options.iter().any(|e| matches!(
        e,
        OptionEffect::Transfer {
            from_user: true,
            ..
        }
    )));
    // The collateral is not exempt: the option does not stay with Alice.
    let marked: Vec<_> = s.outputs.iter().filter(|o| o.option.is_some()).collect();
    assert!(!marked.is_empty());
    assert!(
        marked
            .iter()
            .all(|o| !o.option.unwrap().user_holds_option && o.recipient.is_none())
    );
    let declared = json!({ "recipients": [{
        "assetId": format!("option:{}", hex::encode(child.info.launcher_id)),
        "puzzleHash": hex::encode(bob.puzzle_hash),
        "amount": 1,
    }] });
    assert_eq!(
        verify(&s, declared),
        Err(IntentError::Mismatch("unnamed_recipient"))
    );
    assert!(
        verify(&s, json!({ "kind": "option.mint" }))
            .unwrap()
            .kind_verified
    );
    sim.spend_coins(spends, &[alice.sk]).unwrap();
}

// --- handler paths not covered elsewhere ---

#[test]
fn a_clawback_is_verified_returns_the_collateral_and_is_not_a_loss() {
    for collateral in [Collateral::Xch, Collateral::Cat] {
        let mut sim = Simulator::new();
        let alice = BlsPair::new(1);
        let spec = MintSpec {
            collateral,
            ..MintSpec::simple(&alice)
        };
        let m = fx::minted(&mut sim, &alice, spec);
        sim.set_next_timestamp(100).unwrap();
        let chain = RefCell::new(sim);
        let p = run(
            &chain,
            &alice,
            fx::clawback(&alice, &m),
            Some(json!({ "kind": "option.clawback", "recipients": [] })),
        )
        .unwrap();
        assert_eq!(p["intent"]["kind_verified"], true);
        assert_eq!(p["summary"]["options"][0]["action"], "clawback");
        let asset = p["summary"]["assets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["asset"]["type"] != "xch" || collateral == Collateral::Xch)
            .unwrap()
            .clone();
        assert_eq!(asset["net"], 1000, "{collateral:?}");
    }
}

#[test]
fn an_option_asset_id_parses_in_recipients_and_net_change() {
    let id = Bytes32::new([9; 32]);
    let intent = Intent::from_json(&json!({
        "recipients": [{ "assetId": format!("option:{}", hex::encode(id)), "puzzleHash": hex::encode([1u8; 32]), "amount": 1 }],
        "netChange": [{ "assetId": format!("option:0x{}", hex::encode(id)), "amount": "-1" }],
    }))
    .unwrap();
    assert_eq!(intent.recipients.unwrap()[0].asset, AssetId::Option(id));
    assert_eq!(intent.net.unwrap()[0].asset, AssetId::Option(id));
    for bad in ["option:", "option:12", "option:zz"] {
        assert!(
            Intent::from_json(&json!({ "netChange": [{ "assetId": bad, "amount": 1 }] })).is_err()
        );
    }
}

/// SA-L3: revocable collateral and revocable strikes are not shown (the spends stay
/// unknown and are refused unless the user allows unknown contracts).
#[test]
fn revocable_cat_strikes_are_not_shown() {
    let mut sim = Simulator::new();
    let alice = BlsPair::new(1);
    let spec = MintSpec {
        strike: OptionType::RevocableCat {
            asset_id: Bytes32::new([5; 32]),
            hidden_puzzle_hash: Bytes32::new([6; 32]),
            amount: 40,
        },
        ..MintSpec::simple(&alice)
    };
    let m = fx::mint(&mut sim, &alice, spec);
    let s = sim_of(&m.spends, &alice);
    assert!(s.options.is_empty());
    assert_eq!(s.unknown_puzzles.len(), 2, "launcher and eve");
}

// --- the exercise rule against the chain ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Whatever a dApp builds around an exercise (the strike settlement over-funded and
    /// "refunded", the released collateral split between the holder and a stranger, the
    /// claims asserted or not, the holder's spends linked or not), the wallet accepts it
    /// only if the chain, running it, leaves the holder at least the collateral less the
    /// strike.
    #[test]
    fn an_accepted_exercise_pays_the_holder_the_collateral_on_chain(
        collateral in 1u64..1_000_000,
        strike in 1u64..1_000_000,
        refund in 0u64..1_000_000,
        to_holder_part in 0u64..=4,
        assert_claim in any::<bool>(),
        assert_refund in any::<bool>(),
        link in any::<bool>(),
    ) {
        let (alice, bob, mallory) = (BlsPair::new(1), BlsPair::new(2), BlsPair::new(9));
        let mut sim = Simulator::new();
        let spec = MintSpec {
            creator: bob.puzzle_hash,
            owner: alice.puzzle_hash,
            amount: collateral,
            strike: OptionType::Xch { amount: strike },
            ..MintSpec::simple(&bob)
        };
        let m = fx::minted(&mut sim, &bob, spec);
        let fx::Locked::Xch(locked) = m.locked else { unreachable!() };
        // The released collateral: part to Alice, the rest to Mallory.
        let to_alice = if to_holder_part == 4 { collateral } else { collateral / 4 * to_holder_part };
        let mut ctx = SpendContext::new();
        let p2 = StandardLayer::new(alice.pk);
        // (A settlement payment of 0 does not run: only non-zero parts are paid.)
        let alice_claim = NotarizedPayment::new(
            Bytes32::new([0x42; 32]),
            vec![Payment::new(alice.puzzle_hash, to_alice, Memos::None)],
        );
        let assert_claim = assert_claim && to_alice > 0;
        let mut claims = Vec::new();
        if to_alice > 0 {
            claims.push(alice_claim.clone());
        }
        if collateral > to_alice {
            claims.push(NotarizedPayment::new(
                Bytes32::new([0x44; 32]),
                vec![Payment::new(mallory.puzzle_hash, collateral - to_alice, Memos::None)],
            ));
        }
        let refund_np = NotarizedPayment::new(
            Bytes32::new([0x43; 32]),
            vec![Payment::new(alice.puzzle_hash, refund, Memos::None)],
        );
        let id_of = |ctx: &mut SpendContext, np: &NotarizedPayment| {
            let ptr = ctx.alloc(np).unwrap();
            Bytes32::from(sha256_parts(&[&SETTLEMENT_PAYMENT_HASH, &ctx.tree_hash(ptr).to_bytes()]))
        };
        let claim_id = id_of(&mut ctx, &alice_claim);
        let refund_id = id_of(&mut ctx, &refund_np);
        let funding = sim.new_coin(alice.puzzle_hash, strike + refund);
        let asserts = |c: Conditions| {
            let c = if assert_claim { c.assert_puzzle_announcement(claim_id) } else { c };
            if assert_refund && refund > 0 { c.assert_puzzle_announcement(refund_id) } else { c }
        };
        let melt = if link { Conditions::new().assert_concurrent_spend(funding.coin_id()) } else { Conditions::new() };
        m.option.exercise(&mut ctx, &p2, asserts(melt)).unwrap();
        m.underlying
            .exercise_coin_spend(&mut ctx, locked, m.option.info.inner_puzzle_hash().into(), m.option.coin.amount)
            .unwrap();
        let released = Coin::new(locked.coin_id(), SETTLEMENT, collateral);
        let cs = SettlementLayer
            .construct_coin_spend(&mut ctx, released, SettlementPaymentsSolution::new(claims))
            .unwrap();
        ctx.insert(cs);
        let fund = if link { Conditions::new().assert_concurrent_spend(m.option.coin.coin_id()) } else { Conditions::new() };
        p2.spend(&mut ctx, funding, asserts(fund.create_coin(SETTLEMENT, strike + refund, Memos::None))).unwrap();
        let sc = Coin::new(funding.coin_id(), SETTLEMENT, strike + refund);
        let mut pays = vec![m.underlying.requested_payment(&mut *ctx).unwrap()];
        if refund > 0 {
            pays.push(refund_np);
        }
        let cs = SettlementLayer
            .construct_coin_spend(&mut ctx, sc, SettlementPaymentsSolution::new(pays))
            .unwrap();
        ctx.insert(cs);
        let spends = ctx.take();

        let own = Ownership { p2_puzzle_hashes: [alice.puzzle_hash].into_iter().collect() };
        let report = verify_binding(&spends, &own, DEFAULT_MAX_COST).unwrap();
        let before: u64 = sim.unspent_coins(alice.puzzle_hash, false).iter().map(|c| c.amount).sum();
        sim.spend_coins(spends, std::slice::from_ref(&alice.sk)).unwrap();
        let after: u64 = sim.unspent_coins(alice.puzzle_hash, false).iter().map(|c| c.amount).sum();
        let gain = i128::from(after) - i128::from(before);
        if report.exercises_covered() {
            prop_assert!(gain >= i128::from(collateral) - i128::from(strike), "accepted, gain {gain}");
        }
        // The honest shape is accepted.
        if link && assert_claim && to_alice == collateral && (refund == 0 || assert_refund) {
            prop_assert!(report.exercises_covered(), "{report:?}");
        }
    }
}

/// A refund laundered through a named payment: the user pays Mallory strike + collateral
/// (shown as a payment), Mallory's coin funds a settlement coin that pays the strike and
/// "refunds" the collateral's worth to the user, and the released collateral goes to
/// Mallory. The user ends down the strike with no collateral: refused.
#[test]
fn a_refund_laundered_through_a_payment_to_a_stranger_does_not_cover_the_collateral() {
    let (alice, bob, mallory) = (BlsPair::new(1), BlsPair::new(2), BlsPair::new(9));
    let mut sim = Simulator::new();
    let (c_amt, strike) = (1_000_000u64, 10_000u64);
    let spec = MintSpec {
        creator: bob.puzzle_hash,
        owner: alice.puzzle_hash,
        amount: c_amt,
        strike: OptionType::Xch { amount: strike },
        ..MintSpec::simple(&bob)
    };
    let m = fx::minted(&mut sim, &bob, spec);
    let fx::Locked::Xch(locked) = m.locked else {
        unreachable!()
    };
    let mut ctx = SpendContext::new();
    let p2 = StandardLayer::new(alice.pk);
    let refund = NotarizedPayment::new(
        Bytes32::new([0x43; 32]),
        vec![Payment::new(alice.puzzle_hash, c_amt, Memos::None)],
    );
    let ptr = ctx.alloc(&refund).unwrap();
    let refund_id = Bytes32::from(sha256_parts(&[
        &SETTLEMENT_PAYMENT_HASH,
        &ctx.tree_hash(ptr).to_bytes(),
    ]));
    let funding = sim.new_coin(alice.puzzle_hash, strike + c_amt);
    m.option
        .exercise(
            &mut ctx,
            &p2,
            Conditions::new()
                .assert_concurrent_spend(funding.coin_id())
                .assert_puzzle_announcement(refund_id),
        )
        .unwrap();
    m.underlying
        .exercise_coin_spend(
            &mut ctx,
            locked,
            m.option.info.inner_puzzle_hash().into(),
            m.option.coin.amount,
        )
        .unwrap();
    let released = Coin::new(locked.coin_id(), SETTLEMENT, c_amt);
    let claim = NotarizedPayment::new(
        Bytes32::new([0x42; 32]),
        vec![Payment::new(mallory.puzzle_hash, c_amt, Memos::None)],
    );
    let cs = SettlementLayer
        .construct_coin_spend(
            &mut ctx,
            released,
            SettlementPaymentsSolution::new(vec![claim]),
        )
        .unwrap();
    ctx.insert(cs);
    p2.spend(
        &mut ctx,
        funding,
        Conditions::new()
            .create_coin(mallory.puzzle_hash, strike + c_amt, Memos::None)
            .assert_concurrent_spend(m.option.coin.coin_id())
            .assert_puzzle_announcement(refund_id),
    )
    .unwrap();
    let relay = Coin::new(funding.coin_id(), mallory.puzzle_hash, strike + c_amt);
    StandardLayer::new(mallory.pk)
        .spend(
            &mut ctx,
            relay,
            Conditions::new().create_coin(SETTLEMENT, strike + c_amt, Memos::None),
        )
        .unwrap();
    let sc = Coin::new(relay.coin_id(), SETTLEMENT, strike + c_amt);
    let payment = m.underlying.requested_payment(&mut *ctx).unwrap();
    let cs = SettlementLayer
        .construct_coin_spend(
            &mut ctx,
            sc,
            SettlementPaymentsSolution::new(vec![payment, refund]),
        )
        .unwrap();
    ctx.insert(cs);
    let spends = ctx.take();
    let report = verify_binding(&spends, &owned(alice.puzzle_hash), DEFAULT_MAX_COST).unwrap();
    assert!(report.co_required && report.received(AssetId::Xch) == u128::from(c_amt));
    assert!(!report.exercises[0].covered, "{report:?}");
    sim.spend_coins(spends, &[alice.sk, mallory.sk]).unwrap();
}

/// Collateral the user claws back from an expired option is not new money: it must not
/// make up for the collateral of an exercise that goes to Mallory in the same bundle.
#[test]
fn a_clawback_in_the_same_bundle_does_not_cover_an_exercise() {
    let (alice, bob, mallory) = (BlsPair::new(1), BlsPair::new(2), BlsPair::new(9));
    let mut sim = Simulator::new();
    // Alice's own expired option (expiry 10) and Bob's live option that Alice holds.
    let mine = fx::minted(&mut sim, &alice, MintSpec::simple(&alice));
    let spec = MintSpec {
        creator: bob.puzzle_hash,
        owner: alice.puzzle_hash,
        seconds: EXPIRY,
        ..MintSpec::simple(&bob)
    };
    let held = fx::minted(&mut sim, &bob, spec);
    sim.set_next_timestamp(100).unwrap();
    let (fx::Locked::Xch(expired), fx::Locked::Xch(live)) = (mine.locked, held.locked) else {
        unreachable!()
    };
    let mut ctx = SpendContext::new();
    let p2 = StandardLayer::new(alice.pk);
    held.option
        .exercise(
            &mut ctx,
            &p2,
            Conditions::new().assert_concurrent_spend(expired.coin_id()),
        )
        .unwrap();
    held.underlying
        .exercise_coin_spend(
            &mut ctx,
            live,
            held.option.info.inner_puzzle_hash().into(),
            held.option.coin.amount,
        )
        .unwrap();
    // The released collateral pays the strike to Bob and the rest to Mallory.
    let released = Coin::new(live.coin_id(), SETTLEMENT, 1000);
    let strike_np = held.underlying.requested_payment(&mut *ctx).unwrap();
    let rest = NotarizedPayment::new(
        Bytes32::new([0x42; 32]),
        vec![Payment::new(mallory.puzzle_hash, 700, Memos::None)],
    );
    let cs = SettlementLayer
        .construct_coin_spend(
            &mut ctx,
            released,
            SettlementPaymentsSolution::new(vec![strike_np, rest]),
        )
        .unwrap();
    ctx.insert(cs);
    let inner = chia_sdk_driver::SpendWithConditions::spend_with_conditions(
        &p2,
        &mut ctx,
        Conditions::new()
            .create_coin(alice.puzzle_hash, 1000, Memos::None)
            .assert_concurrent_spend(held.option.coin.coin_id()),
    )
    .unwrap();
    mine.underlying
        .clawback_coin_spend(&mut ctx, expired, inner)
        .unwrap();
    let spends = ctx.take();
    let report = verify_binding(&spends, &owned(alice.puzzle_hash), DEFAULT_MAX_COST).unwrap();
    assert!(report.co_required);
    assert_eq!(report.exercises[0].collateral, 1000);
    assert!(!report.exercises[0].covered, "{report:?}");
    sim.spend_coins(spends, &[alice.sk]).unwrap();
}
