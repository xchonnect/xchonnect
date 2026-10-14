//! Regression tests for the re-audit of the rc.5 option fixes (TASK-78): findings N1-N5,
//! each proof of concept turned into a test that the chain accepts the attack bundle while
//! the wallet refuses it (or reports it as what it is), and where the rule changed, that the
//! honest shape built as spec 11.2 asks is still accepted.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use crate::binding::{Linking, verify_binding, verify_binding_as};
use crate::handlers::SignedCoins;
use crate::intent::{Intent, IntentError};
use crate::option::collateral_lost_to_expiry;
use crate::option_fixture::{self as fx, Collateral, MintSpec, tie};
use crate::option_sage_tests::{Mode, reason, run_as, run_released as run, signature_of};
use crate::simulate::{AssetId, DEFAULT_MAX_COST, Summary, simulate};
use crate::swap_fixture::owned;
use chia_protocol::{Bytes32, Coin, CoinSpend};
use chia_puzzle_types::Memos;
use chia_puzzle_types::offer::{NotarizedPayment, Payment, SettlementPaymentsSolution};
use chia_puzzles::SETTLEMENT_PAYMENT_HASH;
use chia_sdk_driver::{
    Layer, OptionType, SettlementLayer, SingletonInfo, SpendContext, SpendWithConditions,
    StandardLayer,
};
use chia_sdk_test::{BlsPair, Simulator};
use chia_sdk_types::Conditions;
use serde_json::json;
use std::cell::RefCell;
use xchonnect_core::crypto::sha256_parts;

const SETTLEMENT: Bytes32 = Bytes32::new(SETTLEMENT_PAYMENT_HASH);
/// An expiry well after both the simulator's clock and [`NOW`].
const LATER: u64 = 1_900_000_000;
/// The wallet's clock in the intent checks.
const NOW: u64 = 1_790_000_000;

fn spec(creator: Bytes32, owner: Bytes32, amount: u64, strike: u64) -> MintSpec {
    MintSpec {
        creator,
        owner,
        amount,
        strike: OptionType::Xch { amount: strike },
        seconds: LATER,
        collateral: Collateral::Xch,
        fee: 0,
    }
}

/// The user's spends that exercise `m`: the melt (with `extra` conditions) and the release
/// of the collateral. Returns the released settlement coin.
fn melt(ctx: &mut SpendContext, user: &BlsPair, m: &fx::Minted, extra: Conditions) -> Coin {
    m.option
        .exercise(ctx, &StandardLayer::new(user.pk), extra)
        .unwrap();
    let fx::Locked::Xch(coin) = m.locked else {
        panic!("XCH collateral only")
    };
    m.underlying
        .exercise_coin_spend(
            ctx,
            coin,
            m.option.info.inner_puzzle_hash().into(),
            m.option.coin.amount,
        )
        .unwrap();
    Coin::new(coin.coin_id(), SETTLEMENT, coin.amount)
}

fn settle(ctx: &mut SpendContext, coin: Coin, payments: Vec<NotarizedPayment>) {
    let cs = SettlementLayer
        .construct_coin_spend(ctx, coin, SettlementPaymentsSolution::new(payments))
        .unwrap();
    ctx.insert(cs);
}

fn pay(to: Bytes32, amount: u64, nonce: u8) -> NotarizedPayment {
    NotarizedPayment::new(
        Bytes32::new([nonce; 32]),
        vec![Payment::new(to, amount, Memos::None)],
    )
}

fn announcement_id(ctx: &mut SpendContext, puzzle_hash: Bytes32, np: &NotarizedPayment) -> Bytes32 {
    let ptr = ctx.alloc(np).unwrap();
    Bytes32::from(sha256_parts(&[
        puzzle_hash.as_ref(),
        &ctx.tree_hash(ptr).to_bytes(),
    ]))
}

/// Mallory's coin funds a settlement coin of `amount` that makes `payments`.
fn mallory_pays(
    sim: &mut Simulator,
    ctx: &mut SpendContext,
    mallory: &BlsPair,
    amount: u64,
    payments: Vec<NotarizedPayment>,
) -> Coin {
    let coin = sim.new_coin(mallory.puzzle_hash, amount);
    StandardLayer::new(mallory.pk)
        .spend(
            ctx,
            coin,
            Conditions::new().create_coin(SETTLEMENT, amount, Memos::None),
        )
        .unwrap();
    settle(ctx, Coin::new(coin.coin_id(), SETTLEMENT, amount), payments);
    coin
}

fn sim_of(spends: &[CoinSpend], who: &BlsPair) -> Summary {
    simulate(spends, &owned(who.puzzle_hash), DEFAULT_MAX_COST).unwrap()
}

// --- N1: the strike of one exercise padding the cover of another ---

/// PoC S: the user holds A (Carol's, collateral 1,000,000, strike 1,000) and an option B
/// that Mallory airdropped (collateral 1, strike 1,000,000 to Mallory). The user signs both
/// melts (linked as spec 11.2 asks, so only the cover rule stands in the way); Mallory pays
/// both strikes (B's goes back to her) and claims both collaterals. The old rule added both
/// strikes back and called it covered. Now each option counts at most its own collateral.
#[test]
fn n1_an_option_whose_strike_exceeds_its_collateral_does_not_cover_another() {
    let (user, mallory, carol) = (BlsPair::new(1), BlsPair::new(2), BlsPair::new(3));
    let mut sim = Simulator::new();
    let a = fx::minted(
        &mut sim,
        &carol,
        spec(carol.puzzle_hash, user.puzzle_hash, 1_000_000, 1_000),
    );
    let b = fx::minted(
        &mut sim,
        &mallory,
        spec(mallory.puzzle_hash, user.puzzle_hash, 1, 1_000_000),
    );
    let (ida, idb) = (a.option.coin.coin_id(), b.option.coin.coin_id());
    let mut ctx = SpendContext::new();
    let ra = melt(&mut ctx, &user, &a, tie(Conditions::new(), ida, idb));
    let rb = melt(&mut ctx, &user, &b, tie(Conditions::new(), idb, ida));
    settle(
        &mut ctx,
        ra,
        vec![pay(mallory.puzzle_hash, ra.amount, 0x42)],
    );
    settle(
        &mut ctx,
        rb,
        vec![pay(mallory.puzzle_hash, rb.amount, 0x43)],
    );
    let pa = a.underlying.requested_payment(&mut *ctx).unwrap();
    let pb = b.underlying.requested_payment(&mut *ctx).unwrap();
    mallory_pays(&mut sim, &mut ctx, &mallory, 1_001_000, vec![pa, pb]);
    let spends = ctx.take();

    // Signatures released: the melts assert nothing, so they are not co-required.
    let report = verify_binding(&spends, &owned(user.puzzle_hash), DEFAULT_MAX_COST).unwrap();
    assert!(
        !report.co_required && !report.exercises_covered(),
        "{report:?}"
    );
    // Sealed, the melts are tied together; the cover still fails.
    let own = owned(user.puzzle_hash);
    let report = verify_binding_as(&spends, &own, DEFAULT_MAX_COST, Linking::Sealed).unwrap();
    assert!(report.co_required, "{report:?}");
    let cover = report.exercises[0];
    // Nothing reaches the user; A's strike credits 1,000, B's at most its collateral, 1.
    assert_eq!(
        (cover.asset, cover.collateral, cover.received, cover.covered),
        (AssetId::Xch, 1_000_001, 1_001, false)
    );
    // The handlers refuse it (4001 `unbound_exercise`) on this check.
    assert!(!report.exercises_covered());
    // What the re-audit showed: the chain takes it and Mallory gets A's collateral.
    sim.spend_coins(spends, &[user.sk, mallory.sk]).unwrap();
    let stolen = Coin::new(ra.coin_id(), mallory.puzzle_hash, ra.amount);
    assert!(sim.coin_state(stolen.coin_id()).is_some());
}

// --- N3: released collateral becoming the user's "fee" ---

/// PoC F: the melt reserves a fee of 1,000,000, the released collateral is spent with no
/// payment (so it becomes the fee) and Mallory pays the strike. The old rule counted the
/// reserved fee as the user's own spending. Now only the XCH the user's own spends put into
/// the bundle (here the option's 1 mojo) can pay the user's fee.
#[test]
fn n3_collateral_that_becomes_the_fee_is_not_received() {
    let (user, mallory) = (BlsPair::new(1), BlsPair::new(2));
    let mut sim = Simulator::new();
    let a = fx::minted(
        &mut sim,
        &mallory,
        spec(mallory.puzzle_hash, user.puzzle_hash, 1_000_000, 1_000),
    );
    let mut ctx = SpendContext::new();
    let ra = melt(
        &mut ctx,
        &user,
        &a,
        Conditions::new().reserve_fee(1_000_000),
    );
    settle(&mut ctx, ra, vec![]);
    let pa = a.underlying.requested_payment(&mut *ctx).unwrap();
    mallory_pays(&mut sim, &mut ctx, &mallory, 1_000, vec![pa]);
    let spends = ctx.take();

    let report = verify_binding(&spends, &owned(user.puzzle_hash), DEFAULT_MAX_COST).unwrap();
    let cover = report.exercises[0];
    // Strike credit 1,000, fee credit 1 (the melted option's mojo).
    assert_eq!(
        (cover.received, cover.covered),
        (1_001, false),
        "{report:?}"
    );
    // The handlers refuse it (4001 `unbound_exercise`) on this check.
    assert!(!report.exercises_covered());
    sim.spend_coins(spends, &[user.sk, mallory.sk]).unwrap();
}

// --- N2: ASSERT_CONCURRENT_SPEND binds a coin, not a spend ---

/// The user's request R: coin `k` (1,000,000) goes to the settlement puzzle for Mallory,
/// coin `j` asserts Mallory's payment of 2,000,000 to the user. `link`: how `k` requires
/// `j` (and back).
fn sub_request(
    sim: &mut Simulator,
    user: &BlsPair,
    mallory: &BlsPair,
    link: &dyn Fn(Conditions, Bytes32, Bytes32) -> Conditions,
) -> (Vec<CoinSpend>, Coin, Coin) {
    let k = sim.new_coin(user.puzzle_hash, 1_000_000);
    let j = sim.new_coin(user.puzzle_hash, 1);
    let mut ctx = SpendContext::new();
    let p2 = StandardLayer::new(user.pk);
    let price = pay(user.puzzle_hash, 2_000_000, 0x55);
    let price_id = announcement_id(&mut ctx, SETTLEMENT, &price);
    p2.spend(
        &mut ctx,
        k,
        link(Conditions::new(), k.coin_id(), j.coin_id()).create_coin(
            SETTLEMENT,
            1_000_000,
            Memos::None,
        ),
    )
    .unwrap();
    p2.spend(
        &mut ctx,
        j,
        link(Conditions::new(), j.coin_id(), k.coin_id())
            .create_coin(user.puzzle_hash, 1, Memos::None)
            .assert_puzzle_announcement(price_id),
    )
    .unwrap();
    mallory_pays(sim, &mut ctx, mallory, 2_000_000, vec![price]);
    (ctx.take(), k, j)
}

/// The attack: the user's wallet later spends `j` on its own (a send to itself); Mallory
/// attaches R's byte-identical spend of `k` and claims its 1,000,000, paying nothing.
fn sub_attack(
    sim: &mut Simulator,
    user: &BlsPair,
    mallory: &BlsPair,
    r: &[CoinSpend],
    k: Coin,
    j: Coin,
) -> bool {
    let mut ctx = SpendContext::new();
    StandardLayer::new(user.pk)
        .spend(
            &mut ctx,
            j,
            Conditions::new().create_coin(user.puzzle_hash, 1, Memos::None),
        )
        .unwrap();
    let released = Coin::new(k.coin_id(), SETTLEMENT, 1_000_000);
    settle(
        &mut ctx,
        released,
        vec![pay(mallory.puzzle_hash, 1_000_000, 0x66)],
    );
    let mut attack = ctx.take();
    attack.push(r.iter().find(|cs| cs.coin == k).unwrap().clone());
    sim.spend_coins(attack, std::slice::from_ref(&user.sk))
        .is_ok()
}

/// PoC Sub: `k` requires `j` only through a link (ASSERT_CONCURRENT_SPEND, or a coin
/// announcement `j` makes); only `j` asserts the payment. With the signatures released
/// neither link counts (re-audit N2, final audit F1): the partial request is refused, and
/// with the concurrent-spend link the attack works on chain. Built by the wallet and
/// broadcast with no signature leaving it, the user's spends are included together, so
/// both links count; the attack then needs the signature of one of the bundle's spends on
/// its own, which the wallet never makes again (a different spend of `j` is signed as
/// usual), and a coin with a signature outside the wallet makes the request fall back to
/// the strict rule.
#[test]
fn n2_assert_concurrent_spend_does_not_bind_a_partial_request() {
    let (user, mallory) = (BlsPair::new(1), BlsPair::new(2));
    let own = owned(user.puzzle_hash);
    let concurrent = |c: Conditions, _me: Bytes32, other: Bytes32| c.assert_concurrent_spend(other);
    for (name, link) in [
        (
            "concurrent",
            &concurrent as &dyn Fn(Conditions, Bytes32, Bytes32) -> Conditions,
        ),
        ("announcement", &tie),
    ] {
        let mut sim = Simulator::new();
        let (r, k, j) = sub_request(&mut sim, &user, &mallory, link);
        let report = verify_binding(&r, &own, DEFAULT_MAX_COST).unwrap();
        assert!(!report.all_bound, "{name}: {report:?}");
        assert_eq!(report.unbound_user_spends.len(), 1, "{name}");
        if name == "concurrent" {
            assert!(
                sub_attack(&mut sim.clone(), &user, &mallory, &r, k, j),
                "the attack is real"
            );
        }
        let report = verify_binding_as(&r, &own, DEFAULT_MAX_COST, Linking::Sealed).unwrap();
        assert!(report.all_bound, "{name}: {report:?}");
        assert_eq!(report.received(AssetId::Xch), 2_000_000, "{name}");

        // Through the handlers, completing Mallory's side.
        let other = Some(signature_of(&r, &mallory.sk));
        let chain = RefCell::new(sim.clone());
        let released = Mode {
            released: true,
            other: other.clone(),
            ..Mode::default()
        };
        let e = run_as(&chain, &user, r.clone(), None, &released).unwrap_err();
        assert!(reason(&e).contains("unbound_partial"), "{name}: {e:?}");
        let mut seen = SignedCoins::default();
        seen.released.insert(j.coin_id());
        let exposed = Mode {
            signed: seen,
            other: other.clone(),
            ..Mode::default()
        };
        let e = run_as(&chain, &user, r.clone(), None, &exposed).unwrap_err();
        assert!(reason(&e).contains("unbound_partial"), "{name}: {e:?}");
        let sealed = Mode {
            other,
            ..Mode::default()
        };
        let before = RefCell::new(sim.clone());
        let p = run_as(&chain, &user, r.clone(), None, &sealed).unwrap();
        assert_eq!(p["binding"]["linking"], "sealed", "{name}");
        // The bundle's signatures are never made again: the same bundle is refused, a
        // different spend of one of its coins is not (spec 11.2).
        let kept = sealed.kept();
        let again = Mode {
            signed: kept.clone(),
            other: sealed.other.clone(),
            ..Mode::default()
        };
        let e = run_as(&before, &user, r.clone(), None, &again).unwrap_err();
        assert!(reason(&e).contains("sealed_signature"), "{name}: {e:?}");
        let mut ctx = SpendContext::new();
        StandardLayer::new(user.pk)
            .spend(
                &mut ctx,
                j,
                Conditions::new().create_coin(user.puzzle_hash, 1, Memos::None),
            )
            .unwrap();
        let lone = Mode {
            signed: kept,
            ..Mode::sealed()
        };
        let p = run_as(&RefCell::new(sim), &user, ctx.take(), None, &lone).unwrap();
        assert_eq!(p["linking"], "direct", "{name}");
    }
}

/// PoC SubX: an exercise whose melt requires the strike coin `k` only by
/// ASSERT_CONCURRENT_SPEND. The user's spends no longer count as included together, so the
/// exercise is refused; with announcement links it is accepted and the attack (R's melt with
/// a later lone spend of `k`) is invalid on chain.
#[test]
fn n2_assert_concurrent_spend_does_not_tie_an_exercise() {
    let (user, mallory, carol) = (BlsPair::new(1), BlsPair::new(2), BlsPair::new(3));
    let own = owned(user.puzzle_hash);
    for linked in [false, true] {
        let mut sim = Simulator::new();
        let a = fx::minted(
            &mut sim,
            &carol,
            spec(carol.puzzle_hash, user.puzzle_hash, 1_000_000, 1_000),
        );
        let k = sim.new_coin(user.puzzle_hash, 1_000);
        let ida = a.option.coin.coin_id();
        let link = |c: Conditions, me: Bytes32, other: Bytes32| {
            if linked {
                tie(c, me, other)
            } else {
                c.assert_concurrent_spend(other)
            }
        };
        let mut ctx = SpendContext::new();
        let claim = pay(user.puzzle_hash, 1_000_000, 0x42);
        let claim_id = announcement_id(&mut ctx, SETTLEMENT, &claim);
        let ra = melt(
            &mut ctx,
            &user,
            &a,
            link(Conditions::new(), ida, k.coin_id()),
        );
        settle(&mut ctx, ra, vec![claim]);
        StandardLayer::new(user.pk)
            .spend(
                &mut ctx,
                k,
                link(Conditions::new(), k.coin_id(), ida)
                    .create_coin(SETTLEMENT, 1_000, Memos::None)
                    .assert_puzzle_announcement(claim_id),
            )
            .unwrap();
        let pa = a.underlying.requested_payment(&mut *ctx).unwrap();
        settle(
            &mut ctx,
            Coin::new(k.coin_id(), SETTLEMENT, 1_000),
            vec![pa],
        );
        let request = ctx.take();
        // Signatures released: the melt asserts nothing, so neither link ties it (re-audit
        // N2, final audit F1).
        let report = verify_binding(&request, &own, DEFAULT_MAX_COST).unwrap();
        assert!(
            !report.co_required && !report.exercises_covered(),
            "{report:?}"
        );
        let chain = RefCell::new(sim.clone());
        let e = run(&chain, &user, request.clone(), None).unwrap_err();
        assert!(reason(&e).contains("unbound_exercise"), "{e:?}");
        // Built and broadcast by the wallet, signatures kept: both links count.
        let report = verify_binding_as(&request, &own, DEFAULT_MAX_COST, Linking::Sealed).unwrap();
        assert!(
            report.co_required && report.exercises_covered(),
            "{report:?}"
        );
        run_as(&chain, &user, request.clone(), None, &Mode::sealed()).unwrap();

        // The attack: the user's wallet later spends `k` alone; Mallory attaches R's melt,
        // pays the strike herself and claims the collateral.
        let melt_spend = request
            .iter()
            .find(|cs| cs.coin == a.option.coin)
            .unwrap()
            .clone();
        let mut ctx = SpendContext::new();
        StandardLayer::new(user.pk)
            .spend(
                &mut ctx,
                k,
                Conditions::new().create_coin(user.puzzle_hash, 1_000, Memos::None),
            )
            .unwrap();
        let fx::Locked::Xch(locked) = a.locked else {
            unreachable!()
        };
        a.underlying
            .exercise_coin_spend(
                &mut ctx,
                locked,
                a.option.info.inner_puzzle_hash().into(),
                1,
            )
            .unwrap();
        settle(
            &mut ctx,
            ra,
            vec![pay(mallory.puzzle_hash, 1_000_000, 0x44)],
        );
        let pa = a.underlying.requested_payment(&mut *ctx).unwrap();
        mallory_pays(&mut sim, &mut ctx, &mallory, 1_000, vec![pa]);
        let mut attack = ctx.take();
        attack.push(melt_spend);
        let ok = sim.spend_coins(attack, &[user.sk.clone(), mallory.sk.clone()]);
        assert_eq!(ok.is_ok(), !linked, "linked={linked}: {ok:?}");
    }
}

// --- N4: a settlement-held option paying an even amount ---

/// PoC OptEven: an option offered through the settlement puzzle pays 2 mojos to the user
/// (plain XCH: only an odd output is the option) while the option itself returns to
/// Mallory. The bound payment is 2 mojos of XCH, not the option.
#[test]
fn n4_an_even_payment_of_a_settlement_held_option_is_xch() {
    let (user, mallory) = (BlsPair::new(1), BlsPair::new(2));
    let mut sim = Simulator::new();
    let m = fx::minted(
        &mut sim,
        &mallory,
        spec(mallory.puzzle_hash, mallory.puzzle_hash, 1_000, 300),
    );
    sim.spend_coins(
        fx::transfer(&mallory, &m, SETTLEMENT),
        std::slice::from_ref(&mallory.sk),
    )
    .unwrap();
    let offered = m.option.child(SETTLEMENT, m.option.coin.amount);
    let mut ctx = SpendContext::new();
    let to_user = pay(user.puzzle_hash, 2, 7);
    let back = pay(mallory.puzzle_hash, 1, 8);
    let id = announcement_id(&mut ctx, offered.coin.puzzle_hash, &to_user);
    let inner = SettlementLayer
        .construct_spend(
            &mut ctx,
            SettlementPaymentsSolution::new(vec![to_user, back]),
        )
        .unwrap();
    offered.spend(&mut ctx, inner).unwrap();
    let filler = sim.new_coin(mallory.puzzle_hash, 2);
    StandardLayer::new(mallory.pk)
        .spend(&mut ctx, filler, Conditions::new())
        .unwrap();
    let coin = sim.new_coin(user.puzzle_hash, 500);
    StandardLayer::new(user.pk)
        .spend(
            &mut ctx,
            coin,
            Conditions::new()
                .create_coin(mallory.puzzle_hash, 500, Memos::None)
                .assert_puzzle_announcement(id),
        )
        .unwrap();
    let spends = ctx.take();
    let report = verify_binding(&spends, &owned(user.puzzle_hash), DEFAULT_MAX_COST).unwrap();
    assert!(report.all_bound);
    assert_eq!(
        report.received(AssetId::Option(m.launcher_id)),
        0,
        "{report:?}"
    );
    assert_eq!(report.received(AssetId::Xch), 2);
    sim.spend_coins(spends, &[user.sk, mallory.sk]).unwrap();
    let returned = offered.child(mallory.puzzle_hash, 1);
    assert!(
        sim.coin_state(returned.coin.coin_id()).is_some(),
        "the option went back"
    );
}

// --- N5: a loan request that has already expired ---

/// PoC Exp: the user locks 1,000,000 as collateral of an option whose creator (the lender)
/// is Mallory and whose expiry (1) has passed. The old rule verified `loan.request` with
/// `recipients: []`; Mallory clawed the collateral back in the next block. Now the kind does
/// not hold, the wallet refuses the request whatever is declared, and the collateral under
/// another creator is a payment to that creator in `recipients`.
#[test]
fn n5_an_expired_loan_request_is_refused_and_collateral_is_paid_to_the_lender() {
    let (user, mallory) = (BlsPair::new(1), BlsPair::new(2));
    for seconds in [1, LATER] {
        let mut sim = Simulator::new();
        let spec = MintSpec {
            seconds,
            ..spec(mallory.puzzle_hash, user.puzzle_hash, 1_000_000, 1)
        };
        let m = fx::mint(&mut sim, &user, spec);
        let s = sim_of(&m.spends, &user);
        let expired = seconds == 1;
        assert_eq!(collateral_lost_to_expiry(&s.options, NOW), expired);
        let verify =
            |intent: serde_json::Value| Intent::from_json(&intent).unwrap().verify(&s, NOW);
        let declared = json!({ "kind": "loan.request", "recipients": [
            { "puzzleHash": hex::encode(mallory.puzzle_hash), "amount": 1_000_000 },
        ] });
        if expired {
            assert_eq!(verify(declared), Err(IntentError::Mismatch("kind")));
        } else {
            let report = verify(declared).unwrap();
            assert!(report.kind_verified && report.recipients_complete);
        }
        // The collateral is the lender's unless repaid in time: "no payments" is false.
        assert_eq!(
            verify(json!({ "recipients": [] })),
            Err(IntentError::Mismatch("recipients"))
        );
        // The handler refuses the expired one before any prompt, whatever is declared (its
        // clock in `run` is the simulator's).
        if expired {
            let chain = RefCell::new(sim.clone());
            let err = run(
                &chain,
                &user,
                m.spends.clone(),
                Some(json!({ "kind": "swap" })),
            )
            .unwrap_err();
            assert!(reason(&err).contains("option_expires"), "{err:?}");
            // What the re-audit showed: minted, then clawed back by Mallory at once.
            sim.spend_coins(m.spends.clone(), std::slice::from_ref(&user.sk))
                .unwrap();
            let fx::Locked::Xch(coin) = m.locked else {
                unreachable!()
            };
            let mut ctx = SpendContext::new();
            let inner = StandardLayer::new(mallory.pk)
                .spend_with_conditions(
                    &mut ctx,
                    Conditions::new().create_coin(mallory.puzzle_hash, 1_000_000, Memos::None),
                )
                .unwrap();
            m.underlying
                .clawback_coin_spend(&mut ctx, coin, inner)
                .unwrap();
            sim.spend_coins(ctx.take(), std::slice::from_ref(&mallory.sk))
                .unwrap();
        }
    }
}

// --- P: the option asset id grammar ---

/// `option:<64 hex>` (with an optional `0x`) or a bare 32-byte hex id parses; nothing else
/// does, and nothing panics.
#[test]
fn option_asset_ids_follow_the_grammar() {
    let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let alphabet: Vec<char> = "0123456789abcdefABCDEFxX:option-é💥 \u{0}"
        .chars()
        .collect();
    let hex: Vec<char> = "0123456789abcdefABCDEF".chars().collect();
    for i in 0..20_000u32 {
        let pick = |n: u64, len: usize| usize::try_from(n % len as u64).unwrap();
        let body: String = match i % 3 {
            0 => (0..next() % 70)
                .map(|_| alphabet[pick(next(), alphabet.len())])
                .collect(),
            1 => (0..64).map(|_| hex[pick(next(), 16)]).collect(),
            _ => format!(
                "0x{}",
                (0..60 + next() % 8)
                    .map(|_| hex[pick(next(), hex.len())])
                    .collect::<String>()
            ),
        };
        let prefix = ["option:", "Option:", "option", "option::", "", "option: "][pick(next(), 6)];
        let text = format!("{prefix}{body}");
        let parsed =
            Intent::from_json(&json!({ "netChange": [{ "assetId": text, "amount": "1" }] }));
        let digits = body.strip_prefix("0x").unwrap_or(&body);
        let hex32 = digits.len() == 64 && digits.bytes().all(|b| b.is_ascii_hexdigit());
        let expected = (prefix == "option:" || prefix.is_empty()) && hex32;
        assert_eq!(parsed.is_ok(), expected, "{text:?}");
    }
}
