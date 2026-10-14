//! Option bundles built the way Sage builds them (`sage-wallet/src/wallet/options.rs`):
//! the Wallet SDK's action system (`Spends`, `Action::mint_option` / `send` /
//! `melt_singleton` / `settle`), with fees, change and CAT rings, run through [`submit`] and
//! broadcast to the simulator.
//!
//! Sage links its spends with `Relation::AssertConcurrent`, which names coins, not spends:
//! the kit does not count it (spec 11.2 rule 2, re-audit N2), so a raw Sage exercise, and a
//! Sage mint whose collateral and launch come from different coins, are refused with a
//! reason. The same bundles built as spec 11.2 asks a wallet to build them ([`finish`] with
//! `linked`: a ring of coin announcements among the user's spends; for an exercise the
//! released collateral claimed through a settlement payment the user's spend asserts, so a
//! fee comes from the user's own coins) are accepted, shown as what they are, and accepted
//! by the chain (review finding CR-H1/CR-H2).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use crate::handlers::{
    Approver, Broadcast, Broadcaster, Prompt, RequestContext, RpcError, SUBMIT_COIN_SPENDS, Signer,
    SignerError, SubmitRequest, submit,
};
use crate::intent::Intent;
use crate::permissions::DappPermissions;
use crate::policy::Network;
use crate::simulate::{AssetId, Ownership};
use crate::swap_fixture::Mem;
use chia_bls::{PublicKey, SecretKey, Signature};
use chia_protocol::{Bytes32, Coin, CoinSpend, SpendBundle};
use chia_puzzle_types::Memos;
use chia_puzzle_types::offer::SettlementPaymentsSolution;
use chia_puzzle_types::offer::{NotarizedPayment, Payment};
use chia_puzzles::SETTLEMENT_PAYMENT_HASH;
use chia_sdk_driver::{
    Action, Cat, CatSpend, Deltas, Id, Layer, OptionContract, OptionType, OptionUnderlying,
    Outputs, Relation, SettlementLayer, SingletonInfo, SpendContext, SpendKind as Built,
    SpendWithConditions, Spends, StandardLayer,
};
use chia_sdk_test::{BlsPair, Simulator};
use chia_sdk_types::Conditions;
use clvm_utils::ToTreeHash;
use indexmap::{IndexMap, indexmap};
use serde_json::{Value, json};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use xchonnect_core::crypto::sha256_parts;

struct Key(SecretKey);
impl Signer for Key {
    fn sign(&self, _pk: &PublicKey, msg: &[u8]) -> Result<Signature, SignerError> {
        Ok(chia_bls::sign(&self.0, msg))
    }
}

struct Ui(RefCell<Vec<String>>);
impl Approver for Ui {
    fn approve(&self, p: &Prompt<'_>) -> bool {
        self.0.borrow_mut().push(serde_json::to_string(p).unwrap());
        true
    }
}

struct Chain<'a>(&'a RefCell<Simulator>);
impl Broadcaster for Chain<'_> {
    fn submit(&self, b: &SpendBundle) -> Result<Broadcast, String> {
        self.0
            .borrow_mut()
            .new_transaction(b.clone())
            .map_err(|e| e.to_string())?;
        Ok(Broadcast {
            transaction_id: hex::encode(b.name()),
            status: "ok".into(),
        })
    }
}

/// Submit `spends` as `who`'s wallet (wallet-built, as Klimper hands Sage's bundles to the
/// kit) with an optional intent. Ok: the prompt the user saw; the bundle is on the chain.
pub(crate) fn run(
    sim: &RefCell<Simulator>,
    who: &BlsPair,
    spends: Vec<CoinSpend>,
    intent: Option<Value>,
) -> Result<Value, RpcError> {
    let own = Ownership {
        p2_puzzle_hashes: [who.puzzle_hash].into_iter().collect(),
    };
    let keys: HashSet<PublicKey> = [who.pk].into_iter().collect();
    let perms = DappPermissions::new_default(who.pk);
    let limits = Mem::default();
    // The wallet's clock is the chain's.
    let now = sim.borrow().next_timestamp();
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
        now,
        chain: None,
    };
    let intent = intent.map(|i| Intent::from_json(&i).unwrap());
    let ui = Ui(RefCell::default());
    submit(
        SubmitRequest {
            method: SUBMIT_COIN_SPENDS,
            spends,
            other_signature: None,
            intent: intent.as_ref(),
            wallet_built: true,
        },
        &ctx,
        &Key(who.sk.clone()),
        &ui,
        &Chain(sim),
    )?;
    let prompt = ui.0.borrow()[0].clone();
    Ok(serde_json::from_str(&prompt).unwrap())
}

pub(crate) fn reason(e: &RpcError) -> String {
    e.data.clone().unwrap_or_default()
}

fn issue_cat(sim: &mut Simulator, owner: &BlsPair, amount: u64) -> Cat {
    crate::option_fixture::issue_cat(sim, owner, amount)
}

#[derive(Clone, Copy, Debug)]
#[allow(clippy::large_enum_variant)]
enum Asset {
    Xch,
    Cat(Cat),
}

/// Finish a bundle built with the action system. Not `linked`: exactly as Sage does
/// (`Relation::AssertConcurrent`). `linked`: as spec 11.2 asks a wallet to build it for the
/// kit: no `ASSERT_CONCURRENT_SPEND`; instead the user's spends form a ring of coin
/// announcements, spend `i` announcing the id of spend `i + 1` (the one that asserts it) and
/// asserting the announcement spend `i - 1` makes of its own id. Each spend then requires
/// the others' signed spends, not just their coins.
fn finish(
    spends: Spends,
    ctx: &mut SpendContext,
    deltas: &Deltas,
    keys: &IndexMap<Bytes32, PublicKey>,
    linked: bool,
) -> Outputs {
    if !linked {
        return spends
            .finish_with_keys(ctx, deltas, Relation::AssertConcurrent, keys)
            .unwrap();
    }
    let spends = spends.prepare(ctx, deltas, Relation::None).unwrap();
    let unspent = spends.unspent();
    let ids: Vec<Bytes32> = unspent
        .iter()
        .filter(|(_, kind)| kind.is_conditions())
        .map(|(asset, _)| asset.coin().coin_id())
        .collect();
    let mut coin_spends = HashMap::new();
    for (asset, kind) in unspent {
        let id = asset.coin().coin_id();
        let spend = match kind {
            Built::Conditions(spend) => {
                let mut conds = spend.finish();
                if ids.len() > 1 {
                    let i = ids.iter().position(|x| *x == id).unwrap();
                    let next = ids[(i + 1) % ids.len()];
                    let prev = ids[(i + ids.len() - 1) % ids.len()];
                    conds = conds
                        .create_coin_announcement(next.to_vec().into())
                        .assert_coin_announcement(Bytes32::from(sha256_parts(&[
                            prev.as_ref(),
                            id.as_ref(),
                        ])));
                }
                StandardLayer::new(keys[&asset.p2_puzzle_hash()])
                    .spend_with_conditions(ctx, conds)
                    .unwrap()
            }
            Built::Settlement(spend) => SettlementLayer
                .construct_spend(ctx, SettlementPaymentsSolution::new(spend.finish()))
                .unwrap(),
        };
        coin_spends.insert(id, spend);
    }
    spends.spend(ctx, coin_spends).unwrap()
}

/// Sage `mint_option`: creator = owner = the wallet's change puzzle hash.
#[allow(clippy::too_many_arguments)]
fn sage_mint(
    sim: &mut Simulator,
    alice: &BlsPair,
    collateral: Asset,
    amount: u64,
    strike: OptionType,
    seconds: u64,
    fee: u64,
    linked: bool,
) -> (Vec<CoinSpend>, OptionContract) {
    let mut ctx = SpendContext::new();
    let mut spends = Spends::new(alice.puzzle_hash);
    spends.add(sim.new_coin(alice.puzzle_hash, 10_000));
    let id = match collateral {
        Asset::Xch => Id::Xch,
        Asset::Cat(cat) => {
            spends.add(cat);
            Id::Existing(cat.info.asset_id)
        }
    };
    let actions = [
        Action::fee(fee),
        Action::mint_option(alice.puzzle_hash, seconds, id, amount, strike, 1),
    ];
    let deltas = spends.apply(&mut ctx, &actions).unwrap();
    let keys = indexmap! { alice.puzzle_hash => alice.pk };
    let outputs = finish(spends, &mut ctx, &deltas, &keys, linked);
    (ctx.take(), outputs.options[&Id::New(1)])
}

/// Sage `transfer_options` (no clawback).
fn sage_transfer(
    sim: &mut Simulator,
    from: &BlsPair,
    option: OptionContract,
    to: Bytes32,
    fee: u64,
    linked: bool,
) -> Vec<CoinSpend> {
    let mut ctx = SpendContext::new();
    let mut spends = Spends::new(from.puzzle_hash);
    spends.add(option);
    if fee > 0 {
        spends.add(sim.new_coin(from.puzzle_hash, 1000));
    }
    let memos = ctx.hint(to).unwrap();
    let actions = [
        Action::fee(fee),
        Action::send(Id::Existing(option.info.launcher_id), to, 1, memos),
    ];
    let deltas = spends.apply(&mut ctx, &actions).unwrap();
    let keys = indexmap! { from.puzzle_hash => from.pk };
    finish(spends, &mut ctx, &deltas, &keys, linked);
    ctx.take()
}

/// An option to exercise: the singleton, its terms and its collateral coin.
#[derive(Clone, Copy)]
struct Held {
    option: OptionContract,
    underlying: OptionUnderlying,
    locked: Asset,
    locked_coin: Coin,
}

/// Sage `exercise_options`. `linked`: the user's spends linked as a wallet must link them
/// for the kit ([`finish`]). `absorb`: as Sage orders the coins, the released XCH collateral
/// is absorbed into the wallet's own change; otherwise it is added before the wallet's own
/// coins, so the action system pays the change out of it as a settlement payment the
/// wallet's spend asserts and a fee comes from the wallet's own coins (spec 11.1.1).
fn sage_exercise(
    sim: &mut Simulator,
    holder: &BlsPair,
    held: &[Held],
    strike_cat: Option<Cat>,
    fee: u64,
    linked: bool,
    absorb: bool,
) -> Vec<CoinSpend> {
    let mut ctx = SpendContext::new();
    let mut settlement_coins = vec![];
    let mut settlement_cats = vec![];
    let mut actions = vec![Action::fee(fee)];
    for h in held {
        let underlying_spend = h
            .underlying
            .exercise_spend(
                &mut ctx,
                h.option.info.inner_puzzle_hash().into(),
                h.option.coin.amount,
            )
            .unwrap();
        match h.locked {
            Asset::Xch => {
                ctx.spend(h.locked_coin, underlying_spend).unwrap();
                settlement_coins.push(Coin::new(
                    h.locked_coin.coin_id(),
                    SETTLEMENT_PAYMENT_HASH.into(),
                    h.locked_coin.amount,
                ));
            }
            Asset::Cat(cat) => {
                let children =
                    Cat::spend_all(&mut ctx, &[CatSpend::new(cat, underlying_spend)]).unwrap();
                settlement_cats.push(children[0]);
            }
        }
        actions.push(Action::melt_singleton(
            Id::Existing(h.option.info.launcher_id),
            1,
        ));
        let creator = h.underlying.creator_puzzle_hash;
        let nonce = h.option.info.launcher_id;
        actions.push(match h.underlying.strike_type {
            OptionType::Xch { amount } => Action::settle(
                Id::Xch,
                NotarizedPayment::new(nonce, vec![Payment::new(creator, amount, Memos::None)]),
            ),
            OptionType::Cat { asset_id, amount } => {
                let hint = ctx.hint(creator).unwrap();
                Action::settle(
                    Id::Existing(asset_id),
                    NotarizedPayment::new(nonce, vec![Payment::new(creator, amount, hint)]),
                )
            }
            _ => unreachable!(),
        });
    }
    // Sage: prepare_spends selects coins for the actions, then adds the settlement coins.
    let mut spends = Spends::new(holder.puzzle_hash);
    if !absorb {
        for c in &settlement_coins {
            spends.add(*c);
        }
    }
    spends.add(sim.new_coin(holder.puzzle_hash, 10_000));
    for h in held {
        spends.add(h.option);
    }
    if let Some(cat) = strike_cat {
        spends.add(cat);
    }
    if absorb {
        for c in settlement_coins {
            spends.add(c);
        }
    }
    for c in settlement_cats {
        spends.add(c);
    }
    let deltas = spends.apply(&mut ctx, &actions).unwrap();
    let keys = indexmap! { holder.puzzle_hash => holder.pk };
    finish(spends, &mut ctx, &deltas, &keys, linked);
    ctx.take()
}

/// The collateral coin a Sage mint created for `option`.
fn locked_of(
    spends: &[CoinSpend],
    option: &OptionContract,
    underlying: &OptionUnderlying,
    collateral: Asset,
) -> (Asset, Coin) {
    let p2 = Bytes32::from(underlying.tree_hash());
    for cs in spends {
        let c = Coin::new(cs.coin.coin_id(), p2, underlying.amount);
        if c.coin_id() == option.info.underlying_coin_id {
            return (Asset::Xch, c);
        }
        if let Asset::Cat(cat) = collateral
            && cs.coin.coin_id() == cat.coin.coin_id()
        {
            let child = cat.child(p2, underlying.amount);
            if child.coin.coin_id() == option.info.underlying_coin_id {
                return (Asset::Cat(child), child.coin);
            }
        }
    }
    panic!("no collateral coin")
}

fn balance(sim: &RefCell<Simulator>, ph: Bytes32) -> u64 {
    sim.borrow()
        .unspent_coins(ph, false)
        .iter()
        .map(|c| c.amount)
        .sum()
}

/// One full life: Sage mint by Alice, Sage transfer to Bob, Sage exercise by Bob.
fn life(collateral_cat: bool, strike_cat: bool, fee: u64) {
    let label = format!("collateral_cat={collateral_cat} strike_cat={strike_cat} fee={fee}");
    let mut sim = Simulator::new();
    let (alice, bob) = (BlsPair::new(1), BlsPair::new(2));
    let seconds = sim.next_timestamp() + 100_000;
    let coll_cat = issue_cat(&mut sim, &alice, 500);
    let strike_tail_cat = issue_cat(&mut sim, &bob, 700);
    let collateral = if collateral_cat {
        Asset::Cat(coll_cat)
    } else {
        Asset::Xch
    };
    let collateral_asset = match collateral {
        Asset::Xch => AssetId::Xch,
        Asset::Cat(c) => AssetId::Cat(c.info.asset_id),
    };
    let strike = if strike_cat {
        OptionType::Cat {
            asset_id: strike_tail_cat.info.asset_id,
            amount: 300,
        }
    } else {
        OptionType::Xch { amount: 300 }
    };

    // --- mint: guaranteed, the option arrives (+1), verified as option.mint ---
    let intent = json!({ "kind": "option.mint", "recipients": [], "fee": fee.to_string() });
    // As Sage builds it: with XCH collateral one coin creates the collateral and the
    // launcher and asserts the launch, so the launch is guaranteed. With CAT collateral the
    // CAT coin and the XCH coin are tied only by ASSERT_CONCURRENT_SPEND: not guaranteed,
    // so option.mint does not hold.
    let mut raw_sim = sim.clone();
    let (raw, _) = sage_mint(
        &mut raw_sim,
        &alice,
        collateral,
        400,
        strike,
        seconds,
        fee,
        false,
    );
    let raw = run(&RefCell::new(raw_sim), &alice, raw, Some(intent.clone()));
    if collateral_cat {
        let e = raw.unwrap_err();
        assert!(reason(&e).contains("intent_mismatch"), "{label}: {e:?}");
    } else {
        assert_eq!(
            raw.unwrap()["summary"]["options"][0]["guaranteed"],
            true,
            "{label}"
        );
    }
    let (spends, option) = sage_mint(
        &mut sim, &alice, collateral, 400, strike, seconds, fee, true,
    );
    let launcher_id = option.info.launcher_id;
    let underlying = OptionUnderlying::new(launcher_id, alice.puzzle_hash, seconds, 400, strike);
    let (locked, locked_coin) = locked_of(&spends, &option, &underlying, collateral);
    let sim = RefCell::new(sim);
    let p = run(&sim, &alice, spends, Some(intent)).unwrap_or_else(|e| panic!("{label}: {e:?}"));
    let mint = &p["summary"]["options"][0];
    assert_eq!(mint["action"], "mint", "{label}");
    assert_eq!(mint["guaranteed"], true, "{label}");
    assert_eq!(p["intent"]["kind_verified"], true, "{label}");
    assert_eq!(p["intent"]["recipients_complete"], true, "{label}");
    let option_delta = p["summary"]["assets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["asset"]["type"] == "option")
        .unwrap();
    assert_eq!(
        option_delta["net"], 1,
        "{label}: the option arrives (CR-M1)"
    );
    for o in p["summary"]["outputs"].as_array().unwrap() {
        if !o["option"].is_null() {
            assert_eq!(o["option"]["user_holds_option"], true, "{label}");
            assert!(o["recipient"].is_null(), "{label}");
        }
    }

    // --- transfer to Bob: verified, and Bob is a declared recipient of the option ---
    let t = sage_transfer(
        &mut sim.borrow_mut(),
        &alice,
        option,
        bob.puzzle_hash,
        fee,
        true,
    );
    let intent = json!({
        "kind": "option.transfer",
        "recipients": [{
            "assetId": format!("option:{}", hex::encode(launcher_id)),
            "puzzleHash": hex::encode(bob.puzzle_hash),
            "amount": 1,
        }],
        "fee": fee,
    });
    let p = run(&sim, &alice, t, Some(intent)).unwrap_or_else(|e| panic!("{label}: {e:?}"));
    assert_eq!(p["intent"]["recipients_complete"], true, "{label}");
    assert_eq!(
        p["summary"]["options"][0]["to_settlement"], false,
        "{label}"
    );
    let option = option.child(bob.puzzle_hash, 1);

    // --- exercise by Bob: the collateral reaches Bob, so it is signed and broadcast ---
    let before_coll = match locked {
        Asset::Xch => balance(&sim, bob.puzzle_hash),
        Asset::Cat(c) => balance(
            &sim,
            chia_sdk_driver::CatInfo::new(c.info.asset_id, None, bob.puzzle_hash)
                .puzzle_hash()
                .into(),
        ),
    };
    let held = Held {
        option,
        underlying,
        locked,
        locked_coin,
    };
    // As Sage builds it: refused, its spends are tied only by ASSERT_CONCURRENT_SPEND.
    let mut raw_sim = sim.borrow().clone();
    let raw = sage_exercise(
        &mut raw_sim,
        &bob,
        &[held],
        strike_cat.then_some(strike_tail_cat),
        fee,
        false,
        true,
    );
    let raw = run(&RefCell::new(raw_sim), &bob, raw, None).unwrap_err();
    assert!(
        reason(&raw).contains("unbound_exercise"),
        "{label}: {raw:?}"
    );
    // Linked, but the fee paid out of collateral absorbed into the change: the fee is not
    // the user's own money, so the collateral does not reach the user in full (re-audit N3).
    if !collateral_cat && fee > 0 {
        let mut raw_sim = sim.borrow().clone();
        let strike = strike_cat.then_some(strike_tail_cat);
        let absorbed = sage_exercise(&mut raw_sim, &bob, &[held], strike, fee, true, true);
        let e = run(&RefCell::new(raw_sim), &bob, absorbed, None).unwrap_err();
        assert!(reason(&e).contains("unbound_exercise"), "{label}: {e:?}");
    }
    let ex = sage_exercise(
        &mut sim.borrow_mut(),
        &bob,
        &[held],
        strike_cat.then_some(strike_tail_cat),
        fee,
        true,
        false,
    );
    let p = run(&sim, &bob, ex, Some(json!({ "kind": "option.exercise" })))
        .unwrap_or_else(|e| panic!("{label}: exercise refused {e:?}"));
    assert_eq!(p["intent"]["kind_verified"], true, "{label}");
    let binding = &p["binding"];
    assert_eq!(binding["co_required"], true, "{label}");
    let cover = &binding["exercises"][0];
    assert_eq!(cover["covered"], true, "{label}: {binding}");
    assert_eq!(
        serde_json::to_value(collateral_asset).unwrap(),
        cover["asset"],
        "{label}"
    );
    // On the chain, Bob holds the collateral (less the strike when it is the same asset).
    let after_coll = match locked {
        Asset::Xch => balance(&sim, bob.puzzle_hash),
        Asset::Cat(c) => balance(
            &sim,
            chia_sdk_driver::CatInfo::new(c.info.asset_id, None, bob.puzzle_hash)
                .puzzle_hash()
                .into(),
        ),
    };
    let same_asset = !collateral_cat && !strike_cat;
    let paid = if same_asset { 300 } else { 0 };
    let xch_fee = if collateral_cat { 0 } else { fee };
    assert!(
        after_coll + paid + xch_fee >= before_coll + 400,
        "{label}: {before_coll} -> {after_coll}"
    );
}

#[test]
fn every_sage_option_shape_is_accepted_shown_and_valid_on_chain() {
    for (collateral_cat, strike_cat, fee) in [
        (false, false, 0),
        (false, false, 5),
        (true, false, 0),
        (true, false, 5),
        (true, true, 5),
        (false, true, 0),
    ] {
        life(collateral_cat, strike_cat, fee);
    }
}

/// Two options exercised in one Sage-built bundle (linked as spec 11.2 asks): both
/// collaterals must be covered, and are.
#[test]
fn two_options_exercised_in_one_bundle() {
    let mut sim = Simulator::new();
    let (alice, bob) = (BlsPair::new(1), BlsPair::new(2));
    let seconds = sim.next_timestamp() + 100_000;
    let mut held = Vec::new();
    for amount in [400u64, 600] {
        let strike = OptionType::Xch { amount: 100 };
        let (spends, option) = sage_mint(
            &mut sim,
            &alice,
            Asset::Xch,
            amount,
            strike,
            seconds,
            0,
            true,
        );
        sim.spend_coins(spends.clone(), std::slice::from_ref(&alice.sk))
            .unwrap();
        let underlying = OptionUnderlying::new(
            option.info.launcher_id,
            alice.puzzle_hash,
            seconds,
            amount,
            strike,
        );
        let (locked, locked_coin) = locked_of(&spends, &option, &underlying, Asset::Xch);
        let t = sage_transfer(&mut sim, &alice, option, bob.puzzle_hash, 0, true);
        sim.spend_coins(t, std::slice::from_ref(&alice.sk)).unwrap();
        held.push(Held {
            option: option.child(bob.puzzle_hash, 1),
            underlying,
            locked,
            locked_coin,
        });
    }
    let ex = sage_exercise(&mut sim, &bob, &held, None, 0, true, false);
    let sim = RefCell::new(sim);
    let p = run(&sim, &bob, ex, None).unwrap();
    assert_eq!(p["summary"]["options"].as_array().unwrap().len(), 2);
    let cover = &p["binding"]["exercises"][0];
    assert_eq!(
        (cover["collateral"].as_u64(), cover["covered"].as_bool()),
        (Some(1000), Some(true))
    );
}

/// A Sage-shaped exercise in which the released collateral pays Mallory instead of Bob's
/// change absorbing it: valid on the chain, refused by the wallet (SA-H3 reconciled with
/// CR-H1: only what reaches the user counts).
#[test]
fn an_exercise_whose_collateral_goes_elsewhere_is_refused_though_the_chain_takes_it() {
    let mut sim = Simulator::new();
    let (alice, bob, mallory) = (BlsPair::new(1), BlsPair::new(2), BlsPair::new(9));
    let seconds = sim.next_timestamp() + 100_000;
    let strike = OptionType::Xch { amount: 300 };
    let (spends, option) = sage_mint(&mut sim, &alice, Asset::Xch, 400, strike, seconds, 0, true);
    sim.spend_coins(spends.clone(), std::slice::from_ref(&alice.sk))
        .unwrap();
    let underlying = OptionUnderlying::new(
        option.info.launcher_id,
        alice.puzzle_hash,
        seconds,
        400,
        strike,
    );
    let (_, locked_coin) = locked_of(&spends, &option, &underlying, Asset::Xch);
    let t = sage_transfer(&mut sim, &alice, option, bob.puzzle_hash, 0, true);
    sim.spend_coins(t, std::slice::from_ref(&alice.sk)).unwrap();
    let option = option.child(bob.puzzle_hash, 1);

    // Bob's coin keeps its value and requires the melt; the released collateral pays the
    // strike to Alice and the rest to Mallory.
    let mut ctx = SpendContext::new();
    let p2 = StandardLayer::new(bob.pk);
    let funding = sim.new_coin(bob.puzzle_hash, 10_000);
    let strike_np = underlying.requested_payment(&mut *ctx).unwrap();
    let strike_ptr = ctx.alloc(&strike_np).unwrap();
    let strike_id = Bytes32::from(xchonnect_core::crypto::sha256_parts(&[
        &SETTLEMENT_PAYMENT_HASH,
        &ctx.tree_hash(strike_ptr).to_bytes(),
    ]));
    option
        .exercise(
            &mut ctx,
            &p2,
            Conditions::new().assert_concurrent_spend(funding.coin_id()),
        )
        .unwrap();
    underlying
        .exercise_coin_spend(
            &mut ctx,
            locked_coin,
            option.info.inner_puzzle_hash().into(),
            option.coin.amount,
        )
        .unwrap();
    let released = Coin::new(locked_coin.coin_id(), SETTLEMENT_PAYMENT_HASH.into(), 400);
    let to_mallory = NotarizedPayment::new(
        Bytes32::new([0x42; 32]),
        vec![Payment::new(mallory.puzzle_hash, 100, Memos::None)],
    );
    let cs = chia_sdk_driver::Layer::construct_coin_spend(
        &chia_sdk_driver::SettlementLayer,
        &mut ctx,
        released,
        chia_puzzle_types::offer::SettlementPaymentsSolution::new(vec![strike_np, to_mallory]),
    )
    .unwrap();
    ctx.insert(cs);
    p2.spend(
        &mut ctx,
        funding,
        Conditions::new()
            .create_coin(bob.puzzle_hash, 10_000, Memos::None)
            .assert_puzzle_announcement(strike_id)
            .assert_concurrent_spend(option.coin.coin_id()),
    )
    .unwrap();
    let spends = ctx.take();
    let sim = RefCell::new(sim);
    let err = run(&sim, &bob, spends.clone(), None).unwrap_err();
    assert!(reason(&err).contains("unbound_exercise"), "{err:?}");
    assert!(
        sim.borrow_mut()
            .spend_coins(spends, std::slice::from_ref(&bob.sk))
            .is_ok(),
        "the chain would take it: only the wallet stands between Bob and the loss"
    );
}

/// Sage-built bundles as `option_spends` fuzz seeds (see `option_tests::write_seed`): as
/// Sage builds them (`sage-*`) and as spec 11.2 asks (`sage-linked-*`).
#[test]
fn sage_option_fuzz_seeds() {
    for linked in [false, true] {
        let tag = if linked { "sage-linked" } else { "sage" };
        let mut sim = Simulator::new();
        let (alice, bob) = (BlsPair::new(1), BlsPair::new(2));
        let seconds = sim.next_timestamp() + 100_000;
        let strike_cat = issue_cat(&mut sim, &bob, 700);
        let strike = OptionType::Cat {
            asset_id: strike_cat.info.asset_id,
            amount: 300,
        };
        let (spends, option) = sage_mint(
            &mut sim,
            &alice,
            Asset::Xch,
            400,
            strike,
            seconds,
            5,
            linked,
        );
        crate::option_tests::write_seed(&format!("{tag}-mint"), alice.puzzle_hash, &spends);
        sim.spend_coins(spends.clone(), std::slice::from_ref(&alice.sk))
            .unwrap();
        let underlying = OptionUnderlying::new(
            option.info.launcher_id,
            alice.puzzle_hash,
            seconds,
            400,
            strike,
        );
        let (locked, locked_coin) = locked_of(&spends, &option, &underlying, Asset::Xch);
        let t = sage_transfer(&mut sim, &alice, option, bob.puzzle_hash, 5, linked);
        crate::option_tests::write_seed(&format!("{tag}-transfer"), alice.puzzle_hash, &t);
        sim.spend_coins(t, std::slice::from_ref(&alice.sk)).unwrap();
        let held = Held {
            option: option.child(bob.puzzle_hash, 1),
            underlying,
            locked,
            locked_coin,
        };
        let ex = sage_exercise(
            &mut sim,
            &bob,
            &[held],
            Some(strike_cat),
            5,
            linked,
            !linked,
        );
        crate::option_tests::write_seed(&format!("{tag}-exercise"), bob.puzzle_hash, &ex);
    }
}
