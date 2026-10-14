//! Option bundles and offer takes built the way Sage builds them
//! (`sage-wallet/src/wallet/options.rs`, `offer/take_offer.rs`): the Wallet SDK's action
//! system (`Spends`, `Action::mint_option` / `send` / `melt_singleton` / `settle`, an
//! `Offer`'s requested payments), with fees, change and CAT rings, finished with
//! `Relation::AssertConcurrent` exactly as Sage's `complete_spends` does, run through
//! [`submit`] and broadcast to the simulator.
//!
//! Sage's bundles are the source of truth: a wallet hands them to the kit unchanged. Built
//! by the wallet and broadcast by it, with no signature leaving it (`signatures_released`
//! false, spec 11.2 [`crate::binding::Linking::Sealed`]), Sage's own links count, so every Sage shape is
//! accepted, shown as what it is, and accepted by the chain (TASK-78 B1, B2, B4, and the
//! takes). The same bundles with their signatures released ([`crate::binding::Linking::Direct`]) are
//! refused where a spend is linked only through another (final audit F1).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use crate::handlers::{
    Approver, Broadcast, BroadcastRecord, Broadcaster, Prompt, RequestContext, RpcError,
    SUBMIT_COIN_SPENDS, SignedCoins, Signer, SignerError, SubmitRequest, submit,
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

/// Signs without sending: the bundle is handed on as an offer.
struct OfferOnly<'a>(&'a RefCell<Vec<BroadcastRecord>>);
impl Broadcaster for OfferOnly<'_> {
    fn record(&self, r: &BroadcastRecord) -> Result<(), String> {
        self.0.borrow_mut().push(r.clone());
        Ok(())
    }
    fn submit(&self, b: &SpendBundle) -> Result<Broadcast, String> {
        Ok(Broadcast {
            transaction_id: hex::encode(b.name()),
            status: "not_sent".into(),
        })
    }
}

struct Chain<'a>(&'a RefCell<Simulator>, &'a RefCell<Vec<BroadcastRecord>>);
impl Broadcaster for Chain<'_> {
    fn record(&self, r: &BroadcastRecord) -> Result<(), String> {
        self.1.borrow_mut().push(r.clone());
        Ok(())
    }
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

/// How a request reaches the kit.
#[derive(Default)]
pub(crate) struct Mode {
    /// `SubmitRequest::signatures_released`.
    pub(crate) released: bool,
    /// The wallet's record of coins with signatures outside it.
    pub(crate) signed: SignedCoins,
    /// The maker's signature, when taking an offer.
    pub(crate) other: Option<Signature>,
    /// The signed bundle becomes an offer (a loan request): not sent to the chain.
    pub(crate) offer: bool,
    /// What the kit asked the host to record ([`Broadcaster::record`]), one per bundle.
    pub(crate) recorded: RefCell<Vec<BroadcastRecord>>,
}

impl Mode {
    /// The record a host keeps after the bundles run in this mode so far.
    pub(crate) fn kept(&self) -> SignedCoins {
        let mut signed = self.signed.clone();
        for r in self.recorded.borrow().iter() {
            signed.add(r);
        }
        signed
    }
}

impl Mode {
    /// Built and broadcast by the wallet, no signature leaves it: Sage's links count.
    pub(crate) fn sealed() -> Self {
        Mode::default()
    }

    /// The signatures leave the wallet (a signed offer): only direct binding counts.
    pub(crate) fn released() -> Self {
        Mode {
            released: true,
            ..Mode::default()
        }
    }
}

/// Submit `spends` as `who`'s wallet (wallet-built, as Klimper hands Sage's bundles to the
/// kit, broadcast by the wallet) with an optional intent. Ok: the prompt the user saw; the
/// bundle is on the chain.
pub(crate) fn run(
    sim: &RefCell<Simulator>,
    who: &BlsPair,
    spends: Vec<CoinSpend>,
    intent: Option<Value>,
) -> Result<Value, RpcError> {
    run_as(sim, who, spends, intent, &Mode::sealed())
}

/// [`run`] with the signatures released (a signed offer): the strict rules.
pub(crate) fn run_released(
    sim: &RefCell<Simulator>,
    who: &BlsPair,
    spends: Vec<CoinSpend>,
    intent: Option<Value>,
) -> Result<Value, RpcError> {
    run_as(sim, who, spends, intent, &Mode::released())
}

/// [`run`] in a given [`Mode`].
pub(crate) fn run_as(
    sim: &RefCell<Simulator>,
    who: &BlsPair,
    spends: Vec<CoinSpend>,
    intent: Option<Value>,
    mode: &Mode,
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
        signed_coins: &mode.signed,
    };
    let intent = intent.map(|i| Intent::from_json(&i).unwrap());
    let ui = Ui(RefCell::default());
    let chain = Chain(sim, &mode.recorded);
    let offer = OfferOnly(&mode.recorded);
    submit(
        SubmitRequest {
            method: SUBMIT_COIN_SPENDS,
            spends,
            other_signature: mode.other.clone(),
            intent: intent.as_ref(),
            wallet_built: true,
            signatures_released: mode.released,
        },
        &ctx,
        &Key(who.sk.clone()),
        &ui,
        if mode.offer { &offer } else { &chain },
    )?;
    let prompt = ui.0.borrow()[0].clone();
    Ok(serde_json::from_str(&prompt).unwrap())
}

/// The aggregate of the signatures `sk` owes in `spends` (testnet11): another party's
/// share of a bundle, as a maker's offer carries it.
pub(crate) fn signature_of(spends: &[CoinSpend], sk: &SecretKey) -> Signature {
    let mut a = clvmr::Allocator::new();
    let required = chia_sdk_signer::RequiredSignature::from_coin_spends(
        &mut a,
        spends,
        &chia_sdk_signer::AggSigConstants::new(
            chia_sdk_types::TESTNET11_CONSTANTS.agg_sig_me_additional_data,
        ),
    )
    .unwrap();
    let pk = sk.public_key();
    let mut sig = Signature::default();
    for r in required {
        if let chia_sdk_signer::RequiredSignature::Bls(r) = r
            && r.public_key == pk
        {
            sig += &chia_bls::sign(sk, r.message());
        }
    }
    sig
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
    // Signatures released (a dApp could hold them): only a spend that both creates the
    // collateral and asserts the launch makes it guaranteed. Sage's XCH-collateral mint has
    // one such coin; with CAT collateral the CAT coin and the XCH coin that launches are
    // linked only by ASSERT_CONCURRENT_SPEND (or, built as a ring, by coin announcements):
    // not guaranteed, so option.mint does not hold (final audit F1).
    for linked in [false, true] {
        let mut raw_sim = sim.clone();
        let (raw, _) = sage_mint(
            &mut raw_sim,
            &alice,
            collateral,
            400,
            strike,
            seconds,
            fee,
            linked,
        );
        let raw = run_released(&RefCell::new(raw_sim), &alice, raw, Some(intent.clone()));
        if collateral_cat {
            let e = raw.unwrap_err();
            assert!(reason(&e).contains("intent_mismatch"), "{label}: {e:?}");
        } else {
            let p = raw.unwrap_or_else(|e| panic!("{label}: {e:?}"));
            assert_eq!(p["summary"]["options"][0]["guaranteed"], true, "{label}");
        }
    }
    // As Sage builds it, built and broadcast by the wallet with no signature leaving it:
    // Sage's ASSERT_CONCURRENT_SPEND links count, the launch is guaranteed (TASK-78 B1).
    let (spends, option) = sage_mint(
        &mut sim, &alice, collateral, 400, strike, seconds, fee, false,
    );
    let launcher_id = option.info.launcher_id;
    let underlying = OptionUnderlying::new(launcher_id, alice.puzzle_hash, seconds, 400, strike);
    let (locked, locked_coin) = locked_of(&spends, &option, &underlying, collateral);
    let sim = RefCell::new(sim);
    let p = run(&sim, &alice, spends, Some(intent)).unwrap_or_else(|e| panic!("{label}: {e:?}"));
    assert_eq!(p["linking"], "sealed", "{label}");
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
        false,
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
    let strike_coin = strike_cat.then_some(strike_tail_cat);
    // Signatures released: refused, as Sage builds it (its spends are tied only by
    // ASSERT_CONCURRENT_SPEND) and as a ring of coin announcements (final audit F1).
    for linked in [false, true] {
        let mut raw_sim = sim.borrow().clone();
        let raw = sage_exercise(&mut raw_sim, &bob, &[held], strike_coin, fee, linked, true);
        let raw = run_released(&RefCell::new(raw_sim), &bob, raw, None).unwrap_err();
        assert!(
            reason(&raw).contains("unbound_exercise"),
            "{label}: {raw:?}"
        );
    }
    // As Sage builds it (its own coins first, so released XCH collateral is absorbed into
    // the change and pays the fee), built and broadcast by the wallet: accepted (TASK-78 B2,
    // and B4 with a fee).
    let ex = sage_exercise(
        &mut sim.borrow_mut(),
        &bob,
        &[held],
        strike_coin,
        fee,
        false,
        true,
    );
    let p = run(&sim, &bob, ex, Some(json!({ "kind": "option.exercise" })))
        .unwrap_or_else(|e| panic!("{label}: exercise refused {e:?}"));
    assert_eq!(p["intent"]["kind_verified"], true, "{label}");
    let binding = &p["binding"];
    assert_eq!(binding["linking"], "sealed", "{label}");
    assert_eq!(binding["co_required"], true, "{label}");
    let cover = &binding["exercises"][0];
    assert_eq!(cover["covered"], true, "{label}: {binding}");
    assert_eq!(
        serde_json::to_value(collateral_asset).unwrap(),
        cover["asset"],
        "{label}"
    );
    // On the chain, Bob holds the collateral (less the strike when it is the same asset,
    // and the fee when the collateral is XCH).
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

/// B4 (TASK-78): Sage's exercise with a fee and XCH collateral. Sage puts the wallet's own
/// coin first, so the fee comes out of the released collateral absorbed into the change.
/// The user approved the fee shown and nets collateral − strike − fee; built and broadcast
/// by the wallet, the fee it chose is credited and the exercise is accepted. With the
/// signatures released the same bundle is refused: a dApp-chosen fee paid from released
/// collateral is collateral the user does not receive (re-audit N3).
#[test]
fn b4_a_sage_exercise_whose_fee_comes_from_the_released_collateral() {
    let mut sim = Simulator::new();
    let (alice, bob) = (BlsPair::new(1), BlsPair::new(2));
    let seconds = sim.next_timestamp() + 100_000;
    let strike = OptionType::Xch { amount: 300 };
    let (spends, option) = sage_mint(
        &mut sim,
        &alice,
        Asset::Xch,
        1000,
        strike,
        seconds,
        0,
        false,
    );
    sim.spend_coins(spends.clone(), std::slice::from_ref(&alice.sk))
        .unwrap();
    let underlying = OptionUnderlying::new(
        option.info.launcher_id,
        alice.puzzle_hash,
        seconds,
        1000,
        strike,
    );
    let (locked, locked_coin) = locked_of(&spends, &option, &underlying, Asset::Xch);
    let t = sage_transfer(&mut sim, &alice, option, bob.puzzle_hash, 0, false);
    sim.spend_coins(t, std::slice::from_ref(&alice.sk)).unwrap();
    let held = Held {
        option: option.child(bob.puzzle_hash, 1),
        underlying,
        locked,
        locked_coin,
    };
    let fee = 50;
    let mut released_sim = sim.clone();
    let ex = sage_exercise(&mut released_sim, &bob, &[held], None, fee, false, true);
    let e = run_released(&RefCell::new(released_sim), &bob, ex, None).unwrap_err();
    assert!(reason(&e).contains("unbound_exercise"), "{e:?}");

    let ex = sage_exercise(&mut sim, &bob, &[held], None, fee, false, true);
    let sim = RefCell::new(sim);
    let before = balance(&sim, bob.puzzle_hash);
    let p = run(&sim, &bob, ex, None).unwrap();
    assert_eq!(p["summary"]["implied_fee"], fee);
    let cover = &p["binding"]["exercises"][0];
    assert_eq!(
        (cover["collateral"].as_u64(), cover["covered"].as_bool()),
        (Some(1000), Some(true)),
        "{cover}"
    );
    // On the chain: +1000 collateral − 300 strike − 50 fee, and the melted option's mojo.
    assert_eq!(balance(&sim, bob.puzzle_hash), before + 651);
}

/// A coin with a signature outside the wallet (`SignedCoins::released`) makes a wallet-built
/// request fall back to the strict rule, and the signatures of a sealed bundle the wallet
/// broadcast are never made again.
#[test]
fn sealed_linking_needs_coins_without_outside_signatures() {
    let mut sim = Simulator::new();
    let alice = BlsPair::new(1);
    let seconds = sim.next_timestamp() + 100_000;
    let cat = issue_cat(&mut sim, &alice, 500);
    let strike = OptionType::Xch { amount: 300 };
    let (spends, _) = sage_mint(
        &mut sim,
        &alice,
        Asset::Cat(cat),
        400,
        strike,
        seconds,
        5,
        false,
    );
    let intent = json!({ "kind": "option.mint", "recipients": [], "fee": 5 });
    let sim = RefCell::new(sim);
    let mut exposed = SignedCoins::default();
    exposed.released.insert(cat.coin.coin_id());
    let mode = Mode {
        signed: exposed,
        ..Mode::sealed()
    };
    let e = run_as(&sim, &alice, spends.clone(), Some(intent.clone()), &mode).unwrap_err();
    assert!(reason(&e).contains("intent_mismatch"), "{e:?}");
    assert!(mode.recorded.borrow().is_empty());
    let sealed = Mode::sealed();
    let before = sim.clone();
    let p = run_as(&sim, &alice, spends.clone(), Some(intent.clone()), &sealed).unwrap();
    assert_eq!(p["summary"]["options"][0]["guaranteed"], true);
    // The host's record: every coin of the bundle, and each of the wallet's signatures.
    let record = sealed.recorded.borrow()[0].clone();
    assert_eq!(record.coins.len(), spends.len());
    assert!(!record.sealed.is_empty());
    assert!(
        record
            .sealed
            .iter()
            .all(|(coin, _)| record.coins.contains(coin))
    );
    // The same bundle again (as if the first never landed) is not signed a second time.
    let again = Mode {
        signed: sealed.kept(),
        ..Mode::sealed()
    };
    let e = run_as(&before, &alice, spends, Some(intent), &again).unwrap_err();
    assert!(reason(&e).contains("sealed_signature"), "{e:?}");
    assert!(again.recorded.borrow().is_empty());
}

/// A maker's offer of CATs built as Sage's `make_offer` builds it (the requested payments asserted
/// by the maker's spends, `Relation::AssertConcurrent`), and the user's take built as
/// Sage's `take_offer` builds it (the offered coins and the user's coins in one `Spends`,
/// the requested payments as actions, a taker fee, `Relation::AssertConcurrent`). Returns
/// the complete bundle's spends (maker's then taker's) and the maker's signature.
fn sage_take(
    sim: &mut Simulator,
    maker: &BlsPair,
    taker: &BlsPair,
    offered: &[Cat],
    taker_pays: &[Cat],
    (maker_fee, taker_fee): (u64, u64),
) -> (Vec<CoinSpend>, Signature) {
    use chia_sdk_driver::{AssetInfo, CatAssetInfo, Offer, RequestedPayments};
    let mut ctx = SpendContext::new();
    // Maker.
    let mut spends = Spends::new(maker.puzzle_hash);
    let mut actions = vec![Action::fee(maker_fee)];
    let mut maker_coins = vec![];
    let xch = sim.new_coin(maker.puzzle_hash, 10_000);
    spends.add(xch);
    maker_coins.push(xch.coin_id());
    for cat in offered {
        spends.add(*cat);
        maker_coins.push(cat.coin.coin_id());
        actions.push(Action::send(
            Id::Existing(cat.info.asset_id),
            SETTLEMENT_PAYMENT_HASH.into(),
            cat.coin.amount,
            Memos::None,
        ));
    }
    let nonce = Offer::nonce(maker_coins);
    let mut requested_payments = RequestedPayments::new();
    let mut asset_info = AssetInfo::new();
    for (asset_id, amount) in taker_pays.iter().map(|c| (c.info.asset_id, c.coin.amount)) {
        let hint = ctx.hint(maker.puzzle_hash).unwrap();
        requested_payments.cats.insert(
            asset_id,
            vec![NotarizedPayment::new(
                nonce,
                vec![Payment::new(maker.puzzle_hash, amount, hint)],
            )],
        );
        asset_info
            .insert_cat(asset_id, CatAssetInfo::new(None))
            .unwrap();
    }
    let deltas = spends.apply(&mut ctx, &actions).unwrap();
    spends.conditions.required = spends.conditions.required.extend(
        requested_payments
            .assertions(&mut ctx, &asset_info)
            .unwrap(),
    );
    spends
        .finish_with_keys(
            &mut ctx,
            &deltas,
            Relation::AssertConcurrent,
            &indexmap! { maker.puzzle_hash => maker.pk },
        )
        .unwrap();
    let maker_spends = ctx.take();
    let maker_sig = signature_of(&maker_spends, &maker.sk);
    let offer = Offer::from_input_spend_bundle(
        &mut ctx,
        SpendBundle::new(maker_spends, maker_sig.clone()),
        requested_payments,
        asset_info,
    )
    .unwrap();
    let offer_bundle = offer.to_spend_bundle(&mut ctx).unwrap();

    // Taker, as Sage's take_offer.
    let offer = Offer::from_spend_bundle(&mut ctx, &offer_bundle).unwrap();
    let mut actions = vec![Action::fee(taker_fee)];
    let mut spends = Spends::new(taker.puzzle_hash);
    spends.add(offer.offered_coins().clone());
    actions.extend(offer.requested_payments().actions());
    if taker_fee > 0 {
        spends.add(sim.new_coin(taker.puzzle_hash, 1_000));
    }
    for cat in taker_pays {
        spends.add(*cat);
    }
    let deltas = spends.apply(&mut ctx, &actions).unwrap();
    spends
        .finish_with_keys(
            &mut ctx,
            &deltas,
            Relation::AssertConcurrent,
            &indexmap! { taker.puzzle_hash => taker.pk },
        )
        .unwrap();
    let taker_spends = ctx.take();
    let all = [offer.spend_bundle().coin_spends.clone(), taker_spends].concat();
    (all, maker_sig)
}

/// Sage's own takes, unmodified: a CAT for a CAT with fees on both sides, three CATs for
/// one, and one CAT for three. Built and broadcast by the wallet, no signature leaving it:
/// accepted, every user spend bound through Sage's links, and the bundle settles on chain.
/// With the signatures released (a dApp could split them), the user spends that only
/// assert another's concurrent spend are not bound.
#[test]
fn sage_takes_settle_unmodified() {
    for case in [
        "cat_for_cat_both_fees",
        "three_cats_for_one",
        "one_cat_for_three",
    ] {
        let mut sim = Simulator::new();
        let (maker, taker) = (BlsPair::new(1), BlsPair::new(2));
        let (offered, paid): (Vec<Cat>, Vec<Cat>) = match case {
            "cat_for_cat_both_fees" => (
                vec![issue_cat(&mut sim, &maker, 1000)],
                vec![issue_cat(&mut sim, &taker, 1000)],
            ),
            "three_cats_for_one" => (
                (0..3).map(|_| issue_cat(&mut sim, &maker, 1000)).collect(),
                vec![issue_cat(&mut sim, &taker, 1000)],
            ),
            _ => (
                vec![issue_cat(&mut sim, &maker, 1000)],
                (0..3).map(|_| issue_cat(&mut sim, &taker, 1000)).collect(),
            ),
        };
        let (maker_fee, taker_fee) = if case == "cat_for_cat_both_fees" {
            (5, 7)
        } else {
            (0, 3)
        };
        let (spends, maker_sig) = sage_take(
            &mut sim,
            &maker,
            &taker,
            &offered,
            &paid,
            (maker_fee, taker_fee),
        );
        let sim = RefCell::new(sim);
        let released = Mode {
            released: true,
            other: Some(maker_sig.clone()),
            ..Mode::default()
        };
        let strict = run_as(&sim, &taker, spends.clone(), None, &released);
        let sealed = Mode {
            other: Some(maker_sig),
            ..Mode::default()
        };
        let p =
            run_as(&sim, &taker, spends, None, &sealed).unwrap_or_else(|e| panic!("{case}: {e:?}"));
        assert_eq!(p["binding"]["linking"], "sealed", "{case}");
        assert_eq!(p["binding"]["all_bound"], true, "{case}");
        // Every CAT the maker offered reaches the taker on chain.
        for cat in &offered {
            let ph = chia_sdk_driver::CatInfo::new(cat.info.asset_id, None, taker.puzzle_hash)
                .puzzle_hash()
                .into();
            assert_eq!(balance(&sim, ph), 1000, "{case}");
        }
        // Signatures released: Sage's take asserts the payments from one spend and ties the
        // others by ASSERT_CONCURRENT_SPEND, so it is refused.
        let e = strict.unwrap_err();
        assert!(reason(&e).contains("unbound_partial"), "{case}: {e:?}");
    }
}
