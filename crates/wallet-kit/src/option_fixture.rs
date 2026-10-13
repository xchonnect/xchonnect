//! Test fixtures: real option-contract spends built with chia-sdk-driver's option
//! primitives, so the simulator can check that the bundles the wallet classifies are the
//! ones the chain accepts.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    missing_docs,
    unreachable_pub
)]

use chia_protocol::{Bytes32, Coin, CoinSpend};
use chia_puzzle_types::Memos;
use chia_puzzle_types::offer::{NotarizedPayment, Payment, SettlementPaymentsSolution};
use chia_puzzles::SETTLEMENT_PAYMENT_HASH;
use chia_sdk_driver::{
    Cat, CatSpend, Layer, OptionContract, OptionLauncher, OptionLauncherInfo, OptionType,
    OptionUnderlying, SettlementLayer, SingletonInfo, SpendContext, SpendWithConditions,
    StandardLayer,
};
use chia_sdk_test::{BlsPair, Simulator};
use chia_sdk_types::Conditions;
use xchonnect_core::crypto::sha256_parts;

/// Expiry used by the fixtures: the simulator starts before it.
pub const EXPIRY: u64 = 10;

/// Asset of the collateral.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Collateral {
    Xch,
    Cat,
}

/// The collateral coin, in the shape its spend needs.
#[derive(Debug, Clone, Copy)]
pub enum Locked {
    Xch(Coin),
    Cat(Cat),
}

impl Locked {
    pub fn coin(&self) -> Coin {
        match self {
            Locked::Xch(c) => *c,
            Locked::Cat(cat) => cat.coin,
        }
    }
}

/// A mint, before and after it reached the chain.
pub struct Minted {
    pub spends: Vec<CoinSpend>,
    pub option: OptionContract,
    pub underlying: OptionUnderlying,
    pub locked: Locked,
    pub launcher_id: Bytes32,
}

/// What a mint should look like.
#[derive(Debug, Clone, Copy)]
pub struct MintSpec {
    pub creator: Bytes32,
    pub owner: Bytes32,
    pub amount: u64,
    pub strike: OptionType,
    pub seconds: u64,
    pub collateral: Collateral,
    pub fee: u64,
}

impl MintSpec {
    /// `payer` writes an XCH-backed option for themselves, strike in XCH.
    pub fn simple(payer: &BlsPair) -> Self {
        MintSpec {
            creator: payer.puzzle_hash,
            owner: payer.puzzle_hash,
            amount: 1000,
            strike: OptionType::Xch { amount: 300 },
            seconds: EXPIRY,
            collateral: Collateral::Xch,
            fee: 7,
        }
    }
}

/// A CAT of `amount` issued to `owner` on the simulator.
pub fn issue_cat(sim: &mut Simulator, owner: &BlsPair, amount: u64) -> Cat {
    let coin = sim.new_coin(owner.puzzle_hash, amount);
    let mut ctx = SpendContext::new();
    let hint = ctx.hint(owner.puzzle_hash).unwrap();
    let (issue, cats) = Cat::single_issuance(
        &mut ctx,
        coin.coin_id(),
        None,
        amount,
        Conditions::new().create_coin(owner.puzzle_hash, amount, hint),
    )
    .unwrap();
    StandardLayer::new(owner.pk)
        .spend(&mut ctx, coin, issue)
        .unwrap();
    sim.spend_coins(ctx.take(), std::slice::from_ref(&owner.sk))
        .unwrap();
    cats[0]
}

/// Build (not submit) a mint paid by `payer`. `tamper` may change the launcher info's
/// collateral coin id before minting (adversarial fixtures). The payer's spends require
/// one another (`ASSERT_CONCURRENT_SPEND`), as the Wallet SDK's action system links them.
pub fn mint_with(
    sim: &mut Simulator,
    payer: &BlsPair,
    spec: MintSpec,
    tamper: impl FnOnce(Bytes32, Bytes32) -> Bytes32,
) -> Minted {
    let mut ctx = SpendContext::new();
    let p2 = StandardLayer::new(payer.pk);
    let parent = sim.new_coin(payer.puzzle_hash, 1);
    let launcher = OptionLauncher::new(
        &mut ctx,
        parent.coin_id(),
        OptionLauncherInfo::new(
            spec.creator,
            spec.owner,
            spec.seconds,
            spec.amount,
            spec.strike,
        ),
        1,
    )
    .unwrap();
    let underlying = launcher.underlying();
    let p2_option = launcher.p2_puzzle_hash();
    let tie = Conditions::new().assert_concurrent_spend(parent.coin_id());
    let mut linked = Vec::new();
    let locked = match spec.collateral {
        Collateral::Xch => {
            let funding = sim.new_coin(payer.puzzle_hash, spec.amount + 100);
            p2.spend(
                &mut ctx,
                funding,
                tie.clone()
                    .create_coin(p2_option, spec.amount, Memos::None)
                    .create_coin(payer.puzzle_hash, 100 - spec.fee, Memos::None)
                    .reserve_fee(spec.fee),
            )
            .unwrap();
            linked.push(funding.coin_id());
            Locked::Xch(Coin::new(funding.coin_id(), p2_option, spec.amount))
        }
        Collateral::Cat => {
            let cat = issue_cat(sim, payer, spec.amount);
            let hint = ctx.hint(p2_option).unwrap();
            let inner = p2
                .spend_with_conditions(
                    &mut ctx,
                    tie.clone().create_coin(p2_option, spec.amount, hint),
                )
                .unwrap();
            Cat::spend_all(&mut ctx, &[CatSpend::new(cat, inner)]).unwrap();
            linked.push(cat.coin.coin_id());
            if spec.fee > 0 {
                let fee = sim.new_coin(payer.puzzle_hash, spec.fee);
                p2.spend(&mut ctx, fee, tie.clone().reserve_fee(spec.fee))
                    .unwrap();
                linked.push(fee.coin_id());
            }
            Locked::Cat(cat.child(p2_option, spec.amount))
        }
    };
    let collateral_id = tamper(locked.coin().coin_id(), p2_option);
    let launcher = launcher.with_underlying(collateral_id);
    let launcher_id = launcher.info().launcher_id;
    let (mut mint, option) = launcher.mint(&mut ctx).unwrap();
    for id in linked {
        mint = mint.assert_concurrent_spend(id);
    }
    p2.spend(&mut ctx, parent, mint).unwrap();
    Minted {
        spends: ctx.take(),
        option,
        underlying,
        locked,
        launcher_id,
    }
}

pub fn mint(sim: &mut Simulator, payer: &BlsPair, spec: MintSpec) -> Minted {
    mint_with(sim, payer, spec, |id, _| id)
}

/// Mint on the simulator and return the minted option.
pub fn minted(sim: &mut Simulator, payer: &BlsPair, spec: MintSpec) -> Minted {
    let m = mint(sim, payer, spec);
    sim.spend_coins(m.spends.clone(), std::slice::from_ref(&payer.sk))
        .unwrap();
    m
}

/// The notarized payment that claims the released collateral (a settlement coin) for `to`.
fn claim_payment(to: Bytes32, amount: u64) -> NotarizedPayment {
    NotarizedPayment::new(
        Bytes32::new([0x42; 32]),
        vec![Payment::new(to, amount, Memos::None)],
    )
}

/// Exercise `m` (minted, XCH collateral, XCH strike) as `holder`, who also claims the
/// released collateral. `bind`: the holder's spends assert the claim's announcement and
/// require each other.
pub fn exercise(
    sim: &mut Simulator,
    holder: &BlsPair,
    m: &Minted,
    bind: bool,
    pay_strike: bool,
) -> Vec<CoinSpend> {
    exercise_with(sim, holder, m, bind, bind, pay_strike)
}

/// [`exercise`], with the claim assertion (`bind`) and the link between the holder's
/// spends (`link`) chosen separately.
pub fn exercise_with(
    sim: &mut Simulator,
    holder: &BlsPair,
    m: &Minted,
    bind: bool,
    link: bool,
    pay_strike: bool,
) -> Vec<CoinSpend> {
    let mut ctx = SpendContext::new();
    let p2 = StandardLayer::new(holder.pk);
    let Locked::Xch(coin) = m.locked else {
        panic!("XCH collateral only");
    };
    let amount = coin.amount;
    let claim = claim_payment(holder.puzzle_hash, amount);
    let claim_ptr = ctx.alloc(&claim).unwrap();
    let claim_id = Bytes32::from(sha256_parts(&[
        &SETTLEMENT_PAYMENT_HASH,
        &ctx.tree_hash(claim_ptr).to_bytes(),
    ]));
    let assert = |c: Conditions| {
        if bind {
            c.assert_puzzle_announcement(claim_id)
        } else {
            c
        }
    };
    let strike = m.underlying.strike_type.amount();
    let funding = pay_strike.then(|| sim.new_coin(holder.puzzle_hash, strike));
    let melt = match funding {
        Some(f) if link => Conditions::new().assert_concurrent_spend(f.coin_id()),
        _ => Conditions::new(),
    };
    m.option.exercise(&mut ctx, &p2, assert(melt)).unwrap();
    m.underlying
        .exercise_coin_spend(
            &mut ctx,
            coin,
            m.option.info.inner_puzzle_hash().into(),
            m.option.coin.amount,
        )
        .unwrap();
    // Claim the collateral the exercise sends to the settlement puzzle.
    let released = Coin::new(coin.coin_id(), SETTLEMENT_PAYMENT_HASH.into(), amount);
    let cs = SettlementLayer
        .construct_coin_spend(
            &mut ctx,
            released,
            SettlementPaymentsSolution::new(vec![claim]),
        )
        .unwrap();
    ctx.insert(cs);
    if let Some(funding) = funding {
        let conds = if link {
            Conditions::new().assert_concurrent_spend(m.option.coin.coin_id())
        } else {
            Conditions::new()
        };
        p2.spend(
            &mut ctx,
            funding,
            assert(conds.create_coin(SETTLEMENT_PAYMENT_HASH.into(), strike, Memos::None)),
        )
        .unwrap();
        let strike_coin = Coin::new(funding.coin_id(), SETTLEMENT_PAYMENT_HASH.into(), strike);
        let payment = m.underlying.requested_payment(&mut *ctx).unwrap();
        let cs = SettlementLayer
            .construct_coin_spend(
                &mut ctx,
                strike_coin,
                SettlementPaymentsSolution::new(vec![payment]),
            )
            .unwrap();
        ctx.insert(cs);
    }
    ctx.take()
}

/// The creator takes the collateral of `m` back (valid after expiry).
pub fn clawback(creator: &BlsPair, m: &Minted) -> Vec<CoinSpend> {
    let mut ctx = SpendContext::new();
    let p2 = StandardLayer::new(creator.pk);
    match m.locked {
        Locked::Xch(coin) => {
            let inner = p2
                .spend_with_conditions(
                    &mut ctx,
                    Conditions::new().create_coin(creator.puzzle_hash, coin.amount, Memos::None),
                )
                .unwrap();
            m.underlying
                .clawback_coin_spend(&mut ctx, coin, inner)
                .unwrap();
        }
        Locked::Cat(cat) => {
            let hint = ctx.hint(creator.puzzle_hash).unwrap();
            let inner = p2
                .spend_with_conditions(
                    &mut ctx,
                    Conditions::new().create_coin(creator.puzzle_hash, cat.coin.amount, hint),
                )
                .unwrap();
            let spend = m.underlying.clawback_spend(&mut ctx, inner).unwrap();
            Cat::spend_all(&mut ctx, &[CatSpend::new(cat, spend)]).unwrap();
        }
    }
    ctx.take()
}

/// `holder` transfers the option of `m` to `to`.
pub fn transfer(holder: &BlsPair, m: &Minted, to: Bytes32) -> Vec<CoinSpend> {
    let mut ctx = SpendContext::new();
    let _child = m
        .option
        .transfer(
            &mut ctx,
            &StandardLayer::new(holder.pk),
            to,
            Conditions::new(),
        )
        .unwrap();
    ctx.take()
}
