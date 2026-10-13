//! Option contracts (spec 11.1.1): the wallet recognises the spends of a Chia option
//! (chia-sdk-driver `option` primitives) and states what they do, from the bundle alone.
//!
//! An option is a singleton (launched through the singleton launcher) that commits to one
//! collateral coin (`OptionUnderlying`, a `p2_1_of_n` with two paths) and to the exact
//! exercise it allows: before `expiration_seconds`, the option is melted, the strike is paid
//! to the creator as a settlement payment with nonce = launcher id, and the collateral goes
//! to the settlement puzzle; after expiry the creator takes the collateral back.
//!
//! Nothing here is taken from what a dApp says. Every recognised fact is recomputed from the
//! revealed puzzles and their conditions, and a spend is only classified when the whole chain
//! of commitments checks out within the request:
//!
//! - **Mint:** the launcher (at most 1 mojo) is spent in the request, created by a spend in
//!   the request; the eve option singleton (1 mojo) is its only child; the launcher's
//!   metadata (expiry, strike), the creator (the launcher's hint) and the collateral coin
//!   created in the request rebuild both the collateral's puzzle hash and the delegated
//!   puzzle hash the option commits to. It is *guaranteed* only when the user's own signed
//!   spends fix it all ([`OptionEffect::Mint::guaranteed`]).
//! - **Transfer:** the option singleton creates its one odd child, whose puzzle hash is
//!   recomputed from the new owner the inner puzzle chose.
//! - **Exercise:** the option is melted, its collateral coin is spent in the request, and a
//!   settlement payment with nonce = launcher id (the strike) rebuilds the collateral's
//!   puzzle hash and the option's delegated puzzle hash.
//! - **Clawback:** a `p2_1_of_n` with exactly two leaves whose revealed leaf is
//!   `augmented_condition(ASSERT_SECONDS_ABSOLUTE expiry, creator)`. The other leaf (the
//!   exercise path) commits to the launcher id by hash only, so the option is named only
//!   when the request also spends it.
//!
//! Revocable-CAT and NFT strikes or collateral are not shown. Anything that does not verify
//! keeps its previous classification (usually `Unknown`, which is refused unless the user
//! allows unknown contracts): fail closed.

use crate::simulate::{AssetId, ExecutedSpend, Ownership, SpendKind, ser_hex32, ser_opt_hex32};
use chia_protocol::{Bytes32, Coin};
use chia_puzzle_types::Proof;
use chia_puzzle_types::cat::CatSolution;
use chia_puzzle_types::offer::SettlementPaymentsSolution;
use chia_puzzle_types::singleton::{LauncherSolution, SingletonArgs};
use chia_puzzles::{AUGMENTED_CONDITION_HASH, SETTLEMENT_PAYMENT_HASH, SINGLETON_LAUNCHER_HASH};
use chia_sdk_driver::{
    CatInfo, Layer, OptionContract, OptionMetadata, OptionType, OptionUnderlying, P2OneOfManyLayer,
    Puzzle,
};
use chia_sdk_types::puzzles::{
    AugmentedConditionArgs, OptionContractArgs, P2OneOfManySolution, RevocationSolution,
};
use chia_sdk_types::{Condition, Mod, run_puzzle_with_cost};
use clvm_traits::FromClvm;
use clvm_utils::{ToTreeHash, TreeHash, tree_hash};
use clvmr::{Allocator, NodePtr, SExp};
use serde::Serialize;
use std::collections::HashMap;
use xchonnect_core::crypto::sha256_parts;

/// An amount of one asset (smallest units).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct OptionLeg {
    /// Asset.
    pub asset: AssetId,
    /// Amount.
    pub amount: u64,
}

/// The terms of an option, proven by the request (never taken from the dApp).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct OptionTerms {
    /// Who receives the strike on exercise and may take the collateral back after expiry
    /// (p2 puzzle hash, hex). For an option used as a loan, the lender.
    #[serde(serialize_with = "ser_hex32")]
    pub creator_puzzle_hash: Bytes32,
    /// Unix time: exercise is possible strictly before it, clawback from it on.
    pub expiration_seconds: u64,
    /// What is locked and what the option holder receives on exercise.
    pub collateral: OptionLeg,
    /// What the option holder pays the creator to exercise.
    pub strike: OptionLeg,
}

/// What an option singleton spend does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionAction {
    /// The eve spend of a newly launched option.
    Mint,
    /// The option moves to a new owner (possibly the same one).
    Transfer,
    /// The option is melted to exercise it.
    Exercise,
}

/// Which path of the collateral coin is spent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnderlyingPath {
    /// Released by the option's exercise, to the settlement puzzle.
    Exercise,
    /// Taken back by the creator after expiry.
    Clawback,
}

/// Role of an output the user's spends create for an option.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionOutputRole {
    /// The collateral coin: locked under the option, not paid to anyone.
    Collateral,
    /// The singleton launcher coin of the option being minted.
    Launcher,
}

/// Marks an output that belongs to an option mint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct OptionOutput {
    /// The option (launcher id, hex).
    #[serde(serialize_with = "ser_hex32")]
    pub launcher_id: Bytes32,
    /// What the output is.
    pub role: OptionOutputRole,
    /// The user holds the new option, its launch is guaranteed and the request does not
    /// move it on: the output stays under the user's control (exercise, or clawback by its
    /// creator) and is not a payment. Otherwise it is a payment to the option's owner
    /// (spec 9.1, 11.1.1).
    pub user_holds_option: bool,
}

/// What a request does with an option, for the approval prompt (spec 11.1.1). Every field
/// is computed by the wallet. `#[non_exhaustive]`, as are its variants: later versions may
/// add effects and fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
#[non_exhaustive]
pub enum OptionEffect {
    /// A new option is launched and its collateral locked.
    #[non_exhaustive]
    Mint {
        /// Option id (launcher id, hex).
        #[serde(serialize_with = "ser_hex32")]
        launcher_id: Bytes32,
        /// Who holds the new option (p2 puzzle hash, hex).
        #[serde(serialize_with = "ser_hex32")]
        owner: Bytes32,
        /// The user holds the new option.
        owner_is_user: bool,
        /// The user is the creator: receives the strike, may take the collateral back.
        creator_is_user: bool,
        /// The collateral comes from the user's own coins.
        funded_by_user: bool,
        /// The user's own spends fix the whole mint: the collateral is created by a user
        /// spend, a user spend asserts the launcher's announcement, those two spends require
        /// each other, and the eve spend's outputs are fixed (a quoted inner puzzle, or the
        /// user's own). Otherwise the new option, or its collateral, is only conditional.
        guaranteed: bool,
        /// Collateral coin id (hex).
        #[serde(serialize_with = "ser_hex32")]
        collateral_coin_id: Bytes32,
        /// Terms.
        terms: OptionTerms,
    },
    /// An existing option changes owner.
    #[non_exhaustive]
    Transfer {
        /// Option id (hex).
        #[serde(serialize_with = "ser_hex32")]
        launcher_id: Bytes32,
        /// The user held it.
        from_user: bool,
        /// New owner (p2 puzzle hash, hex).
        #[serde(serialize_with = "ser_hex32")]
        to: Bytes32,
        /// The new owner is the user.
        to_user: bool,
        /// The new owner is the offer settlement puzzle: the option is offered, and whoever
        /// takes the offer receives it.
        to_settlement: bool,
    },
    /// An option is exercised: strike to the creator, collateral to the settlement puzzle.
    #[non_exhaustive]
    Exercise {
        /// Option id (hex).
        #[serde(serialize_with = "ser_hex32")]
        launcher_id: Bytes32,
        /// The user holds the option and exercises it.
        by_user: bool,
        /// The user is the creator (receives the strike).
        creator_is_user: bool,
        /// Terms.
        terms: OptionTerms,
    },
    /// Collateral taken back by its creator after expiry.
    #[non_exhaustive]
    Clawback {
        /// Option id (hex) when the request proves it; the clawback path commits to it by
        /// hash only.
        #[serde(serialize_with = "ser_opt_hex32")]
        launcher_id: Option<Bytes32>,
        /// Creator (p2 puzzle hash, hex).
        #[serde(serialize_with = "ser_hex32")]
        creator: Bytes32,
        /// The user is the creator.
        creator_is_user: bool,
        /// The collateral coin's asset and amount.
        collateral: OptionLeg,
        /// Unix time from which the clawback is valid (the option's expiry).
        unlocks_at_seconds: u64,
    },
}

/// A spend's revealed puzzle and solution, already run by `execute`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Revealed {
    pub(crate) puzzle: NodePtr,
    pub(crate) solution: NodePtr,
    /// CLVM cost of the run, the budget for re-running its inner puzzle.
    pub(crate) cost: u64,
}

/// An option singleton spend that parsed and is consistent with its own coin.
#[derive(Debug, Clone, Copy)]
struct ParsedOption {
    index: usize,
    launcher_id: Bytes32,
    underlying_coin_id: Bytes32,
    delegated_puzzle_hash: Bytes32,
    p2_puzzle_hash: Bytes32,
    amount: u64,
    eve: bool,
    /// The odd child's new p2 puzzle hash; `None` when melted.
    new_owner: Option<Bytes32>,
    /// The inner puzzle is a quoted program: its outputs do not depend on the solution.
    fixed_outputs: bool,
}

/// A coin created by a spend of the request.
#[derive(Debug, Clone, Copy)]
struct Created {
    spend: usize,
    puzzle_hash: Bytes32,
    amount: u64,
    hint: Option<Bytes32>,
}

/// A payment in a settlement spend of the request (a candidate strike).
#[derive(Debug, Clone, Copy)]
struct SettlementPayment {
    nonce: Bytes32,
    puzzle_hash: Bytes32,
    amount: u64,
    asset: AssetId,
    hidden_puzzle_hash: Option<Bytes32>,
}

impl SettlementPayment {
    fn strike_type(&self) -> OptionType {
        match (self.asset, self.hidden_puzzle_hash) {
            (AssetId::Cat(asset_id), None) => OptionType::Cat {
                asset_id,
                amount: self.amount,
            },
            (AssetId::Cat(asset_id), Some(hidden_puzzle_hash)) => OptionType::RevocableCat {
                asset_id,
                hidden_puzzle_hash,
                amount: self.amount,
            },
            _ => OptionType::Xch {
                amount: self.amount,
            },
        }
    }
}

/// Strike as an asset, or `None` for strike types the wallet does not show (NFT, revocable
/// CAT).
fn strike_leg(strike: &OptionType) -> Option<OptionLeg> {
    match *strike {
        OptionType::Xch { amount } => Some(OptionLeg {
            asset: AssetId::Xch,
            amount,
        }),
        OptionType::Cat { asset_id, amount } => Some(OptionLeg {
            asset: AssetId::Cat(asset_id),
            amount,
        }),
        // A revocable CAT can be taken back by its issuer, which `OptionLeg` cannot state:
        // not shown, so the spend stays unknown (spec 11.1.1).
        OptionType::RevocableCat { .. } | OptionType::Nft { .. } => None,
    }
}

/// Reclassify the option-related spends of an executed request. Only spends whose kind is
/// `Unknown` (or a CAT whose inner puzzle is the collateral) are considered; `owned` is
/// recomputed for every spend that changes kind.
pub(crate) fn classify(
    a: &mut Allocator,
    revealed: &[Revealed],
    executed: &mut [ExecutedSpend],
    ownership: &Ownership,
) {
    let options: Vec<ParsedOption> = executed
        .iter()
        .zip(revealed)
        .enumerate()
        .filter_map(|(i, (es, rev))| parse_option(a, i, rev, es))
        .collect();
    let created = created_coins(executed);
    let payments = settlement_payments(a, revealed, executed);

    let mut kinds: HashMap<usize, SpendKind> = HashMap::new();
    let mut mints: Vec<(&ParsedOption, VerifiedMint)> = Vec::new();
    for opt in &options {
        if opt.eve {
            if let Some(mint) = verify_mint(a, opt, revealed, executed, &created) {
                kinds.insert(
                    mint.launcher,
                    SpendKind::SingletonLauncher {
                        launcher_id: opt.launcher_id,
                    },
                );
                kinds.insert(
                    opt.index,
                    option_kind(opt, OptionAction::Mint, Some(mint.terms)),
                );
                mints.push((opt, mint));
            }
        } else if opt.new_owner.is_some() {
            kinds.insert(opt.index, option_kind(opt, OptionAction::Transfer, None));
        } else if let Some((underlying, kind, terms)) = verify_exercise(opt, executed, &payments) {
            kinds.insert(underlying, kind);
            kinds.insert(
                opt.index,
                option_kind(opt, OptionAction::Exercise, Some(terms)),
            );
        }
    }
    for (i, (es, rev)) in executed.iter().zip(revealed).enumerate() {
        if kinds.contains_key(&i) {
            continue;
        }
        if let Some(kind) = parse_clawback(a, rev, es, &options) {
            kinds.insert(i, kind);
        }
    }

    for (i, kind) in kinds {
        let Some(es) = executed.get_mut(i) else {
            continue;
        };
        es.owned = match &kind {
            SpendKind::Option { p2_puzzle_hash, .. } => ownership.owns(p2_puzzle_hash),
            SpendKind::OptionUnderlying {
                path: UnderlyingPath::Clawback,
                creator_puzzle_hash,
                ..
            } => ownership.owns(creator_puzzle_hash),
            _ => false,
        };
        es.kind = kind;
    }
    // Guaranteed launches, decided on the final ownership of every spend.
    let requires = crate::binding::Requirements::new(executed);
    let guaranteed: Vec<usize> = mints
        .iter()
        .filter(|(opt, mint)| mint_guaranteed(opt, mint, executed, ownership, &requires))
        .map(|(opt, _)| opt.index)
        .collect();
    for i in guaranteed {
        if let Some(es) = executed.get_mut(i) {
            es.outputs_bound = true;
        }
    }
}

/// A mint whose commitments verified.
#[derive(Debug, Clone)]
struct VerifiedMint {
    /// The launcher's spend.
    launcher: usize,
    /// The spend that creates the collateral coin.
    funder: usize,
    /// Spends that assert the launcher's announcement (fixing the eve's puzzle and the
    /// option's metadata).
    asserters: Vec<usize>,
    terms: OptionTerms,
}

/// Spec 11.1.1 item 1: the launch, the eve's outputs and the collateral are all fixed by the
/// user's own signed spends, which include one another.
///
/// - The eve's outputs are fixed: a quoted inner puzzle, or the user's own puzzle.
/// - The collateral is created by a user spend. A counterparty's spend that funds it can
///   always be replaced by one that keeps the money while making the same announcements,
///   so nothing a user spend asserts about it binds its outputs (audit SA-H2).
/// - A user spend asserts the launcher's announcement, and it and the funding spend require
///   each other (`ASSERT_CONCURRENT_SPEND` or coin announcements in the user's signed
///   conditions): neither the collateral nor the launch can be included without the other.
fn mint_guaranteed(
    opt: &ParsedOption,
    mint: &VerifiedMint,
    executed: &[ExecutedSpend],
    ownership: &Ownership,
    requires: &crate::binding::Requirements,
) -> bool {
    let eve_fixed = opt.fixed_outputs || ownership.owns(&opt.p2_puzzle_hash);
    let funded_by_user = executed.get(mint.funder).is_some_and(|es| es.owned);
    eve_fixed
        && funded_by_user
        && mint.asserters.iter().any(|&a| {
            executed.get(a).is_some_and(|es| es.owned)
                && requires.reaches(a, mint.funder)
                && requires.reaches(mint.funder, a)
        })
}

fn option_kind(opt: &ParsedOption, action: OptionAction, terms: Option<OptionTerms>) -> SpendKind {
    SpendKind::Option {
        launcher_id: opt.launcher_id,
        p2_puzzle_hash: opt.p2_puzzle_hash,
        underlying_coin_id: opt.underlying_coin_id,
        underlying_delegated_puzzle_hash: opt.delegated_puzzle_hash,
        action,
        new_owner: opt.new_owner,
        terms,
    }
}

/// Every `ASSERT_MY_*` condition of a spend agrees with the coin it claims to spend, and the
/// spend asserts its parent (the singleton's lineage check). A spend that fails this could
/// never be valid on chain, so it is not shown as an option.
fn self_consistent(es: &ExecutedSpend) -> bool {
    let mut parent = false;
    for c in &es.conditions {
        let ok = match c {
            Condition::AssertMyParentId(p) => {
                parent = true;
                p.parent_id == es.coin.parent_coin_info
            }
            Condition::AssertMyCoinId(p) => p.coin_id == es.coin.coin_id(),
            Condition::AssertMyAmount(p) => p.amount == es.coin.amount,
            Condition::AssertMyPuzzleHash(p) => p.puzzle_hash == es.coin.puzzle_hash,
            _ => true,
        };
        if !ok {
            return false;
        }
    }
    parent
}

fn is_quote(a: &Allocator, node: NodePtr) -> bool {
    match a.sexp(node) {
        SExp::Pair(first, _) => {
            matches!(a.sexp(first), SExp::Atom) && a.atom(first).as_ref() == [1u8]
        }
        SExp::Atom => false,
    }
}

/// Full puzzle hash of an option singleton owned by `p2`.
pub(crate) fn option_puzzle_hash(
    launcher_id: Bytes32,
    underlying_coin_id: Bytes32,
    delegated_puzzle_hash: Bytes32,
    p2: Bytes32,
) -> Bytes32 {
    SingletonArgs::curry_tree_hash(
        launcher_id,
        OptionContractArgs::new(
            underlying_coin_id,
            delegated_puzzle_hash,
            TreeHash::from(p2),
        )
        .curry_tree_hash(),
    )
    .into()
}

fn parse_option(
    a: &mut Allocator,
    index: usize,
    rev: &Revealed,
    es: &ExecutedSpend,
) -> Option<ParsedOption> {
    if es.kind != SpendKind::Unknown {
        return None;
    }
    let puzzle = Puzzle::parse(a, rev.puzzle);
    let (option, p2, p2_solution) = OptionContract::parse(a, es.coin, puzzle, rev.solution)
        .ok()
        .flatten()?;
    if !self_consistent(es) {
        return None;
    }
    let info = option.info;
    // Re-run the owner's inner puzzle to learn the new owner the singleton wrapped.
    let output = run_puzzle_with_cost(a, p2.ptr(), p2_solution, rev.cost, true).ok()?;
    let inner = Vec::<Condition<NodePtr>>::from_clvm(a, output.1).ok()?;
    let mut odd = inner.iter().filter_map(|c| match c {
        Condition::CreateCoin(cc) if cc.amount % 2 == 1 => Some(cc),
        _ => None,
    });
    let child = odd.next();
    if odd.next().is_some() {
        return None;
    }
    let melted = inner
        .iter()
        .any(|c| matches!(c, Condition::MeltSingleton(_)));
    let new_owner = match (child, melted) {
        (Some(cc), false) => {
            let full = option_puzzle_hash(
                info.launcher_id,
                info.underlying_coin_id,
                info.underlying_delegated_puzzle_hash,
                cc.puzzle_hash,
            );
            let wrapped = es.conditions.iter().any(|c| {
                matches!(c, Condition::CreateCoin(out)
                    if out.puzzle_hash == full && out.amount == cc.amount)
            });
            if !wrapped {
                return None;
            }
            Some(cc.puzzle_hash)
        }
        (None, true) => None,
        _ => return None,
    };
    Some(ParsedOption {
        index,
        launcher_id: info.launcher_id,
        underlying_coin_id: info.underlying_coin_id,
        delegated_puzzle_hash: info.underlying_delegated_puzzle_hash,
        p2_puzzle_hash: info.p2_puzzle_hash,
        amount: es.coin.amount,
        eve: matches!(option.proof, Proof::Eve(_)),
        new_owner,
        fixed_outputs: is_quote(a, p2.ptr()),
    })
}

/// Every coin created in the request, by coin id.
fn created_coins(executed: &[ExecutedSpend]) -> HashMap<Bytes32, Created> {
    let mut out = HashMap::new();
    for (i, es) in executed.iter().enumerate() {
        let parent = es.coin.coin_id();
        let mut hints = es.hints.iter();
        for c in &es.conditions {
            if let Condition::CreateCoin(cc) = c {
                let hint = hints.next().copied().flatten();
                out.insert(
                    Coin::new(parent, cc.puzzle_hash, cc.amount).coin_id(),
                    Created {
                        spend: i,
                        puzzle_hash: cc.puzzle_hash,
                        amount: cc.amount,
                        hint,
                    },
                );
            }
        }
    }
    out
}

/// The settlement-payments solution inside a settlement spend (XCH, CAT or revocable CAT).
fn settlement_inner(
    a: &Allocator,
    es: &ExecutedSpend,
    solution: NodePtr,
) -> Option<(AssetId, Option<Bytes32>, NodePtr)> {
    let settlement = Bytes32::from(SETTLEMENT_PAYMENT_HASH);
    match &es.kind {
        SpendKind::Settlement => Some((AssetId::Xch, None, solution)),
        SpendKind::Cat {
            asset_id,
            p2_puzzle_hash,
            hidden_puzzle_hash,
        } if *p2_puzzle_hash == settlement => {
            let inner = CatSolution::<NodePtr>::from_clvm(a, solution)
                .ok()?
                .inner_puzzle_solution;
            let inner = match hidden_puzzle_hash {
                None => inner,
                Some(_) => {
                    RevocationSolution::<NodePtr, NodePtr>::from_clvm(a, inner)
                        .ok()?
                        .solution
                }
            };
            Some((AssetId::Cat(*asset_id), *hidden_puzzle_hash, inner))
        }
        _ => None,
    }
}

fn settlement_payments(
    a: &Allocator,
    revealed: &[Revealed],
    executed: &[ExecutedSpend],
) -> Vec<SettlementPayment> {
    let mut out = Vec::new();
    for (es, rev) in executed.iter().zip(revealed) {
        let Some((asset, hidden_puzzle_hash, inner)) = settlement_inner(a, es, rev.solution) else {
            continue;
        };
        let Ok(parsed) = SettlementPaymentsSolution::<NodePtr>::from_clvm(a, inner) else {
            continue;
        };
        for np in parsed.notarized_payments {
            for p in np.payments {
                out.push(SettlementPayment {
                    nonce: np.nonce,
                    puzzle_hash: p.puzzle_hash,
                    amount: p.amount,
                    asset,
                    hidden_puzzle_hash,
                });
            }
        }
    }
    out
}

/// The CAT wrapping of a spend's outputs, if its asset is a CAT.
fn cat_wrapping(kind: &SpendKind) -> Option<(Bytes32, Option<Bytes32>)> {
    match kind {
        SpendKind::Cat {
            asset_id,
            hidden_puzzle_hash,
            ..
        } => Some((*asset_id, *hidden_puzzle_hash)),
        _ => None,
    }
}

/// Mint: the launcher, the collateral's funder and the spends asserting the launch.
fn verify_mint(
    a: &mut Allocator,
    opt: &ParsedOption,
    revealed: &[Revealed],
    executed: &[ExecutedSpend],
    created: &HashMap<Bytes32, Created>,
) -> Option<VerifiedMint> {
    let launcher_ph = Bytes32::from(SINGLETON_LAUNCHER_HASH);
    let eve = executed.get(opt.index)?;
    // One mojo, as every wallet mints: a larger eve (or launcher, below) would carry value
    // to the option's holder that no field states (audit SA-H1).
    if eve.coin.parent_coin_info != opt.launcher_id || opt.amount != 1 {
        return None;
    }
    let (l, launcher) = executed.iter().enumerate().find(|(_, es)| {
        es.coin.coin_id() == opt.launcher_id
            && es.coin.puzzle_hash == launcher_ph
            && es.kind == SpendKind::Unknown
    })?;
    let solution =
        LauncherSolution::<OptionMetadata>::from_clvm(a, revealed.get(l)?.solution).ok()?;
    if solution.singleton_puzzle_hash != eve.coin.puzzle_hash || solution.amount != eve.coin.amount
    {
        return None;
    }
    let metadata = solution.key_value_list;
    let strike = strike_leg(&metadata.strike_type)?;

    // The launcher was created in this request; its hint names the creator.
    // The launcher carries at most the eve's one mojo (the Wallet SDK launches from a
    // 0-mojo launcher, the eve's mojo coming from the bundle's surplus).
    let made = created.get(&opt.launcher_id)?;
    if made.puzzle_hash != launcher_ph || made.amount != launcher.coin.amount || made.amount > 1 {
        return None;
    }
    let creator = made.hint?;

    // The collateral coin was created in this request, as XCH or a CAT.
    let collateral = created.get(&opt.underlying_coin_id)?;
    let funder = executed.get(collateral.spend)?;
    let wrapping = match &funder.kind {
        SpendKind::Standard => None,
        // A revocable CAT can be taken back by its issuer: not shown as collateral.
        SpendKind::Cat {
            hidden_puzzle_hash: Some(_),
            ..
        } => return None,
        kind @ SpendKind::Cat { .. } => Some(cat_wrapping(kind)?),
        _ => return None,
    };
    let underlying = OptionUnderlying::new(
        opt.launcher_id,
        creator,
        metadata.expiration_seconds,
        collateral.amount,
        metadata.strike_type,
    );
    let p2 = Bytes32::from(underlying.tree_hash());
    let expected = match wrapping {
        None => p2,
        Some((asset_id, hidden)) => Bytes32::from(CatInfo::new(asset_id, hidden, p2).puzzle_hash()),
    };
    if collateral.puzzle_hash != expected
        || Bytes32::from(underlying.delegated_puzzle().tree_hash()) != opt.delegated_puzzle_hash
    {
        return None;
    }

    // The spends asserting the launcher's announcement (whether they are the user's is
    // decided once every spend is classified).
    let ids: Vec<Bytes32> = launcher
        .conditions
        .iter()
        .filter_map(|c| match c {
            Condition::CreateCoinAnnouncement(ann) => Some(Bytes32::from(sha256_parts(&[
                opt.launcher_id.as_ref(),
                ann.message.as_ref(),
            ]))),
            _ => None,
        })
        .collect();
    let asserters = executed
        .iter()
        .enumerate()
        .filter(|(_, es)| {
            es.conditions.iter().any(
                |c| matches!(c, Condition::AssertCoinAnnouncement(x) if ids.contains(&x.announcement_id)),
            )
        })
        .map(|(i, _)| i)
        .collect();
    let terms = OptionTerms {
        creator_puzzle_hash: creator,
        expiration_seconds: metadata.expiration_seconds,
        collateral: OptionLeg {
            asset: wrapping.map_or(AssetId::Xch, |(asset_id, _)| AssetId::Cat(asset_id)),
            amount: collateral.amount,
        },
        strike,
    };
    Some(VerifiedMint {
        launcher: l,
        funder: collateral.spend,
        asserters,
        terms,
    })
}

/// Exercise: returns the collateral spend's index and kind, and the terms.
fn verify_exercise(
    opt: &ParsedOption,
    executed: &[ExecutedSpend],
    payments: &[SettlementPayment],
) -> Option<(usize, SpendKind, OptionTerms)> {
    let (u, es) = executed
        .iter()
        .enumerate()
        .find(|(_, es)| es.coin.coin_id() == opt.underlying_coin_id)?;
    let (p2, asset, hidden) = match &es.kind {
        SpendKind::Unknown => (es.coin.puzzle_hash, AssetId::Xch, None),
        // Revocable collateral is not shown (as in a mint).
        SpendKind::Cat {
            asset_id,
            p2_puzzle_hash,
            hidden_puzzle_hash: None,
        } => (*p2_puzzle_hash, AssetId::Cat(*asset_id), None),
        _ => return None,
    };
    // The exercise path emits exactly one deadline: the expiry.
    let mut deadlines = es.conditions.iter().filter_map(|c| match c {
        Condition::AssertBeforeSecondsAbsolute(t) => Some(t.seconds),
        _ => None,
    });
    let seconds = deadlines.next()?;
    if deadlines.any(|t| t != seconds) {
        return None;
    }
    let payment = payments.iter().find(|p| {
        let underlying = OptionUnderlying::new(
            opt.launcher_id,
            p.puzzle_hash,
            seconds,
            es.coin.amount,
            p.strike_type(),
        );
        p.nonce == opt.launcher_id
            && Bytes32::from(underlying.tree_hash()) == p2
            && Bytes32::from(underlying.delegated_puzzle().tree_hash()) == opt.delegated_puzzle_hash
    })?;
    let terms = OptionTerms {
        creator_puzzle_hash: payment.puzzle_hash,
        expiration_seconds: seconds,
        collateral: OptionLeg {
            asset,
            amount: es.coin.amount,
        },
        strike: strike_leg(&payment.strike_type())?,
    };
    let kind = SpendKind::OptionUnderlying {
        launcher_id: Some(opt.launcher_id),
        creator_puzzle_hash: payment.puzzle_hash,
        expiration_seconds: seconds,
        path: UnderlyingPath::Exercise,
        asset,
        hidden_puzzle_hash: hidden,
    };
    Some((u, kind, terms))
}

/// Clawback: a two-leaf `p2_1_of_n` (bare, or inside a CAT without revocation) spent through
/// `augmented_condition(ASSERT_SECONDS_ABSOLUTE t, creator)`.
fn parse_clawback(
    a: &Allocator,
    rev: &Revealed,
    es: &ExecutedSpend,
    options: &[ParsedOption],
) -> Option<SpendKind> {
    let (p2, p2_solution, asset) = match &es.kind {
        SpendKind::Unknown => (rev.puzzle, rev.solution, AssetId::Xch),
        SpendKind::Cat {
            asset_id,
            hidden_puzzle_hash: None,
            ..
        } => {
            let (_, inner) = CatInfo::parse(a, Puzzle::parse(a, rev.puzzle)).ok()??;
            let solution = CatSolution::<NodePtr>::from_clvm(a, rev.solution)
                .ok()?
                .inner_puzzle_solution;
            (inner?.ptr(), solution, AssetId::Cat(*asset_id))
        }
        _ => return None,
    };
    let layer = P2OneOfManyLayer::parse_puzzle(a, Puzzle::parse(a, p2)).ok()??;
    let solution = P2OneOfManySolution::<NodePtr, NodePtr>::from_clvm(a, p2_solution).ok()?;
    let curried = Puzzle::parse(a, solution.puzzle).as_curried()?;
    if curried.mod_hash != TreeHash::new(AUGMENTED_CONDITION_HASH) {
        return None;
    }
    let args = AugmentedConditionArgs::<NodePtr, NodePtr>::from_clvm(a, curried.args).ok()?;
    let Condition::AssertSecondsAbsolute(t) = args.condition else {
        return None;
    };
    let creator = Bytes32::from(tree_hash(a, args.inner_puzzle));
    let leaf = Bytes32::from(tree_hash(a, solution.puzzle));
    // The option's tree is [exercise path, clawback path]: a two-leaf tree whose second leaf
    // is the one revealed, so the proof is one node (the hashed exercise leaf) at path 1.
    let [sibling] = solution.merkle_proof.proof.as_slice() else {
        return None;
    };
    if solution.merkle_proof.path != 1 {
        return None;
    }
    let root = Bytes32::from(sha256_parts(&[
        &[2],
        sibling.as_ref(),
        &sha256_parts(&[&[1], leaf.as_ref()]),
    ]));
    if root != layer.merkle_root {
        return None;
    }
    let launcher_id = options.iter().map(|o| o.launcher_id).find(|l| {
        let exercise = OptionUnderlying::new(
            *l,
            creator,
            t.seconds,
            es.coin.amount,
            OptionType::Xch { amount: 0 },
        )
        .exercise_path_hash();
        Bytes32::from(sha256_parts(&[&[1], exercise.as_ref()])) == *sibling
    });
    Some(SpendKind::OptionUnderlying {
        launcher_id,
        creator_puzzle_hash: creator,
        expiration_seconds: t.seconds,
        path: UnderlyingPath::Clawback,
        asset,
        hidden_puzzle_hash: None,
    })
}
