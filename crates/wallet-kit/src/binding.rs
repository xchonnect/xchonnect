//! Multi-party spend binding (spec 11.2, invariant 13.4 item 4, threat T2), and the
//! coverage of an option exercise (spec 11.1.1).
//!
//! Before producing a partial signature the wallet must be sure that none of its spends
//! can be included on-chain without the counterparty delivering what the user expects.
//!
//! **Settlement announcements.** A user spend *asserts a payment* when it asserts a puzzle
//! announcement created by an offer **settlement payments** spend in the request (XCH
//! settlement puzzle, the settlement puzzle inside a CAT, or an option singleton whose
//! owner is the settlement puzzle). The settlement puzzle announces `sha256tree(np)` only
//! while creating exactly those payments, so the assertion
//! `sha256(settlement_puzzle_hash || sha256tree(np))` can only be satisfied by a spend that
//! pays them. Announcements from any other puzzle never bind: their creator can produce
//! them without paying. `SEND_MESSAGE` / `RECEIVE_MESSAGE` bindings are not recognised yet
//! (refused).
//!
//! **Linking ([`Linking`]).** Whether one user spend may stand in for another depends on
//! who can hold the user's signatures:
//!
//! - [`Linking::Direct`] — the signatures are **released** (every `signCoinSpends`, every
//!   dApp-built bundle, a signed offer such as a loan request). Only direct binding counts:
//!   every user spend must itself assert **every** settlement announcement that any user
//!   spend asserts. No link between two spends counts. A coin announcement names a coin
//!   and a message, not a spend, and `ASSERT_CONCURRENT_SPEND` names only a coin: a dApp
//!   that holds the signature of one spend of the request (it can ask for that spend on its
//!   own first, and subtract it from the aggregate) and another signed spend of the same
//!   coin making the same announcement can put the one in place of the other (final audit
//!   F1, re-audit N2).
//! - [`Linking::Sealed`] — a wallet-built request whose signatures never leave the wallet
//!   (it broadcasts the bundle itself and returns only the transaction id), in which no
//!   coin of a user spend has a signature outside the wallet ([`crate::SignedCoins`]),
//!   every user spend is signed with `AGG_SIG_ME` only, the user's spends reserve exactly
//!   the fee the wallet chose, and (with more than one) every user spend requires every
//!   other through the links below. Each user signature then exists
//!   only inside the one aggregate, which can be used only whole: the user's spends are
//!   included together or not at all. The links Sage's builders make between the user's
//!   spends count: a user spend is bound if it asserts a payment, or requires a bound user
//!   spend through `ASSERT_CONCURRENT_SPEND` of its coin or a coin announcement it makes in
//!   its signed conditions. A CAT's ring announcements (`0xcb…`, derived from the solution)
//!   and puzzle announcements never link.
//!
//! A user spend is every spend the wallet signs ([`crate::simulate::claim_signed`]),
//! whether or not it recognises the coin. A multi-party request (partial, completed by
//! another party's signature, or spending another party's coin) is signable only if
//! **every** user spend is bound; otherwise any unbound coin could be submitted on its own.
//!
//! **Exercise coverage (spec 11.1.1).** An exercise releases the collateral to the
//! settlement puzzle, where anyone may claim it. The user's spends are signed only if they
//! are co-required ([`BindingReport::co_required`]: under `Direct` every user spend asserts
//! every payment the user's spends assert; under `Sealed` every user spend reaches every
//! other) and, in each collateral asset `X`:
//!
//! ```text
//! outcome(X) + Σ min(collateral_e, strike_e) + fee_credit  >=  Σ collateral_e
//! ```
//!
//! over the options `e` the user exercises whose collateral is in `X`; the strike term
//! counts only for an option whose strike is also in `X`. `outcome(X)` is the user's
//! guaranteed change in `X`, from the payments the user's spends assert and the user's own
//! spends. Under `Sealed` it is the whole request's: what the user's spends pay to the user,
//! plus asserted payments to the user, minus everything the user's spends remove, minus
//! collateral clawed back in the same request (so collateral the user's change absorbs
//! counts). Under `Direct` any subset of the user's spends may reach the chain, so each
//! user spend counts only when it loses (`min(0, paid to the user − removed − clawed)`),
//! plus the payments every user spend asserts. `fee_credit` (XCH only) is the user's own
//! reserved fee: under `Direct` up to the XCH the user's own spends put into the bundle
//! (removed minus created; released collateral that becomes the fee is not received,
//! re-audit N3); under `Sealed` up to the bundle's fee and the fee the wallet chose
//! ([`crate::SubmitRequest::wallet_fee`]), which the user approved. Under `Sealed` the
//! mojos of a melted option count as one mojo per option. So the user ends at least `Σ max(0, collateral_e - strike_e)` less the fee:
//! each option is worth at most its own collateral, and an out-of-the-money option cannot
//! offset another (re-audit N1). Every other payment counts as spent, so a "refund" of the
//! user's own money never covers the collateral (audit SA-H3).

use crate::error::KitError;
use crate::option::OptionAction;
use crate::option::OptionEffect;
use crate::simulate::{
    AssetId, ExecutedSpend, Ownership, SpendKind, Summary, asset_of, claim_signed, execute,
    summarize,
};
use chia_bls::PublicKey;
use chia_protocol::{Bytes32, CoinSpend};
use chia_puzzle_types::cat::CatSolution;
use chia_puzzle_types::offer::{NotarizedPayment, SettlementPaymentsSolution};
use chia_puzzles::SETTLEMENT_PAYMENT_HASH;
use chia_sdk_driver::{OptionContract, Puzzle};
use chia_sdk_types::Condition;
use clvm_traits::{FromClvm, ToClvm};
use clvm_utils::tree_hash;
use clvmr::{Allocator, NodePtr};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use xchonnect_core::crypto::sha256_parts;

/// Which links between the user's spends count (spec 11.2; the module documentation has the
/// rules).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Linking {
    /// The request's signatures are released (returned to the dApp, or a dApp-built bundle):
    /// only direct binding counts. The default.
    #[default]
    Direct,
    /// A wallet-built request whose signatures never leave the wallet, every user spend
    /// sealed (its coin has no signature outside the wallet, `AGG_SIG_ME` only):
    /// `ASSERT_CONCURRENT_SPEND` and coin announcements between the user's spends link
    /// them.
    Sealed,
}

/// A payment to the user guaranteed by an asserted settlement announcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BoundPayment {
    /// User spend that asserts it.
    pub user_spend: usize,
    /// Settlement spend that announces it.
    pub settlement_spend: usize,
    /// Asset paid.
    pub asset: AssetId,
    /// Amount paid to the user's puzzle hashes.
    pub amount: u128,
}

/// Whether an exercise by the user is covered, per collateral asset (spec 11.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ExerciseCover {
    /// Asset of the collateral.
    pub asset: AssetId,
    /// Collateral the user's exercises release, in this asset.
    pub collateral: u128,
    /// What the user's guaranteed outcome shows the user receiving from the exercises in
    /// this asset: the guaranteed net change (without clawbacks; under [`Linking::Direct`]
    /// each user spend counted only when it loses), plus each exercised option's strike
    /// when it is in this asset (at most that option's collateral), plus (XCH) the
    /// fee credit; 0 when negative.
    pub received: u128,
    /// `received >= collateral`.
    pub covered: bool,
}

/// Result of [`verify_binding`]. `#[non_exhaustive]`: later versions may add facts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct BindingReport {
    /// Which links between the user's spends counted.
    pub linking: Linking,
    /// Every user spend is bound.
    pub all_bound: bool,
    /// Indexes of user spends that are not bound.
    pub unbound_user_spends: Vec<usize>,
    /// Payments the user's spends depend on (each announcement counted once).
    pub bound_payments: Vec<BoundPayment>,
    /// Total bound receipts per asset.
    pub bound_received: Vec<AssetAmount>,
    /// The user's spends cannot be split from what they depend on. [`Linking::Direct`]:
    /// every user spend asserts every payment the user's spends assert (at least one), so
    /// whichever of them reach the chain, those payments do. [`Linking::Sealed`]: every
    /// user spend requires every other (spec 11.2), and they are included together or not
    /// at all.
    pub co_required: bool,
    /// For a request in which the user exercises options: the coverage per collateral
    /// asset. Empty otherwise.
    pub exercises: Vec<ExerciseCover>,
}

/// An amount of one asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AssetAmount {
    /// Asset.
    pub asset: AssetId,
    /// Amount (smallest units).
    pub amount: u128,
}

impl BindingReport {
    /// Bound receipts of one asset.
    pub fn received(&self, asset: AssetId) -> u128 {
        self.bound_received
            .iter()
            .filter(|a| a.asset == asset)
            .map(|a| a.amount)
            .sum()
    }

    /// Every exercise by the user is covered and the user's spends are included together
    /// (spec 11.1.1); `true` when the request exercises nothing.
    pub fn exercises_covered(&self) -> bool {
        self.exercises.is_empty() || (self.co_required && self.exercises.iter().all(|e| e.covered))
    }
}

/// What each user spend requires of the other user spends (spec 11.2), under a [`Linking`].
#[derive(Debug, Clone)]
pub(crate) struct Requirements {
    edges: Vec<Vec<usize>>,
}

/// The CAT layer's ring announcements start with this byte; inner puzzles may not.
const RING_MORPH_BYTE: u8 = 0xcb;

impl Requirements {
    /// Edges between the user's spends. [`Linking::Direct`]: none. [`Linking::Sealed`]:
    /// `i -> j` when user spend `i` asserts the concurrent spend of user spend `j`'s coin,
    /// or a coin announcement that `j` creates in its own (signed) conditions, other than a
    /// CAT's ring announcement.
    pub(crate) fn new(executed: &[ExecutedSpend], linking: Linking) -> Self {
        if linking == Linking::Direct {
            return Requirements {
                edges: vec![Vec::new(); executed.len()],
            };
        }
        let mut announcements: HashMap<Bytes32, usize> = HashMap::new();
        let mut coins: HashMap<Bytes32, usize> = HashMap::new();
        for (j, es) in executed.iter().enumerate() {
            // Only the user's spends, and only announcements in conditions the user signed.
            if !es.owned {
                continue;
            }
            coins.insert(es.coin.coin_id(), j);
            let cat_layer = matches!(
                es.kind,
                SpendKind::Cat { .. }
                    | SpendKind::OptionUnderlying {
                        asset: AssetId::Cat(_),
                        ..
                    }
            );
            for c in &es.conditions {
                if let Condition::CreateCoinAnnouncement(ann) = c {
                    if cat_layer && ann.message.first() == Some(&RING_MORPH_BYTE) {
                        continue;
                    }
                    let id = sha256_parts(&[es.coin.coin_id().as_ref(), ann.message.as_ref()]);
                    announcements.insert(Bytes32::from(id), j);
                }
            }
        }
        let edges = executed
            .iter()
            .enumerate()
            .map(|(i, es)| {
                if !es.owned {
                    return Vec::new();
                }
                es.conditions
                    .iter()
                    .filter_map(|c| match c {
                        Condition::AssertCoinAnnouncement(x) => {
                            announcements.get(&x.announcement_id)
                        }
                        Condition::AssertConcurrentSpend(x) => coins.get(&x.coin_id),
                        _ => None,
                    })
                    .copied()
                    .filter(|&j| j != i)
                    .collect()
            })
            .collect();
        Requirements { edges }
    }

    /// Every spend `from` requires, directly or through other user spends (and itself).
    fn closure(&self, from: usize) -> HashSet<usize> {
        let mut seen: HashSet<usize> = [from].into_iter().collect();
        let mut stack = vec![from];
        while let Some(i) = stack.pop() {
            for &j in self.edges.get(i).map_or(&[][..], Vec::as_slice) {
                if seen.insert(j) {
                    stack.push(j);
                }
            }
        }
        seen
    }

    /// `from` cannot be included without `to`.
    pub(crate) fn reaches(&self, from: usize, to: usize) -> bool {
        self.closure(from).contains(&to)
    }

    /// Every one of `spends` requires every other.
    pub(crate) fn all_together(&self, spends: &[usize]) -> bool {
        spends.iter().all(|&i| {
            let reach = self.closure(i);
            spends.iter().all(|j| reach.contains(j))
        })
    }

    fn requires_any(&self, i: usize, targets: &HashSet<usize>) -> bool {
        self.edges
            .get(i)
            .is_some_and(|e| e.iter().any(|j| targets.contains(j)))
    }
}

struct SettlementAnnouncement {
    spend: usize,
    /// What the payments pay to the user, per asset.
    to_user: BTreeMap<AssetId, u128>,
}

/// The settlement-payments solution of a spend that pays through the settlement puzzle.
fn settlement_solution(
    a: &mut Allocator,
    cs: &CoinSpend,
    es: &ExecutedSpend,
    solution: NodePtr,
) -> Option<NodePtr> {
    let settlement = Bytes32::from(SETTLEMENT_PAYMENT_HASH);
    match &es.kind {
        SpendKind::Settlement => Some(solution),
        SpendKind::Cat {
            p2_puzzle_hash,
            hidden_puzzle_hash: None,
            ..
        } if *p2_puzzle_hash == settlement => CatSolution::<NodePtr>::from_clvm(a, solution)
            .ok()
            .map(|s| s.inner_puzzle_solution),
        // An option offered through the settlement puzzle: its singleton announces the
        // notarized payments its inner (settlement) puzzle makes, from its own full puzzle
        // hash, which only this singleton has.
        SpendKind::Option { p2_puzzle_hash, .. } if *p2_puzzle_hash == settlement => {
            let puzzle = cs.puzzle_reveal.to_clvm(a).ok()?;
            let puzzle = Puzzle::parse(a, puzzle);
            OptionContract::parse(a, es.coin, puzzle, solution)
                .ok()
                .flatten()
                .map(|(_, _, inner)| inner)
        }
        _ => None,
    }
}

/// Check that every user spend in `coin_spends` is bound to counterparty payments, and
/// how the user's exercises are covered, for a request whose signatures are released
/// ([`Linking::Direct`], the strict rule).
pub fn verify_binding(
    coin_spends: &[CoinSpend],
    ownership: &Ownership,
    max_cost: u64,
) -> Result<BindingReport, KitError> {
    verify_binding_as(coin_spends, ownership, max_cost, Linking::Direct)
}

/// [`verify_binding`] under a given [`Linking`], for analysis and tests. A wallet never
/// picks the linking itself: [`crate::submit`] decides it from the request and the host's
/// [`crate::SignedCoins`] (spec 11.2), and only a sealed wallet-built request may be read
/// under [`Linking::Sealed`].
pub fn verify_binding_as(
    coin_spends: &[CoinSpend],
    ownership: &Ownership,
    max_cost: u64,
    linking: Linking,
) -> Result<BindingReport, KitError> {
    verify_binding_signed(coin_spends, ownership, &HashSet::new(), max_cost, linking)
}

/// [`verify_binding_as`] with the wallet's keys: every spend the wallet would sign is a
/// user spend ([`crate::simulate::claim_signed`]), as in the request handlers. Under
/// [`Linking::Sealed`] the fee credit is the fee the user's spends reserve (up to the
/// bundle's fee): the handlers also cap it at the fee the wallet chose.
pub fn verify_binding_signed(
    coin_spends: &[CoinSpend],
    ownership: &Ownership,
    keys: &HashSet<PublicKey>,
    max_cost: u64,
    linking: Linking,
) -> Result<BindingReport, KitError> {
    let mut a = Allocator::new();
    let (mut executed, costs) = execute(&mut a, coin_spends, ownership, max_cost)?;
    claim_signed(&mut executed, keys);
    if linking != Linking::Direct {
        crate::option::guarantee(&mut executed, linking);
    }
    let mut report = check_binding(&mut a, coin_spends, &executed, ownership, linking)?;
    let summary = summarize(&executed, &costs, ownership)?;
    cover_exercises(&mut report, &summary, None);
    Ok(report)
}

/// [`verify_binding`] for spends already run by [`execute`] in `a`, under `linking`
/// (without the exercise coverage: see [`cover_exercises`]).
pub(crate) fn check_binding(
    a: &mut Allocator,
    coin_spends: &[CoinSpend],
    executed: &[ExecutedSpend],
    ownership: &Ownership,
    linking: Linking,
) -> Result<BindingReport, KitError> {
    // 1. Announcements created by settlement spends the user does not own.
    let mut settlement: HashMap<Bytes32, SettlementAnnouncement> = HashMap::new();
    for (i, (cs, es)) in coin_spends.iter().zip(executed).enumerate() {
        if es.owned {
            continue;
        }
        let solution = cs
            .solution
            .to_clvm(a)
            .map_err(|_| KitError::InvalidRequest("solution"))?;
        let Some(inner) = settlement_solution(a, cs, es, solution) else {
            continue;
        };
        let Ok(parsed) = SettlementPaymentsSolution::<NodePtr>::from_clvm(a, inner) else {
            continue;
        };
        let created: HashSet<&[u8]> = es
            .conditions
            .iter()
            .filter_map(|c| match c {
                Condition::CreatePuzzleAnnouncement(p) => Some(p.message.as_ref()),
                _ => None,
            })
            .collect();
        for np in parsed.notarized_payments {
            let node = np
                .to_clvm(a)
                .map_err(|_| KitError::InvalidRequest("notarized payment"))?;
            let message: [u8; 32] = tree_hash(a, node).to_bytes();
            // The settlement puzzle must actually have announced it in this execution.
            if !created.contains(message.as_slice()) {
                continue;
            }
            let id = Bytes32::from(sha256_parts(&[es.coin.puzzle_hash.as_ref(), &message]));
            settlement.insert(
                id,
                SettlementAnnouncement {
                    spend: i,
                    to_user: paid_to_user(&np, &es.kind, ownership),
                },
            );
        }
    }

    let user: Vec<usize> = executed
        .iter()
        .enumerate()
        .filter(|(_, e)| e.owned)
        .map(|(i, _)| i)
        .collect();

    // 2. The settlement announcements each user spend asserts.
    let asserted: Vec<HashSet<Bytes32>> = user
        .iter()
        .map(|&i| {
            executed.get(i).map_or_else(HashSet::new, |es| {
                es.conditions
                    .iter()
                    .filter_map(|c| match c {
                        Condition::AssertPuzzleAnnouncement(x)
                            if settlement.contains_key(&x.announcement_id) =>
                        {
                            Some(x.announcement_id)
                        }
                        _ => None,
                    })
                    .collect()
            })
        })
        .collect();
    let all: HashSet<Bytes32> = asserted.iter().flatten().copied().collect();

    // 3. Bound spends. Direct: a spend that asserts every payment any user spend asserts.
    //    Sealed: a spend that asserts a payment, or requires a bound user spend.
    let requires = Requirements::new(executed, linking);
    let mut bound: HashSet<usize> = HashSet::new();
    for (&i, own) in user.iter().zip(&asserted) {
        let direct = match linking {
            Linking::Direct => !all.is_empty() && own.is_superset(&all),
            Linking::Sealed => !own.is_empty(),
        };
        if direct {
            bound.insert(i);
        }
    }
    loop {
        let before = bound.len();
        for &i in &user {
            if !bound.contains(&i) && requires.requires_any(i, &bound) {
                bound.insert(i);
            }
        }
        if bound.len() == before {
            break;
        }
    }

    // 4. The payments, each announcement counted once, attributed to the first user spend
    //    that asserts it.
    let mut payments: Vec<BoundPayment> = Vec::new();
    let mut counted: HashSet<Bytes32> = HashSet::new();
    for (&i, own) in user.iter().zip(&asserted) {
        let Some(es) = executed.get(i) else { continue };
        for c in &es.conditions {
            let Condition::AssertPuzzleAnnouncement(x) = c else {
                continue;
            };
            if !own.contains(&x.announcement_id) || !counted.insert(x.announcement_id) {
                continue;
            }
            let Some(s) = settlement.get(&x.announcement_id) else {
                continue;
            };
            for (&asset, &amount) in &s.to_user {
                payments.push(BoundPayment {
                    user_spend: i,
                    settlement_spend: s.spend,
                    asset,
                    amount,
                });
            }
        }
    }

    let unbound: Vec<usize> = user
        .iter()
        .copied()
        .filter(|i| !bound.contains(i))
        .collect();
    let all_bound = !user.is_empty() && unbound.is_empty();
    let mut totals: BTreeMap<AssetId, u128> = BTreeMap::new();
    for p in &payments {
        *totals.entry(p.asset).or_default() += p.amount;
    }
    Ok(BindingReport {
        linking,
        all_bound,
        unbound_user_spends: unbound,
        bound_payments: payments,
        bound_received: totals
            .into_iter()
            .map(|(asset, amount)| AssetAmount { asset, amount })
            .collect(),
        co_required: match linking {
            Linking::Direct => all_bound,
            Linking::Sealed => !user.is_empty() && requires.all_together(&user),
        },
        exercises: Vec::new(),
    })
}

/// Fill in [`BindingReport::exercises`] for the options the user exercises in `summary`
/// (spec 11.1.1; the rule is in the module documentation). `wallet_fee`: under
/// [`Linking::Sealed`], the fee the wallet chose ([`crate::SubmitRequest::wallet_fee`]),
/// the most the fee credit can be.
pub(crate) fn cover_exercises(
    report: &mut BindingReport,
    summary: &Summary,
    wallet_fee: Option<u64>,
) {
    // Per collateral asset: the collateral released, and the strike credited (each option's
    // own strike when it is paid in the collateral's asset, at most its own collateral).
    let mut collateral: BTreeMap<AssetId, (u128, u128)> = BTreeMap::new();
    for effect in &summary.options {
        if let OptionEffect::Exercise {
            by_user: true,
            terms,
            ..
        } = effect
        {
            let c = u128::from(terms.collateral.amount);
            let credit = if terms.strike.asset == terms.collateral.asset {
                c.min(u128::from(terms.strike.amount))
            } else {
                0
            };
            let entry = collateral.entry(terms.collateral.asset).or_default();
            entry.0 = entry.0.saturating_add(c);
            entry.1 = entry.1.saturating_add(credit);
        }
    }
    let fee_credit = match report.linking {
        // XCH the user's own spends put into the bundle: removed minus created. Only that
        // much of the user's reserved fee is the user's own money; the rest would be paid by
        // released collateral, which is then not received (re-audit N3).
        Linking::Direct => {
            let removed: u128 = summary
                .spends
                .iter()
                .filter(|sp| sp.owned && asset_of(&sp.kind).is_mojo_backed())
                .map(|sp| u128::from(sp.amount))
                .sum();
            let created: u128 = summary
                .outputs
                .iter()
                .filter(|o| o.asset.is_mojo_backed())
                .map(|o| u128::from(o.amount))
                .sum();
            u128::from(summary.owned_reserve_fee).min(removed.saturating_sub(created))
        }
        // The wallet built the request and chose the fee, which the user approved as shown:
        // the fee the user's spends reserve, up to the bundle's fee.
        // The wallet built the request and chose the fee (`wallet_fee`, never a dApp's),
        // which the user approved as shown: the fee the user's spends reserve, up to the
        // bundle's fee and the wallet's (rc.5 audit H1).
        Linking::Sealed => u128::from(summary.owned_reserve_fee)
            .min(summary.implied_fee.map_or(0, u128::from))
            .min(wallet_fee.map_or(u128::MAX, u128::from)),
    };
    // Under `Sealed`: the mojos of the options the user melts beyond one per option. They
    // land in the bundle's surplus and the user's change as XCH, but they were inside the
    // option, not received from the exercise: only one mojo per option counts (rc.5 audit
    // N-a).
    let melted_excess: u128 = summary
        .spends
        .iter()
        .filter(|sp| {
            sp.owned
                && matches!(
                    sp.kind,
                    SpendKind::Option {
                        action: OptionAction::Exercise,
                        ..
                    }
                )
        })
        .map(|sp| u128::from(sp.amount.saturating_sub(1)))
        .sum();
    let signed = |v: u128| i128::try_from(v).unwrap_or(i128::MAX);
    report.exercises = collateral
        .into_iter()
        .map(|(asset, (amount, strike_credit))| {
            let own = match report.linking {
                // Any subset of the user's spends may reach the chain: each counts only
                // when it loses.
                Linking::Direct => summary
                    .owned_flows
                    .iter()
                    .filter_map(|flows| flows.get(&asset))
                    .map(|f| {
                        signed(f.to_user)
                            .saturating_sub(signed(f.removed))
                            .saturating_sub(signed(f.clawed))
                            .min(0)
                    })
                    .fold(0i128, i128::saturating_add),
                // The user's spends are included together: the whole request counts.
                Linking::Sealed => {
                    let sent = summary.asset(asset).map_or(0, |d| d.sent);
                    // What the user's own spends pay to the user (fixed by the signature).
                    let to_user: u128 = summary
                        .outputs
                        .iter()
                        .filter(|o| o.asset == asset && o.to_user && !o.unaccounted)
                        .map(|o| u128::from(o.amount))
                        .sum();
                    let melted = if asset == AssetId::Xch {
                        melted_excess
                    } else {
                        0
                    };
                    // A clawback returns collateral that was locked, not part of the
                    // balance: it must not make up for collateral the exercise loses.
                    let clawed: u128 = summary
                        .owned_flows
                        .iter()
                        .filter_map(|flows| flows.get(&asset))
                        .map(|f| f.clawed)
                        .sum();
                    signed(to_user)
                        .saturating_sub(signed(sent))
                        .saturating_sub(signed(clawed))
                        .saturating_sub(signed(melted))
                }
            };
            let fee = if asset == AssetId::Xch { fee_credit } else { 0 };
            let outcome = own
                .saturating_add(signed(report.received(asset)))
                .saturating_add(signed(strike_credit))
                .saturating_add(signed(fee));
            let received = u128::try_from(outcome).unwrap_or(0);
            ExerciseCover {
                asset,
                collateral: amount,
                received,
                covered: received >= amount,
            }
        })
        .collect();
}

/// What a notarized payment of a settlement spend pays to the user, per asset. An option
/// singleton held by the settlement puzzle wraps only its odd output: that one carries the
/// option (one option, and any further mojos as XCH); an even output is plain XCH
/// (re-audit N4).
fn paid_to_user(
    np: &NotarizedPayment<NodePtr>,
    kind: &SpendKind,
    ownership: &Ownership,
) -> BTreeMap<AssetId, u128> {
    let mut out: BTreeMap<AssetId, u128> = BTreeMap::new();
    let asset = asset_of(kind);
    for p in np
        .payments
        .iter()
        .filter(|p| ownership.p2_puzzle_hashes.contains(&p.puzzle_hash) && p.amount > 0)
    {
        let amount = u128::from(p.amount);
        match asset {
            AssetId::Option(_) if p.amount % 2 == 1 => {
                *out.entry(asset).or_default() += 1;
                if amount > 1 {
                    *out.entry(AssetId::Xch).or_default() += amount - 1;
                }
            }
            AssetId::Option(_) => *out.entry(AssetId::Xch).or_default() += amount,
            _ => *out.entry(asset).or_default() += amount,
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::simulate::DEFAULT_MAX_COST;
    use crate::swap_fixture::{anyone_can_spend, lookalike, requested};
    use chia_protocol::Coin;
    use chia_puzzle_types::Memos;
    use chia_sdk_driver::{SpendContext, StandardLayer};
    use chia_sdk_test::BlsPair;
    use chia_sdk_types::Conditions;

    fn owned(p: &BlsPair) -> Ownership {
        crate::swap_fixture::owned(p.puzzle_hash)
    }

    fn user_spend(p: &BlsPair, parent: u8, conds: Conditions) -> CoinSpend {
        let mut ctx = SpendContext::new();
        StandardLayer::new(p.pk)
            .spend(
                &mut ctx,
                Coin::new(Bytes32::new([parent; 32]), p.puzzle_hash, 1000),
                conds,
            )
            .unwrap();
        ctx.take().remove(0)
    }

    fn give() -> Conditions {
        Conditions::new().create_coin(Bytes32::from(SETTLEMENT_PAYMENT_HASH), 1000, Memos::None)
    }

    #[test]
    fn offer_maker_spend_is_bound_to_the_requested_payment() {
        let alice = BlsPair::new(1);
        let (req, id) = requested(alice.puzzle_hash, 500);
        let spends = [
            user_spend(&alice, 1, give().assert_puzzle_announcement(id)),
            req,
        ];
        let r = verify_binding(&spends, &owned(&alice), DEFAULT_MAX_COST).unwrap();
        assert!(r.all_bound, "{r:?}");
        assert_eq!(r.received(AssetId::Xch), 500);
        assert!(
            serde_json::to_string(&r).is_ok(),
            "report must serialise for approval UIs"
        );
        assert_eq!(
            r.bound_payments,
            vec![BoundPayment {
                user_spend: 0,
                settlement_spend: 1,
                asset: AssetId::Xch,
                amount: 500
            }]
        );
    }

    #[test]
    fn missing_assertion_is_unbound() {
        let alice = BlsPair::new(1);
        let (req, _) = requested(alice.puzzle_hash, 500);
        let r = verify_binding(
            &[user_spend(&alice, 1, give()), req],
            &owned(&alice),
            DEFAULT_MAX_COST,
        )
        .unwrap();
        assert!(!r.all_bound);
        assert_eq!(r.unbound_user_spends, vec![0]);
        assert!(r.bound_received.is_empty());
    }

    #[test]
    fn announcement_asserted_from_a_different_coin_does_not_bind() {
        // The user asserts a coin announcement made by some other coin that "pays" them.
        let alice = BlsPair::new(1);
        let attacker = anyone_can_spend(
            5,
            500,
            Conditions::new()
                .create_coin_announcement(vec![1, 2, 3].into())
                .create_coin(alice.puzzle_hash, 500, Memos::None),
        );
        let id = Bytes32::from(sha256_parts(&[
            attacker.coin.coin_id().as_ref(),
            &[1, 2, 3],
        ]));
        let spends = [
            user_spend(&alice, 1, give().assert_coin_announcement(id)),
            attacker,
        ];
        let r = verify_binding(&spends, &owned(&alice), DEFAULT_MAX_COST).unwrap();
        assert!(!r.all_bound && r.unbound_user_spends == vec![0]);
    }

    #[test]
    fn settlement_lookalike_puzzle_announcement_from_attacker_coin_does_not_bind() {
        // Same message a settlement spend would announce, but from a coin the attacker
        // controls: it can be spent to announce without paying.
        let alice = BlsPair::new(1);
        let (attacker, id) = lookalike(alice.puzzle_hash);
        let spends = [
            user_spend(&alice, 1, give().assert_puzzle_announcement(id)),
            attacker,
        ];
        assert!(
            !verify_binding(&spends, &owned(&alice), DEFAULT_MAX_COST)
                .unwrap()
                .all_bound
        );
    }

    #[test]
    fn every_user_coin_must_be_bound_directly_or_transitively() {
        let alice = BlsPair::new(1);
        let (req, id) = requested(alice.puzzle_hash, 500);
        let first = user_spend(
            &alice,
            1,
            give()
                .assert_puzzle_announcement(id)
                .create_coin_announcement(vec![9].into()),
        );
        // Second coin not bound: it could be submitted alone.
        let loose = user_spend(&alice, 2, give());
        let r = verify_binding(
            &[first.clone(), loose, req.clone()],
            &owned(&alice),
            DEFAULT_MAX_COST,
        )
        .unwrap();
        assert_eq!(r.unbound_user_spends, vec![1]);
        // Second coin asserting the first coin's announcement: bound transitively only when
        // the user's spends are sealed (final audit F1). With the signatures released, a
        // dApp holding another signed spend of the first coin with the same announcement
        // can put it in place of the one that asserts the payment.
        let link = Bytes32::from(sha256_parts(&[first.coin.coin_id().as_ref(), &[9]]));
        let tied = user_spend(&alice, 2, give().assert_coin_announcement(link));
        let spends = [first.clone(), tied, req.clone()];
        let r = verify_binding(&spends, &owned(&alice), DEFAULT_MAX_COST).unwrap();
        assert_eq!(r.unbound_user_spends, vec![1]);
        let r =
            verify_binding_as(&spends, &owned(&alice), DEFAULT_MAX_COST, Linking::Sealed).unwrap();
        assert!(r.all_bound && !r.co_required);
        // So is ASSERT_CONCURRENT_SPEND of the first coin.
        let concurrent = user_spend(
            &alice,
            2,
            give().assert_concurrent_spend(first.coin.coin_id()),
        );
        let spends = [first.clone(), concurrent.clone(), req.clone()];
        assert!(
            !verify_binding(&spends, &owned(&alice), DEFAULT_MAX_COST)
                .unwrap()
                .all_bound
        );
        let r =
            verify_binding_as(&spends, &owned(&alice), DEFAULT_MAX_COST, Linking::Sealed).unwrap();
        assert!(r.all_bound);
        // Direct binding: the second coin asserts the payment itself.
        let (_, id) = requested(alice.puzzle_hash, 500);
        let direct = user_spend(&alice, 2, give().assert_puzzle_announcement(id));
        let r = verify_binding(&[first, direct, req], &owned(&alice), DEFAULT_MAX_COST).unwrap();
        assert!(r.all_bound && r.co_required);
        assert_eq!(
            r.received(AssetId::Xch),
            500,
            "each announcement counted once"
        );
    }

    #[test]
    fn every_user_spend_must_assert_every_payment_when_signatures_are_released() {
        // Two payments, each asserted by one of the user's spends: with the signatures
        // released either spend could reach the chain with only its own payment.
        let alice = BlsPair::new(1);
        let (req_a, id_a) = requested(alice.puzzle_hash, 500);
        let (req_b, id_b) = crate::swap_fixture::requested_nonce(alice.puzzle_hash, 700, 9);
        let one = user_spend(&alice, 1, give().assert_puzzle_announcement(id_a));
        let two = user_spend(&alice, 2, give().assert_puzzle_announcement(id_b));
        let spends = [one, two, req_a.clone(), req_b.clone()];
        let r = verify_binding(&spends, &owned(&alice), DEFAULT_MAX_COST).unwrap();
        assert!(!r.all_bound && r.unbound_user_spends == vec![0, 1], "{r:?}");
        let both = |parent| {
            user_spend(
                &alice,
                parent,
                give()
                    .assert_puzzle_announcement(id_a)
                    .assert_puzzle_announcement(id_b),
            )
        };
        let spends = [both(1), both(2), req_a, req_b];
        let r = verify_binding(&spends, &owned(&alice), DEFAULT_MAX_COST).unwrap();
        assert!(r.all_bound && r.co_required, "{r:?}");
        assert_eq!(r.received(AssetId::Xch), 1200);
    }

    /// N-a (rc.5 audit round 5): under `Sealed`, the mojos of a melted option beyond one land
    /// in the user's change as XCH; they were inside the option, not received from the
    /// exercise, so they never cover collateral. A 1001-mojo option whose collateral goes
    /// elsewhere is not covered; an honest 1-mojo option whose collateral is paid is.
    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn n_a_a_melted_options_extra_mojos_never_cover_collateral() {
        use crate::option::{OptionLeg, OptionTerms};
        use crate::simulate::{AssetDelta, OutputInfo, SpendInfo};
        let terms = OptionTerms {
            creator_puzzle_hash: Bytes32::default(),
            expiration_seconds: 0,
            collateral: OptionLeg {
                asset: AssetId::Xch,
                amount: 1000,
            },
            strike: OptionLeg {
                asset: AssetId::Xch,
                amount: 300,
            },
        };
        let launcher = Bytes32::new([5; 32]);
        // The user's 5000 pays the 300 strike; the change absorbs the option's mojos.
        let summary = |option_mojos: u64| {
            let mut change = OutputInfo::default();
            change.asset = AssetId::Xch;
            change.amount = 5000 - 300 + option_mojos;
            change.to_user = true;
            let mut s = Summary::default();
            s.options = vec![OptionEffect::Exercise {
                launcher_id: launcher,
                by_user: true,
                creator_is_user: false,
                terms,
            }];
            s.spends = vec![SpendInfo {
                coin_id: String::new(),
                puzzle_hash: String::new(),
                amount: option_mojos,
                kind: SpendKind::Option {
                    launcher_id: launcher,
                    p2_puzzle_hash: Bytes32::default(),
                    underlying_coin_id: Bytes32::default(),
                    underlying_delegated_puzzle_hash: Bytes32::default(),
                    action: OptionAction::Exercise,
                    new_owner: None,
                    terms: Some(terms),
                },
                owned: true,
                agg_sigs: Vec::new(),
                cost: 0,
            }];
            s.assets = vec![AssetDelta {
                asset: AssetId::Xch,
                sent: 5000,
                received: u128::from(change.amount),
                conditional_received: 0,
                net: i128::from(change.amount) - 5000,
            }];
            s.outputs = vec![change];
            s
        };
        let cover = |option_mojos: u64, collateral_paid: u128| {
            let mut report = BindingReport {
                linking: Linking::Sealed,
                co_required: true,
                all_bound: true,
                ..BindingReport::default()
            };
            if collateral_paid > 0 {
                report.bound_received = vec![AssetAmount {
                    asset: AssetId::Xch,
                    amount: collateral_paid,
                }];
            }
            cover_exercises(&mut report, &summary(option_mojos), Some(0));
            report.exercises[0]
        };
        let attack = cover(1001, 0);
        assert!(!attack.covered && attack.received == 1, "{attack:?}");
        let honest = cover(1, 1000);
        assert!(honest.covered && honest.received == 1001, "{honest:?}");
    }

    #[test]
    fn a_request_with_no_user_spend_is_not_bound() {
        let alice = BlsPair::new(1);
        let (req, _) = requested(alice.puzzle_hash, 500);
        assert!(
            !verify_binding(&[req], &owned(&alice), DEFAULT_MAX_COST)
                .unwrap()
                .all_bound
        );
    }
}
