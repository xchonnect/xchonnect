//! Multi-party spend binding (spec 11.2, invariant 13.4 item 4, threat T2), and the
//! coverage of an option exercise (spec 11.1.1).
//!
//! Before producing a partial signature the wallet must be sure that none of its spends
//! can be included on-chain without the counterparty delivering what the user expects.
//!
//! **Rule implemented (conservative):**
//! 1. A user spend is *directly bound* if it asserts a puzzle announcement created by an
//!    offer **settlement payments** spend in the request (XCH settlement puzzle, the
//!    settlement puzzle inside a CAT, or an option singleton whose owner is the settlement
//!    puzzle). The settlement puzzle announces `sha256tree(notarized_payment)` only while
//!    creating exactly those payments, so the assertion
//!    `sha256(settlement_puzzle_hash || sha256tree(np))` can only be satisfied by a spend
//!    that pays them.
//! 2. A user spend is *transitively bound* if its own signed conditions require another
//!    bound user spend: an `ASSERT_CONCURRENT_SPEND` of that coin, or an
//!    `ASSERT_COIN_ANNOUNCEMENT` of an announcement that coin creates. A CAT's ring
//!    announcements (`0xcb…`) do not count: the CAT layer derives them from the solution,
//!    which the user's signature does not cover.
//! 3. Announcements from any other puzzle do **not** bind: the creator (a counterparty or
//!    an anyone-can-spend coin) can produce the same announcement without paying.
//!    `SEND_MESSAGE` / `RECEIVE_MESSAGE` bindings are not recognised yet (refused).
//!
//! A partial request is signable only if **every** user spend is bound; otherwise any
//! unbound coin could be submitted on its own.
//!
//! **Exercise coverage (spec 11.1.1).** An exercise releases the collateral to the
//! settlement puzzle, where anyone may claim it. The user's spends are signed only if they
//! require one another (rule 2's edges, every user spend reaching every other: they are
//! included together or not at all) and, in the collateral's asset, the user's guaranteed
//! outcome — what the user's own spends pay to the user, plus bound payments to the user,
//! minus everything the user's spends remove from the balance — is at least the collateral
//! less the strike paid in that asset and the user's reserved fee. Every other payment
//! counts as spent, so a "refund" of the user's own money, whoever it passes through,
//! never covers the collateral (audit SA-H3); collateral the user's own change absorbs
//! does. A clawback in the same request counts as nothing: its collateral was locked.

use crate::error::KitError;
use crate::option::{OptionEffect, UnderlyingPath};
use crate::simulate::{
    AssetId, ExecutedSpend, Ownership, SpendKind, Summary, asset_of, execute, summarize,
};
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
    /// this asset: the guaranteed net change (without clawbacks) plus the strike paid in
    /// this asset and the reserved fee (0 when negative).
    pub received: u128,
    /// `received >= collateral`.
    pub covered: bool,
}

/// Result of [`verify_binding`]. `#[non_exhaustive]`: later versions may add facts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct BindingReport {
    /// Every user spend is bound.
    pub all_bound: bool,
    /// Indexes of user spends that are not bound.
    pub unbound_user_spends: Vec<usize>,
    /// Payments the user's spends depend on (each announcement counted once).
    pub bound_payments: Vec<BoundPayment>,
    /// Total bound receipts per asset.
    pub bound_received: Vec<AssetAmount>,
    /// Every user spend requires every other through its own signed conditions
    /// (`ASSERT_CONCURRENT_SPEND`, coin announcements): the user's spends are included
    /// together or not at all.
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

/// What each user spend requires, from the user's own signed conditions (rule 2).
#[derive(Debug, Clone)]
pub(crate) struct Requirements {
    edges: Vec<Vec<usize>>,
}

/// The CAT layer's ring announcements start with this byte; inner puzzles may not.
const RING_MORPH_BYTE: u8 = 0xcb;

impl Requirements {
    pub(crate) fn new(executed: &[ExecutedSpend]) -> Self {
        let by_coin: HashMap<Bytes32, usize> = executed
            .iter()
            .enumerate()
            .map(|(i, es)| (es.coin.coin_id(), i))
            .collect();
        let mut announcements: HashMap<Bytes32, usize> = HashMap::new();
        for (j, es) in executed.iter().enumerate() {
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
                        Condition::AssertConcurrentSpend(x) => by_coin.get(&x.coin_id),
                        Condition::AssertCoinAnnouncement(x) => {
                            announcements.get(&x.announcement_id)
                        }
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
    fn all_together(&self, spends: &[usize]) -> bool {
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
    asset: AssetId,
    to_user: u128,
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
/// how the user's exercises are covered.
pub fn verify_binding(
    coin_spends: &[CoinSpend],
    ownership: &Ownership,
    max_cost: u64,
) -> Result<BindingReport, KitError> {
    let mut a = Allocator::new();
    let (executed, costs) = execute(&mut a, coin_spends, ownership, max_cost)?;
    let mut report = check_binding(&mut a, coin_spends, &executed, ownership)?;
    let summary = summarize(&executed, &costs, ownership)?;
    cover_exercises(&mut report, &summary);
    Ok(report)
}

/// [`verify_binding`] for spends already run by [`execute`] in `a` (without the exercise
/// coverage: see [`cover_exercises`]).
pub(crate) fn check_binding(
    a: &mut Allocator,
    coin_spends: &[CoinSpend],
    executed: &[ExecutedSpend],
    ownership: &Ownership,
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
                    asset: asset_of(&es.kind),
                    to_user: paid_to_user(&np, ownership),
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

    // 2. Direct bindings.
    let mut bound: HashSet<usize> = HashSet::new();
    let mut payments: Vec<BoundPayment> = Vec::new();
    let mut counted: HashSet<Bytes32> = HashSet::new();
    for &i in &user {
        let Some(es) = executed.get(i) else { continue };
        for c in &es.conditions {
            let Condition::AssertPuzzleAnnouncement(assert) = c else {
                continue;
            };
            let Some(s) = settlement.get(&assert.announcement_id) else {
                continue;
            };
            bound.insert(i);
            if counted.insert(assert.announcement_id) && s.to_user > 0 {
                payments.push(BoundPayment {
                    user_spend: i,
                    settlement_spend: s.spend,
                    asset: s.asset,
                    amount: s.to_user,
                });
            }
        }
    }

    // 3. Transitive bindings: a user spend whose signed conditions require a bound one.
    let requires = Requirements::new(executed);
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

    let unbound: Vec<usize> = user
        .iter()
        .copied()
        .filter(|i| !bound.contains(i))
        .collect();
    let mut totals: BTreeMap<AssetId, u128> = BTreeMap::new();
    for p in &payments {
        *totals.entry(p.asset).or_default() += p.amount;
    }
    Ok(BindingReport {
        all_bound: !user.is_empty() && unbound.is_empty(),
        unbound_user_spends: unbound,
        bound_payments: payments,
        bound_received: totals
            .into_iter()
            .map(|(asset, amount)| AssetAmount { asset, amount })
            .collect(),
        co_required: !user.is_empty() && requires.all_together(&user),
        exercises: Vec::new(),
    })
}

/// Fill in [`BindingReport::exercises`] for the options the user exercises in `summary`
/// (spec 11.1.1; the rule is in the module documentation).
pub(crate) fn cover_exercises(report: &mut BindingReport, summary: &Summary) {
    let mut collateral: BTreeMap<AssetId, u128> = BTreeMap::new();
    let mut strike: BTreeMap<AssetId, u128> = BTreeMap::new();
    for effect in &summary.options {
        if let OptionEffect::Exercise {
            by_user: true,
            terms,
            ..
        } = effect
        {
            *collateral.entry(terms.collateral.asset).or_default() +=
                u128::from(terms.collateral.amount);
            *strike.entry(terms.strike.asset).or_default() += u128::from(terms.strike.amount);
        }
    }
    let signed = |v: u128| i128::try_from(v).unwrap_or(i128::MAX);
    report.exercises = collateral
        .into_iter()
        .map(|(asset, amount)| {
            let sent = summary.asset(asset).map_or(0, |d| d.sent);
            // What the user's own spends pay to the user (fixed by the user's signature).
            let to_user: u128 = summary
                .outputs
                .iter()
                .filter(|o| o.asset == asset && o.to_user)
                .map(|o| u128::from(o.amount))
                .sum();
            // A clawback returns collateral that was locked, not part of the balance: it
            // must not make up for collateral the exercise loses.
            let clawed: u128 = summary
                .spends
                .iter()
                .filter(|sp| {
                    sp.owned
                        && matches!(
                            &sp.kind,
                            SpendKind::OptionUnderlying {
                                path: UnderlyingPath::Clawback,
                                asset: a,
                                ..
                            } if *a == asset
                        )
                })
                .map(|sp| u128::from(sp.amount))
                .sum();
            let fee = if asset == AssetId::Xch {
                u128::from(summary.owned_reserve_fee)
            } else {
                0
            };
            let outcome = signed(to_user)
                .saturating_add(signed(report.received(asset)))
                .saturating_sub(signed(sent))
                .saturating_sub(signed(clawed))
                .saturating_add(signed(strike.get(&asset).copied().unwrap_or(0)))
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

fn paid_to_user(np: &NotarizedPayment<NodePtr>, ownership: &Ownership) -> u128 {
    np.payments
        .iter()
        .filter(|p| ownership.p2_puzzle_hashes.contains(&p.puzzle_hash))
        .map(|p| u128::from(p.amount))
        .sum()
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
        // Second coin asserting the first coin's announcement is bound transitively.
        let link = Bytes32::from(sha256_parts(&[first.coin.coin_id().as_ref(), &[9]]));
        let tied = user_spend(&alice, 2, give().assert_coin_announcement(link));
        assert!(
            verify_binding(&[first, tied, req], &owned(&alice), DEFAULT_MAX_COST)
                .unwrap()
                .all_bound
        );
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
