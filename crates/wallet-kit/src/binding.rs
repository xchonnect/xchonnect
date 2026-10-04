//! Multi-party spend binding (spec 11.2, invariant 13.4 item 4, threat T2).
//!
//! Before producing a partial signature the wallet must be sure that none of its spends
//! can be included on-chain without the counterparty delivering what the user expects.
//!
//! **Rule implemented (conservative):**
//! 1. A user spend is *directly bound* if it asserts a puzzle announcement created by an
//!    offer **settlement payments** spend in the request (XCH settlement puzzle, or the
//!    settlement puzzle inside a CAT). The settlement puzzle announces
//!    `sha256tree(notarized_payment)` only while creating exactly those payments, so the
//!    assertion `sha256(settlement_puzzle_hash || sha256tree(np))` can only be satisfied
//!    by a spend that pays them.
//! 2. A user spend is *transitively bound* if it asserts a coin announcement created by
//!    another bound user spend (e.g. a CAT ring or a second funding coin).
//! 3. Announcements from any other puzzle do **not** bind: the creator (a counterparty or
//!    an anyone-can-spend coin) can produce the same announcement without paying.
//!    `SEND_MESSAGE` / `RECEIVE_MESSAGE` bindings are not recognised yet (refused).
//!
//! A partial request is signable only if **every** user spend is bound; otherwise any
//! unbound coin could be submitted on its own.

use crate::error::KitError;
use crate::simulate::{AssetId, ExecutedSpend, Ownership, SpendKind, execute};
use chia_protocol::{Bytes32, CoinSpend};
use chia_puzzle_types::cat::CatSolution;
use chia_puzzle_types::offer::{NotarizedPayment, SettlementPaymentsSolution};
use chia_puzzles::SETTLEMENT_PAYMENT_HASH;
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

/// Result of [`verify_binding`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BindingReport {
    /// Every user spend is bound.
    pub all_bound: bool,
    /// Indexes of user spends that are not bound.
    pub unbound_user_spends: Vec<usize>,
    /// Payments the user's spends depend on (each announcement counted once).
    pub bound_payments: Vec<BoundPayment>,
    /// Total bound receipts per asset.
    pub bound_received: Vec<AssetAmount>,
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
}

struct SettlementAnnouncement {
    spend: usize,
    asset: AssetId,
    to_user: u128,
}

fn settlement_solution(a: &Allocator, es: &ExecutedSpend, solution: NodePtr) -> Option<NodePtr> {
    match &es.kind {
        SpendKind::Settlement => Some(solution),
        SpendKind::Cat {
            p2_puzzle_hash,
            hidden_puzzle_hash: None,
            ..
        } if *p2_puzzle_hash == Bytes32::from(SETTLEMENT_PAYMENT_HASH) => {
            CatSolution::<NodePtr>::from_clvm(a, solution)
                .ok()
                .map(|s| s.inner_puzzle_solution)
        }
        _ => None,
    }
}

/// Check that every user spend in `coin_spends` is bound to counterparty payments.
pub fn verify_binding(
    coin_spends: &[CoinSpend],
    ownership: &Ownership,
    max_cost: u64,
) -> Result<BindingReport, KitError> {
    let mut a = Allocator::new();
    let (executed, _) = execute(&mut a, coin_spends, ownership, max_cost)?;

    // 1. Announcements created by settlement spends the user does not own.
    let mut settlement: HashMap<Bytes32, SettlementAnnouncement> = HashMap::new();
    for (i, (cs, es)) in coin_spends.iter().zip(&executed).enumerate() {
        if es.owned {
            continue;
        }
        let solution = cs
            .solution
            .to_clvm(&mut a)
            .map_err(|_| KitError::InvalidRequest("solution"))?;
        let Some(inner) = settlement_solution(&a, es, solution) else {
            continue;
        };
        let Ok(parsed) = SettlementPaymentsSolution::<NodePtr>::from_clvm(&a, inner) else {
            continue;
        };
        let created: HashSet<Vec<u8>> = es
            .conditions
            .iter()
            .filter_map(|c| match c {
                Condition::CreatePuzzleAnnouncement(p) => Some(p.message.to_vec()),
                _ => None,
            })
            .collect();
        let asset = match &es.kind {
            SpendKind::Cat { asset_id, .. } => AssetId::Cat(*asset_id),
            _ => AssetId::Xch,
        };
        for np in parsed.notarized_payments {
            let node = np
                .to_clvm(&mut a)
                .map_err(|_| KitError::InvalidRequest("notarized payment"))?;
            let message: [u8; 32] = tree_hash(&a, node).to_bytes();
            // The settlement puzzle must actually have announced it in this execution.
            if !created.contains(message.as_slice()) {
                continue;
            }
            let to_user = paid_to_user(&np, ownership);
            let id = Bytes32::from(sha256_parts(&[es.coin.puzzle_hash.as_ref(), &message]));
            settlement.insert(
                id,
                SettlementAnnouncement {
                    spend: i,
                    asset,
                    to_user,
                },
            );
        }
    }

    // 2. Coin announcements created by user spends: id -> spend index.
    let mut user_coin_announcements: HashMap<Bytes32, usize> = HashMap::new();
    for (i, es) in executed.iter().enumerate().filter(|(_, e)| e.owned) {
        for c in &es.conditions {
            if let Condition::CreateCoinAnnouncement(ann) = c {
                user_coin_announcements.insert(
                    Bytes32::from(sha256_parts(&[
                        es.coin.coin_id().as_ref(),
                        ann.message.as_ref(),
                    ])),
                    i,
                );
            }
        }
    }

    // 3. Direct bindings.
    let user: Vec<usize> = executed
        .iter()
        .enumerate()
        .filter(|(_, e)| e.owned)
        .map(|(i, _)| i)
        .collect();
    let mut bound: HashSet<usize> = HashSet::new();
    let mut payments: Vec<BoundPayment> = Vec::new();
    let mut counted: HashSet<Bytes32> = HashSet::new();
    for (i, es) in executed.iter().enumerate().filter(|(_, e)| e.owned) {
        for c in &es.conditions {
            if let Condition::AssertPuzzleAnnouncement(assert) = c {
                if let Some(s) = settlement.get(&assert.announcement_id) {
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
        }
    }

    // 4. Transitive bindings through coin announcements of bound user spends.
    loop {
        let before = bound.len();
        for (i, es) in executed.iter().enumerate().filter(|(_, e)| e.owned) {
            if bound.contains(&i) {
                continue;
            }
            let via_bound = es.conditions.iter().any(|c| {
                matches!(c, Condition::AssertCoinAnnouncement(assert)
                    if user_coin_announcements.get(&assert.announcement_id).is_some_and(|src| *src != i && bound.contains(src)))
            });
            if via_bound {
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
    let bound_received = totals
        .into_iter()
        .map(|(asset, amount)| AssetAmount { asset, amount })
        .collect();
    Ok(BindingReport {
        all_bound: !user.is_empty() && unbound.is_empty(),
        unbound_user_spends: unbound,
        bound_payments: payments,
        bound_received,
    })
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
    use chia_protocol::{Coin, Program};
    use chia_puzzle_types::Memos;
    use chia_puzzle_types::offer::Payment;
    use chia_sdk_driver::{Layer, SettlementLayer, SpendContext, StandardLayer};
    use chia_sdk_test::BlsPair;
    use chia_sdk_types::Conditions;

    fn owned(p: &BlsPair) -> Ownership {
        Ownership {
            p2_puzzle_hashes: [p.puzzle_hash].into_iter().collect(),
        }
    }

    /// Requested payment of `amount` to `to`, as an offer's zero-parent settlement spend.
    /// Returns the spend and the announcement id a maker must assert.
    fn requested(to: Bytes32, amount: u64) -> (CoinSpend, Bytes32) {
        let mut ctx = SpendContext::new();
        let np = NotarizedPayment::new(
            Bytes32::new([7; 32]),
            vec![Payment::new(to, amount, Memos::None)],
        );
        let np_node = ctx.alloc(&np).unwrap();
        let msg = ctx.tree_hash(np_node).to_bytes();
        let puzzle = SettlementLayer.construct_puzzle(&mut ctx).unwrap();
        let ph = Bytes32::from(ctx.tree_hash(puzzle));
        let solution = SettlementLayer
            .construct_solution(&mut ctx, SettlementPaymentsSolution::new(vec![np]))
            .unwrap();
        let cs = CoinSpend::new(
            Coin::new(Bytes32::default(), ph, 0),
            ctx.serialize(&puzzle).unwrap(),
            ctx.serialize(&solution).unwrap(),
        );
        (cs, Bytes32::from(sha256_parts(&[ph.as_ref(), &msg])))
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

    /// Anyone-can-spend coin (puzzle `1`) emitting `conds` — an attacker-controlled coin.
    fn attacker_spend(conds: Conditions) -> CoinSpend {
        let mut a = Allocator::new();
        let puzzle = Program::from(vec![0x01]);
        let node = puzzle.to_clvm(&mut a).unwrap();
        let ph = Bytes32::from(tree_hash(&a, node));
        let sol = conds.to_clvm(&mut a).unwrap();
        CoinSpend::new(
            Coin::new(Bytes32::new([5; 32]), ph, 500),
            puzzle,
            Program::from_clvm(&a, sol).unwrap(),
        )
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
        let attacker = attacker_spend(
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
        let mut ctx = SpendContext::new();
        let np = NotarizedPayment::new(
            Bytes32::new([7; 32]),
            vec![Payment::new(alice.puzzle_hash, 500, Memos::None)],
        );
        let node = ctx.alloc(&np).unwrap();
        let msg = ctx.tree_hash(node).to_bytes();
        let attacker = attacker_spend(
            Conditions::new()
                .create_puzzle_announcement(msg.to_vec().into())
                .create_coin(alice.puzzle_hash, 500, Memos::None),
        );
        let id = Bytes32::from(sha256_parts(&[attacker.coin.puzzle_hash.as_ref(), &msg]));
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
