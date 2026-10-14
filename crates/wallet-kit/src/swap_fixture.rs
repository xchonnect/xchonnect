//! Test fixtures, chiefly an atomic two-party XCH swap through offer settlement payments.
//!
//! Alice gives 1000 mojos, Bob gives 500. Each user coin pays into the settlement puzzle and
//! asserts the settlement announcement of the payment it expects; the two settlement coins
//! are spent in the same bundle, each paying the other party. Neither user spend can be
//! included without the payment it asserts (spec 11.2).
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    missing_docs,
    unreachable_pub
)]

use crate::permissions::{DailySpend, LimitStore, PermissionError};
use crate::simulate::Ownership;
use chia_protocol::{Bytes32, Coin, CoinSpend, Program};
use chia_puzzle_types::Memos;
use chia_puzzle_types::offer::{NotarizedPayment, Payment, SettlementPaymentsSolution};
use chia_puzzles::SETTLEMENT_PAYMENT_HASH;
use chia_sdk_driver::{Layer, SettlementLayer, SpendContext, StandardLayer};
use chia_sdk_test::{BlsPair, Simulator};
use chia_sdk_types::Conditions;
use clvm_traits::{FromClvm, ToClvm};
use clvm_utils::tree_hash;
use clvmr::Allocator;
use std::cell::RefCell;
use xchonnect_core::crypto::sha256_parts;

pub struct Swap {
    pub alice: BlsPair,
    pub bob: BlsPair,
    pub spends: Vec<CoinSpend>,
}

/// In-memory [`LimitStore`].
#[derive(Default)]
pub struct Mem(pub RefCell<DailySpend>);

impl LimitStore for Mem {
    fn load(&self) -> Result<DailySpend, PermissionError> {
        Ok(self.0.borrow().clone())
    }
    fn save(&self, r: &DailySpend) -> Result<(), PermissionError> {
        *self.0.borrow_mut() = r.clone();
        Ok(())
    }
}

pub fn owned(ph: Bytes32) -> Ownership {
    Ownership {
        p2_puzzle_hashes: [ph].into_iter().collect(),
    }
}

/// Anyone-can-spend coin (puzzle `1`) whose solution is `conds`: an attacker-controlled or
/// unrecognised coin.
pub fn anyone_can_spend(parent: u8, amount: u64, conds: Conditions) -> CoinSpend {
    let mut a = Allocator::new();
    let puzzle = Program::from(vec![0x01]);
    let node = puzzle.to_clvm(&mut a).unwrap();
    let ph = Bytes32::from(tree_hash(&a, node));
    let sol = conds.to_clvm(&mut a).unwrap();
    CoinSpend::new(
        Coin::new(Bytes32::new([parent; 32]), ph, amount),
        puzzle,
        Program::from_clvm(&a, sol).unwrap(),
    )
}

fn settlement(
    ctx: &mut SpendContext,
    parent: Bytes32,
    amount: u64,
    np: NotarizedPayment,
) -> CoinSpend {
    let puzzle = SettlementLayer.construct_puzzle(ctx).unwrap();
    let solution = SettlementLayer
        .construct_solution(ctx, SettlementPaymentsSolution::new(vec![np]))
        .unwrap();
    CoinSpend::new(
        Coin::new(parent, Bytes32::from(SETTLEMENT_PAYMENT_HASH), amount),
        ctx.serialize(&puzzle).unwrap(),
        ctx.serialize(&solution).unwrap(),
    )
}

fn announcement(ctx: &mut SpendContext, np: &NotarizedPayment) -> Bytes32 {
    let node = ctx.alloc(np).unwrap();
    let msg = ctx.tree_hash(node).to_bytes();
    Bytes32::from(sha256_parts(&[SETTLEMENT_PAYMENT_HASH.as_slice(), &msg]))
}

/// Requested payment of `amount` to `to`, as an offer's zero-parent settlement spend.
/// Returns the spend and the announcement id a maker must assert.
pub fn requested(to: Bytes32, amount: u64) -> (CoinSpend, Bytes32) {
    let mut ctx = SpendContext::new();
    let np = NotarizedPayment::new(
        Bytes32::new([7; 32]),
        vec![Payment::new(to, amount, Memos::None)],
    );
    let id = announcement(&mut ctx, &np);
    (settlement(&mut ctx, Bytes32::default(), 0, np), id)
}

/// [`requested`] with its own nonce (and a settlement coin of its own), for requests that
/// ask for more than one payment.
pub fn requested_nonce(to: Bytes32, amount: u64, nonce: u8) -> (CoinSpend, Bytes32) {
    let mut ctx = SpendContext::new();
    let np = NotarizedPayment::new(
        Bytes32::new([nonce; 32]),
        vec![Payment::new(to, amount, Memos::None)],
    );
    let id = announcement(&mut ctx, &np);
    (settlement(&mut ctx, Bytes32::new([nonce; 32]), 0, np), id)
}

/// A settlement lookalike: an anyone-can-spend coin announcing the message a settlement
/// spend paying `to` 500 would announce (and paying it, droppably). Returns the coin and
/// the announcement id a user spend would assert.
pub fn lookalike(to: Bytes32) -> (CoinSpend, Bytes32) {
    let mut ctx = SpendContext::new();
    let np = NotarizedPayment::new(
        Bytes32::new([7; 32]),
        vec![Payment::new(to, 500, Memos::None)],
    );
    let node = ctx.alloc(&np).unwrap();
    let msg = ctx.tree_hash(node).to_bytes();
    let attacker = anyone_can_spend(
        5,
        500,
        Conditions::new()
            .create_puzzle_announcement(msg.to_vec().into())
            .create_coin(to, 500, Memos::None),
    );
    let id = Bytes32::from(sha256_parts(&[attacker.coin.puzzle_hash.as_ref(), &msg]));
    (attacker, id)
}

/// Build the swap; `bind_alice` / `bind_bob` control whether each side asserts its payment.
pub fn swap(sim: &mut Simulator, bind_alice: bool, bind_bob: bool) -> Swap {
    let (alice, bob) = (BlsPair::new(11), BlsPair::new(12));
    let a = sim.new_coin(alice.puzzle_hash, 1000);
    let b = sim.new_coin(bob.puzzle_hash, 500);
    let settlement_ph = Bytes32::from(SETTLEMENT_PAYMENT_HASH);
    let np_alice = NotarizedPayment::new(
        a.coin_id(),
        vec![Payment::new(alice.puzzle_hash, 500, Memos::None)],
    );
    let np_bob = NotarizedPayment::new(
        b.coin_id(),
        vec![Payment::new(bob.puzzle_hash, 1000, Memos::None)],
    );
    let mut ctx = SpendContext::new();
    let ann_alice = announcement(&mut ctx, &np_alice);
    let ann_bob = announcement(&mut ctx, &np_bob);
    let mut ca = Conditions::new().create_coin(settlement_ph, 1000, Memos::None);
    if bind_alice {
        ca = ca.assert_puzzle_announcement(ann_alice);
    }
    let mut cb = Conditions::new().create_coin(settlement_ph, 500, Memos::None);
    if bind_bob {
        cb = cb.assert_puzzle_announcement(ann_bob);
    }
    StandardLayer::new(alice.pk).spend(&mut ctx, a, ca).unwrap();
    StandardLayer::new(bob.pk).spend(&mut ctx, b, cb).unwrap();
    let mut spends = ctx.take();
    // Alice's settlement coin pays Bob; Bob's pays Alice (ephemeral, same bundle).
    spends.push(settlement(&mut ctx, a.coin_id(), 1000, np_bob));
    spends.push(settlement(&mut ctx, b.coin_id(), 500, np_alice));
    Swap { alice, bob, spends }
}

/// CHIP-0002 `signCoinSpends` params for `spends`.
pub fn params(spends: &[CoinSpend], partial: bool) -> String {
    let arr: Vec<serde_json::Value> = spends
        .iter()
        .map(|cs| {
            serde_json::json!({
                "coin": { "parent_coin_info": format!("0x{}", hex::encode(cs.coin.parent_coin_info)), "puzzle_hash": format!("0x{}", hex::encode(cs.coin.puzzle_hash)), "amount": cs.coin.amount },
                "puzzle_reveal": format!("0x{}", hex::encode(cs.puzzle_reveal.as_ref())),
                "solution": format!("0x{}", hex::encode(cs.solution.as_ref())),
            })
        })
        .collect();
    serde_json::json!({ "coinSpends": arr, "partialSign": partial }).to_string()
}

/// A spend of `coin`, a standard coin of `pk`, through the delegated path: `delegated` runs
/// on `delegated_solution`. Honest wallets pass a quoted program (`StandardLayer::spend`);
/// the tests pass other programs to check the wallet refuses them.
pub fn delegated_spend(
    ctx: &mut SpendContext,
    coin: Coin,
    pk: chia_bls::PublicKey,
    delegated: clvmr::NodePtr,
    delegated_solution: clvmr::NodePtr,
) -> CoinSpend {
    let layer = StandardLayer::new(pk);
    let puzzle = layer.construct_puzzle(ctx).unwrap();
    let solution = layer
        .construct_solution(
            ctx,
            chia_puzzle_types::standard::StandardSolution {
                original_public_key: None,
                delegated_puzzle: delegated,
                solution: delegated_solution,
            },
        )
        .unwrap();
    CoinSpend::new(
        coin,
        ctx.serialize(&puzzle).unwrap(),
        ctx.serialize(&solution).unwrap(),
    )
}

/// Delegated puzzles that are not a quoted program, each with a solution that makes it
/// output `conds`: `(name, delegated puzzle, delegated solution)`.
pub fn non_quote_delegations(
    ctx: &mut SpendContext,
    conds: &Conditions,
) -> Vec<(&'static str, clvmr::NodePtr, clvmr::NodePtr)> {
    let list = ctx.alloc(conds).unwrap();
    let mut out = Vec::new();
    // `1`: the solution itself.
    let one = ctx.alloc(&1u8).unwrap();
    out.push(("identity", one, list));
    // `(f 1)`: the first element of the solution.
    let first = ctx.alloc(&(5u8, (1u8, ()))).unwrap();
    let wrapped = ctx.alloc(&(list, ())).unwrap();
    out.push(("first of solution", first, wrapped));
    // `(a 2 3)`: runs a program the solution supplies.
    let eval = ctx.alloc(&(2u8, (2u8, (3u8, ())))).unwrap();
    let program_and_args = ctx.alloc(&(1u8, list)).unwrap();
    out.push(("eval", eval, program_and_args));
    // A curried program: `(c 2 5)` with a fixed first condition, the rest from the solution.
    let mut it = conds.clone().into_iter();
    if let Some(head) = it.next() {
        let head = ctx.alloc(&head).unwrap();
        let rest: Vec<_> = it.collect();
        let rest = ctx.alloc(&rest).unwrap();
        let body = ctx.alloc(&(4u8, (2u8, (5u8, ())))).unwrap();
        let curried = ctx
            .alloc(&(2u8, ((1u8, body), ((4u8, ((1u8, head), (1u8, ()))), ()))))
            .unwrap();
        let sol = ctx.alloc(&(rest, ())).unwrap();
        out.push(("curried", curried, sol));
        // `(c (q . head) 1)`: a quoted condition followed by the solution.
        let prefix = ctx.alloc(&(4u8, ((1u8, head), (1u8, ())))).unwrap();
        out.push(("quoted prefix", prefix, rest));
    }
    out
}
