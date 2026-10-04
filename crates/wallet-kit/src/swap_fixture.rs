//! Test fixture: an atomic two-party XCH swap through offer settlement payments.
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

use chia_protocol::{Bytes32, Coin, CoinSpend};
use chia_puzzle_types::Memos;
use chia_puzzle_types::offer::{NotarizedPayment, Payment, SettlementPaymentsSolution};
use chia_puzzles::SETTLEMENT_PAYMENT_HASH;
use chia_sdk_driver::{Layer, SettlementLayer, SpendContext, StandardLayer};
use chia_sdk_test::{BlsPair, Simulator};
use chia_sdk_types::Conditions;
use xchonnect_core::crypto::sha256_parts;

pub struct Swap {
    pub alice: BlsPair,
    pub bob: BlsPair,
    pub spends: Vec<CoinSpend>,
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

/// CHIP-0002 `signCoinSpends` params for the swap.
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
