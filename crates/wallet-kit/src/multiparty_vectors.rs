//! Published multi-party conformance vectors (`docs/spec/vectors/multiparty.json`, TASK-58).
//!
//! `vectors_are_current` regenerates the file from the deterministic swap fixture and
//! requires a byte-identical match (`XCHONNECT_WRITE_VECTORS=1` rewrites it);
//! `vectors_decide_as_expected` runs every case through binding verification and the
//! request handler.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use crate::binding::verify_binding;
use crate::simulate::{AssetId, DEFAULT_MAX_COST};
use crate::spend::{decode_hex, parse_coin_spends};
use crate::swap_fixture::{self, owned, params, swap};
use chia_protocol::{Bytes32, Coin, CoinSpend};
use chia_puzzle_types::Memos;
use chia_sdk_driver::{SpendContext, StandardLayer};
use chia_sdk_test::{BlsPair, Simulator};
use chia_sdk_types::Conditions;
use serde_json::{Value, json};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/spec/vectors/multiparty.json"
);

fn case(
    name: &str,
    description: &str,
    spends: &[CoinSpend],
    wallet: &BlsPair,
    expected: Value,
) -> Value {
    json!({
        "name": name,
        "description": description,
        "wallet": { "owned_puzzle_hashes": [format!("0x{}", hex::encode(wallet.puzzle_hash))], "public_key": format!("0x{}", hex::encode(wallet.pk.to_bytes())) },
        "request": serde_json::from_str::<Value>(&params(spends, true)).unwrap(),
        "expected": expected,
    })
}

/// A settlement-lookalike: an anyone-can-spend coin announcing the message a settlement
/// spend would announce, and the user asserting it.
fn lookalike() -> (Vec<CoinSpend>, BlsPair) {
    let alice = BlsPair::new(11);
    let (attacker, id) = swap_fixture::lookalike(alice.puzzle_hash);
    let mut ctx = SpendContext::new();
    StandardLayer::new(alice.pk)
        .spend(
            &mut ctx,
            Coin::new(Bytes32::new([1; 32]), alice.puzzle_hash, 1000),
            Conditions::new()
                .create_coin(Bytes32::new([3; 32]), 1000, Memos::None)
                .assert_puzzle_announcement(id),
        )
        .unwrap();
    let mut spends = ctx.take();
    spends.push(attacker);
    (spends, alice)
}

fn generate() -> String {
    let mut sim = Simulator::new();
    let bound = swap(&mut sim, true, true);
    let alice_unbound = swap(&mut sim, false, true);
    let bob_unbound = swap(&mut sim, true, false);
    let (fake, fake_wallet) = lookalike();
    let signed = |received: u64| json!({ "outcome": "signed", "bound_received": [{ "asset": { "type": "xch" }, "amount": received }] });
    let refused = json!({ "outcome": "refused", "code": 4001, "reason": "unbound_partial" });
    let cases = vec![
        case(
            "swap-maker-bound",
            "Alice's coin pays 1000 into settlement and asserts the settlement announcement paying her 500.",
            &bound.spends,
            &bound.alice,
            signed(500),
        ),
        case(
            "swap-taker-bound",
            "Bob's coin pays 500 into settlement and asserts the settlement announcement paying him 1000.",
            &bound.spends,
            &bound.bob,
            signed(1000),
        ),
        case(
            "swap-maker-unbound",
            "Same swap, but Alice's spend does not assert the payment she expects: it could be included alone.",
            &alice_unbound.spends,
            &alice_unbound.alice,
            refused.clone(),
        ),
        case(
            "swap-taker-unbound",
            "Same swap, but Bob's spend does not assert his payment.",
            &bob_unbound.spends,
            &bob_unbound.bob,
            refused.clone(),
        ),
        case(
            "settlement-lookalike",
            "The user asserts the message a settlement payment would announce, but from an anyone-can-spend coin: it can announce without paying.",
            &fake,
            &fake_wallet,
            refused,
        ),
    ];
    let mut s = serde_json::to_string_pretty(&json!({
        "version": 1,
        "description": "Multi-party partialSign conformance (spec 11.2). For each case a conforming wallet owning `wallet.owned_puzzle_hashes` and holding the key `wallet.public_key` must sign (`signed`, and treat `bound_received` as guaranteed) or refuse with the given code and reason. Network: testnet11.",
        "cases": cases,
    }))
    .unwrap();
    s.push('\n');
    s
}

#[test]
fn vectors_are_current() {
    let generated = generate();
    if std::env::var_os("XCHONNECT_WRITE_VECTORS").is_some() {
        std::fs::write(PATH, &generated).unwrap();
    }
    let committed = std::fs::read_to_string(PATH)
        .expect("run with XCHONNECT_WRITE_VECTORS=1 to create the file");
    assert_eq!(
        committed, generated,
        "multiparty.json is stale: rerun with XCHONNECT_WRITE_VECTORS=1"
    );
}

#[test]
fn vectors_decide_as_expected() {
    let file: Value = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    for c in file["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let spends = parse_coin_spends(&c["request"]["coinSpends"]).unwrap();
        let ph: [u8; 32] = decode_hex(c["wallet"]["owned_puzzle_hashes"][0].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let report = verify_binding(&spends, &owned(Bytes32::from(ph)), DEFAULT_MAX_COST).unwrap();
        match c["expected"]["outcome"].as_str().unwrap() {
            "signed" => {
                assert!(report.all_bound, "{name}");
                let want = c["expected"]["bound_received"][0]["amount"].as_u64();
                assert_eq!(
                    report.received(AssetId::Xch),
                    u128::from(want.unwrap()),
                    "{name}"
                );
            }
            "refused" => assert!(!report.all_bound, "{name}"),
            other => panic!("{name}: unknown outcome {other}"),
        }
    }
}
