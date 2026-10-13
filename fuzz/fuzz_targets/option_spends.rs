//! Option-contract recognition in the wallet's simulation (wallet-kit `option.rs`, spec
//! 11.1.1) on dApp-chosen coin spends.
//!
//! Input: 32 bytes, the p2 puzzle hash the wallet owns; then frames
//! `parent (32) || amount (u64be) || u32be len || puzzle || u32be len || solution`. Each
//! coin's puzzle hash is the tree hash of its puzzle, so the fuzzer reaches the parsers
//! instead of the puzzle-hash check. Seeds (mint, transfer, exercise, clawback) come from
//! the `option_fuzz_seeds` test in `crates/wallet-kit`.
#![no_main]

use chia_protocol::{Bytes32, Coin, CoinSpend, Program};
use clvm_utils::tree_hash_from_bytes;
use libfuzzer_sys::fuzz_target;
use xchonnect_wallet_kit::option::OptionEffect;
use xchonnect_wallet_kit::permissions::guaranteed_loss;
use xchonnect_wallet_kit::simulate::{AssetId, Ownership, SpendKind, simulate};

/// Lower than a block so one input stays fast.
const MAX_COST: u64 = 1_000_000_000;

fn take<'a>(data: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if data.len() < n {
        return None;
    }
    let (head, rest) = data.split_at(n);
    *data = rest;
    Some(head)
}

fn blob<'a>(data: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len = u32::from_be_bytes(take(data, 4)?.try_into().ok()?) as usize;
    take(data, len)
}

fn decode(mut data: &[u8]) -> Option<(Bytes32, Vec<CoinSpend>)> {
    let owner = Bytes32::try_from(take(&mut data, 32)?).ok()?;
    let mut spends = Vec::new();
    while !data.is_empty() && spends.len() < 64 {
        let parent = Bytes32::try_from(take(&mut data, 32)?).ok()?;
        let amount = u64::from_be_bytes(take(&mut data, 8)?.try_into().ok()?);
        let puzzle = blob(&mut data)?;
        let solution = blob(&mut data)?;
        let puzzle_hash = Bytes32::from(tree_hash_from_bytes(puzzle).ok()?);
        spends.push(CoinSpend::new(
            Coin::new(parent, puzzle_hash, amount),
            Program::from(puzzle.to_vec()),
            Program::from(solution.to_vec()),
        ));
    }
    Some((owner, spends))
}

fuzz_target!(|data: &[u8]| {
    let Some((owner, spends)) = decode(data) else {
        return;
    };
    let ownership = Ownership {
        p2_puzzle_hashes: [owner].into_iter().collect(),
    };
    let Ok(summary) = simulate(&spends, &ownership, MAX_COST) else {
        return;
    };
    // The prompt always serialises.
    assert!(serde_json::to_string(&summary).is_ok());
    // A launcher is recognised only together with the mint it launches, and a mint always
    // carries its proven terms.
    let launchers = summary
        .spends
        .iter()
        .filter(|s| matches!(s.kind, SpendKind::SingletonLauncher { .. }))
        .count();
    let mints = summary
        .options
        .iter()
        .filter(|e| matches!(e, OptionEffect::Mint { .. }))
        .count();
    assert_eq!(launchers, mints);
    // Unknown puzzles are exactly the unclassified spends.
    let unknown = summary
        .spends
        .iter()
        .filter(|s| s.kind == SpendKind::Unknown)
        .count();
    assert_eq!(unknown, summary.unknown_puzzles.len());
    // Options themselves never count against spending limits.
    assert!(
        guaranteed_loss(&summary)
            .keys()
            .all(|a| !matches!(a, AssetId::Option(_)))
    );
});
