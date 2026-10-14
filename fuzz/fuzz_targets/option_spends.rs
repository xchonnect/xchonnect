//! Option-contract recognition in the wallet's simulation (wallet-kit `option.rs`, spec
//! 11.1.1) on dApp-chosen coin spends.
//!
//! Input: 32 bytes, the p2 puzzle hash the wallet owns; then frames
//! `parent (32) || amount (u64be) || u32be len || puzzle || u32be len || solution`. Each
//! coin's puzzle hash is the tree hash of its puzzle, so the fuzzer reaches the parsers
//! instead of the puzzle-hash check. Seeds (mint, transfer, exercise, clawback, and the
//! same built the way Sage builds them) come from the `option_fuzz_seeds` tests in
//! `crates/wallet-kit`. The binding and exercise-coverage check (spec 11.1.1, 11.2) runs on
//! every input that simulates, under both linkings (signatures released: direct only;
//! sealed wallet-built: the user's own links), and so does the signature policy (spec 11.1
//! item 2) for every key the request asks to sign.
#![no_main]

use chia_bls::PublicKey;
use chia_protocol::{Bytes32, Coin, CoinSpend, Program};
use chia_puzzle_types::standard::StandardSolution;
use clvm_traits::{FromClvm, ToClvm};
use clvm_utils::tree_hash_from_bytes;
use clvmr::{Allocator, NodePtr, SExp};
use libfuzzer_sys::fuzz_target;
use std::collections::HashSet;
use xchonnect_wallet_kit::policy::{AGG_SIG_ME, Network, PolicyOptions, plan};
use xchonnect_wallet_kit::simulate::execute;
use xchonnect_wallet_kit::option::{OptionEffect, OptionOutputRole};
use xchonnect_wallet_kit::{Linking, verify_binding, verify_binding_as};
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
    // A mint output of an option the user holds is never the user's, and is named as paid
    // to someone only when it is collateral under another creator (spec 11.1.1).
    for o in &summary.outputs {
        if let Some(x) = o.option.filter(|x| x.user_holds_option) {
            assert!(!o.to_user);
            assert!(o.recipient.is_none() || x.role == OptionOutputRole::Collateral);
        }
    }
    let report = verify_binding(&spends, &ownership, MAX_COST).expect("simulated above");
    // The binding report covers exactly the user's exercises, and serialises.
    let exercises = summary
        .options
        .iter()
        .any(|e| matches!(e, OptionEffect::Exercise { by_user: true, .. }));
    assert_eq!(report.exercises.is_empty(), !exercises);
    assert!(
        report
            .exercises
            .iter()
            .all(|e| e.covered == (e.received >= e.collateral))
    );
    if report.exercises_covered() && exercises {
        assert!(report.co_required);
    }
    assert!(serde_json::to_string(&report).is_ok());
    // Sealed linking only adds links: whatever binds directly binds sealed too.
    let sealed = verify_binding_as(&spends, &ownership, MAX_COST, Linking::Sealed)
        .expect("simulated above");
    if report.all_bound {
        assert!(sealed.all_bound);
    }
    assert_eq!(sealed.exercises.len(), report.exercises.len());
    if sealed.exercises_covered() && exercises {
        assert!(sealed.co_required);
    }
    assert!(serde_json::to_string(&sealed).is_ok());
    signed_standard_spends_are_quoted(&spends, &ownership);
});

/// Spec 11.1 item 2: whatever key the wallet holds, it signs an `AGG_SIG_ME` in a standard
/// spend only when the delegated puzzle is a quoted program, so the conditions the user saw
/// are the only ones the signature allows.
fn signed_standard_spends_are_quoted(spends: &[CoinSpend], ownership: &Ownership) {
    let mut a = Allocator::new();
    let Ok((executed, _)) = execute(&mut a, spends, ownership, MAX_COST) else {
        return;
    };
    let keys: HashSet<PublicKey> = executed
        .iter()
        .flat_map(|es| es.conditions.iter())
        .filter_map(|c| c.clone().into_agg_sig())
        .map(|s| s.public_key)
        .collect();
    let opts = PolicyOptions {
        network: Network::Testnet11,
        session_chain_id: "testnet11".to_owned(),
        allow_agg_sig_unsafe: true,
        partial: true,
    };
    let Ok(plan) = plan(&executed, &keys, &opts) else {
        return;
    };
    for r in plan.ours.iter().filter(|r| r.opcode == AGG_SIG_ME) {
        if executed[r.spend].kind != SpendKind::Standard {
            continue;
        }
        let solution = spends[r.spend].solution.to_clvm(&mut a).expect("executed above");
        let parsed = StandardSolution::<NodePtr, NodePtr>::from_clvm(&a, solution)
            .expect("a standard spend that ran has a standard solution");
        let quoted = match a.sexp(parsed.delegated_puzzle) {
            SExp::Pair(first, _) => {
                matches!(a.sexp(first), SExp::Atom) && a.atom(first).as_ref() == [1u8]
            }
            SExp::Atom => false,
        };
        assert!(quoted, "signed a standard spend whose delegated puzzle is not quoted");
    }
}
