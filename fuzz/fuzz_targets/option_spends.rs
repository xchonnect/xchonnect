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
//! item 2) for every key the request asks to sign. The request handlers run too, as a
//! wallet holding every key the request names (the user rejects every prompt): a partial
//! request that reaches the prompt is bound and has no spend the wallet signs without
//! recognising it (rc.5 round 5, U1), and a wallet-built request read as sealed has its
//! user spends co-required (S1).
#![no_main]

use chia_bls::{PublicKey, Signature};
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
use xchonnect_wallet_kit::handlers::{
    Approver, Broadcast, BroadcastRecord, Broadcaster, Prompt, RequestContext, SUBMIT_COIN_SPENDS,
    SignedCoins, Signer, SignerError, SubmitRequest, handle, submit,
};
use xchonnect_wallet_kit::permissions::{
    DailySpend, DappPermissions, LimitStore, PermissionError, guaranteed_loss,
};
use xchonnect_wallet_kit::simulate::claim_signed;
use xchonnect_wallet_kit::{Linking, verify_binding, verify_binding_as, verify_binding_signed};
use std::cell::RefCell;
use chia_protocol::SpendBundle;
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
    // An option leaving the user counts once, whatever its mojos (the option limit).
    assert!(
        guaranteed_loss(&summary)
            .iter()
            .all(|(a, n)| !matches!(a, AssetId::Option(_)) || *n == 1)
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
    handlers_hold(&spends, &ownership, &summary);
});

struct NoKey;
impl Signer for NoKey {
    fn sign(&self, _pk: &PublicKey, _msg: &[u8]) -> Result<Signature, SignerError> {
        Err(SignerError::KeyUnavailable)
    }
}

/// Keeps every prompt as JSON and rejects it.
#[derive(Default)]
struct Reject(RefCell<Vec<serde_json::Value>>);
impl Approver for Reject {
    fn approve(&self, p: &Prompt<'_>) -> bool {
        // Every prompt serialises, and no number in it exceeds 2^53 (amounts and times are
        // decimal strings): a host reads it exactly in JavaScript, Swift or Kotlin.
        let value = serde_json::to_value(p).expect("a prompt serialises");
        assert_exact_numbers(&value);
        self.0.borrow_mut().push(value);
        false
    }
}

/// Panics on a JSON number above 2^53 anywhere in `v`.
fn assert_exact_numbers(v: &serde_json::Value) {
    const EXACT: u64 = 1 << 53;
    match v {
        serde_json::Value::Number(n) => assert!(
            n.as_u64().is_some_and(|x| x <= EXACT)
                || n.as_i64().is_some_and(|x| x.unsigned_abs() <= EXACT),
            "a prompt number above 2^53: {n}"
        ),
        serde_json::Value::Array(a) => a.iter().for_each(assert_exact_numbers),
        serde_json::Value::Object(o) => o.values().for_each(assert_exact_numbers),
        _ => {}
    }
}

#[derive(Default)]
struct Limits(RefCell<DailySpend>);
impl LimitStore for Limits {
    fn load(&self) -> Result<DailySpend, PermissionError> {
        Ok(self.0.borrow().clone())
    }
    fn save(&self, r: &DailySpend) -> Result<(), PermissionError> {
        *self.0.borrow_mut() = r.clone();
        Ok(())
    }
}

struct Nowhere;
impl Broadcaster for Nowhere {
    fn record(&self, _r: &BroadcastRecord) -> Result<(), String> {
        Ok(())
    }
    fn submit(&self, _b: &SpendBundle) -> Result<Broadcast, String> {
        Err("not sent".to_owned())
    }
}

fn params(spends: &[CoinSpend], partial: bool) -> String {
    let list: Vec<serde_json::Value> = spends
        .iter()
        .map(|cs| {
            serde_json::json!({
                "coin": {
                    "parent_coin_info": format!("0x{}", hex(cs.coin.parent_coin_info.as_ref())),
                    "puzzle_hash": format!("0x{}", hex(cs.coin.puzzle_hash.as_ref())),
                    "amount": cs.coin.amount,
                },
                "puzzle_reveal": format!("0x{}", hex(cs.puzzle_reveal.as_ref())),
                "solution": format!("0x{}", hex(cs.solution.as_ref())),
            })
        })
        .collect();
    serde_json::json!({ "coinSpends": list, "partialSign": partial }).to_string()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Spec 11.2 through the request handlers, as a wallet that holds every key the request
/// names and allows unknown contracts; every prompt is rejected, so nothing is signed.
fn handlers_hold(spends: &[CoinSpend], ownership: &Ownership, summary: &xchonnect_wallet_kit::Summary) {
    let mut a = Allocator::new();
    let Ok((mut executed, _)) = execute(&mut a, spends, ownership, MAX_COST) else {
        return;
    };
    let keys: HashSet<PublicKey> = executed
        .iter()
        .flat_map(|es| es.conditions.iter())
        .filter_map(|c| c.clone().into_agg_sig())
        .map(|s| s.public_key)
        .filter(|k| !k.is_inf())
        .collect();
    let Some(&first) = keys.iter().next() else {
        return;
    };
    claim_signed(&mut executed, &keys);
    let user_spends = executed.iter().filter(|es| es.owned).count();
    let perms = DappPermissions::new_default(first);
    let limits = Limits::default();
    let signed = SignedCoins::default();
    let ctx = RequestContext {
        dapp: "fuzz.invalid",
        network: Network::Testnet11,
        session_chain_id: "testnet11",
        permissions: &perms,
        allow_agg_sig_unsafe: true,
        allow_unknown_contracts: true,
        ownership,
        keys: &keys,
        limits: &limits,
        now: 1_790_000_000,
        chain: None,
        signed_coins: &signed,
    };
    // A partial request reaches the prompt only bound, and with no spend the wallet signs
    // without recognising it.
    let ui = Reject::default();
    let _ = handle("signCoinSpends", &params(spends, true), &ctx, &NoKey, &ui);
    if let Some(p) = ui.0.borrow().first() {
        assert_eq!(p["binding"]["all_bound"], true, "an unbound partial request was shown");
        assert_eq!(
            p["summary"]["unaccounted_spends"].as_array().map_or(0, Vec::len),
            0,
            "a partial request with an unrecognised user-key spend was shown"
        );
    }
    // A wallet-built request read as sealed: its user spends require one another.
    let ui = Reject::default();
    let _ = submit(
        SubmitRequest {
            method: SUBMIT_COIN_SPENDS,
            spends: spends.to_vec(),
            other_signature: None,
            intent: None,
            wallet_built: true,
            wallet_fee: summary.owned_reserve_fee,
            signatures_released: false,
        },
        &ctx,
        &NoKey,
        &ui,
        &Nowhere,
    );
    if let Some(p) = ui.0.borrow().first()
        && p["linking"] == "sealed"
        && user_spends > 1
    {
        let report = verify_binding_signed(spends, ownership, &keys, MAX_COST, Linking::Sealed)
            .expect("simulated above");
        assert!(report.co_required, "a sealed request whose user spends are not co-required");
    }
}

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
