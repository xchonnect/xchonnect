//! Option-contract recognition (spec 11.1.1): real spends from chia-sdk-driver, checked
//! against the simulator, and adversarial variants that must stay unrecognised.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use crate::option::{
    OptionAction, OptionEffect, OptionLeg, OptionOutputRole, OptionTerms, UnderlyingPath,
};
use crate::option_fixture::{
    Collateral, EXPIRY, Locked, MintSpec, clawback, exercise, mint, mint_with, minted, transfer,
};
use crate::permissions::guaranteed_loss;
use crate::simulate::{AssetId, DEFAULT_MAX_COST, Ownership, SpendKind, Summary, simulate};
use crate::swap_fixture::owned;
use chia_protocol::{Bytes32, CoinSpend, Program};
use chia_puzzle_types::singleton::LauncherSolution;
use chia_puzzles::SINGLETON_LAUNCHER_HASH;
use chia_sdk_driver::{OptionMetadata, OptionType};
use chia_sdk_test::{BlsPair, Simulator};
use clvm_traits::{FromClvm, ToClvm};
use clvmr::Allocator;
use proptest::prelude::*;

fn sim_of(spends: &[CoinSpend], who: &Ownership) -> Summary {
    simulate(spends, who, DEFAULT_MAX_COST).unwrap()
}

fn kinds(s: &Summary) -> Vec<&SpendKind> {
    s.spends.iter().map(|x| &x.kind).collect()
}

fn mint_effect(s: &Summary) -> (bool, bool, bool, bool, OptionTerms) {
    match s.options.as_slice() {
        [
            OptionEffect::Mint {
                owner_is_user,
                creator_is_user,
                funded_by_user,
                guaranteed,
                terms,
                ..
            },
        ] => (
            *owner_is_user,
            *creator_is_user,
            *funded_by_user,
            *guaranteed,
            *terms,
        ),
        other => panic!("expected one mint, got {other:?}"),
    }
}

#[test]
fn an_xch_mint_locks_collateral_instead_of_paying_a_stranger() {
    let mut sim = Simulator::new();
    let alice = BlsPair::new(1);
    let spec = MintSpec::simple(&alice);
    let m = mint(&mut sim, &alice, spec);
    let s = sim_of(&m.spends, &owned(alice.puzzle_hash));

    assert!(s.unknown_puzzles.is_empty(), "{:?}", kinds(&s));
    assert!(kinds(&s).iter().any(
        |k| matches!(k, SpendKind::SingletonLauncher { launcher_id } if *launcher_id == m.launcher_id)
    ));
    let (owner, creator, funded, guaranteed, terms) = mint_effect(&s);
    assert!(owner && creator && funded && guaranteed);
    assert_eq!(
        terms,
        OptionTerms {
            creator_puzzle_hash: alice.puzzle_hash,
            expiration_seconds: EXPIRY,
            collateral: OptionLeg {
                asset: AssetId::Xch,
                amount: 1000
            },
            strike: OptionLeg {
                asset: AssetId::Xch,
                amount: 300
            },
        }
    );
    // XCH: collateral, the option's mojo and the fee leave the balance.
    let xch = s.asset(AssetId::Xch).unwrap();
    assert_eq!(xch.net, -(1000 + 1 + 7));
    assert_eq!(s.implied_fee, Some(7));
    // The option arrives, guaranteed by the user's own launcher assertion.
    let opt = s.asset(AssetId::Option(m.launcher_id)).unwrap();
    assert_eq!((opt.received, opt.conditional_received, opt.net), (1, 0, 1));
    // The collateral and launcher outputs are marked, not shown as payments.
    let marked: Vec<_> = s
        .outputs
        .iter()
        .filter_map(|o| o.option.map(|x| (x.role, o.amount, o.recipient.is_none())))
        .collect();
    assert_eq!(
        marked,
        vec![
            (OptionOutputRole::Collateral, 1000, true),
            (OptionOutputRole::Launcher, 1, true)
        ]
    );
    // Limits count the locked collateral; the option itself is not a loss.
    let loss = guaranteed_loss(&s);
    assert_eq!(loss.get(&AssetId::Xch), Some(&1008));
    assert!(!loss.contains_key(&AssetId::Option(m.launcher_id)));
    // The prompt serialises with the new fields.
    let json = serde_json::to_value(&s).unwrap();
    assert_eq!(json["options"][0]["action"], "mint");
    assert_eq!(
        json["options"][0]["terms"]["collateral"],
        serde_json::json!({ "asset": { "type": "xch" }, "amount": "1000" })
    );
    let option_asset = json["assets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["asset"]["type"] == "option")
        .unwrap();
    assert_eq!(
        option_asset["asset"]["asset_id"],
        hex::encode(m.launcher_id)
    );
    assert_eq!(json["outputs"][0]["option"]["role"], "collateral");
    sim.spend_coins(m.spends, &[alice.sk]).unwrap();
}

#[test]
fn a_cat_collateral_with_a_cat_strike_is_recognised() {
    let mut sim = Simulator::new();
    let alice = BlsPair::new(1);
    let strike_tail = Bytes32::new([5; 32]);
    let spec = MintSpec {
        collateral: Collateral::Cat,
        strike: OptionType::Cat {
            asset_id: strike_tail,
            amount: 40,
        },
        ..MintSpec::simple(&alice)
    };
    let m = mint(&mut sim, &alice, spec);
    let Locked::Cat(cat) = m.locked else {
        unreachable!()
    };
    let s = sim_of(&m.spends, &owned(alice.puzzle_hash));
    assert!(s.unknown_puzzles.is_empty(), "{:?}", kinds(&s));
    let (.., terms) = mint_effect(&s);
    assert_eq!(terms.collateral.asset, AssetId::Cat(cat.info.asset_id));
    assert_eq!(
        terms.strike,
        OptionLeg {
            asset: AssetId::Cat(strike_tail),
            amount: 40
        }
    );
    assert_eq!(
        s.asset(AssetId::Cat(cat.info.asset_id)).unwrap().net,
        -1000,
        "the CAT collateral leaves the balance"
    );
    sim.spend_coins(m.spends, &[alice.sk]).unwrap();
}

#[test]
fn a_loan_mint_shows_the_lender_as_creator() {
    // Alice borrows: she locks collateral and holds the option (her right to repay);
    // Bob, the lender, is the creator and may take the collateral after expiry.
    let mut sim = Simulator::new();
    let (alice, bob) = (BlsPair::new(1), BlsPair::new(2));
    let spec = MintSpec {
        creator: bob.puzzle_hash,
        ..MintSpec::simple(&alice)
    };
    let m = mint(&mut sim, &alice, spec);
    let (owner, creator, funded, guaranteed, terms) =
        mint_effect(&sim_of(&m.spends, &owned(alice.puzzle_hash)));
    assert_eq!(
        (owner, creator, funded, guaranteed),
        (true, false, true, true)
    );
    assert_eq!(terms.creator_puzzle_hash, bob.puzzle_hash);
    // Bob's view of the same bundle.
    let (owner, creator, funded, guaranteed, _) =
        mint_effect(&sim_of(&m.spends, &owned(bob.puzzle_hash)));
    assert_eq!(
        (owner, creator, funded, guaranteed),
        (false, true, false, false)
    );
    sim.spend_coins(m.spends, &[alice.sk]).unwrap();
}

#[test]
fn a_transfer_moves_the_option_and_nothing_else() {
    let mut sim = Simulator::new();
    let (alice, bob) = (BlsPair::new(1), BlsPair::new(2));
    let m = minted(&mut sim, &alice, MintSpec::simple(&alice));
    let spends = transfer(&alice, &m, bob.puzzle_hash);
    let s = sim_of(&spends, &owned(alice.puzzle_hash));
    assert!(s.unknown_puzzles.is_empty());
    assert!(matches!(
        s.options.as_slice(),
        [OptionEffect::Transfer { from_user: true, to, to_user: false, .. }] if *to == bob.puzzle_hash
    ));
    assert!(matches!(
        &s.spends[0].kind,
        SpendKind::Option {
            action: OptionAction::Transfer,
            terms: None,
            ..
        }
    ));
    let d = s.asset(AssetId::Option(m.launcher_id)).unwrap();
    assert_eq!((d.sent, d.received, d.net), (1, 0, -1));
    assert!(s.asset(AssetId::Xch).is_none());
    assert_eq!(s.implied_fee, Some(0));
    assert_eq!(
        s.outputs[0].recipient,
        Some(hex::encode(bob.puzzle_hash)),
        "the new owner, not the singleton puzzle hash"
    );
    // Bob sees the option arrive, conditionally (Alice's spend, not his).
    let b = sim_of(&spends, &owned(bob.puzzle_hash));
    assert_eq!(
        b.asset(AssetId::Option(m.launcher_id))
            .unwrap()
            .conditional_received,
        1
    );
    sim.spend_coins(spends, &[alice.sk]).unwrap();
}

#[test]
fn an_exercise_shows_strike_paid_and_collateral_conditional() {
    let mut sim = Simulator::new();
    let (alice, bob) = (BlsPair::new(1), BlsPair::new(2));
    // Bob wrote the option; Alice holds it and exercises.
    let spec = MintSpec {
        creator: bob.puzzle_hash,
        owner: alice.puzzle_hash,
        ..MintSpec::simple(&bob)
    };
    let m = minted(&mut sim, &bob, spec);
    let spends = exercise(&mut sim, &alice, &m, true, true);
    let s = sim_of(&spends, &owned(alice.puzzle_hash));
    assert!(s.unknown_puzzles.is_empty(), "{:?}", kinds(&s));
    let OptionEffect::Exercise {
        by_user,
        creator_is_user,
        terms,
        ..
    } = &s.options[0]
    else {
        panic!("{:?}", s.options)
    };
    assert!(*by_user && !creator_is_user);
    assert_eq!(terms.creator_puzzle_hash, bob.puzzle_hash);
    assert_eq!(terms.strike.amount, 300);
    assert!(s.spends.iter().any(|x| matches!(
        x.kind,
        SpendKind::OptionUnderlying {
            path: UnderlyingPath::Exercise,
            ..
        }
    )));
    let xch = s.asset(AssetId::Xch).unwrap();
    assert_eq!(
        (xch.sent, xch.received),
        (300, 0),
        "strike leaves the balance"
    );
    assert_eq!(
        xch.conditional_received, 1000,
        "collateral arrives via settlement"
    );
    assert_eq!(guaranteed_loss(&s).get(&AssetId::Xch), Some(&300));
    // The creator sees the strike arrive.
    let b = sim_of(&spends, &owned(bob.puzzle_hash));
    assert!(matches!(
        &b.options[0],
        OptionEffect::Exercise {
            by_user: false,
            creator_is_user: true,
            ..
        }
    ));
    assert_eq!(b.asset(AssetId::Xch).unwrap().conditional_received, 300);
    sim.spend_coins(spends, &[alice.sk]).unwrap();
}

#[test]
fn a_clawback_after_expiry_returns_the_collateral() {
    for collateral in [Collateral::Xch, Collateral::Cat] {
        let mut sim = Simulator::new();
        let alice = BlsPair::new(1);
        let spec = MintSpec {
            collateral,
            ..MintSpec::simple(&alice)
        };
        let m = minted(&mut sim, &alice, spec);
        let spends = clawback(&alice, &m);
        let s = sim_of(&spends, &owned(alice.puzzle_hash));
        assert!(s.unknown_puzzles.is_empty(), "{:?}", kinds(&s));
        let asset = match m.locked {
            Locked::Xch(_) => AssetId::Xch,
            Locked::Cat(cat) => AssetId::Cat(cat.info.asset_id),
        };
        assert_eq!(
            s.options,
            vec![OptionEffect::Clawback {
                launcher_id: None,
                creator: alice.puzzle_hash,
                creator_is_user: true,
                collateral: OptionLeg {
                    asset,
                    amount: 1000
                },
                unlocks_at_seconds: EXPIRY,
            }]
        );
        assert!(s.spends[0].owned, "the creator signs it");
        // The collateral was locked, not part of the balance: it comes back (review CR-M2).
        let d = s.asset(asset).unwrap();
        assert_eq!((d.sent, d.received, d.net), (0, 1000, 1000));
        assert_eq!(s.time_locks.not_before_seconds, Some(EXPIRY));
        assert!(guaranteed_loss(&s).is_empty());
        // Too early for the chain; fine after expiry.
        assert!(
            sim.clone()
                .spend_coins(spends.clone(), std::slice::from_ref(&alice.sk))
                .is_err()
        );
        sim.set_next_timestamp(100).unwrap();
        sim.spend_coins(spends, &[alice.sk]).unwrap();
    }
}

// --- adversarial: none of these may be shown as an option ---

fn unknown_count(spends: &[CoinSpend], who: &BlsPair) -> usize {
    sim_of(spends, &owned(who.puzzle_hash))
        .unknown_puzzles
        .len()
}

#[test]
fn a_mint_without_its_launcher_spend_is_unknown() {
    let mut sim = Simulator::new();
    let alice = BlsPair::new(1);
    let m = mint(&mut sim, &alice, MintSpec::simple(&alice));
    let spends: Vec<_> = m
        .spends
        .into_iter()
        .filter(|cs| cs.coin.puzzle_hash != SINGLETON_LAUNCHER_HASH.into())
        .collect();
    let s = sim_of(&spends, &owned(alice.puzzle_hash));
    assert_eq!(s.unknown_puzzles.len(), 1, "the eve option");
    assert!(s.options.is_empty());
}

#[test]
fn collateral_at_a_fake_puzzle_hash_is_unknown() {
    // The option commits to a coin the payer sends to their own address instead of the
    // collateral puzzle: nothing would be locked.
    let mut sim = Simulator::new();
    let alice = BlsPair::new(1);
    let mut fake = None;
    let m = mint_with(&mut sim, &alice, MintSpec::simple(&alice), |id, _| {
        fake = Some(id);
        Bytes32::new([3; 32])
    });
    assert!(fake.is_some());
    assert_eq!(unknown_count(&m.spends, &alice), 2, "launcher and eve");
}

#[test]
fn an_option_that_does_not_commit_to_the_created_collateral_is_unknown() {
    let mut sim = Simulator::new();
    let alice = BlsPair::new(1);
    // Point the option at a coin of the right puzzle hash that the request does not create.
    let m = mint_with(&mut sim, &alice, MintSpec::simple(&alice), |_, p2| {
        chia_protocol::Coin::new(Bytes32::new([9; 32]), p2, 1000).coin_id()
    });
    assert_eq!(unknown_count(&m.spends, &alice), 2);
}

/// Replace the launcher's metadata (expiry or strike) in a mint bundle.
fn retarget(spends: &[CoinSpend], f: impl Fn(&mut OptionMetadata)) -> Vec<CoinSpend> {
    spends
        .iter()
        .map(|cs| {
            if cs.coin.puzzle_hash != SINGLETON_LAUNCHER_HASH.into() {
                return cs.clone();
            }
            let mut a = Allocator::new();
            let node = cs.solution.to_clvm(&mut a).unwrap();
            let mut sol = LauncherSolution::<OptionMetadata>::from_clvm(&a, node).unwrap();
            f(&mut sol.key_value_list);
            let node = sol.to_clvm(&mut a).unwrap();
            CoinSpend::new(
                cs.coin,
                cs.puzzle_reveal.clone(),
                Program::from_clvm(&a, node).unwrap(),
            )
        })
        .collect()
}

#[test]
fn launcher_metadata_that_disagrees_with_the_collateral_is_unknown() {
    let mut sim = Simulator::new();
    let alice = BlsPair::new(1);
    let m = mint(&mut sim, &alice, MintSpec::simple(&alice));
    let later = retarget(&m.spends, |md| md.expiration_seconds = 10_000);
    assert_eq!(unknown_count(&later, &alice), 2, "expiry mismatch");
    let cheaper = retarget(&m.spends, |md| {
        md.strike_type = OptionType::Xch { amount: 1 }
    });
    assert_eq!(unknown_count(&cheaper, &alice), 2, "strike mismatch");
    let nft = retarget(&m.spends, |md| {
        md.strike_type = OptionType::Nft {
            launcher_id: Bytes32::default(),
            settlement_puzzle_hash: Bytes32::default(),
            amount: 1,
        }
    });
    assert_eq!(unknown_count(&nft, &alice), 2, "NFT strikes are not shown");
}

#[test]
fn a_wrong_creator_hint_is_unknown() {
    // The launcher hint names Mallory, but the collateral pays Alice: they disagree.
    let mut sim = Simulator::new();
    let (alice, mallory) = (BlsPair::new(1), BlsPair::new(9));
    let m = mint(&mut sim, &alice, MintSpec::simple(&alice));
    let alice_hint = alice.puzzle_hash.to_vec();
    let spends: Vec<_> = m
        .spends
        .iter()
        .map(|cs| {
            let bytes = cs.solution.to_vec();
            // The launcher's parent is the only spend whose solution carries the hint.
            let replaced = replace(&bytes, &alice_hint, &mallory.puzzle_hash);
            CoinSpend::new(cs.coin, cs.puzzle_reveal.clone(), Program::from(replaced))
        })
        .collect();
    // The standard spends now sign different conditions; the classification is what we test.
    let s = sim_of(&spends, &owned(alice.puzzle_hash));
    assert!(s.options.is_empty());
    assert!(!s.unknown_puzzles.is_empty());
}

fn replace(haystack: &[u8], needle: &[u8], with: &Bytes32) -> Vec<u8> {
    let mut out = haystack.to_vec();
    let mut i = 0;
    while i + needle.len() <= out.len() {
        if &out[i..i + needle.len()] == needle {
            out[i..i + needle.len()].copy_from_slice(with.as_ref());
            i += needle.len();
        } else {
            i += 1;
        }
    }
    out
}

#[test]
fn a_grafted_option_coin_is_unknown() {
    // The same option spend, claimed for a coin with another parent: the singleton's
    // lineage assertion no longer matches, so the bundle could never be valid.
    let mut sim = Simulator::new();
    let (alice, bob) = (BlsPair::new(1), BlsPair::new(2));
    let m = minted(&mut sim, &alice, MintSpec::simple(&alice));
    let mut spends = transfer(&alice, &m, bob.puzzle_hash);
    spends[0].coin.parent_coin_info = Bytes32::new([7; 32]);
    let s = sim_of(&spends, &owned(alice.puzzle_hash));
    assert_eq!(s.unknown_puzzles.len(), 1);
    assert!(s.options.is_empty());
}

#[test]
fn an_exercise_without_the_strike_payment_is_unknown() {
    let mut sim = Simulator::new();
    let alice = BlsPair::new(1);
    let m = minted(&mut sim, &alice, MintSpec::simple(&alice));
    let spends = exercise(&mut sim, &alice, &m, true, false);
    let s = sim_of(&spends, &owned(alice.puzzle_hash));
    assert_eq!(s.unknown_puzzles.len(), 2, "the option and its collateral");
    assert!(s.options.is_empty());
}

#[test]
fn a_strike_paid_to_someone_else_is_unknown() {
    // A settlement payment with the option's nonce but to Mallory cannot rebuild the
    // collateral puzzle, so the exercise is not recognised.
    let mut sim = Simulator::new();
    let (alice, mallory) = (BlsPair::new(1), BlsPair::new(9));
    let m = minted(&mut sim, &alice, MintSpec::simple(&alice));
    let spends = exercise(&mut sim, &alice, &m, true, true);
    let strike_spend = spends.len() - 1;
    let spends: Vec<_> = spends
        .iter()
        .enumerate()
        .map(|(i, cs)| {
            if i != strike_spend {
                return cs.clone();
            }
            let bytes = replace(
                &cs.solution.to_vec(),
                &alice.puzzle_hash,
                &mallory.puzzle_hash,
            );
            CoinSpend::new(cs.coin, cs.puzzle_reveal.clone(), Program::from(bytes))
        })
        .collect();
    let s = sim_of(&spends, &owned(alice.puzzle_hash));
    assert!(s.options.is_empty());
    assert_eq!(s.unknown_puzzles.len(), 2);
}

#[test]
fn an_early_exercise_or_late_clawback_is_visible_in_the_time_locks() {
    let mut sim = Simulator::new();
    let alice = BlsPair::new(1);
    let m = minted(&mut sim, &alice, MintSpec::simple(&alice));
    let s = sim_of(
        &exercise(&mut sim, &alice, &m, true, true),
        &owned(alice.puzzle_hash),
    );
    assert_eq!(s.time_locks.expires_seconds, Some(EXPIRY));
}

// --- properties ---

fn arb_strike() -> impl Strategy<Value = OptionType> {
    prop_oneof![
        (1u64..u64::MAX).prop_map(|amount| OptionType::Xch { amount }),
        (any::<[u8; 32]>(), 1u64..u64::MAX).prop_map(|(id, amount)| OptionType::Cat {
            asset_id: Bytes32::new(id),
            amount
        }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// Whatever the terms, the wallet reads back exactly the terms the mint was built with.
    #[test]
    fn mint_terms_round_trip(
        amount in 1u64..1_000_000,
        seconds in 1u64..u64::MAX,
        strike in arb_strike(),
        loan in any::<bool>(),
        cat in any::<bool>(),
    ) {
        let mut sim = Simulator::new();
        let (alice, bob) = (BlsPair::new(1), BlsPair::new(2));
        let spec = MintSpec {
            creator: if loan { bob.puzzle_hash } else { alice.puzzle_hash },
            amount,
            strike,
            seconds,
            collateral: if cat { Collateral::Cat } else { Collateral::Xch },
            ..MintSpec::simple(&alice)
        };
        let m = mint(&mut sim, &alice, spec);
        let s = sim_of(&m.spends, &owned(alice.puzzle_hash));
        prop_assert!(s.unknown_puzzles.is_empty());
        let (owner, creator, funded, guaranteed, terms) = mint_effect(&s);
        prop_assert!(owner && funded && guaranteed);
        prop_assert_eq!(creator, !loan);
        prop_assert_eq!(terms.expiration_seconds, seconds);
        prop_assert_eq!(terms.collateral.amount, amount);
        prop_assert_eq!(terms.strike.amount, strike.amount());
    }

    /// One flipped byte anywhere in a mint never panics, and never yields an option whose
    /// terms differ from the real ones: a change either breaks the commitments (unknown or a
    /// simulation error) or does not touch them.
    #[test]
    fn a_flipped_byte_never_shows_other_terms(spend in 0usize..8, which in any::<bool>(), at in any::<usize>(), bit in 0u8..8) {
        let mut sim = Simulator::new();
        let alice = BlsPair::new(1);
        let m = mint(&mut sim, &alice, MintSpec::simple(&alice));
        let real = mint_effect(&sim_of(&m.spends, &owned(alice.puzzle_hash))).4;
        let mut spends = m.spends.clone();
        let i = spend % spends.len();
        let cs = &mut spends[i];
        let mut bytes = if which { cs.solution.to_vec() } else { cs.puzzle_reveal.to_vec() };
        let at = at % bytes.len();
        bytes[at] ^= 1 << bit;
        if which { cs.solution = Program::from(bytes) } else { cs.puzzle_reveal = Program::from(bytes) }
        if let Ok(s) = simulate(&spends, &owned(alice.puzzle_hash), DEFAULT_MAX_COST) {
            for e in &s.options {
                if let OptionEffect::Mint { terms, .. } = e {
                    prop_assert_eq!(*terms, real);
                }
            }
        }
    }
}

// --- fuzz seeds ---

/// The `option_spends` fuzz input: owned p2 puzzle hash, then per spend
/// `parent || amount (u64be) || u32be len || puzzle || u32be len || solution`.
pub(crate) fn fuzz_input(owner: Bytes32, spends: &[CoinSpend]) -> Vec<u8> {
    let mut out = owner.to_vec();
    for cs in spends {
        out.extend_from_slice(cs.coin.parent_coin_info.as_ref());
        out.extend_from_slice(&cs.coin.amount.to_be_bytes());
        for program in [&cs.puzzle_reveal, &cs.solution] {
            let bytes = program.to_vec();
            out.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
            out.extend_from_slice(&bytes);
        }
    }
    out
}

/// Seeds for `fuzz/fuzz_targets/option_spends.rs`. Each is checked to be recognised; with
/// `XCHONNECT_FUZZ_SEEDS=$PWD/fuzz/corpus` they are written to `option_spends/seed-*`.
#[test]
fn option_fuzz_seeds() {
    let mut sim = Simulator::new();
    let (alice, bob) = (BlsPair::new(1), BlsPair::new(2));
    let xch = mint(&mut sim, &alice, MintSpec::simple(&alice));
    let cat_spec = MintSpec {
        collateral: Collateral::Cat,
        ..MintSpec::simple(&alice)
    };
    let cat = mint(&mut sim, &alice, cat_spec);
    let m = minted(&mut sim, &alice, MintSpec::simple(&alice));
    let seeds = [
        ("mint-xch", xch.spends),
        ("mint-cat", cat.spends),
        ("transfer", transfer(&alice, &m, bob.puzzle_hash)),
        ("exercise", exercise(&mut sim, &alice, &m, true, true)),
        ("clawback", clawback(&alice, &m)),
    ];
    for (name, spends) in &seeds {
        write_seed(name, alice.puzzle_hash, spends);
    }
}

/// Check that `spends` are recognised for `owner` and, with `XCHONNECT_FUZZ_SEEDS`, write
/// them as the `option_spends` seed `seed-<name>`.
pub(crate) fn write_seed(name: &str, owner: Bytes32, spends: &[CoinSpend]) {
    let s = sim_of(spends, &owned(owner));
    assert!(
        s.unknown_puzzles.is_empty() && !s.options.is_empty(),
        "{name}"
    );
    if let Some(dir) = std::env::var_os("XCHONNECT_FUZZ_SEEDS") {
        let dir = std::path::PathBuf::from(dir).join("option_spends");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("seed-{name}")), fuzz_input(owner, spends)).unwrap();
    }
}

/// A p2 that spends through the delegated puzzle `1`: its conditions are its solution.
struct Unquoted(chia_bls::PublicKey);

impl chia_sdk_driver::SpendWithConditions for Unquoted {
    fn spend_with_conditions(
        &self,
        ctx: &mut chia_sdk_driver::SpendContext,
        conditions: chia_sdk_types::Conditions,
    ) -> Result<chia_sdk_driver::Spend, chia_sdk_driver::DriverError> {
        use chia_sdk_driver::Layer;
        let layer = chia_sdk_driver::StandardLayer::new(self.0);
        let delegated_puzzle = ctx.alloc(&1u8)?;
        let solution = ctx.alloc(&conditions)?;
        let puzzle = layer.construct_puzzle(ctx)?;
        let solution = layer.construct_solution(
            ctx,
            chia_puzzle_types::standard::StandardSolution {
                original_public_key: None,
                delegated_puzzle,
                solution,
            },
        )?;
        Ok(chia_sdk_driver::Spend::new(puzzle, solution))
    }
}

fn plan_for(spends: &[CoinSpend], who: &BlsPair) -> Result<usize, crate::Refusal> {
    let mut a = Allocator::new();
    let (executed, _) =
        crate::execute(&mut a, spends, &owned(who.puzzle_hash), DEFAULT_MAX_COST).unwrap();
    let opts = crate::PolicyOptions {
        network: crate::Network::Testnet11,
        session_chain_id: "testnet11".into(),
        allow_agg_sig_unsafe: false,
        partial: true,
    };
    crate::plan(&executed, &[who.pk].into_iter().collect(), &opts).map(|p| p.ours.len())
}

#[test]
fn an_option_or_its_collateral_through_an_unquoted_delegated_puzzle_is_never_signed() {
    use chia_sdk_driver::{SpendContext, SpendWithConditions, StandardLayer};
    use chia_sdk_types::Conditions;
    let mut sim = Simulator::new();
    let (alice, bob) = (BlsPair::new(1), BlsPair::new(2));
    let m = minted(&mut sim, &alice, MintSpec::simple(&alice));
    // The holder's transfer.
    let mut ctx = SpendContext::new();
    let _child = m
        .option
        .transfer(
            &mut ctx,
            &Unquoted(alice.pk),
            bob.puzzle_hash,
            Conditions::new(),
        )
        .unwrap();
    let unquoted = ctx.take();
    assert_eq!(
        plan_for(&unquoted, &alice),
        Err(crate::Refusal::UnsignedConditions)
    );
    write_seed("unquoted-transfer", alice.puzzle_hash, &unquoted);
    assert_eq!(
        plan_for(&transfer(&alice, &m, bob.puzzle_hash), &alice),
        Ok(1)
    );
    // The creator's clawback of the collateral.
    let crate::option_fixture::Locked::Xch(coin) = m.locked else {
        panic!("XCH collateral");
    };
    let mut ctx = SpendContext::new();
    let back = Conditions::new().create_coin(
        alice.puzzle_hash,
        coin.amount,
        chia_puzzle_types::Memos::None,
    );
    let inner = Unquoted(alice.pk)
        .spend_with_conditions(&mut ctx, back.clone())
        .unwrap();
    m.underlying
        .clawback_coin_spend(&mut ctx, coin, inner)
        .unwrap();
    let unquoted = ctx.take();
    assert_eq!(
        plan_for(&unquoted, &alice),
        Err(crate::Refusal::UnsignedConditions)
    );
    write_seed("unquoted-clawback", alice.puzzle_hash, &unquoted);
    let mut ctx = SpendContext::new();
    let inner = StandardLayer::new(alice.pk)
        .spend_with_conditions(&mut ctx, back)
        .unwrap();
    m.underlying
        .clawback_coin_spend(&mut ctx, coin, inner)
        .unwrap();
    assert_eq!(plan_for(&ctx.take(), &alice), Ok(1));
}
