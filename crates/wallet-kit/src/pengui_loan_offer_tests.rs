//! Pengui's open loan offers through the kit, as a Klimper wallet runs it (TASK-79).
//!
//! `fixtures/pengui-loan-offers.json` is exported by Pengui's own builder
//! (`src/shared/lib/wallet/options/__fixtures__/exportLoanOfferFixtures.test.ts`) on the
//! chia-wallet-sdk simulator: the lender mints an option (collateral locked, strike = the
//! repayment, creator = owner = lender), then offers the option plus the principal for
//! exactly the collateral. For each case the file holds the request Pengui hands to CHIP-0002
//! `signCoinSpends` (`partialSign: true`), the requested-payment placeholders it appends when
//! it assembles the offer, the signed `offer1…` string with the bundle it encodes, and the
//! lender's test key.
//!
//! # Keeping the fixture current
//!
//! The file is compiled in ([`FIXTURE`]) and its SHA-256 is pinned ([`FIXTURE_SHA256`]), so a
//! copy that drifts from Pengui's fails [`cases`] before any test runs. Pengui's own suite
//! fails when its committed file is stale; the two together keep the fixture current. To
//! regenerate, in the Pengui repo (`../../pengui/pengui`):
//!
//! ```sh
//! EXPORT_LOAN_OFFER_FIXTURES=1 bun test src/shared/lib/wallet/options/__fixtures__/exportLoanOfferFixtures.test.ts
//! cp src/shared/lib/wallet/options/__fixtures__/pengui-loan-offers.json \
//!    ../../xchonnect/xchonnect/crates/wallet-kit/fixtures/pengui-loan-offers.json
//! shasum -a 256 ../../xchonnect/xchonnect/crates/wallet-kit/fixtures/pengui-loan-offers.json
//! ```
//!
//! then set [`FIXTURE_SHA256`] to the new digest. The file's `generator` field names the
//! first command; [`cases`] checks it matches [`GENERATOR`] so this text cannot go stale alone.
//!
//! Fields of the fixture these tests do not read, carried for Pengui's own tests: `about`,
//! `network.chain_id` and `network.genesis_challenge` (the kit checks
//! `agg_sig_me_additional_data`), `terms.mint_fee` (the mint is before the offer),
//! `cancellable_coin_ids`, `option.lineage_proof`, and in `lender_coins` everything beside
//! `coin` (`coin_id`, `kind`, `launcher_id`, `p2_puzzle_hash`, `lineage_proof`, `asset_id`).
//!
//! # What is checked
//!
//! Two sides, nothing in the kit being changed for the fixture:
//!
//! - **signing** (spec 11.1, 11.1.1, 11.2): the request through [`handle`] as Klimper calls
//!   it, as Pengui sends it and with the placeholders;
//! - **taking** (Klimper's `chia_takeOffer`): the signed offer read with chia-sdk-driver
//!   0.36 as Sage reads offers, Klimper's `check_offer` mirrored, and the take built with the
//!   action system as Sage's `take_offer` builds it, run through [`crate::handlers::submit`]
//!   onto a simulator holding the lender's coins.
//!
//! Findings (the tests pin them): Pengui's request, maker spends followed by the
//! requested-payment placeholder (a runnable CAT solution around the settlement solution when
//! the collateral is a CAT; the assembled offer keeps the bare shape `Offer::to_spend_bundle`
//! writes, which Sage reads and which cannot run), is signed for both loans and shown as one
//! option offered through the settlement puzzle plus the principal, bound to the collateral
//! payment. The same maker spends without the placeholder are refused 4001 `unbound_partial`:
//! no spend of the request then creates the settlement announcement every user spend asserts
//! (spec 11.2). Taking either signed offer works as Sage reads it.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use crate::error::KitError;
use crate::handlers::{RequestContext, RpcError, SignedCoins, handle};
use crate::option::OptionAction;
use crate::option_sage_tests::{Mode, reason, run_as, signature_of};
use crate::permissions::DappPermissions;
use crate::policy::Network;
use crate::simulate::{AssetId, DEFAULT_MAX_COST, ExecutedSpend, Ownership, SpendKind, execute};
use crate::spend::{decode_hex, parse_coin_spends};
use crate::swap_fixture::{Key, Mem, Ui, owned, spend_json};
use chia_bls::SecretKey;
use chia_bls::{PublicKey, Signature};
use chia_protocol::{Bytes32, Coin, CoinSpend, Program, SpendBundle};
use chia_puzzle_types::cat::CatSolution;
use chia_puzzle_types::standard::StandardArgs;
use chia_puzzle_types::{CoinProof, DeriveSynthetic, LineageProof};
use chia_puzzles::SETTLEMENT_PAYMENT_HASH;
use chia_sdk_driver::{
    Action, Cat, CatInfo, DriverError, Offer, OptionType, OptionUnderlying, Relation, SpendContext,
    Spends,
};
use chia_sdk_signer::{AggSigConstants, RequiredSignature};
use chia_sdk_test::{BlsPair, Simulator};
use chia_sdk_types::{Condition, TESTNET11_CONSTANTS};
use clvm_traits::{FromClvm, ToClvm};
use clvm_utils::ToTreeHash;
use clvmr::Allocator;
use indexmap::indexmap;
use serde_json::{Value, json};
use std::cell::RefCell;
use std::collections::HashSet;
use xchonnect_core::crypto::sha256_parts;
use xchonnect_core::rpc::codes;

/// The fixture Pengui exported, compiled in (the folder is not in the published crate).
const FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/pengui-loan-offers.json"
));

/// SHA-256 of [`FIXTURE`] as Pengui committed it: see the module doc to regenerate.
const FIXTURE_SHA256: &str = "0e49355125ed922269ce9a0f8302c3ed3caed9b3c2a7b6376554a2a8ade599bf";

/// The command that writes the fixture, run in the Pengui repo (its `generator` field).
const GENERATOR: &str = "EXPORT_LOAN_OFFER_FIXTURES=1 bun test \
                         src/shared/lib/wallet/options/__fixtures__/exportLoanOfferFixtures.test.ts";

/// Which loan of the fixture.
const XCH_COLLATERAL: usize = 0;
const CAT_COLLATERAL: usize = 1;

/// One exported loan offer.
struct Case {
    name: String,
    /// The simulator's clock when the offer was made: the wallet's `now`.
    now: u64,
    lender: BlsPair,
    launcher_id: Bytes32,
    collateral: (AssetId, u64),
    principal: (AssetId, u64),
    /// The strike: what the borrower pays to exercise.
    repayment: (AssetId, u64),
    /// From when the lender may take the collateral back (`terms.expires_at`).
    expires_at: u64,
    offer_fee: u64,
    /// The option coin the offer spends (`option.coin`) and the collateral coin it commits
    /// to (`option.underlying_coin`), with the delegated puzzle hash Pengui computed for the
    /// terms (`option.underlying_delegated_puzzle_hash`).
    option_coin: Coin,
    underlying_coin: Coin,
    underlying_delegated_puzzle_hash: Bytes32,
    /// `sign_request` verbatim: what Pengui hands to `signCoinSpends` (the maker spends, then
    /// the placeholder it can run).
    sign_request: Value,
    /// The maker's spends alone: the option, the principal coin and (for a CAT principal) an
    /// XCH coin for the fee.
    maker_spends_json: Vec<Value>,
    maker_spends: Vec<CoinSpend>,
    /// The requested-payment placeholder spends in the offer's shape (the bare settlement
    /// solution), as JSON and parsed.
    placeholders_json: Vec<Value>,
    placeholders: Vec<CoinSpend>,
    /// The signed offer: the `offer1…` string and the bundle it encodes (Pengui checks the
    /// two agree when it exports; the kit does not link the offer compressor).
    offer: String,
    offer_bundle: SpendBundle,
    /// The lender's coins the request consumes, for a simulator.
    lender_coins: Vec<Coin>,
}

fn hex32(v: &Value) -> Bytes32 {
    let bytes: [u8; 32] = decode_hex(v.as_str().unwrap()).unwrap().try_into().unwrap();
    Bytes32::from(bytes)
}

fn signature(v: &Value) -> Signature {
    let bytes: [u8; 96] = decode_hex(v.as_str().unwrap()).unwrap().try_into().unwrap();
    Signature::from_bytes(&bytes).unwrap()
}

fn amount(v: &Value) -> (AssetId, u64) {
    let asset = match &v["asset_id"] {
        Value::Null => AssetId::Xch,
        id => AssetId::Cat(hex32(id)),
    };
    (asset, v["amount"].as_str().unwrap().parse().unwrap())
}

fn coin(v: &Value) -> Coin {
    Coin::new(
        hex32(&v["parent_coin_info"]),
        hex32(&v["puzzle_hash"]),
        v["amount"].as_str().unwrap().parse().unwrap(),
    )
}

/// The lender's key, derived as Pengui's test wallet derives it:
/// `SecretKey.fromSeed(new Uint8Array(32).fill(seed)).deriveSynthetic()`.
fn lender(name: &str, v: &Value) -> BlsPair {
    let seed = u8::try_from(v["seed"].as_u64().unwrap()).unwrap();
    let sk = SecretKey::from_seed(&[seed; 32]).derive_synthetic();
    let pk = sk.public_key();
    let puzzle_hash: Bytes32 = StandardArgs::curry_tree_hash(pk).into();
    assert_eq!(
        pk.to_bytes().to_vec(),
        decode_hex(v["public_key"].as_str().unwrap()).unwrap(),
        "{name}: the fixture's lender key derives from its seed"
    );
    assert_eq!(puzzle_hash, hex32(&v["puzzle_hash"]), "{name}");
    BlsPair {
        sk,
        pk,
        puzzle_hash,
    }
}

fn cases() -> Vec<Case> {
    assert_eq!(
        hex::encode(sha256_parts(&[FIXTURE.as_bytes()])),
        FIXTURE_SHA256,
        "fixtures/pengui-loan-offers.json is not the file FIXTURE_SHA256 pins: copy the \
         current file from Pengui and set FIXTURE_SHA256 to its digest (module doc)"
    );
    let file: Value = serde_json::from_str(FIXTURE).unwrap();
    assert_eq!(
        file["generator"], GENERATOR,
        "the fixture names another generator than the module doc"
    );
    assert_eq!(
        hex32(&file["network"]["agg_sig_me_additional_data"]),
        TESTNET11_CONSTANTS.agg_sig_me_additional_data,
        "the fixture was signed for testnet11, the network the kit is run on here"
    );
    let cases: Vec<Case> = file["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            let name = c["name"].as_str().unwrap().to_owned();
            let placeholders_json = c["requested_payment_spends"].as_array().unwrap().clone();
            let maker_spends_json = c["maker_spends"].as_array().unwrap().clone();
            let lender = lender(&name, &c["lender"]);
            let option = &c["option"];
            let option_coin = coin(&option["coin"]);
            let underlying_coin = coin(&option["underlying_coin"]);
            // The ids the fixture spells out are those of the coins it gives.
            assert_eq!(option_coin.coin_id(), hex32(&option["coin_id"]), "{name}");
            assert_eq!(
                underlying_coin.coin_id(),
                hex32(&option["underlying_coin_id"]),
                "{name}"
            );
            // Creator = owner = lender.
            assert_eq!(
                hex32(&option["p2_puzzle_hash"]),
                lender.puzzle_hash,
                "{name}"
            );
            assert_eq!(
                hex32(&c["terms"]["creator_puzzle_hash"]),
                lender.puzzle_hash,
                "{name}"
            );
            Case {
                now: c["chain_time"].as_str().unwrap().parse().unwrap(),
                lender,
                launcher_id: hex32(&c["launcher_id"]),
                collateral: amount(&c["terms"]["collateral"]),
                principal: amount(&c["terms"]["principal"]),
                repayment: amount(&c["terms"]["repayment"]),
                expires_at: c["terms"]["expires_at"].as_str().unwrap().parse().unwrap(),
                offer_fee: c["terms"]["offer_fee"].as_str().unwrap().parse().unwrap(),
                option_coin,
                underlying_coin,
                underlying_delegated_puzzle_hash: hex32(
                    &option["underlying_delegated_puzzle_hash"],
                ),
                sign_request: c["sign_request"].clone(),
                maker_spends: parse_coin_spends(&Value::Array(maker_spends_json.clone())).unwrap(),
                maker_spends_json,
                placeholders: parse_coin_spends(&Value::Array(placeholders_json.clone())).unwrap(),
                placeholders_json,
                offer: c["offer"].as_str().unwrap().to_owned(),
                offer_bundle: SpendBundle::new(
                    parse_coin_spends(&c["offer_spend_bundle"]["coin_spends"]).unwrap(),
                    signature(&c["offer_spend_bundle"]["aggregated_signature"]),
                ),
                lender_coins: c["lender_coins"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|l| coin(&l["coin"]))
                    .collect(),
                name,
            }
        })
        .collect();
    assert_eq!(cases.len(), 2);
    assert_eq!(cases[XCH_COLLATERAL].collateral.0, AssetId::Xch);
    assert!(matches!(
        cases[CAT_COLLATERAL].collateral.0,
        AssetId::Cat(_)
    ));
    cases
}

impl Case {
    fn request(&self) -> Vec<CoinSpend> {
        parse_coin_spends(&self.sign_request["coinSpends"]).unwrap()
    }

    /// The request as Pengui sends it.
    fn params(&self) -> String {
        self.sign_request.to_string()
    }

    /// A `signCoinSpends` request of the maker spends followed by `extra`, otherwise as
    /// Pengui's.
    fn params_with(&self, extra: &[Value]) -> String {
        let mut params = self.sign_request.clone();
        let spends: Vec<Value> = self
            .maker_spends_json
            .iter()
            .chain(extra)
            .cloned()
            .collect();
        params["coinSpends"] = Value::Array(spends);
        params.to_string()
    }

    /// Where the principal goes: the settlement puzzle, bare or inside the principal's CAT.
    fn principal_settlement_puzzle_hash(&self) -> Bytes32 {
        match self.principal.0 {
            AssetId::Cat(asset_id) => CatInfo::new(asset_id, None, SETTLEMENT_PAYMENT_HASH.into())
                .puzzle_hash()
                .into(),
            _ => SETTLEMENT_PAYMENT_HASH.into(),
        }
    }

    /// The option's terms as the Wallet SDK (and Pengui, over the same SDK) writes them into
    /// the collateral's `p2_1_of_n`: the lender takes the collateral back from `expires_at`,
    /// the borrower exercises before by paying the repayment to the lender.
    fn underlying(&self) -> OptionUnderlying {
        let strike = match self.repayment {
            (AssetId::Xch, amount) => OptionType::Xch { amount },
            (AssetId::Cat(asset_id), amount) => OptionType::Cat { asset_id, amount },
            (other, _) => panic!("{}: repayment in {other:?}", self.name),
        };
        OptionUnderlying::new(
            self.launcher_id,
            self.lender.puzzle_hash,
            self.expires_at,
            self.collateral.1,
            strike,
        )
    }

    /// The puzzle hash of `amount` of `asset` held by `owner`.
    fn held_at(asset: AssetId, owner: Bytes32) -> Bytes32 {
        match asset {
            AssetId::Cat(asset_id) => CatInfo::new(asset_id, None, owner).puzzle_hash().into(),
            _ => owner,
        }
    }
}

/// The lender's Klimper: owns the lender's puzzle hash, holds the key, default
/// permissions (one option per request), the fixture's clock.
struct Wallet {
    perms: DappPermissions,
    own: Ownership,
    keys: HashSet<PublicKey>,
    limits: Mem,
    signer: Key,
    now: u64,
}

impl Wallet {
    fn of(case: &Case) -> Self {
        Wallet {
            perms: DappPermissions::new_default(case.lender.pk),
            own: owned(case.lender.puzzle_hash),
            keys: [case.lender.pk].into_iter().collect(),
            limits: Mem::default(),
            signer: Key(case.lender.sk.clone()),
            now: case.now,
        }
    }

    /// `signCoinSpends` as Klimper calls the kit: the outcome and the prompt shown (if any).
    fn sign(&self, params: &str) -> (Result<Signature, RpcError>, Option<Value>) {
        let signed = SignedCoins::default();
        let ctx = RequestContext {
            dapp: "pengui.example",
            network: Network::Testnet11,
            session_chain_id: "testnet11",
            permissions: &self.perms,
            allow_agg_sig_unsafe: false,
            allow_unknown_contracts: false,
            ownership: &self.own,
            keys: &self.keys,
            limits: &self.limits,
            now: self.now,
            chain: None,
            signed_coins: &signed,
        };
        let ui = Ui::default();
        let out = handle("signCoinSpends", params, &ctx, &self.signer, &ui).map(|json| {
            let hex: String = serde_json::from_str(&json).unwrap();
            signature(&Value::String(hex))
        });
        (out, ui.0.into_inner().pop())
    }
}

fn refusal(e: &RpcError) -> (i64, String) {
    let data: Value = serde_json::from_str(&reason(e)).unwrap();
    (e.code, data["reason"].as_str().unwrap().to_owned())
}

fn asset_json(asset: AssetId) -> Value {
    serde_json::to_value(asset).unwrap()
}

/// The asset delta of `asset` in a prompt's summary.
fn delta(prompt: &Value, asset: AssetId) -> Value {
    prompt["summary"]["assets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["asset"] == asset_json(asset))
        .cloned()
        .unwrap_or_else(|| panic!("no delta for {asset:?}"))
}

/// The outputs of the user's spends that are settlement coins, as `(asset, amount)`.
fn settlement_outputs(prompt: &Value) -> Vec<(Value, u64)> {
    prompt["summary"]["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|o| o["settlement"] == true)
        .map(|o| (o["asset"].clone(), o["amount"].as_u64().unwrap()))
        .collect()
}

/// The puzzle announcements `spends` assert and create, as announcement ids
/// (`sha256(puzzle hash || message)` for the created ones).
fn puzzle_announcements(spends: &[ExecutedSpend]) -> (Vec<Vec<Bytes32>>, HashSet<Bytes32>) {
    let asserted = spends
        .iter()
        .map(|es| {
            es.conditions
                .iter()
                .filter_map(|c| match c {
                    Condition::AssertPuzzleAnnouncement(ann) => Some(ann.announcement_id),
                    _ => None,
                })
                .collect()
        })
        .collect();
    let created = spends
        .iter()
        .flat_map(|es| {
            es.conditions.iter().filter_map(move |c| match c {
                Condition::CreatePuzzleAnnouncement(ann) => Some(Bytes32::from(sha256_parts(&[
                    es.coin.puzzle_hash.as_ref(),
                    ann.message.as_ref(),
                ]))),
                _ => None,
            })
        })
        .collect();
    (asserted, created)
}

/// What a signed open loan offer must show (spec 11.1.1, 11.2): one option leaving through
/// the settlement puzzle, the principal paid to settlement, the collateral payment bound.
fn assert_loan_offer_prompt(case: &Case, prompt: &Value) {
    let p = prompt;
    let name = &case.name;
    assert_eq!(p["type"], "sign_coin_spends", "{name}");
    assert_eq!(p["partial"], true, "{name}");
    assert_eq!(p["summary"]["unknown_puzzles"], json!([]), "{name}");
    assert_eq!(p["summary"]["unaccounted_spends"], json!([]), "{name}");
    assert_eq!(p["plan"]["has_unsafe"], false, "{name}");
    assert_eq!(p["plan"]["foreign"], json!([]), "{name}");
    // One option leaves the user, offered through the settlement puzzle.
    assert_eq!(
        p["summary"]["options"],
        json!([{
            "action": "transfer",
            "launcher_id": hex::encode(case.launcher_id),
            "from_user": true,
            "to": hex::encode(SETTLEMENT_PAYMENT_HASH),
            "to_user": false,
            "to_settlement": true,
        }]),
        "{name}"
    );
    let option = delta(p, AssetId::Option(case.launcher_id));
    assert_eq!(
        (option["sent"].as_u64(), option["received"].as_u64()),
        (Some(1), Some(0)),
        "{name}"
    );
    // The principal goes to settlement; the fee comes from the user's XCH.
    let (principal_asset, principal) = case.principal;
    let d = delta(p, principal_asset);
    let paid = d["sent"].as_u64().unwrap() - d["received"].as_u64().unwrap();
    let fee = if principal_asset == AssetId::Xch {
        case.offer_fee
    } else {
        0
    };
    assert_eq!(paid, principal + fee, "{name}");
    assert_eq!(p["summary"]["reserve_fee"], case.offer_fee, "{name}");
    let settled = settlement_outputs(p);
    assert!(
        settled.contains(&(asset_json(AssetId::Option(case.launcher_id)), 1)),
        "{name}: {settled:?}"
    );
    assert!(
        settled.contains(&(asset_json(principal_asset), principal)),
        "{name}: {settled:?}"
    );
    assert_eq!(settled.len(), 2, "{name}: {settled:?}");
    // Every user spend asserts the collateral payment to the lender (direct binding).
    let (collateral_asset, collateral) = case.collateral;
    assert_eq!(p["binding"]["linking"], "direct", "{name}");
    assert_eq!(p["binding"]["all_bound"], true, "{name}");
    assert_eq!(p["binding"]["co_required"], true, "{name}");
    assert_eq!(p["binding"]["unbound_user_spends"], json!([]), "{name}");
    assert_eq!(
        p["binding"]["bound_received"],
        json!([{ "asset": asset_json(collateral_asset), "amount": collateral }]),
        "{name}"
    );
    let user_spends = case.maker_spends.len();
    assert_eq!(
        p["plan"]["ours"].as_array().unwrap().len(),
        user_spends,
        "{name}"
    );
    assert_eq!(
        p["binding"]["bound_payments"].as_array().unwrap().len(),
        1,
        "{name}: one payment, counted once"
    );
}

#[test]
fn the_fixture_is_what_pengui_signed() {
    for case in cases() {
        let name = &case.name;
        let makers = &case.maker_spends;
        // The offer is the maker spends followed by the bare placeholder.
        let mut expected = makers.clone();
        expected.extend(case.placeholders.iter().cloned());
        assert_eq!(case.offer_bundle.coin_spends, expected, "{name}");
        // Its signature is the lender's over every AGG_SIG_ME of the maker spends (testnet11).
        assert_eq!(
            case.offer_bundle.aggregated_signature,
            signature_of(makers, &case.lender.sk),
            "{name}"
        );
        assert!(case.offer.starts_with("offer1"), "{name}");
        // One placeholder: the collateral, requested to the lender.
        assert_eq!(case.placeholders.len(), 1, "{name}");
        let bare = &case.placeholders[0];
        assert_eq!(bare.coin.parent_coin_info, Bytes32::default(), "{name}");
        assert_eq!(bare.coin.amount, 0, "{name}");
        // The request is the maker spends and the same placeholder coin, solved so that it
        // runs: the bare solution for XCH, a CAT solution around it for a CAT.
        let request = case.request();
        assert_eq!(request[..makers.len()], makers[..], "{name}");
        assert_eq!(request.len(), makers.len() + 1, "{name}");
        let sent = &request[makers.len()];
        assert_eq!(sent.coin, bare.coin, "{name}");
        assert_eq!(sent.puzzle_reveal, bare.puzzle_reveal, "{name}");
        match case.collateral.0 {
            AssetId::Xch => assert_eq!(sent.solution, bare.solution, "{name}"),
            _ => {
                let mut a = Allocator::new();
                let node = sent.solution.to_clvm(&mut a).unwrap();
                let cat = CatSolution::<clvmr::NodePtr>::from_clvm(&a, node).unwrap();
                let inner = Program::from_clvm(&a, cat.inner_puzzle_solution).unwrap();
                assert_eq!(
                    inner, bare.solution,
                    "{name}: the settlement solution inside"
                );
                assert_eq!(
                    cat.this_coin_info.puzzle_hash, bare.coin.puzzle_hash,
                    "{name}"
                );
            }
        }
        // Every maker spend is one of the lender's coins.
        assert_eq!(case.lender_coins.len(), makers.len(), "{name}");
        for (cs, c) in makers.iter().zip(&case.lender_coins) {
            assert_eq!(cs.coin, *c, "{name}");
        }
        // The terms (expiry, repayment as the strike, creator, collateral) are the ones the
        // option commits to: they hash to the delegated puzzle hash Pengui recorded, and the
        // collateral coin is the lender's `p2_1_of_n` of them, bare or inside the CAT.
        let underlying = case.underlying();
        assert_eq!(
            Bytes32::from(underlying.delegated_puzzle().tree_hash()),
            case.underlying_delegated_puzzle_hash,
            "{name}: terms.expires_at / repayment / creator_puzzle_hash are the option's"
        );
        assert_eq!(
            case.underlying_coin.puzzle_hash,
            Case::held_at(case.collateral.0, underlying.tree_hash().into()),
            "{name}"
        );
        assert_eq!(case.underlying_coin.amount, case.collateral.1, "{name}");
        assert!(
            case.expires_at > case.now,
            "{name}: the option is live when offered"
        );
    }
}

/// The request as Pengui sends it, through `signCoinSpends` as Klimper calls the kit: signed
/// for both loans, shown as one option offered through settlement plus the principal, bound
/// to the collateral payment, and the signature is the one Pengui's own signer produced (the
/// placeholder is never signed).
#[test]
fn as_pengui_sends_it_the_request_is_signed() {
    for case in cases() {
        let name = &case.name;
        let wallet = Wallet::of(&case);
        let (out, prompt) = wallet.sign(&case.params());
        let sig = out.unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(sig, case.offer_bundle.aggregated_signature, "{name}");
        assert_loan_offer_prompt(&case, &prompt.unwrap());
        // The option counts against the option limit (one per request by default), the
        // principal (with the fee, when both are XCH) against its asset's.
        assert_eq!(wallet.limits.0.borrow().options, 1, "{name}");
        let (principal_asset, principal) = case.principal;
        let fee = if principal_asset == AssetId::Xch {
            case.offer_fee
        } else {
            0
        };
        assert_eq!(
            wallet.limits.0.borrow().spent.get(&principal_asset),
            Some(&u128::from(principal + fee)),
            "{name}"
        );
    }
}

/// Spec 11.2: a `signCoinSpends` with `partialSign` is a multi-party request, and every user
/// spend must assert a settlement payment the request contains. The maker spends alone (what
/// Pengui sent before TASK-79) assert the collateral payment's announcement, which no spend of
/// such a request creates: nothing is bound, and the kit refuses before prompting or signing.
#[test]
fn without_the_placeholder_the_request_is_refused_as_unbound() {
    for case in cases() {
        let name = &case.name;
        let wallet = Wallet::of(&case);
        let (out, prompt) = wallet.sign(&case.params_with(&[]));
        let e = out.unwrap_err();
        assert_eq!(
            refusal(&e),
            (codes::UNAUTHORIZED, "unbound_partial".to_owned()),
            "{name}"
        );
        assert!(prompt.is_none(), "{name}: refused before the prompt");
        assert_eq!(wallet.limits.0.borrow().options, 0, "{name}");
        // The cause: every user spend asserts one puzzle announcement, the collateral payment's
        // (`sha256(settlement puzzle hash || sha256tree(notarized payment))`), and no spend of
        // the request creates it.
        let mut a = Allocator::new();
        let (executed, _) =
            execute(&mut a, &case.maker_spends, &wallet.own, DEFAULT_MAX_COST).unwrap();
        assert!(
            executed.iter().all(|es| es.owned),
            "{name}: every spend of the request is the lender's"
        );
        let (asserted, created) = puzzle_announcements(&executed);
        let mut payments = HashSet::new();
        for ids in &asserted {
            assert_eq!(ids.len(), 1, "{name}: one announcement asserted per spend");
            payments.insert(ids[0]);
        }
        assert_eq!(
            payments.len(),
            1,
            "{name}: the same payment from every spend"
        );
        let payment = payments.into_iter().next().unwrap();
        assert!(
            !created.contains(&payment),
            "{name}: no spend of the request creates the announcement it asserts (spec 11.2)"
        );
        assert!(
            !executed.iter().any(|es| es.kind == SpendKind::Settlement
                || matches!(es.kind, SpendKind::Cat { p2_puzzle_hash, .. } if p2_puzzle_hash == SETTLEMENT_PAYMENT_HASH.into())),
            "{name}: no settlement spend in the request"
        );
    }
}

/// Spec 11.1 item 5: the option leaving the user counts against the option limit, refused
/// before the prompt when the dApp's limit does not allow one.
#[test]
fn the_option_limit_applies_to_the_offer() {
    let case = &cases()[XCH_COLLATERAL];
    let mut wallet = Wallet::of(case);
    wallet.perms.options.per_request = Some(0);
    let (out, prompt) = wallet.sign(&case.params());
    assert_eq!(
        refusal(&out.unwrap_err()),
        (codes::LIMIT_EXCEEDED, "options_per_request".to_owned())
    );
    assert!(prompt.is_none());
    // Five a day by default: the sixth offer of a day is refused.
    let wallet = Wallet::of(case);
    wallet.limits.0.borrow_mut().options = 5;
    // The fixture clock's UTC day, so `options = 5` reads as today.
    wallet.limits.0.borrow_mut().day = case.now / 86_400;
    let (out, _) = wallet.sign(&case.params());
    assert_eq!(
        refusal(&out.unwrap_err()),
        (codes::LIMIT_EXCEEDED, "options_per_day".to_owned())
    );
}

/// Why the CAT placeholder Pengui sends differs from the one in the offer: the offer's
/// placeholder of a requested CAT payment (as `Offer::to_spend_bundle` writes it) is the CAT
/// puzzle curried around the settlement puzzle, solved with the bare settlement solution. That
/// is not a CAT solution, so the puzzle cannot run, and the kit, which runs every spend of a
/// request (spec 11.1 item 1), refuses the request as a whole.
#[test]
fn the_offers_bare_cat_placeholder_does_not_run() {
    let case = &cases()[CAT_COLLATERAL];
    let wallet = Wallet::of(case);
    // The spend that fails is the placeholder (the last spend), not one of the lender's.
    let placeholder_index = case.maker_spends.len();
    let (out, prompt) = wallet.sign(&case.params_with(&case.placeholders_json));
    let e = out.unwrap_err();
    assert_eq!(
        refusal(&e),
        (codes::INVALID_PARAMS, "simulation_failed".to_owned())
    );
    assert_eq!(
        e.message,
        format!("spend {placeholder_index}: puzzle failed to run"),
        "the error names the placeholder spend"
    );
    assert!(prompt.is_none());
    let mut request = case.maker_spends.clone();
    request.extend(case.placeholders.iter().cloned());
    let mut a = Allocator::new();
    let err = execute(&mut a, &request, &wallet.own, DEFAULT_MAX_COST).unwrap_err();
    assert!(
        matches!(err, KitError::Execution { spend } if spend == placeholder_index),
        "{err:?}"
    );
    let AssetId::Cat(asset_id) = case.collateral.0 else {
        unreachable!()
    };
    assert_eq!(
        case.placeholders[0].coin.puzzle_hash,
        CatInfo::new(asset_id, None, SETTLEMENT_PAYMENT_HASH.into())
            .puzzle_hash()
            .into(),
        "the placeholder is the CAT around the settlement puzzle"
    );
    // Solved with a CAT solution around the settlement solution (as Pengui now sends it) the
    // same placeholder runs and the request is signed; the offer itself keeps the bare shape,
    // since Sage's reader takes the placeholder's solution as the settlement solution
    // (`SettlementPaymentsSolution::from_clvm` in `RequestedPayments::parse`) and cannot read
    // a CAT solution. The placeholder is unsigned, so the two may differ.
    let placeholder = runnable_cat_placeholder(&case.placeholders[0]);
    let (out, prompt) = wallet.sign(&case.params_with(&[spend_json(&placeholder)]));
    assert_eq!(out.unwrap(), case.offer_bundle.aggregated_signature);
    assert_loan_offer_prompt(case, &prompt.unwrap());
    let mut wrapped = case.offer_bundle.clone();
    *wrapped.coin_spends.last_mut().unwrap() = placeholder;
    let mut ctx = SpendContext::new();
    let err = Offer::from_spend_bundle(&mut ctx, &wrapped).unwrap_err();
    assert!(
        matches!(err, DriverError::FromClvm(_)),
        "Sage's reader fails to read the CAT solution as a settlement solution: {err}"
    );
}

/// `cs` (a CAT around the settlement puzzle, solved with the bare settlement solution) with a
/// CAT solution whose inner solution is that settlement solution. The CAT puzzle checks its
/// lineage proof against the parent id in `this_coin_info` (`is_parent_cat`, raising when they
/// differ), so the solution carries a self-consistent stand-in lineage; the coin itself stays
/// the zero-parent placeholder. It never reaches the chain, it only has to run so that the kit
/// can read the payment it announces.
fn runnable_cat_placeholder(cs: &CoinSpend) -> CoinSpend {
    let mut a = Allocator::new();
    let inner = cs.solution.to_clvm(&mut a).unwrap();
    let settlement: Bytes32 = SETTLEMENT_PAYMENT_HASH.into();
    let parent_parent = Bytes32::new([0xfe; 32]);
    let parent = Coin::new(parent_parent, cs.coin.puzzle_hash, 0);
    let this_coin = Coin::new(parent.coin_id(), cs.coin.puzzle_hash, 0);
    let solution = CatSolution {
        inner_puzzle_solution: inner,
        lineage_proof: Some(LineageProof {
            parent_parent_coin_info: parent_parent,
            parent_inner_puzzle_hash: settlement,
            parent_amount: 0,
        }),
        prev_coin_id: this_coin.coin_id(),
        this_coin_info: this_coin,
        next_coin_proof: CoinProof {
            parent_coin_info: this_coin.parent_coin_info,
            inner_puzzle_hash: settlement,
            amount: 0,
        },
        prev_subtotal: 0,
        extra_delta: 0,
    }
    .to_clvm(&mut a)
    .unwrap();
    CoinSpend::new(
        cs.coin,
        cs.puzzle_reveal.clone(),
        Program::from_clvm(&a, solution).unwrap(),
    )
}

/// The first part of Klimper's `check_offer`, before any spend runs: at most 64 spends,
/// something requested (a zero-parent spend) and the maker's coins spent once. These are shape
/// bounds that this fixture cannot fail; they are mirrored so the check is complete. Returns
/// the placeholders and the maker's spends.
fn check_offer_mirror(case: &Case, bundle: &SpendBundle) -> (Vec<CoinSpend>, Vec<CoinSpend>) {
    let name = &case.name;
    assert!(bundle.coin_spends.len() <= 64, "{name}");
    let (placeholders, makers): (Vec<CoinSpend>, Vec<CoinSpend>) = bundle
        .coin_spends
        .iter()
        .cloned()
        .partition(|cs| cs.coin.parent_coin_info == Bytes32::default());
    assert!(!placeholders.is_empty(), "{name}: asks for something");
    let ids: HashSet<Bytes32> = makers.iter().map(|cs| cs.coin.coin_id()).collect();
    assert_eq!(ids.len(), makers.len(), "{name}: no coin spent twice");
    (placeholders, makers)
}

/// Klimper's `chia_takeOffer` before Sage builds anything (`check_offer`): the shape bounds
/// of [`check_offer_mirror`], every maker spend a puzzle the kit recognises under `execute`
/// (the borrower owning none of them), and the maker's signature covering the maker's spends.
/// Then the offer as Sage reads it (`Offer::from_spend_bundle`): one option offered, the
/// principal offered, the collateral requested to the lender.
#[test]
fn klimper_reads_the_signed_offer_as_sage_does() {
    for case in cases() {
        let name = &case.name;
        let bundle = &case.offer_bundle;
        let (_, makers) = check_offer_mirror(&case, bundle);
        // The borrower's wallet owns none of the maker's coins.
        let borrower = BlsPair::new(7);
        let mut a = Allocator::new();
        let (executed, _) = execute(
            &mut a,
            &makers,
            &owned(borrower.puzzle_hash),
            DEFAULT_MAX_COST,
        )
        .unwrap();
        assert!(
            executed.iter().all(|es| es.kind != SpendKind::Unknown),
            "{name}: {:?}",
            executed.iter().map(|es| &es.kind).collect::<Vec<_>>()
        );
        assert!(executed.iter().all(|es| !es.owned), "{name}");
        let options: Vec<&ExecutedSpend> = executed
            .iter()
            .filter(|es| matches!(es.kind, SpendKind::Option { .. }))
            .collect();
        assert_eq!(options.len(), 1, "{name}");
        // The option spend is the fixture's option coin, transferred by the lender to the
        // settlement puzzle, committing to the fixture's collateral coin and terms.
        assert_eq!(options[0].coin, case.option_coin, "{name}");
        assert!(
            matches!(
                &options[0].kind,
                SpendKind::Option { launcher_id, p2_puzzle_hash, underlying_coin_id, underlying_delegated_puzzle_hash, new_owner: Some(to), action: OptionAction::Transfer, .. }
                    if *launcher_id == case.launcher_id
                        && *p2_puzzle_hash == case.lender.puzzle_hash
                        && *underlying_coin_id == case.underlying_coin.coin_id()
                        && *underlying_delegated_puzzle_hash == case.underlying_delegated_puzzle_hash
                        && *to == Bytes32::from(SETTLEMENT_PAYMENT_HASH)
            ),
            "{name}: {:?}",
            options[0].kind
        );
        // `check_maker_signature`.
        let required = RequiredSignature::from_coin_spends(
            &mut a,
            &makers,
            &AggSigConstants::new(TESTNET11_CONSTANTS.agg_sig_me_additional_data),
        )
        .unwrap();
        let pairs: Vec<(PublicKey, Vec<u8>)> = required
            .into_iter()
            .map(|r| match r {
                RequiredSignature::Bls(b) => (b.public_key, b.message()),
                RequiredSignature::Secp(_) => panic!("{name}: secp"),
            })
            .collect();
        assert_eq!(pairs.len(), makers.len(), "{name}");
        assert!(pairs.iter().all(|(pk, _)| *pk == case.lender.pk), "{name}");
        assert!(
            chia_bls::aggregate_verify(
                &bundle.aggregated_signature,
                pairs.iter().map(|(pk, msg)| (pk, msg.as_slice()))
            ),
            "{name}: the maker's signature covers the maker's spends"
        );
        // As Sage reads it.
        let mut ctx = SpendContext::new();
        let offer = Offer::from_spend_bundle(&mut ctx, bundle).unwrap();
        let offered = offer.offered_coins();
        assert_eq!(
            offered.options.keys().copied().collect::<Vec<_>>(),
            vec![case.launcher_id],
            "{name}"
        );
        // The offered option is the child of the fixture's option coin, at the settlement
        // puzzle, with the same collateral and terms.
        let option = offered.options[&case.launcher_id];
        assert_eq!(
            option.coin.parent_coin_info,
            case.option_coin.coin_id(),
            "{name}"
        );
        assert_eq!(
            option.info.p2_puzzle_hash,
            SETTLEMENT_PAYMENT_HASH.into(),
            "{name}"
        );
        assert_eq!(option.coin.amount, 1, "{name}");
        assert_eq!(
            option.info.underlying_coin_id,
            case.underlying_coin.coin_id(),
            "{name}"
        );
        assert_eq!(
            option.info.underlying_delegated_puzzle_hash, case.underlying_delegated_puzzle_hash,
            "{name}"
        );
        assert!(offered.nfts.is_empty(), "{name}");
        assert_eq!(offered.fee, case.offer_fee, "{name}");
        let (principal_asset, principal) = case.principal;
        match principal_asset {
            AssetId::Xch => {
                assert_eq!(
                    offered.xch.iter().map(|c| c.amount).sum::<u64>(),
                    principal,
                    "{name}"
                );
                assert!(offered.cats.is_empty(), "{name}");
            }
            AssetId::Cat(asset_id) => {
                assert!(offered.xch.is_empty(), "{name}");
                assert_eq!(
                    offered.cats.keys().copied().collect::<Vec<_>>(),
                    vec![asset_id],
                    "{name}"
                );
                assert_eq!(
                    offered.cats[&asset_id]
                        .iter()
                        .map(|c| c.coin.amount)
                        .sum::<u64>(),
                    principal,
                    "{name}"
                );
            }
            _ => unreachable!(),
        }
        let requested = offer.requested_payments();
        let (collateral_asset, collateral) = case.collateral;
        let payments = match collateral_asset {
            AssetId::Xch => {
                assert!(requested.cats.is_empty(), "{name}");
                &requested.xch
            }
            AssetId::Cat(asset_id) => {
                assert!(requested.xch.is_empty(), "{name}");
                assert_eq!(
                    requested.cats.keys().copied().collect::<Vec<_>>(),
                    vec![asset_id],
                    "{name}"
                );
                &requested.cats[&asset_id]
            }
            _ => unreachable!(),
        };
        assert!(
            requested.nfts.is_empty() && requested.options.is_empty(),
            "{name}"
        );
        assert_eq!(payments.len(), 1, "{name}");
        assert_eq!(payments[0].payments.len(), 1, "{name}");
        assert_eq!(
            payments[0].payments[0].puzzle_hash, case.lender.puzzle_hash,
            "{name}"
        );
        assert_eq!(payments[0].payments[0].amount, collateral, "{name}");
        assert_eq!(
            payments[0].nonce,
            Offer::nonce(makers.iter().map(|cs| cs.coin.coin_id()).collect()),
            "{name}: notarised against the maker's coins"
        );
    }
}

/// The borrower takes each signed offer the way Klimper does: Sage's `take_offer` (the
/// action system over `Offer::from_spend_bundle`, `Relation::AssertConcurrent`) builds the
/// user's side from the borrower's coins, and the kit's `submit` (wallet-built, sealed, the
/// maker's signature added) checks, signs and broadcasts it. The simulator holds the lender's
/// coins as the fixture recorded them, and accepts the take: the borrower holds the option
/// and the principal, the lender the collateral.
#[test]
fn klimper_takes_each_signed_offer_on_a_simulator() {
    const TAKER_FEE: u64 = 3000;
    for case in cases() {
        let name = &case.name;
        let mut sim = Simulator::new();
        sim.set_next_timestamp(case.now).unwrap();
        for c in &case.lender_coins {
            sim.insert_coin(*c);
        }
        let borrower = BlsPair::new(7);
        let mut ctx = SpendContext::new();
        let offer = Offer::from_spend_bundle(&mut ctx, &case.offer_bundle).unwrap();
        let mut spends = Spends::new(borrower.puzzle_hash);
        spends.add(offer.offered_coins().clone());
        let mut actions = vec![Action::fee(TAKER_FEE)];
        actions.extend(offer.requested_payments().actions());
        let (collateral_asset, collateral) = case.collateral;
        match collateral_asset {
            AssetId::Xch => {
                spends.add(sim.new_coin(borrower.puzzle_hash, collateral + TAKER_FEE));
            }
            AssetId::Cat(asset_id) => {
                spends.add(sim.new_coin(borrower.puzzle_hash, TAKER_FEE));
                // A CAT of the collateral's asset with a consistent lineage, as Pengui's
                // simulator fixtures make them (the TAIL is never run).
                let info = CatInfo::new(asset_id, None, borrower.puzzle_hash);
                let grandparent = Bytes32::new([0x77; 32]);
                let parent = Coin::new(grandparent, info.puzzle_hash().into(), collateral);
                let coin = Coin::new(parent.coin_id(), info.puzzle_hash().into(), collateral);
                sim.insert_coin(coin);
                spends.add(Cat::new(
                    coin,
                    Some(LineageProof {
                        parent_parent_coin_info: grandparent,
                        parent_inner_puzzle_hash: borrower.puzzle_hash,
                        parent_amount: collateral,
                    }),
                    info,
                ));
            }
            _ => unreachable!(),
        }
        let deltas = spends.apply(&mut ctx, &actions).unwrap();
        spends
            .finish_with_keys(
                &mut ctx,
                &deltas,
                Relation::AssertConcurrent,
                &indexmap! { borrower.puzzle_hash => borrower.pk },
            )
            .unwrap();
        let taker_spends = ctx.take();
        let all = [offer.spend_bundle().coin_spends.clone(), taker_spends].concat();
        let lender_before: u64 = sim
            .unspent_coins(
                Case::held_at(collateral_asset, case.lender.puzzle_hash),
                false,
            )
            .iter()
            .map(|c| c.amount)
            .sum();
        let sim = RefCell::new(sim);
        let mode = Mode {
            other: Some(case.offer_bundle.aggregated_signature.clone()),
            ..Mode::default()
        };
        let prompt =
            run_as(&sim, &borrower, all, None, &mode).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(prompt["binding"]["all_bound"], true, "{name}");
        assert_eq!(prompt["summary"]["unknown_puzzles"], json!([]), "{name}");
        // The option reaches the borrower: the settlement spend of the option singleton pays
        // it to the borrower's puzzle hash.
        let options = prompt["summary"]["options"].as_array().unwrap();
        assert!(
            options.iter().any(|o| o["action"] == "transfer"
                && o["launcher_id"] == hex::encode(case.launcher_id)
                && o["to_user"] == true),
            "{name}: {options:?}"
        );
        // On chain: the lender holds the collateral, the borrower the principal.
        let held = |ph: Bytes32| -> u64 {
            sim.borrow()
                .unspent_coins(ph, false)
                .iter()
                .map(|c| c.amount)
                .sum()
        };
        // The lender gains the collateral (less the maker fee when both are XCH).
        let lender_fee = if collateral_asset == AssetId::Xch {
            case.offer_fee
        } else {
            0
        };
        assert_eq!(
            held(Case::held_at(collateral_asset, case.lender.puzzle_hash)),
            lender_before + collateral - lender_fee,
            "{name}"
        );
        let (principal_asset, principal) = case.principal;
        let borrower_principal = held(Case::held_at(principal_asset, borrower.puzzle_hash));
        assert_eq!(borrower_principal, principal, "{name}");
        let principal_settlement = case.principal_settlement_puzzle_hash();
        assert_eq!(
            held(principal_settlement),
            0,
            "{name}: settlement coins are spent"
        );
        for c in &case.lender_coins {
            assert!(
                sim.borrow()
                    .coin_state(c.coin_id())
                    .unwrap()
                    .spent_height
                    .is_some(),
                "{name}: the offer's coins are spent"
            );
        }
    }
}
