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
//! Two sides are checked, nothing in the kit being changed for the fixture:
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
use crate::handlers::{
    Approver, Prompt, RequestContext, RpcError, SignedCoins, Signer, SignerError, handle,
};
use crate::option_sage_tests::{Mode, reason, run_as, signature_of};
use crate::permissions::DappPermissions;
use crate::policy::Network;
use crate::simulate::{AssetId, DEFAULT_MAX_COST, Ownership, SpendKind, execute};
use crate::spend::{decode_hex, parse_coin_spends};
use crate::swap_fixture::{Mem, owned};
use chia_bls::{PublicKey, SecretKey, Signature};
use chia_protocol::{Bytes32, Coin, CoinSpend, Program, SpendBundle};
use chia_puzzle_types::cat::CatSolution;
use chia_puzzle_types::standard::StandardArgs;
use chia_puzzle_types::{CoinProof, DeriveSynthetic, LineageProof};
use chia_puzzles::SETTLEMENT_PAYMENT_HASH;
use chia_sdk_driver::{Action, Cat, CatInfo, Offer, Relation, SpendContext, Spends};
use chia_sdk_signer::{AggSigConstants, RequiredSignature};
use chia_sdk_test::{BlsPair, Simulator};
use chia_sdk_types::TESTNET11_CONSTANTS;
use clvm_traits::{FromClvm, ToClvm};
use clvmr::Allocator;
use indexmap::indexmap;
use serde_json::{Value, json};
use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use xchonnect_core::rpc::codes;

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/pengui-loan-offers.json"
);

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
    offer_fee: u64,
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

/// A coin spend in the JSON shape Pengui sends (hex without `0x`, amounts as strings).
fn spend_json(cs: &CoinSpend) -> Value {
    json!({
        "coin": {
            "parent_coin_info": hex::encode(cs.coin.parent_coin_info),
            "puzzle_hash": hex::encode(cs.coin.puzzle_hash),
            "amount": cs.coin.amount.to_string(),
        },
        "puzzle_reveal": hex::encode(cs.puzzle_reveal.as_ref()),
        "solution": hex::encode(cs.solution.as_ref()),
    })
}

/// The lender's key, derived as Pengui's test wallet derives it:
/// `SecretKey.fromSeed(new Uint8Array(32).fill(seed)).deriveSynthetic()`.
fn lender(v: &Value) -> BlsPair {
    let seed = u8::try_from(v["seed"].as_u64().unwrap()).unwrap();
    let sk = SecretKey::from_seed(&[seed; 32]).derive_synthetic();
    let pk = sk.public_key();
    let puzzle_hash: Bytes32 = StandardArgs::curry_tree_hash(pk).into();
    assert_eq!(
        pk.to_bytes().to_vec(),
        decode_hex(v["public_key"].as_str().unwrap()).unwrap(),
        "the fixture's lender key derives from its seed"
    );
    assert_eq!(puzzle_hash, hex32(&v["puzzle_hash"]));
    BlsPair {
        sk,
        pk,
        puzzle_hash,
    }
}

fn cases() -> Vec<Case> {
    let file: Value = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
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
            let placeholders_json = c["requested_payment_spends"].as_array().unwrap().clone();
            let maker_spends_json = c["maker_spends"].as_array().unwrap().clone();
            Case {
                name: c["name"].as_str().unwrap().to_owned(),
                now: c["chain_time"].as_str().unwrap().parse().unwrap(),
                lender: lender(&c["lender"]),
                launcher_id: hex32(&c["launcher_id"]),
                collateral: amount(&c["terms"]["collateral"]),
                principal: amount(&c["terms"]["principal"]),
                offer_fee: c["terms"]["offer_fee"].as_str().unwrap().parse().unwrap(),
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
}

struct Key(SecretKey);
impl Signer for Key {
    fn sign(&self, pk: &PublicKey, msg: &[u8]) -> Result<Signature, SignerError> {
        if self.0.public_key() != *pk {
            return Err(SignerError::KeyUnavailable);
        }
        Ok(chia_bls::sign(&self.0, msg))
    }
}

struct Ui(RefCell<Vec<Value>>, Cell<bool>);
impl Approver for Ui {
    fn approve(&self, p: &Prompt<'_>) -> bool {
        self.0.borrow_mut().push(serde_json::to_value(p).unwrap());
        self.1.get()
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
        let ui = Ui(RefCell::default(), Cell::new(true));
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

/// What a signed open loan offer must show (spec 11.1.1, 11.2): one option leaving through
/// the settlement puzzle, the principal paid to settlement, the collateral payment bound.
fn assert_loan_offer_prompt(case: &Case, prompt: &Value) {
    let p = prompt;
    assert_eq!(p["type"], "sign_coin_spends");
    assert_eq!(p["partial"], true);
    assert_eq!(p["summary"]["unknown_puzzles"], json!([]), "{}", case.name);
    assert_eq!(
        p["summary"]["unaccounted_spends"],
        json!([]),
        "{}",
        case.name
    );
    assert_eq!(p["plan"]["has_unsafe"], false);
    assert_eq!(p["plan"]["foreign"], json!([]));
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
        "{}",
        case.name
    );
    let option = delta(p, AssetId::Option(case.launcher_id));
    assert_eq!(
        (option["sent"].as_u64(), option["received"].as_u64()),
        (Some(1), Some(0))
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
    assert_eq!(paid, principal + fee, "{}", case.name);
    assert_eq!(p["summary"]["reserve_fee"], case.offer_fee);
    let settled = settlement_outputs(p);
    assert!(
        settled.contains(&(asset_json(AssetId::Option(case.launcher_id)), 1)),
        "{}: {settled:?}",
        case.name
    );
    assert!(
        settled.contains(&(asset_json(principal_asset), principal)),
        "{}: {settled:?}",
        case.name
    );
    assert_eq!(settled.len(), 2, "{}: {settled:?}", case.name);
    // Every user spend asserts the collateral payment to the lender (direct binding).
    let (collateral_asset, collateral) = case.collateral;
    assert_eq!(p["binding"]["linking"], "direct");
    assert_eq!(p["binding"]["all_bound"], true, "{}", case.name);
    assert_eq!(p["binding"]["co_required"], true, "{}", case.name);
    assert_eq!(p["binding"]["unbound_user_spends"], json!([]));
    assert_eq!(
        p["binding"]["bound_received"],
        json!([{ "asset": asset_json(collateral_asset), "amount": collateral }]),
        "{}",
        case.name
    );
    let user_spends = case.maker_spends.len();
    assert_eq!(p["plan"]["ours"].as_array().unwrap().len(), user_spends);
    assert_eq!(
        p["binding"]["bound_payments"].as_array().unwrap().len(),
        1,
        "one payment, counted once"
    );
}

#[test]
fn the_fixture_is_what_pengui_signed() {
    for case in cases() {
        let makers = &case.maker_spends;
        // The offer is the maker spends followed by the bare placeholder.
        let mut expected = makers.clone();
        expected.extend(case.placeholders.iter().cloned());
        assert_eq!(case.offer_bundle.coin_spends, expected, "{}", case.name);
        // Its signature is the lender's over every AGG_SIG_ME of the maker spends (testnet11).
        assert_eq!(
            case.offer_bundle.aggregated_signature,
            signature_of(makers, &case.lender.sk),
            "{}",
            case.name
        );
        assert!(case.offer.starts_with("offer1"));
        // One placeholder: the collateral, requested to the lender.
        assert_eq!(case.placeholders.len(), 1);
        let bare = &case.placeholders[0];
        assert_eq!(bare.coin.parent_coin_info, Bytes32::default());
        assert_eq!(bare.coin.amount, 0);
        // The request is the maker spends and the same placeholder coin, solved so that it
        // runs: the bare solution for XCH, a CAT solution around it for a CAT.
        let request = case.request();
        assert_eq!(request[..makers.len()], makers[..], "{}", case.name);
        assert_eq!(request.len(), makers.len() + 1);
        let sent = &request[makers.len()];
        assert_eq!(sent.coin, bare.coin);
        assert_eq!(sent.puzzle_reveal, bare.puzzle_reveal);
        match case.collateral.0 {
            AssetId::Xch => assert_eq!(sent.solution, bare.solution),
            _ => {
                let mut a = Allocator::new();
                let node = sent.solution.to_clvm(&mut a).unwrap();
                let cat = CatSolution::<clvmr::NodePtr>::from_clvm(&a, node).unwrap();
                let inner = Program::from_clvm(&a, cat.inner_puzzle_solution).unwrap();
                assert_eq!(
                    inner, bare.solution,
                    "{}: the settlement solution inside",
                    case.name
                );
                assert_eq!(cat.this_coin_info.puzzle_hash, bare.coin.puzzle_hash);
            }
        }
        // Every maker spend is one of the lender's coins.
        assert_eq!(case.lender_coins.len(), makers.len());
        for (cs, c) in makers.iter().zip(&case.lender_coins) {
            assert_eq!(cs.coin, *c);
        }
    }
}

/// The request as Pengui sends it, through `signCoinSpends` as Klimper calls the kit: signed
/// for both loans, shown as one option offered through settlement plus the principal, bound
/// to the collateral payment, and the signature is the one Pengui's own signer produced (the
/// placeholder is never signed).
#[test]
fn as_pengui_sends_it_the_request_is_signed() {
    for case in cases() {
        let wallet = Wallet::of(&case);
        let (out, prompt) = wallet.sign(&case.params());
        let sig = out.unwrap_or_else(|e| panic!("{}: {e:?}", case.name));
        assert_eq!(sig, case.offer_bundle.aggregated_signature, "{}", case.name);
        assert_loan_offer_prompt(&case, &prompt.unwrap());
        // The option counts against the option limit (one per request by default), the
        // principal (with the fee, when both are XCH) against its asset's.
        assert_eq!(wallet.limits.0.borrow().options, 1);
        let (principal_asset, principal) = case.principal;
        let fee = if principal_asset == AssetId::Xch {
            case.offer_fee
        } else {
            0
        };
        assert_eq!(
            wallet.limits.0.borrow().spent.get(&principal_asset),
            Some(&u128::from(principal + fee)),
            "{}",
            case.name
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
        let wallet = Wallet::of(&case);
        let (out, prompt) = wallet.sign(&case.params_with(&[]));
        let e = out.unwrap_err();
        assert_eq!(
            refusal(&e),
            (codes::UNAUTHORIZED, "unbound_partial".to_owned()),
            "{}",
            case.name
        );
        assert!(prompt.is_none(), "{}: refused before the prompt", case.name);
        assert_eq!(wallet.limits.0.borrow().options, 0);
        // The cause: every user spend asserts one puzzle announcement, the collateral payment's
        // (`sha256(settlement puzzle hash || sha256tree(notarized payment))`), and no spend of
        // the request creates it.
        let mut a = Allocator::new();
        let (executed, _) =
            execute(&mut a, &case.maker_spends, &wallet.own, DEFAULT_MAX_COST).unwrap();
        let mut asserted = HashSet::new();
        for es in &executed {
            assert!(
                es.owned,
                "{}: every spend of the request is the lender's",
                case.name
            );
            let ids: Vec<Bytes32> = es
                .conditions
                .iter()
                .filter_map(|c| match c {
                    chia_sdk_types::Condition::AssertPuzzleAnnouncement(ann) => {
                        Some(ann.announcement_id)
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(ids.len(), 1, "{}", case.name);
            asserted.insert(ids[0]);
        }
        assert_eq!(
            asserted.len(),
            1,
            "{}: the same payment from every spend",
            case.name
        );
        assert!(
            !executed.iter().any(|es| es.kind == SpendKind::Settlement
                || matches!(es.kind, SpendKind::Cat { p2_puzzle_hash, .. } if p2_puzzle_hash == SETTLEMENT_PAYMENT_HASH.into())),
            "{}: no settlement spend in the request",
            case.name
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
    let (out, prompt) = wallet.sign(&case.params_with(&case.placeholders_json));
    assert_eq!(
        refusal(&out.unwrap_err()),
        (codes::INVALID_PARAMS, "simulation_failed".to_owned())
    );
    assert!(prompt.is_none());
    // The spend that fails is the placeholder (the last spend), not one of the lender's.
    let mut request = case.maker_spends.clone();
    let placeholder_index = request.len();
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
    // since Sage's reader takes the placeholder's solution as the settlement solution and
    // cannot read a CAT solution. The placeholder is unsigned, so the two may differ.
    let placeholder = runnable_cat_placeholder(&case.placeholders[0]);
    let (out, prompt) = wallet.sign(&case.params_with(&[spend_json(&placeholder)]));
    assert_eq!(out.unwrap(), case.offer_bundle.aggregated_signature);
    assert_loan_offer_prompt(case, &prompt.unwrap());
    let mut wrapped = case.offer_bundle.clone();
    *wrapped.coin_spends.last_mut().unwrap() = placeholder;
    let mut ctx = SpendContext::new();
    assert!(Offer::from_spend_bundle(&mut ctx, &wrapped).is_err());
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

/// Klimper's `chia_takeOffer` before Sage builds anything (`check_offer`): at most 64 spends,
/// the maker's coins spent once, something requested, every maker spend a puzzle the kit
/// recognises under `execute` (the borrower owning none of them), and the maker's signature
/// covering the maker's spends. Then the offer as Sage reads it (`Offer::from_spend_bundle`):
/// one option offered, the principal offered, the collateral requested to the lender.
#[test]
fn klimper_reads_the_signed_offer_as_sage_does() {
    for case in cases() {
        let bundle = &case.offer_bundle;
        assert!(bundle.coin_spends.len() <= 64);
        let (placeholders, makers): (Vec<CoinSpend>, Vec<CoinSpend>) = bundle
            .coin_spends
            .iter()
            .cloned()
            .partition(|cs| cs.coin.parent_coin_info == Bytes32::default());
        assert!(
            !placeholders.is_empty(),
            "{}: asks for something",
            case.name
        );
        let ids: HashSet<Bytes32> = makers.iter().map(|cs| cs.coin.coin_id()).collect();
        assert_eq!(
            ids.len(),
            makers.len(),
            "{}: no coin spent twice",
            case.name
        );
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
            "{}: {:?}",
            case.name,
            executed.iter().map(|es| &es.kind).collect::<Vec<_>>()
        );
        assert!(executed.iter().all(|es| !es.owned));
        let options: Vec<&SpendKind> = executed
            .iter()
            .map(|es| &es.kind)
            .filter(|k| matches!(k, SpendKind::Option { .. }))
            .collect();
        assert_eq!(options.len(), 1, "{}", case.name);
        assert!(
            matches!(
                options[0],
                SpendKind::Option { launcher_id, p2_puzzle_hash, new_owner: Some(to), action: crate::option::OptionAction::Transfer, .. }
                    if *launcher_id == case.launcher_id
                        && *p2_puzzle_hash == case.lender.puzzle_hash
                        && *to == Bytes32::from(SETTLEMENT_PAYMENT_HASH)
            ),
            "{}: {:?}",
            case.name,
            options[0]
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
                RequiredSignature::Secp(_) => panic!("secp"),
            })
            .collect();
        assert_eq!(pairs.len(), makers.len());
        assert!(pairs.iter().all(|(pk, _)| *pk == case.lender.pk));
        assert!(
            chia_bls::aggregate_verify(
                &bundle.aggregated_signature,
                pairs.iter().map(|(pk, msg)| (pk, msg.as_slice()))
            ),
            "{}: the maker's signature covers the maker's spends",
            case.name
        );
        // As Sage reads it.
        let mut ctx = SpendContext::new();
        let offer = Offer::from_spend_bundle(&mut ctx, bundle).unwrap();
        let offered = offer.offered_coins();
        assert_eq!(
            offered.options.keys().copied().collect::<Vec<_>>(),
            vec![case.launcher_id],
            "{}",
            case.name
        );
        let option = offered.options[&case.launcher_id];
        assert_eq!(option.info.p2_puzzle_hash, SETTLEMENT_PAYMENT_HASH.into());
        assert_eq!(option.coin.amount, 1);
        assert!(offered.nfts.is_empty());
        assert_eq!(offered.fee, case.offer_fee);
        let (principal_asset, principal) = case.principal;
        match principal_asset {
            AssetId::Xch => {
                assert_eq!(offered.xch.iter().map(|c| c.amount).sum::<u64>(), principal);
                assert!(offered.cats.is_empty());
            }
            AssetId::Cat(asset_id) => {
                assert!(offered.xch.is_empty());
                assert_eq!(
                    offered.cats.keys().copied().collect::<Vec<_>>(),
                    vec![asset_id]
                );
                assert_eq!(
                    offered.cats[&asset_id]
                        .iter()
                        .map(|c| c.coin.amount)
                        .sum::<u64>(),
                    principal
                );
            }
            _ => unreachable!(),
        }
        let requested = offer.requested_payments();
        let (collateral_asset, collateral) = case.collateral;
        let payments = match collateral_asset {
            AssetId::Xch => {
                assert!(requested.cats.is_empty());
                &requested.xch
            }
            AssetId::Cat(asset_id) => {
                assert!(requested.xch.is_empty());
                assert_eq!(
                    requested.cats.keys().copied().collect::<Vec<_>>(),
                    vec![asset_id]
                );
                &requested.cats[&asset_id]
            }
            _ => unreachable!(),
        };
        assert!(requested.nfts.is_empty() && requested.options.is_empty());
        assert_eq!(payments.len(), 1);
        assert_eq!(payments[0].payments.len(), 1);
        assert_eq!(payments[0].payments[0].puzzle_hash, case.lender.puzzle_hash);
        assert_eq!(payments[0].payments[0].amount, collateral);
        assert_eq!(
            payments[0].nonce,
            Offer::nonce(makers.iter().map(|cs| cs.coin.coin_id()).collect()),
            "{}: notarised against the maker's coins",
            case.name
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
        let at = |asset: AssetId, owner: Bytes32| -> Bytes32 {
            match asset {
                AssetId::Cat(asset_id) => CatInfo::new(asset_id, None, owner).puzzle_hash().into(),
                _ => owner,
            }
        };
        let lender_before: u64 = sim
            .unspent_coins(at(collateral_asset, case.lender.puzzle_hash), false)
            .iter()
            .map(|c| c.amount)
            .sum();
        let sim = RefCell::new(sim);
        let mode = Mode {
            other: Some(case.offer_bundle.aggregated_signature.clone()),
            ..Mode::default()
        };
        let prompt = run_as(&sim, &borrower, all, None, &mode)
            .unwrap_or_else(|e| panic!("{}: {e:?}", case.name));
        assert_eq!(prompt["binding"]["all_bound"], true, "{}", case.name);
        assert_eq!(prompt["summary"]["unknown_puzzles"], json!([]));
        // The option reaches the borrower: the settlement spend of the option singleton pays
        // it to the borrower's puzzle hash.
        let options = prompt["summary"]["options"].as_array().unwrap();
        assert!(
            options.iter().any(|o| o["action"] == "transfer"
                && o["launcher_id"] == hex::encode(case.launcher_id)
                && o["to_user"] == true),
            "{}: {options:?}",
            case.name
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
            held(at(collateral_asset, case.lender.puzzle_hash)),
            lender_before + collateral - lender_fee,
            "{}",
            case.name
        );
        let (principal_asset, principal) = case.principal;
        let borrower_principal = held(at(principal_asset, borrower.puzzle_hash));
        assert_eq!(borrower_principal, principal, "{}", case.name);
        let principal_settlement = case.principal_settlement_puzzle_hash();
        assert_eq!(held(principal_settlement), 0, "settlement coins are spent");
        for c in &case.lender_coins {
            assert!(
                sim.borrow()
                    .coin_state(c.coin_id())
                    .unwrap()
                    .spent_height
                    .is_some(),
                "{}: the offer's coins are spent",
                case.name
            );
        }
    }
}
