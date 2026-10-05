//! The exported wallet-kit API, driven the way Swift/Kotlin hosts drive it.
#![cfg(feature = "wallet-kit")]
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use chia_bls::{SecretKey, Signature};
use chia_protocol::SpendBundle;
use chia_puzzle_types::Memos;
use chia_sdk_driver::{SpendContext, StandardLayer};
use chia_sdk_test::{BlsPair, Simulator};
use chia_sdk_types::Conditions;
use std::sync::{Arc, Mutex};
use xchonnect_uniffi::{
    LimitStorage, RpcOutcome, WalletApprover, WalletRequestContext, WalletSigner,
    handle_wallet_request,
};

struct Keys(Vec<SecretKey>);
impl WalletSigner for Keys {
    fn sign(&self, public_key: String, message: Vec<u8>) -> Option<Vec<u8>> {
        self.0
            .iter()
            .find(|sk| hex::encode(sk.public_key().to_bytes()) == public_key)
            .map(|sk| chia_bls::sign(sk, &message).to_bytes().to_vec())
    }
}

struct Wrong;
impl WalletSigner for Wrong {
    fn sign(&self, _public_key: String, message: Vec<u8>) -> Option<Vec<u8>> {
        Some(
            chia_bls::sign(&BlsPair::new(77).sk, &message)
                .to_bytes()
                .to_vec(),
        )
    }
}

struct Ui(bool, Mutex<Vec<String>>);
impl WalletApprover for Ui {
    fn approve(&self, prompt_json: String) -> bool {
        self.1.lock().unwrap().push(prompt_json);
        self.0
    }
}

#[derive(Default)]
struct Store(Mutex<Option<String>>);
impl LimitStorage for Store {
    fn load(&self) -> Option<String> {
        self.0.lock().unwrap().clone()
    }
    fn save(&self, json: String) -> bool {
        *self.0.lock().unwrap() = Some(json);
        true
    }
}

fn context(alice: &BlsPair, per_day: Option<&str>) -> WalletRequestContext {
    WalletRequestContext {
        dapp: "dapp.example".into(),
        network: "testnet11".into(),
        session_chain_id: "testnet11".into(),
        methods: vec!["signCoinSpends".into(), "getPublicKeys".into()],
        exposed_keys: vec![hex::encode(alice.pk.to_bytes())],
        xch_per_request: None,
        xch_per_day: per_day.map(str::to_owned),
        allow_agg_sig_unsafe: false,
        allow_unknown_contracts: false,
        owned_puzzle_hashes: vec![hex::encode(alice.puzzle_hash)],
        keys: vec![hex::encode(alice.pk.to_bytes())],
        now: 1_790_000_000,
    }
}

fn request(
    sim: &mut Simulator,
    alice: &BlsPair,
    amount: u64,
) -> (Vec<chia_protocol::CoinSpend>, String) {
    let coin = sim.new_coin(alice.puzzle_hash, amount);
    let mut ctx = SpendContext::new();
    StandardLayer::new(alice.pk)
        .spend(
            &mut ctx,
            coin,
            Conditions::new().create_coin(BlsPair::new(2).puzzle_hash, amount, Memos::None),
        )
        .unwrap();
    let spends = ctx.take();
    let json = serde_json::json!({
        "coinSpends": spends.iter().map(|cs| serde_json::json!({
            "coin": { "parent_coin_info": hex::encode(cs.coin.parent_coin_info), "puzzle_hash": hex::encode(cs.coin.puzzle_hash), "amount": cs.coin.amount },
            "puzzle_reveal": hex::encode(cs.puzzle_reveal.as_ref()), "solution": hex::encode(cs.solution.as_ref()),
        })).collect::<Vec<_>>()
    })
    .to_string();
    (spends, json)
}

fn sign_coin_spends(
    params: String,
    context: WalletRequestContext,
    signer: impl WalletSigner + 'static,
    ui: Arc<Ui>,
    store: Arc<Store>,
) -> RpcOutcome {
    let signer = Arc::new(signer);
    handle_wallet_request("signCoinSpends".into(), params, context, signer, ui, store).unwrap()
}

fn ui(approve: bool) -> Arc<Ui> {
    Arc::new(Ui(approve, Mutex::new(vec![])))
}

#[test]
fn host_callbacks_sign_a_valid_spend_and_track_limits() {
    let alice = BlsPair::new(1);
    let mut sim = Simulator::new();
    let (spends, params) = request(&mut sim, &alice, 300);
    let (ui, store) = (ui(true), Arc::new(Store::default()));
    let keys = || Keys(vec![alice.sk.clone()]);
    let out = sign_coin_spends(
        params,
        context(&alice, Some("500")),
        keys(),
        ui.clone(),
        store.clone(),
    );
    let RpcOutcome::Success { result_json } = out else {
        panic!("expected success: {out:?}")
    };
    let sig_hex: String = serde_json::from_str(&result_json).unwrap();
    let sig = Signature::from_bytes(
        &hex::decode(sig_hex.trim_start_matches("0x"))
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    sim.new_transaction(SpendBundle::new(spends, sig)).unwrap();
    assert!(ui.1.lock().unwrap()[0].contains("\"type\":\"sign_coin_spends\""));
    assert!(
        store
            .0
            .lock()
            .unwrap()
            .as_deref()
            .unwrap()
            .contains("\"xch\":\"300\"")
    );

    // A second 300-mojo request exceeds the 500/day limit (state read back from storage).
    let (_, params) = request(&mut sim, &alice, 300);
    let out = sign_coin_spends(params, context(&alice, Some("500")), keys(), ui, store);
    assert!(
        matches!(out, RpcOutcome::Failure { code: 4029, .. }),
        "{out:?}"
    );
}

#[test]
fn rejection_and_bad_platform_signatures_never_produce_a_result() {
    let alice = BlsPair::new(1);
    let mut sim = Simulator::new();
    let (_, params) = request(&mut sim, &alice, 10);
    let keys = Keys(vec![alice.sk.clone()]);
    let out = sign_coin_spends(
        params.clone(),
        context(&alice, None),
        keys,
        ui(false),
        Arc::default(),
    );
    assert!(matches!(out, RpcOutcome::Failure { code: 4002, .. }));
    // A platform signer returning a signature from the wrong key is caught.
    let out = sign_coin_spends(
        params,
        context(&alice, None),
        Wrong,
        ui(true),
        Arc::default(),
    );
    assert!(
        matches!(out, RpcOutcome::Failure { code: 4005, .. }),
        "{out:?}"
    );
}
