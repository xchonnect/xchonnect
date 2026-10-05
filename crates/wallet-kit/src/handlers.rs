//! CHIP-0002 request handlers for wallets (spec 9.1, 11.1).
//!
//! One entry point, [`handle`], turns a decrypted `rpc.request` into the JSON result or a
//! CHIP-0002 error. For `signCoinSpends` it chains simulation, signature policy,
//! permissions and limits, shows the host the exact effect and signing plan, and signs
//! only after explicit approval — through the host's [`Signer`], so private keys never
//! enter this crate (spec 11.3).

use crate::binding::{BindingReport, check_binding};
use crate::chain::{self, ChainData};
use crate::permissions::{self, DappPermissions, LimitStore, PermissionError};
use crate::policy::{self, Network, PolicyOptions, Refusal, SigningPlan};
use crate::simulate::{DEFAULT_MAX_COST, Ownership, Summary, execute, summarize};
use crate::spend::decode_hex;
use crate::{KitError, parse_coin_spends};
use chia_bls::{PublicKey, Signature};
use clvm_utils::{tree_hash_atom, tree_hash_pair};
use clvmr::Allocator;
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::HashSet;
use xchonnect_core::rpc::{canonical_method, codes};

/// Signs with keys held outside this crate (Secure Enclave / StrongBox wrapped, biometric
/// gated). `sign` is called only after the user approved the exact request.
pub trait Signer {
    /// BLS augmented-scheme signature of `message` with the key for `public_key`
    /// (`chia_bls::sign`). Return an error if the key is unavailable or the user cancels
    /// the biometric prompt. [`handle`] verifies every returned signature.
    fn sign(&self, public_key: &PublicKey, message: &[u8]) -> Result<Signature, SignerError>;
}

/// Sign and verify: a signature that does not verify for `pk` (faulty platform signer,
/// wrong key) is treated as the key being unavailable, never passed on.
fn sign_verified(
    signer: &dyn Signer,
    pk: &PublicKey,
    message: &[u8],
) -> Result<Signature, SignerError> {
    let sig = signer.sign(pk, message)?;
    if chia_bls::verify(&sig, pk, message) {
        Ok(sig)
    } else {
        Err(SignerError::KeyUnavailable)
    }
}

/// Signer failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerError {
    /// The user cancelled (e.g. biometric prompt).
    Cancelled,
    /// The key is not available.
    KeyUnavailable,
}

/// What the user is asked to approve. The host renders it; the decision applies to
/// exactly this content.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Prompt<'a> {
    /// `signCoinSpends`: net effect and the signatures that would be produced.
    SignCoinSpends {
        /// dApp domain shown with the request.
        dapp: &'a str,
        /// Simulated effect (render this, never dApp-provided labels).
        summary: &'a Summary,
        /// Signatures to produce (highlight `is_unsafe`).
        plan: &'a SigningPlan,
        /// `partialSign` requested.
        partial: bool,
        /// For partial requests: the counterparty payments the user's spends depend on
        /// (always `all_bound`; unbound partial requests never reach the prompt).
        binding: Option<&'a BindingReport>,
    },
    /// `signMessage`.
    SignMessage {
        /// dApp domain.
        dapp: &'a str,
        /// Message bytes (hex).
        message_hex: String,
        /// Message as text, if it is printable UTF-8.
        message_text: Option<String>,
        /// Key that would sign (hex).
        public_key: String,
    },
}

/// Approval UI provided by the host.
pub trait Approver {
    /// Show the prompt; return `true` only on an explicit user approval.
    fn approve(&self, prompt: &Prompt<'_>) -> bool;
}

/// Per-request context assembled by the wallet from its session record.
pub struct RequestContext<'a> {
    /// Verified dApp domain of the session.
    pub dapp: &'a str,
    /// Wallet network.
    pub network: Network,
    /// Chain the session was approved for.
    pub session_chain_id: &'a str,
    /// Permissions granted to this dApp.
    pub permissions: &'a DappPermissions,
    /// The user enabled `AGG_SIG_UNSAFE` for this dApp.
    pub allow_agg_sig_unsafe: bool,
    /// The user allows requests that spend unrecognised contracts (spec 11.1 item 3).
    pub allow_unknown_contracts: bool,
    /// Puzzle hashes the wallet owns.
    pub ownership: &'a Ownership,
    /// Public keys the wallet can sign with.
    pub keys: &'a HashSet<PublicKey>,
    /// Daily limit storage for this dApp.
    pub limits: &'a dyn LimitStore,
    /// Current unix time.
    pub now: u64,
    /// The wallet's view of the chain, for the optional read and broadcast methods
    /// ([`crate::chain`]). `None`: those methods answer `4004`.
    pub chain: Option<&'a dyn ChainData>,
}

impl core::fmt::Debug for RequestContext<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RequestContext")
            .field("dapp", &self.dapp)
            .field("network", &self.network)
            .finish_non_exhaustive()
    }
}

/// CHIP-0002 error to return in `rpc.response`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcError {
    /// Code (spec 9.1).
    pub code: i64,
    /// Message.
    pub message: String,
    /// Optional JSON text.
    pub data: Option<String>,
}

impl RpcError {
    fn new(code: i64, message: &str) -> Self {
        RpcError {
            code,
            message: message.to_owned(),
            data: None,
        }
    }

    fn with_reason(mut self, reason: &str) -> Self {
        self.data = Some(json!({ "reason": reason }).to_string());
        self
    }
}

fn invalid_params() -> RpcError {
    RpcError::new(codes::INVALID_PARAMS, "invalid params")
}

fn unauthorized() -> RpcError {
    RpcError::new(codes::UNAUTHORIZED, "unauthorized")
}

fn user_rejected() -> RpcError {
    RpcError::new(codes::USER_REJECTED, "user rejected request")
}

fn no_secret_key() -> RpcError {
    RpcError::new(codes::NO_SECRET_KEY, "no secret key for public key")
}

fn limit_exceeded(reason: &str) -> RpcError {
    RpcError::new(codes::LIMIT_EXCEEDED, "spending limit exceeded").with_reason(reason)
}

impl From<KitError> for RpcError {
    fn from(e: KitError) -> Self {
        match e {
            KitError::InvalidRequest(_) => invalid_params(),
            KitError::CostExceeded => invalid_params().with_reason("cost_exceeded"),
            other => RpcError::new(codes::INVALID_PARAMS, &other.to_string())
                .with_reason("simulation_failed"),
        }
    }
}

impl From<Refusal> for RpcError {
    fn from(r: Refusal) -> Self {
        match r {
            Refusal::WrongNetwork => unauthorized().with_reason("wrong_network"),
            Refusal::AggSigUnsafe => unauthorized().with_reason("agg_sig_unsafe"),
            Refusal::NoSecretKey => no_secret_key(),
            Refusal::InfinityKey => invalid_params().with_reason("infinity_key"),
            Refusal::NothingToSign => invalid_params().with_reason("nothing_to_sign"),
        }
    }
}

impl From<PermissionError> for RpcError {
    fn from(e: PermissionError) -> Self {
        match e {
            PermissionError::MethodNotAllowed => unauthorized(),
            PermissionError::PerRequestLimit(_) => limit_exceeded("per_request"),
            PermissionError::DailyLimit(_) => limit_exceeded("per_day"),
            PermissionError::Storage => unauthorized().with_reason("limit_storage"),
        }
    }
}

fn hex_param(params: &Value, key: &str) -> Result<Vec<u8>, RpcError> {
    params
        .get(key)
        .and_then(Value::as_str)
        .and_then(decode_hex)
        .ok_or_else(invalid_params)
}

fn hex_json(bytes: &[u8]) -> String {
    json!(format!("0x{}", hex::encode(bytes))).to_string()
}

fn key_hex(k: &PublicKey) -> String {
    format!("0x{}", hex::encode(k.to_bytes()))
}

/// Handle one CHIP-0002 request. `params_json` is the request's JSON text.
pub fn handle(
    method: &str,
    params_json: &str,
    ctx: &RequestContext<'_>,
    signer: &dyn Signer,
    approver: &dyn Approver,
) -> Result<String, RpcError> {
    let params: Value = serde_json::from_str(params_json).map_err(|_| invalid_params())?;
    let method = canonical_method(method);
    let method_not_found = || RpcError::new(codes::METHOD_NOT_FOUND, "method not found");
    if !matches!(method, "chainId" | "connect") && !ctx.permissions.allows_method(method) {
        return Err(
            if matches!(method, "getPublicKeys" | "signCoinSpends" | "signMessage") {
                unauthorized()
            } else {
                method_not_found()
            },
        );
    }
    match method {
        "chainId" => Ok(json!(ctx.network.chain_id()).to_string()),
        // Within Xchonnect the completed pairing is the connection (spec 9.1).
        "connect" => Ok("true".to_owned()),
        "getPublicKeys" => {
            let num = |key| params.get(key).and_then(Value::as_u64);
            let limit = num("limit").unwrap_or(10).min(100) as usize;
            let offset = num("offset").unwrap_or(0) as usize;
            let keys: Vec<String> = ctx
                .permissions
                .exposed_keys
                .iter()
                .skip(offset)
                .take(limit)
                .map(key_hex)
                .collect();
            Ok(json!(keys).to_string())
        }
        "signCoinSpends" => sign_coin_spends(&params, ctx, signer, approver),
        "signMessage" => sign_message(&params, ctx, signer, approver),
        "walletSwitchChain" => chain::wallet_switch_chain(&params, ctx.session_chain_id),
        "getAssetCoins" | "getAssetBalance" | "filterUnlockedCoins" | "sendTransaction" => {
            let data = ctx.chain.ok_or_else(method_not_found)?;
            let keys = &ctx.permissions.exposed_keys;
            match method {
                "getAssetCoins" => chain::get_asset_coins(&params, keys, data),
                "getAssetBalance" => chain::get_asset_balance(&params, keys, data),
                "filterUnlockedCoins" => chain::filter_unlocked_coins(&params, keys, data),
                _ => chain::send_transaction(&params, data),
            }
        }
        _ => Err(method_not_found()),
    }
}

fn sign_coin_spends(
    params: &Value,
    ctx: &RequestContext<'_>,
    signer: &dyn Signer,
    approver: &dyn Approver,
) -> Result<String, RpcError> {
    let spends = parse_coin_spends(params.get("coinSpends").unwrap_or(&Value::Null))?;
    let partial = params
        .get("partialSign")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    // Run the puzzles once: the summary, signing plan and binding check all derive from
    // this execution.
    let mut a = Allocator::new();
    let (executed, costs) = execute(&mut a, &spends, ctx.ownership, DEFAULT_MAX_COST)?;
    let summary = summarize(&executed, &costs, ctx.ownership)?;
    if !summary.unknown_puzzles.is_empty() && !ctx.allow_unknown_contracts {
        return Err(RpcError::new(
            codes::UNSUPPORTED_CONTENT,
            "unknown contract",
        ));
    }
    let opts = PolicyOptions {
        network: ctx.network.clone(),
        session_chain_id: ctx.session_chain_id.to_owned(),
        allow_agg_sig_unsafe: ctx.allow_agg_sig_unsafe,
        partial,
    };
    let plan = policy::plan(&executed, ctx.keys, &opts)?;
    // Spec 11.2 / invariant 4: never produce a partial signature for an unbound
    // multi-party spend. There is no override.
    let binding = if partial {
        let report = check_binding(&mut a, &spends, &executed, ctx.ownership)?;
        if !report.all_bound {
            return Err(unauthorized().with_reason("unbound_partial"));
        }
        Some(report)
    } else {
        None
    };
    let loss = permissions::check_spend(
        ctx.permissions,
        "signCoinSpends",
        &summary,
        ctx.limits,
        ctx.now,
    )?;
    let prompt = Prompt::SignCoinSpends {
        dapp: ctx.dapp,
        summary: &summary,
        plan: &plan,
        partial,
        binding: binding.as_ref(),
    };
    if !approver.approve(&prompt) {
        return Err(user_rejected());
    }
    // Sign exactly the plan the user approved.
    let mut aggregate = Signature::default();
    for req in &plan.ours {
        let sig =
            sign_verified(signer, req.public_key(), req.message_bytes()).map_err(|e| match e {
                SignerError::Cancelled => user_rejected(),
                SignerError::KeyUnavailable => no_secret_key(),
            })?;
        aggregate.aggregate(&sig);
    }
    permissions::commit_spend(ctx.limits, &loss, ctx.now)?;
    Ok(hex_json(&aggregate.to_bytes()))
}

/// `sha256tree(cons("Chia Signed Message", message))` (CHIP-0002 `signMessage`).
pub fn signed_message_hash(message: &[u8]) -> [u8; 32] {
    tree_hash_pair(
        tree_hash_atom(b"Chia Signed Message"),
        tree_hash_atom(message),
    )
    .to_bytes()
}

fn sign_message(
    params: &Value,
    ctx: &RequestContext<'_>,
    signer: &dyn Signer,
    approver: &dyn Approver,
) -> Result<String, RpcError> {
    let message = hex_param(params, "message")?;
    let pk = <[u8; 48]>::try_from(hex_param(params, "publicKey")?)
        .ok()
        .and_then(|b| PublicKey::from_bytes(&b).ok())
        .ok_or_else(invalid_params)?;
    if !ctx.permissions.exposed_keys.contains(&pk) {
        return Err(unauthorized());
    }
    if !ctx.keys.contains(&pk) {
        return Err(no_secret_key());
    }
    let text = String::from_utf8(message.clone())
        .ok()
        .filter(|t| t.chars().all(|c| !c.is_control() || c == '\n'));
    let prompt = Prompt::SignMessage {
        dapp: ctx.dapp,
        message_hex: hex::encode(&message),
        message_text: text,
        public_key: key_hex(&pk),
    };
    if !approver.approve(&prompt) {
        return Err(user_rejected());
    }
    let sig =
        sign_verified(signer, &pk, &signed_message_hash(&message)).map_err(|_| user_rejected())?;
    Ok(hex_json(&sig.to_bytes()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::permissions::AssetLimit;
    use crate::simulate::AssetId;
    use crate::swap_fixture::{Mem, anyone_can_spend, owned, params, requested, swap};
    use chia_bls::SecretKey;
    use chia_protocol::{Bytes32, Coin, CoinSpend, SpendBundle};
    use chia_puzzle_types::Memos;
    use chia_sdk_driver::{SpendContext, StandardLayer};
    use chia_sdk_test::{BlsPair, Simulator};
    use chia_sdk_types::Conditions;
    use std::cell::{Cell, RefCell};

    /// Signs with one key and counts calls. `.2`: a faulty signer that returns a
    /// signature by an unrelated key.
    struct KeySigner(SecretKey, Cell<usize>, bool);
    impl Signer for KeySigner {
        fn sign(&self, pk: &PublicKey, msg: &[u8]) -> Result<Signature, SignerError> {
            self.1.set(self.1.get() + 1);
            if self.0.public_key() != *pk {
                return Err(SignerError::KeyUnavailable);
            }
            if self.2 {
                return Ok(chia_bls::sign(&BlsPair::new(9).sk, msg));
            }
            Ok(chia_bls::sign(&self.0, msg))
        }
    }

    /// Records every prompt (as the JSON hosts receive) and answers with `.0`.
    struct Ui(bool, RefCell<Vec<String>>);
    impl Approver for Ui {
        fn approve(&self, p: &Prompt<'_>) -> bool {
            self.1.borrow_mut().push(serde_json::to_string(p).unwrap());
            self.0
        }
    }

    /// A wallet owning and holding the key of `who`.
    struct Fixture {
        who: BlsPair,
        perms: DappPermissions,
        own: Ownership,
        keys: HashSet<PublicKey>,
        limits: Mem,
        signer: KeySigner,
    }

    fn fixture_for(who: BlsPair) -> Fixture {
        Fixture {
            perms: DappPermissions::new_default(who.pk),
            own: owned(who.puzzle_hash),
            keys: [who.pk].into_iter().collect(),
            limits: Mem::default(),
            signer: KeySigner(who.sk.clone(), Cell::new(0), false),
            who,
        }
    }

    fn fixture() -> Fixture {
        fixture_for(BlsPair::new(1))
    }

    impl Fixture {
        /// Run one request; returns the outcome and the prompts shown.
        fn call(
            &self,
            method: &str,
            params: &str,
            approve: bool,
        ) -> (Result<String, RpcError>, Vec<String>) {
            let ctx = RequestContext {
                dapp: "dapp.example",
                network: Network::Testnet11,
                session_chain_id: "testnet11",
                permissions: &self.perms,
                allow_agg_sig_unsafe: false,
                allow_unknown_contracts: false,
                ownership: &self.own,
                keys: &self.keys,
                limits: &self.limits,
                now: 1_790_000_000,
                chain: None,
            };
            let ui = Ui(approve, RefCell::default());
            let out = handle(method, params, &ctx, &self.signer, &ui);
            (out, ui.1.into_inner())
        }
    }

    fn sig(out: &str) -> Signature {
        let hex: String = serde_json::from_str(out).unwrap();
        Signature::from_bytes(&decode_hex(&hex).unwrap().try_into().unwrap()).unwrap()
    }

    fn send(sim: &mut Simulator, alice: &BlsPair, amount: u64) -> Vec<CoinSpend> {
        let bob = BlsPair::new(2);
        let coin = sim.new_coin(alice.puzzle_hash, amount);
        let mut sc = SpendContext::new();
        let conds = Conditions::new().create_coin(bob.puzzle_hash, amount, Memos::None);
        StandardLayer::new(alice.pk)
            .spend(&mut sc, coin, conds)
            .unwrap();
        sc.take()
    }

    #[test]
    fn sign_coin_spends_end_to_end_is_accepted_by_the_chain() {
        let f = fixture();
        let mut sim = Simulator::new();
        let spends = send(&mut sim, &f.who, 500);
        let (out, prompts) = f.call("chip0002_signCoinSpends", &params(&spends, false), true);
        sim.new_transaction(SpendBundle::new(spends, sig(&out.unwrap())))
            .unwrap();
        // The user saw the simulated loss, not a dApp label.
        assert!(prompts[0].contains("\"net\":-500"));
        assert_eq!(
            f.limits.0.borrow().spent.get(&AssetId::Xch),
            Some(&500),
            "committed after signing"
        );
    }

    #[test]
    fn no_signature_without_approval() {
        let f = fixture();
        let spends = send(&mut Simulator::new(), &f.who, 500);
        let (out, _) = f.call("signCoinSpends", &params(&spends, false), false);
        assert_eq!(out.unwrap_err().code, codes::USER_REJECTED);
        assert_eq!(f.signer.1.get(), 0, "signer never called");
        assert!(f.limits.0.borrow().spent.is_empty());
    }

    #[test]
    fn signatures_from_a_faulty_signer_are_never_returned() {
        let mut f = fixture();
        f.signer.2 = true;
        let spends = send(&mut Simulator::new(), &f.who, 500);
        let (out, _) = f.call("signCoinSpends", &params(&spends, false), true);
        assert_eq!(out.unwrap_err().code, codes::NO_SECRET_KEY);
        assert!(f.limits.0.borrow().spent.is_empty(), "nothing committed");
        let params = json!({ "message": "00", "publicKey": key_hex(&f.who.pk) }).to_string();
        assert_eq!(
            f.call("signMessage", &params, true).0.unwrap_err().code,
            codes::USER_REJECTED
        );
    }

    #[test]
    fn limits_unknown_contracts_and_permissions_refuse_before_prompting() {
        let mut f = fixture();
        f.perms.limits.insert(
            AssetId::Xch,
            AssetLimit {
                per_request: Some(100),
                per_day: None,
            },
        );
        let spends = send(&mut Simulator::new(), &f.who, 500);
        let (out, prompts) = f.call("signCoinSpends", &params(&spends, false), true);
        let err = out.unwrap_err();
        assert_eq!(
            (err.code, err.data.as_deref()),
            (codes::LIMIT_EXCEEDED, Some(r#"{"reason":"per_request"}"#))
        );
        assert!(prompts.is_empty(), "never prompted");
        // A spend of an unrecognised puzzle, even one that needs the user's signature.
        let unknown =
            anyone_can_spend(0, 1, Conditions::new().agg_sig_me(f.who.pk, vec![1].into()));
        let (out, prompts) = f.call("signCoinSpends", &params(&[unknown], false), true);
        assert_eq!(out.unwrap_err().code, codes::UNSUPPORTED_CONTENT);
        assert!(prompts.is_empty(), "never prompted");
        f.perms.methods.retain(|m| m != "signCoinSpends");
        let (out, prompts) = f.call("signCoinSpends", &params(&spends, false), true);
        assert_eq!(out.unwrap_err().code, codes::UNAUTHORIZED);
        assert!(prompts.is_empty(), "never prompted");
        assert_eq!(f.signer.1.get(), 0);
    }

    #[test]
    fn simple_methods_and_unknown_methods() {
        let f = fixture();
        let call = |method, params| f.call(method, params, true).0;
        assert_eq!(call("chainId", "{}").unwrap(), "\"testnet11\"");
        assert_eq!(call("connect", r#"{"eager":true}"#).unwrap(), "true");
        let keys: Vec<String> =
            serde_json::from_str(&call("getPublicKeys", r#"{"limit":5}"#).unwrap()).unwrap();
        assert_eq!(keys, vec![key_hex(&f.who.pk)]);
        assert_eq!(
            call("chia_takeOffer", "{}").unwrap_err().code,
            codes::METHOD_NOT_FOUND
        );
        assert_eq!(
            call("signCoinSpends", "not json").unwrap_err().code,
            codes::INVALID_PARAMS
        );
    }

    #[test]
    fn sign_message_follows_chip0002() {
        let f = fixture();
        let params =
            json!({ "message": "0x48656c6c6f", "publicKey": key_hex(&f.who.pk) }).to_string();
        let (out, prompts) = f.call("signMessage", &params, true);
        assert!(chia_bls::verify(
            &sig(&out.unwrap()),
            &f.who.pk,
            signed_message_hash(b"Hello")
        ));
        assert!(prompts[0].contains("\"message_text\":\"Hello\""));
        // A key that was not exposed to this dApp is refused.
        let other = BlsPair::new(5);
        let params = json!({ "message": "00", "publicKey": key_hex(&other.pk) }).to_string();
        assert_eq!(
            f.call("signMessage", &params, true).0.unwrap_err().code,
            codes::UNAUTHORIZED
        );
    }

    /// Partial (offer maker) requests are signed only when every user spend is bound.
    #[test]
    fn partial_sign_requires_binding() {
        let f = fixture();
        // Requested payment of 500 to Alice (zero-parent settlement spend).
        let (requested, id) = requested(f.who.puzzle_hash, 500);
        let coin = Coin::new(Bytes32::new([1; 32]), f.who.puzzle_hash, 1000);
        let maker = |assert: bool| {
            let mut c = SpendContext::new();
            let conds =
                Conditions::new().create_coin(requested.coin.puzzle_hash, 1000, Memos::None);
            let conds = if assert {
                conds.assert_puzzle_announcement(id)
            } else {
                conds
            };
            StandardLayer::new(f.who.pk)
                .spend(&mut c, coin, conds)
                .unwrap();
            params(&[c.take().remove(0), requested.clone()], true)
        };
        // Unbound: refused without prompting or signing.
        let (out, prompts) = f.call("signCoinSpends", &maker(false), true);
        let err = out.unwrap_err();
        assert_eq!(
            (err.code, err.data.as_deref()),
            (codes::UNAUTHORIZED, Some(r#"{"reason":"unbound_partial"}"#))
        );
        assert!(prompts.is_empty() && f.signer.1.get() == 0);
        // Bound: signed, and the prompt shows the payment the signature depends on.
        let (out, prompts) = f.call("signCoinSpends", &maker(true), true);
        assert!(out.unwrap().starts_with("\"0x"));
        assert!(
            prompts[0].contains("\"all_bound\":true") && prompts[0].contains("\"amount\":500"),
            "{}",
            prompts[0]
        );
    }

    /// TASK-57 end to end: two wallets each partially sign one atomic swap through the
    /// handlers; the dApp aggregates the signatures into a bundle the chain accepts.
    #[test]
    fn two_wallets_partial_sign_an_atomic_swap() {
        let mut sim = Simulator::new();
        let s = swap(&mut sim, true, true);
        let sign_as = |who: &BlsPair| {
            let (out, prompts) =
                fixture_for(who.clone()).call("signCoinSpends", &params(&s.spends, true), true);
            (sig(&out.unwrap()), prompts[0].clone())
        };
        let (sig_a, prompt_a) = sign_as(&s.alice);
        let (sig_b, prompt_b) = sign_as(&s.bob);
        // Each prompt states what the user gives and what the counterparty must deliver.
        assert!(
            prompt_a.contains("\"sent\":1000") && prompt_a.contains("\"amount\":500"),
            "{prompt_a}"
        );
        assert!(
            prompt_b.contains("\"sent\":500") && prompt_b.contains("\"amount\":1000"),
            "{prompt_b}"
        );
        // Either partial signature alone is not enough; the aggregate is a valid bundle.
        assert!(
            sim.clone()
                .new_transaction(SpendBundle::new(s.spends.clone(), sig_a.clone()))
                .is_err()
        );
        let mut agg = sig_a;
        agg.aggregate(&sig_b);
        sim.new_transaction(SpendBundle::new(s.spends, agg))
            .unwrap();
    }

    #[test]
    fn a_swap_side_that_does_not_assert_its_payment_is_refused() {
        let s = swap(&mut Simulator::new(), false, true);
        let (out, _) = fixture_for(s.alice).call("signCoinSpends", &params(&s.spends, true), true);
        assert_eq!(
            out.unwrap_err().data.as_deref(),
            Some(r#"{"reason":"unbound_partial"}"#)
        );
    }
}
