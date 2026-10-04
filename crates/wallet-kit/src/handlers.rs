//! CHIP-0002 request handlers for wallets (spec 9.1, 11.1).
//!
//! One entry point, [`handle`], turns a decrypted `rpc.request` into the JSON result or a
//! CHIP-0002 error. For `signCoinSpends` it chains simulation, signature policy,
//! permissions and limits, shows the host the exact effect and signing plan, and signs
//! only after explicit approval — through the host's [`Signer`], so private keys never
//! enter this crate (spec 11.3).

use crate::permissions::{self, DappPermissions, LimitStore, PermissionError};
use crate::policy::{self, Network, PolicyOptions, Refusal, SigningPlan};
use crate::simulate::{DEFAULT_MAX_COST, Ownership, Summary, execute, simulate};
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
    /// the biometric prompt.
    fn sign(&self, public_key: &PublicKey, message: &[u8]) -> Result<Signature, SignerError>;
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

    fn reason(code: i64, message: &str, reason: &str) -> Self {
        RpcError {
            code,
            message: message.to_owned(),
            data: Some(json!({ "reason": reason }).to_string()),
        }
    }
}

impl From<KitError> for RpcError {
    fn from(e: KitError) -> Self {
        match e {
            KitError::InvalidRequest(_) => RpcError::new(codes::INVALID_PARAMS, "invalid params"),
            KitError::CostExceeded => {
                RpcError::reason(codes::INVALID_PARAMS, "invalid params", "cost_exceeded")
            }
            other => RpcError::reason(
                codes::INVALID_PARAMS,
                &other.to_string(),
                "simulation_failed",
            ),
        }
    }
}

impl From<Refusal> for RpcError {
    fn from(r: Refusal) -> Self {
        match r {
            Refusal::WrongNetwork => {
                RpcError::reason(codes::UNAUTHORIZED, "unauthorized", "wrong_network")
            }
            Refusal::AggSigUnsafe => {
                RpcError::reason(codes::UNAUTHORIZED, "unauthorized", "agg_sig_unsafe")
            }
            Refusal::NoSecretKey => {
                RpcError::new(codes::NO_SECRET_KEY, "no secret key for public key")
            }
            Refusal::InfinityKey => {
                RpcError::reason(codes::INVALID_PARAMS, "invalid params", "infinity_key")
            }
            Refusal::NothingToSign => {
                RpcError::reason(codes::INVALID_PARAMS, "invalid params", "nothing_to_sign")
            }
        }
    }
}

impl From<PermissionError> for RpcError {
    fn from(e: PermissionError) -> Self {
        match e {
            PermissionError::MethodNotAllowed => RpcError::new(codes::UNAUTHORIZED, "unauthorized"),
            PermissionError::PerRequestLimit(_) => RpcError::reason(
                codes::LIMIT_EXCEEDED,
                "spending limit exceeded",
                "per_request",
            ),
            PermissionError::DailyLimit(_) => {
                RpcError::reason(codes::LIMIT_EXCEEDED, "spending limit exceeded", "per_day")
            }
            PermissionError::Storage => {
                RpcError::reason(codes::UNAUTHORIZED, "unauthorized", "limit_storage")
            }
        }
    }
}

fn hex_param<'a>(params: &'a Value, key: &str) -> Result<&'a str, RpcError> {
    params
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new(codes::INVALID_PARAMS, "invalid params"))
}

fn decode_hex(s: &str) -> Result<Vec<u8>, RpcError> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    hex::decode(s).map_err(|_| RpcError::new(codes::INVALID_PARAMS, "invalid params"))
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
    let params: Value = serde_json::from_str(params_json)
        .map_err(|_| RpcError::new(codes::INVALID_PARAMS, "invalid params"))?;
    let method = canonical_method(method);
    if !matches!(method, "chainId" | "connect") && !ctx.permissions.allows_method(method) {
        return Err(
            if matches!(method, "getPublicKeys" | "signCoinSpends" | "signMessage") {
                RpcError::new(codes::UNAUTHORIZED, "unauthorized")
            } else {
                RpcError::new(codes::METHOD_NOT_FOUND, "method not found")
            },
        );
    }
    match method {
        "chainId" => Ok(json!(ctx.network.chain_id()).to_string()),
        // Within Xchonnect the completed pairing is the connection (spec 9.1).
        "connect" => Ok("true".to_owned()),
        "getPublicKeys" => {
            let limit = params
                .get("limit")
                .and_then(Value::as_u64)
                .unwrap_or(10)
                .min(100) as usize;
            let offset = params.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
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
        _ => Err(RpcError::new(codes::METHOD_NOT_FOUND, "method not found")),
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
    let summary = simulate(&spends, ctx.ownership, DEFAULT_MAX_COST)?;
    if !summary.unknown_puzzles.is_empty() && !ctx.allow_unknown_contracts {
        return Err(RpcError::new(
            codes::UNSUPPORTED_CONTENT,
            "unknown contract",
        ));
    }
    let mut a = Allocator::new();
    let (executed, _) = execute(&mut a, &spends, ctx.ownership, DEFAULT_MAX_COST)?;
    let opts = PolicyOptions {
        network: ctx.network.clone(),
        session_chain_id: ctx.session_chain_id.to_owned(),
        allow_agg_sig_unsafe: ctx.allow_agg_sig_unsafe,
        partial,
    };
    let plan = policy::plan(&executed, ctx.keys, &opts)?;
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
    };
    if !approver.approve(&prompt) {
        return Err(RpcError::new(codes::USER_REJECTED, "user rejected request"));
    }
    // Sign exactly the plan the user approved.
    let mut aggregate = Signature::default();
    for req in &plan.ours {
        let sig = signer
            .sign(req.public_key(), req.message_bytes())
            .map_err(|e| match e {
                SignerError::Cancelled => {
                    RpcError::new(codes::USER_REJECTED, "user rejected request")
                }
                SignerError::KeyUnavailable => {
                    RpcError::new(codes::NO_SECRET_KEY, "no secret key for public key")
                }
            })?;
        aggregate.aggregate(&sig);
    }
    permissions::commit_spend(ctx.limits, &loss, ctx.now)?;
    Ok(json!(format!("0x{}", hex::encode(aggregate.to_bytes()))).to_string())
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
    let message = decode_hex(hex_param(params, "message")?)?;
    let pk_bytes: [u8; 48] = decode_hex(hex_param(params, "publicKey")?)?
        .try_into()
        .map_err(|_| RpcError::new(codes::INVALID_PARAMS, "invalid params"))?;
    let pk = PublicKey::from_bytes(&pk_bytes)
        .map_err(|_| RpcError::new(codes::INVALID_PARAMS, "invalid params"))?;
    if !ctx.permissions.exposed_keys.contains(&pk) {
        return Err(RpcError::new(codes::UNAUTHORIZED, "unauthorized"));
    }
    if !ctx.keys.contains(&pk) {
        return Err(RpcError::new(
            codes::NO_SECRET_KEY,
            "no secret key for public key",
        ));
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
        return Err(RpcError::new(codes::USER_REJECTED, "user rejected request"));
    }
    let sig = signer
        .sign(&pk, &signed_message_hash(&message))
        .map_err(|_| RpcError::new(codes::USER_REJECTED, "user rejected request"))?;
    Ok(json!(format!("0x{}", hex::encode(sig.to_bytes()))).to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::permissions::{AssetLimit, DailySpend};
    use crate::simulate::AssetId;
    use chia_bls::SecretKey;
    use chia_protocol::{CoinSpend, SpendBundle};
    use chia_puzzle_types::Memos;
    use chia_sdk_driver::{SpendContext, StandardLayer};
    use chia_sdk_test::{BlsPair, Simulator};
    use chia_sdk_types::Conditions;
    use std::cell::{Cell, RefCell};

    struct KeySigner(Vec<SecretKey>, Cell<usize>);
    impl Signer for KeySigner {
        fn sign(&self, pk: &PublicKey, msg: &[u8]) -> Result<Signature, SignerError> {
            self.1.set(self.1.get() + 1);
            self.0
                .iter()
                .find(|sk| sk.public_key() == *pk)
                .map(|sk| chia_bls::sign(sk, msg))
                .ok_or(SignerError::KeyUnavailable)
        }
    }

    struct Ui(bool, RefCell<Vec<String>>);
    impl Approver for Ui {
        fn approve(&self, p: &Prompt<'_>) -> bool {
            self.1.borrow_mut().push(serde_json::to_string(p).unwrap());
            self.0
        }
    }

    #[derive(Default)]
    struct Mem(RefCell<DailySpend>);
    impl LimitStore for Mem {
        fn load(&self) -> Result<DailySpend, PermissionError> {
            Ok(self.0.borrow().clone())
        }
        fn save(&self, r: &DailySpend) -> Result<(), PermissionError> {
            *self.0.borrow_mut() = r.clone();
            Ok(())
        }
    }

    struct Fixture {
        alice: BlsPair,
        perms: DappPermissions,
        own: Ownership,
        keys: HashSet<PublicKey>,
        limits: Mem,
    }

    fn fixture() -> Fixture {
        let alice = BlsPair::new(1);
        Fixture {
            perms: DappPermissions::new_default(alice.pk),
            own: Ownership {
                p2_puzzle_hashes: [alice.puzzle_hash].into_iter().collect(),
            },
            keys: [alice.pk].into_iter().collect(),
            limits: Mem::default(),
            alice,
        }
    }

    fn ctx(f: &Fixture) -> RequestContext<'_> {
        RequestContext {
            dapp: "pengui.xyz",
            network: Network::Testnet11,
            session_chain_id: "testnet11",
            permissions: &f.perms,
            allow_agg_sig_unsafe: false,
            allow_unknown_contracts: false,
            ownership: &f.own,
            keys: &f.keys,
            limits: &f.limits,
            now: 1_790_000_000,
        }
    }

    fn coin_spends_json(spends: &[CoinSpend]) -> String {
        let arr: Vec<Value> = spends
            .iter()
            .map(|cs| {
                json!({
                    "coin": { "parent_coin_info": format!("0x{}", hex::encode(cs.coin.parent_coin_info)), "puzzle_hash": format!("0x{}", hex::encode(cs.coin.puzzle_hash)), "amount": cs.coin.amount },
                    "puzzle_reveal": format!("0x{}", hex::encode(cs.puzzle_reveal.as_ref())),
                    "solution": format!("0x{}", hex::encode(cs.solution.as_ref())),
                })
            })
            .collect();
        json!({ "coinSpends": arr, "partialSign": false }).to_string()
    }

    fn send(sim: &mut Simulator, alice: &BlsPair, amount: u64) -> Vec<CoinSpend> {
        let bob = BlsPair::new(2);
        let coin = sim.new_coin(alice.puzzle_hash, amount);
        let mut sc = SpendContext::new();
        StandardLayer::new(alice.pk)
            .spend(
                &mut sc,
                coin,
                Conditions::new().create_coin(bob.puzzle_hash, amount, Memos::None),
            )
            .unwrap();
        sc.take()
    }

    #[test]
    fn sign_coin_spends_end_to_end_is_accepted_by_the_chain() {
        let f = fixture();
        let mut sim = Simulator::new();
        let spends = send(&mut sim, &f.alice, 500);
        let signer = KeySigner(vec![f.alice.sk.clone()], Cell::new(0));
        let ui = Ui(true, RefCell::new(vec![]));
        let out = handle(
            "chip0002_signCoinSpends",
            &coin_spends_json(&spends),
            &ctx(&f),
            &signer,
            &ui,
        )
        .unwrap();
        let sig_hex: String = serde_json::from_str(&out).unwrap();
        let sig =
            Signature::from_bytes(&decode_hex(&sig_hex).unwrap().try_into().unwrap()).unwrap();
        sim.new_transaction(SpendBundle::new(spends, sig)).unwrap();
        // The user saw the simulated loss, not a dApp label.
        assert!(ui.1.borrow()[0].contains("\"net\":-500"));
        assert_eq!(
            f.limits.0.borrow().spent.get(&AssetId::Xch),
            Some(&500),
            "committed after signing"
        );
    }

    #[test]
    fn no_signature_without_approval() {
        let f = fixture();
        let mut sim = Simulator::new();
        let spends = send(&mut sim, &f.alice, 500);
        let signer = KeySigner(vec![f.alice.sk.clone()], Cell::new(0));
        let err = handle(
            "signCoinSpends",
            &coin_spends_json(&spends),
            &ctx(&f),
            &signer,
            &Ui(false, RefCell::new(vec![])),
        )
        .unwrap_err();
        assert_eq!(err.code, codes::USER_REJECTED);
        assert_eq!(signer.1.get(), 0, "signer never called");
        assert!(f.limits.0.borrow().spent.is_empty());
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
        let mut sim = Simulator::new();
        let spends = send(&mut sim, &f.alice, 500);
        let signer = KeySigner(vec![f.alice.sk.clone()], Cell::new(0));
        let ui = Ui(true, RefCell::new(vec![]));
        let err = handle(
            "signCoinSpends",
            &coin_spends_json(&spends),
            &ctx(&f),
            &signer,
            &ui,
        )
        .unwrap_err();
        assert_eq!(
            (err.code, err.data.as_deref()),
            (codes::LIMIT_EXCEEDED, Some(r#"{"reason":"per_request"}"#))
        );
        f.perms.methods.retain(|m| m != "signCoinSpends");
        assert_eq!(
            handle(
                "signCoinSpends",
                &coin_spends_json(&spends),
                &ctx(&f),
                &signer,
                &ui
            )
            .unwrap_err()
            .code,
            codes::UNAUTHORIZED
        );
        assert!(ui.1.borrow().is_empty(), "never prompted");
        assert_eq!(signer.1.get(), 0);
    }

    #[test]
    fn simple_methods_and_unknown_methods() {
        let f = fixture();
        let signer = KeySigner(vec![], Cell::new(0));
        let ui = Ui(true, RefCell::new(vec![]));
        assert_eq!(
            handle("chainId", "{}", &ctx(&f), &signer, &ui).unwrap(),
            "\"testnet11\""
        );
        assert_eq!(
            handle("connect", r#"{"eager":true}"#, &ctx(&f), &signer, &ui).unwrap(),
            "true"
        );
        let keys: Vec<String> = serde_json::from_str(
            &handle("getPublicKeys", r#"{"limit":5}"#, &ctx(&f), &signer, &ui).unwrap(),
        )
        .unwrap();
        assert_eq!(keys, vec![key_hex(&f.alice.pk)]);
        assert_eq!(
            handle("chia_takeOffer", "{}", &ctx(&f), &signer, &ui)
                .unwrap_err()
                .code,
            codes::METHOD_NOT_FOUND
        );
        assert_eq!(
            handle("signCoinSpends", "not json", &ctx(&f), &signer, &ui)
                .unwrap_err()
                .code,
            codes::INVALID_PARAMS
        );
    }

    #[test]
    fn sign_message_follows_chip0002() {
        let f = fixture();
        let signer = KeySigner(vec![f.alice.sk.clone()], Cell::new(0));
        let ui = Ui(true, RefCell::new(vec![]));
        let params =
            json!({ "message": "0x48656c6c6f", "publicKey": key_hex(&f.alice.pk) }).to_string();
        let sig_hex: String =
            serde_json::from_str(&handle("signMessage", &params, &ctx(&f), &signer, &ui).unwrap())
                .unwrap();
        let sig =
            Signature::from_bytes(&decode_hex(&sig_hex).unwrap().try_into().unwrap()).unwrap();
        assert!(chia_bls::verify(
            &sig,
            &f.alice.pk,
            signed_message_hash(b"Hello")
        ));
        assert!(ui.1.borrow()[0].contains("\"message_text\":\"Hello\""));
        // A key that was not exposed to this dApp is refused.
        let other = BlsPair::new(5);
        let params = json!({ "message": "00", "publicKey": key_hex(&other.pk) }).to_string();
        assert_eq!(
            handle("signMessage", &params, &ctx(&f), &signer, &ui)
                .unwrap_err()
                .code,
            codes::UNAUTHORIZED
        );
    }
}
