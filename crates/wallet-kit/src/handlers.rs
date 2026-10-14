//! CHIP-0002 request handlers for wallets (spec 9.1, 11.1).
//!
//! One entry point, [`handle`], turns a decrypted `rpc.request` into the JSON result or a
//! CHIP-0002 error. For `signCoinSpends` it chains simulation, signature policy,
//! permissions and limits, shows the host the exact effect and signing plan, and signs
//! only after explicit approval — through the host's [`Signer`], so private keys never
//! enter this crate (spec 11.3).

use crate::binding::{BindingReport, Linking, check_binding, cover_exercises};
use crate::chain::{self, ChainData};
use crate::intent::{Intent, IntentError, IntentReport};
use crate::option::OptionEffect;
use crate::permissions::{self, DappPermissions, LimitStore, PermissionError};
use crate::policy::{self, Network, PolicyOptions, Refusal, SigningPlan};
use crate::simulate::{DEFAULT_MAX_COST, ExecutedSpend, Ownership, Summary, execute, summarize};
use crate::spend::decode_hex;
use crate::{KitError, parse_coin_spends};
use chia_bls::{PublicKey, Signature};
use chia_protocol::{Bytes32, CoinSpend, SpendBundle};
use chia_sdk_types::Condition;
use clvm_utils::{tree_hash_atom, tree_hash_pair};
use clvmr::Allocator;
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use xchonnect_core::crypto::sha256_parts;
use xchonnect_core::rpc::{canonical_method, codes};

/// The wallet's own record of the signatures it let leave it (spec 11.2, "Signatures
/// released" and "Sealed signatures"). The host keeps it across requests and sessions and
/// passes it with every request ([`RequestContext::signed_coins`]); an empty record is
/// correct only for a wallet that has never let a signature leave it.
///
/// The kit says what to add before every broadcast and before it returns the signature of
/// a `signCoinSpends` ([`Broadcaster::record`], [`SignedCoins::add`]); the host adds the
/// coins of every signature it makes outside the kit (its own interface, offers, other
/// dApp protocols) to [`Self::released`] itself. The host removes a coin only once its
/// own verified sync holds the spend at a reorg-safe depth (spec 11.2 recommends at least
/// 6 blocks), never on a peer's unverified report ([`SignedCoins::spent`]); never removing
/// anything is also correct.
///
/// The host MUST process signing requests one at a time against this record, holding it
/// from building the [`RequestContext`] until [`handle_with_host`] or [`submit`] returns:
/// the kit reads it when the request starts, before the approval prompt (spec 11.2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignedCoins {
    /// Unspent coins of the wallet for which a signature covering a spend of the coin has
    /// left the wallet: returned to a dApp (every `signCoinSpends`, a signed offer such as a
    /// loan request) or broadcast (any bundle, including one the network refused). A coin
    /// leaves the set once it is spent on chain. The user's spends of a request that
    /// spends one of these coins are linked only directly ([`Linking::Direct`]).
    pub released: HashSet<Bytes32>,
    /// Every signature the wallet made in a sealed bundle it broadcast (or tried to: a
    /// bundle the network refused counts), as the [`sealed_digest`] of `(public key, signed
    /// message)`, with the unspent coin(s) of that bundle it was made for. Keyed by digest,
    /// so the check before every signature is one lookup. The kit refuses to sign any of
    /// these again, in any request (4001 `"sealed_signature"`): a second signature over the
    /// same message, alone or in another aggregate, would let the broadcast aggregate be
    /// split. Another spend of the coin signs another message and is not affected. An entry
    /// leaves only when its coin is spent on chain (the message can then never be valid
    /// again), never because another coin of the bundle was spent or the bundle expired.
    /// A digest leaves when the last coin it is held for is spent.
    pub sealed: HashMap<Bytes32, HashSet<Bytes32>>,
}

impl SignedCoins {
    /// Add what [`Broadcaster::record`] reports for one bundle.
    pub fn add(&mut self, record: &BroadcastRecord) {
        self.released.extend(record.coins.iter().copied());
        for (coin, digest) in &record.sealed {
            self.sealed.entry(*digest).or_default().insert(*coin);
        }
    }

    /// `coin_id` is spent on chain, at the wallet's reorg-safe depth: forget it.
    pub fn spent(&mut self, coin_id: &Bytes32) {
        self.released.remove(coin_id);
        self.sealed.retain(|_, coins| {
            coins.remove(coin_id);
            !coins.is_empty()
        });
    }

    /// The wallet signed `(public_key, message)` in a sealed bundle it broadcast.
    pub fn is_sealed(&self, public_key: &PublicKey, message: &[u8]) -> bool {
        self.sealed
            .contains_key(&sealed_digest(public_key, message))
    }
}

/// `sha256(public key (48 bytes) || message)`: how [`SignedCoins::sealed`] names one
/// signature, `message` being the exact bytes signed (for `AGG_SIG_ME` the condition's
/// message, the coin id and the network's additional data).
pub fn sealed_digest(public_key: &PublicKey, message: &[u8]) -> Bytes32 {
    Bytes32::new(sha256_parts(&[&public_key.to_bytes(), message]))
}

/// What the host adds to its [`SignedCoins`] for one bundle, before the bundle leaves the
/// wallet ([`Broadcaster::record`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BroadcastRecord {
    /// Every coin the bundle spends: into [`SignedCoins::released`].
    pub coins: Vec<Bytes32>,
    /// `(coin id, sealed_digest)` of every signature the wallet made, when the request was
    /// sealed ([`Linking::Sealed`]); empty otherwise. Into [`SignedCoins::sealed`].
    pub sealed: Vec<(Bytes32, Bytes32)>,
}

/// Signs with keys held outside this crate (Secure Enclave / StrongBox wrapped, biometric
/// gated). `sign` is called only after the user approved the exact request.
pub trait Signer {
    /// BLS augmented-scheme signature of `message` with the key for `public_key`
    /// (`chia_bls::sign`). Return an error if the key is unavailable or the user cancels
    /// the biometric prompt. [`handle`] verifies every returned signature.
    fn sign(&self, public_key: &PublicKey, message: &[u8]) -> Result<Signature, SignerError>;

    /// Every signature of one approved request, in order.
    ///
    /// Spec 11.1 item 4: **one** fresh user authentication per signing request, covering
    /// all of its signatures. A host that authenticates (biometric, passkey) or unlocks its
    /// keys does that once here and signs everything; the default calls [`Self::sign`] per
    /// signature for hosts without such a step. Every returned signature is verified.
    fn sign_all(&self, requests: &[(&PublicKey, &[u8])]) -> Result<Vec<Signature>, SignerError> {
        requests
            .iter()
            .map(|(pk, msg)| self.sign(pk, msg))
            .collect()
    }
}

/// Hands a fully signed spend bundle to the network (spec 8.3: the wallet submits).
pub trait Broadcaster {
    /// Persist `record` into the wallet's [`SignedCoins`] ([`SignedCoins::add`]). Called
    /// for every bundle before [`Self::submit`], so the record holds whether or not the
    /// network accepts the bundle, and by [`handle_with_host`] for every `signCoinSpends`
    /// it answers, after signing and before the signature is returned (`coins`: every coin
    /// of the request; `sealed`: empty). Return an error if it could not be stored durably:
    /// the bundle is then not broadcast, or the signature not returned (4000
    /// `"record_failed"`).
    fn record(&self, record: &BroadcastRecord) -> Result<(), String>;

    /// Submit `bundle`. Returns the transaction id (the bundle's hash) and a short status
    /// (e.g. `"submitted"`, `"pending"`), or why the network refused it.
    fn submit(&self, bundle: &SpendBundle) -> Result<Broadcast, String>;
}

/// What a [`Broadcaster`] reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Broadcast {
    /// Transaction id: the spend bundle hash (hex, `0x` prefixed).
    pub transaction_id: String,
    /// Status as reported by the network layer.
    pub status: String,
}

/// What the wallet brings to a request beyond the session context.
pub struct Host<'a> {
    /// Signs after approval.
    pub signer: &'a dyn Signer,
    /// Shows the prompt.
    pub approver: &'a dyn Approver,
    /// Submits signed bundles and records what leaves the wallet ([`Broadcaster::record`]),
    /// also for `signCoinSpends`. Without one, the methods that broadcast are not offered
    /// and the host records the coins of each `signCoinSpends` answer itself.
    pub broadcaster: Option<&'a dyn Broadcaster>,
}

impl core::fmt::Debug for Host<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Host")
            .field("broadcaster", &self.broadcaster.is_some())
            .finish_non_exhaustive()
    }
}

/// Sign every planned requirement in one batch and verify each signature.
fn sign_batch(signer: &dyn Signer, plan: &SigningPlan) -> Result<Signature, RpcError> {
    let requests: Vec<(&PublicKey, &[u8])> = plan
        .ours
        .iter()
        .map(|r| (r.public_key(), r.message_bytes()))
        .collect();
    let signatures = signer.sign_all(&requests).map_err(|e| match e {
        SignerError::Cancelled => user_rejected(),
        SignerError::KeyUnavailable => no_secret_key(),
    })?;
    if signatures.len() != requests.len() {
        return Err(no_secret_key());
    }
    let mut aggregate = Signature::default();
    for ((pk, msg), sig) in requests.iter().zip(&signatures) {
        if !chia_bls::verify(sig, pk, msg) {
            return Err(no_secret_key());
        }
        aggregate.aggregate(sig);
    }
    Ok(aggregate)
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
        /// For partial requests and option exercises: the counterparty payments the user's
        /// spends depend on (always `all_bound`; unbound requests never reach the prompt).
        binding: Option<&'a BindingReport>,
    },
    /// `xchonnect_submitCoinSpends` (and spends the wallet built itself, e.g. `chia_send`):
    /// the wallet signs **and broadcasts**.
    SubmitCoinSpends {
        /// dApp domain shown with the request.
        dapp: &'a str,
        /// The method that asked for it (`xchonnect_submitCoinSpends`, `chia_send`, …).
        method: &'a str,
        /// The wallet built the spend itself from the request's parameters; `false` for a
        /// spend bundle the dApp built.
        wallet_built: bool,
        /// Simulated effect.
        summary: &'a Summary,
        /// Signatures to produce.
        plan: &'a SigningPlan,
        /// Present when another party's signature completes the bundle (taking an offer) or
        /// the user exercises an option: the user's spends are bound to the payments they
        /// depend on.
        binding: Option<&'a BindingReport>,
        /// The dApp's declared intent, every claim verified.
        intent: Option<&'a IntentReport>,
        /// Which links between the user's spends counted (spec 11.2): `sealed` only for a
        /// wallet-built bundle whose signatures never leave the wallet.
        linking: Linking,
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
    /// Which of the wallet's coins have signatures outside it (spec 11.2).
    pub signed_coins: &'a SignedCoins,
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
            Refusal::UnsignedConditions => unauthorized().with_reason("unsigned_conditions"),
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
///
/// Without a broadcaster: the methods that submit a transaction are not offered, and the
/// coins of a `signCoinSpends` answer are not recorded by the kit; the host adds them to
/// [`SignedCoins::released`] before passing the answer on. See [`handle_with_host`].
pub fn handle(
    method: &str,
    params_json: &str,
    ctx: &RequestContext<'_>,
    signer: &dyn Signer,
    approver: &dyn Approver,
) -> Result<String, RpcError> {
    handle_with_host(
        method,
        params_json,
        ctx,
        &Host {
            signer,
            approver,
            broadcaster: None,
        },
    )
}

/// The method a dApp uses for a spend bundle it built and the wallet signs and broadcasts.
pub const SUBMIT_COIN_SPENDS: &str = "xchonnect_submitCoinSpends";

/// Handle one request, with a host that may also broadcast.
pub fn handle_with_host(
    method: &str,
    params_json: &str,
    ctx: &RequestContext<'_>,
    host: &Host<'_>,
) -> Result<String, RpcError> {
    let (signer, approver) = (host.signer, host.approver);
    let params: Value = serde_json::from_str(params_json).map_err(|_| invalid_params())?;
    let method = canonical_method(method);
    let method_not_found = || RpcError::new(codes::METHOD_NOT_FOUND, "method not found");
    if !matches!(method, "chainId" | "connect") && !ctx.permissions.allows_method(method) {
        return Err(
            if matches!(
                method,
                "getPublicKeys" | "signCoinSpends" | "signMessage" | SUBMIT_COIN_SPENDS
            ) {
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
        "signCoinSpends" => sign_coin_spends(&params, ctx, signer, approver, host.broadcaster),
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
        SUBMIT_COIN_SPENDS => {
            let broadcaster = host.broadcaster.ok_or_else(method_not_found)?;
            let spends = parse_coin_spends(params.get("coinSpends").unwrap_or(&Value::Null))?;
            let extra = match params.get("aggregatedSignature") {
                None | Some(Value::Null) => None,
                Some(_) => {
                    let bytes = <[u8; 96]>::try_from(hex_param(&params, "aggregatedSignature")?)
                        .map_err(|_| invalid_params())?;
                    Some(Signature::from_bytes(&bytes).map_err(|_| invalid_params())?)
                }
            };
            let intent = match params.get("intent") {
                None | Some(Value::Null) => None,
                Some(value) => Some(Intent::from_json(value).map_err(intent_error)?),
            };
            let submitted = submit(
                SubmitRequest {
                    method: SUBMIT_COIN_SPENDS,
                    spends,
                    other_signature: extra,
                    intent: intent.as_ref(),
                    wallet_built: false,
                    signatures_released: true,
                },
                ctx,
                signer,
                approver,
                broadcaster,
            )?;
            Ok(submitted.to_json())
        }
        _ => Err(method_not_found()),
    }
}

fn sign_coin_spends(
    params: &Value,
    ctx: &RequestContext<'_>,
    signer: &dyn Signer,
    approver: &dyn Approver,
    recorder: Option<&dyn Broadcaster>,
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
    refuse_sealed(&plan, ctx)?;
    refuse_expiring_collateral(&summary, ctx.now)?;
    // Spec 11.2 / invariant 4: never produce a partial signature for an unbound
    // multi-party spend. There is no override.
    // The signature goes back to the dApp: only direct binding counts.
    let binding = bind(
        &mut a,
        &spends,
        &executed,
        ctx.ownership,
        &summary,
        partial,
        Linking::Direct,
    )?;
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
    // Sign exactly the plan the user approved: one batch, one authentication.
    let aggregate = sign_batch(signer, &plan)?;
    // The signature leaves the wallet: its coins are released (spec 11.2), recorded before
    // it is returned. Without a recorder the host records them (see `handle`).
    if let Some(recorder) = recorder {
        store_record(
            recorder,
            &BroadcastRecord {
                coins: spends.iter().map(|cs| cs.coin.coin_id()).collect(),
                sealed: Vec::new(),
            },
        )?;
    }
    permissions::commit_spend(ctx.limits, &loss, ctx.now)?;
    Ok(hex_json(&aggregate.to_bytes()))
}

/// The binding check of spec 11.2 for a multi-party request, and the coverage check of
/// spec 11.1.1 for an option exercise by the user. The exercise releases the collateral to
/// the settlement puzzle, where anyone could claim it, so the user's spends must be included
/// together and their guaranteed outcome must contain the collateral
/// ([`BindingReport::exercises_covered`]). There is no override.
fn bind(
    a: &mut Allocator,
    spends: &[CoinSpend],
    executed: &[ExecutedSpend],
    ownership: &Ownership,
    summary: &Summary,
    multi_party: bool,
    linking: Linking,
) -> Result<Option<BindingReport>, RpcError> {
    let exercises = summary
        .options
        .iter()
        .any(|e| matches!(e, OptionEffect::Exercise { by_user: true, .. }));
    if !multi_party && !exercises {
        return Ok(None);
    }
    let mut report = check_binding(a, spends, executed, ownership, linking)?;
    cover_exercises(&mut report, summary);
    if multi_party && !report.all_bound {
        return Err(unauthorized().with_reason("unbound_partial"));
    }
    if !report.exercises_covered() {
        return Err(unauthorized().with_reason("unbound_exercise"));
    }
    Ok(Some(report))
}

/// Spec 11.1.1 item 7: the user's collateral locked under another creator in an option that
/// expires within [`crate::option::MIN_OPTION_LIFETIME_SECONDS`] would be the creator's as
/// soon as the mint lands. There is no override.
fn refuse_expiring_collateral(summary: &Summary, now: u64) -> Result<(), RpcError> {
    if crate::option::collateral_lost_to_expiry(&summary.options, now) {
        return Err(unauthorized().with_reason("option_expires"));
    }
    Ok(())
}

/// Spec 11.2: a signature the wallet made in a sealed bundle is never made again, so it
/// exists only inside that bundle's aggregate.
fn refuse_sealed(plan: &SigningPlan, ctx: &RequestContext<'_>) -> Result<(), RpcError> {
    if plan.ours.iter().any(|r| {
        ctx.signed_coins
            .is_sealed(r.public_key(), r.message_bytes())
    }) {
        return Err(unauthorized().with_reason("sealed_signature"));
    }
    Ok(())
}

/// Which links between the user's spends count (spec 11.2). [`Linking::Sealed`] only for a
/// wallet-built request whose signatures the host keeps (`signatures_released` false) and
/// whose every user spend is sealed: its coin has no signature outside the wallet
/// ([`SignedCoins::released`]) and the wallet signs it with `AGG_SIG_ME` only (a message
/// bound to the coin id). Each user signature then exists only inside the one aggregate the
/// wallet broadcasts, so the user's spends are included together or not at all.
fn linking_of(
    executed: &[ExecutedSpend],
    ctx: &RequestContext<'_>,
    wallet_built: bool,
    signatures_released: bool,
) -> Linking {
    if !wallet_built || signatures_released {
        return Linking::Direct;
    }
    let mut user = executed.iter().filter(|es| es.owned).peekable();
    if user.peek().is_none() {
        return Linking::Direct;
    }
    let sealed = user.all(|es| {
        !ctx.signed_coins.released.contains(&es.coin.coin_id()) && signed_by_coin(es, ctx.keys)
    });
    if sealed {
        Linking::Sealed
    } else {
        Linking::Direct
    }
}

/// The wallet signs this spend, and only with `AGG_SIG_ME`: every signature of it names
/// the coin (spec 11.1 item 2; the other variants name a parent, puzzle or amount that
/// another coin can share).
fn signed_by_coin(es: &ExecutedSpend, keys: &HashSet<PublicKey>) -> bool {
    let mut signs = false;
    for c in &es.conditions {
        let Some(sig) = c.clone().into_agg_sig() else {
            continue;
        };
        if !keys.contains(&sig.public_key) {
            continue;
        }
        if !matches!(c, Condition::AggSigMe(_)) {
            return false;
        }
        signs = true;
    }
    signs
}

fn intent_error(e: IntentError) -> RpcError {
    match e {
        IntentError::Invalid(_) => invalid_params().with_reason("invalid_intent"),
        IntentError::Mismatch(_) => unauthorized().with_reason("intent_mismatch"),
    }
}

/// A spend the wallet signs and broadcasts.
#[derive(Debug)]
pub struct SubmitRequest<'a> {
    /// The method shown on the prompt.
    pub method: &'a str,
    /// Coin spends (built by the dApp, or by the wallet itself).
    pub spends: Vec<CoinSpend>,
    /// Another party's signature that completes the bundle (taking an offer).
    pub other_signature: Option<Signature>,
    /// Claims to verify against the simulation.
    pub intent: Option<&'a Intent>,
    /// The wallet built the spend itself.
    pub wallet_built: bool,
    /// Any signature of the request, or the signed bundle, leaves the wallet other than in
    /// the broadcast bundle: returned to the dApp, or handed on as an offer (spec 11.2).
    /// `true` is the strict default and is always right; a host MAY pass `false` only for
    /// a wallet-built request whose bundle it broadcasts itself, returning only the
    /// transaction id and status. Whatever it passes, it MUST store what
    /// [`Broadcaster::record`] reports before that returns, also when the network then
    /// refuses the bundle (4000 `"broadcast_failed"`). To send a sealed bundle again it
    /// rebroadcasts the bytes it already has: the kit never signs its messages a second
    /// time (4001 `"sealed_signature"`). A dApp-built bundle is always treated as released.
    pub signatures_released: bool,
}

/// What [`submit`] returns to the dApp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Submitted {
    /// The broadcast.
    pub broadcast: Broadcast,
    /// The signed bundle that was broadcast.
    pub bundle: SpendBundle,
}

impl Submitted {
    /// The JSON result: `{ "transactionId": "0x…", "status": "…" }`.
    pub fn to_json(&self) -> String {
        json!({
            "transactionId": self.broadcast.transaction_id,
            "status": self.broadcast.status,
        })
        .to_string()
    }
}

/// Validate, show once, sign once, check the whole bundle, broadcast.
///
/// The same checks as `signCoinSpends` — simulation, unknown contracts, signature policy,
/// limits — plus: a verified intent when one is given; with another party's signature,
/// the binding check of spec 11.2; and before anything leaves the wallet, the aggregated
/// signature must cover **every** requirement of the bundle, so the wallet never broadcasts
/// a bundle the chain would refuse.
pub fn submit(
    request: SubmitRequest<'_>,
    ctx: &RequestContext<'_>,
    signer: &dyn Signer,
    approver: &dyn Approver,
    broadcaster: &dyn Broadcaster,
) -> Result<Submitted, RpcError> {
    let SubmitRequest {
        method,
        spends,
        other_signature,
        intent,
        wallet_built,
        signatures_released,
    } = request;
    let completes_other = other_signature.is_some();
    let mut a = Allocator::new();
    let (mut executed, costs) = execute(&mut a, &spends, ctx.ownership, DEFAULT_MAX_COST)?;
    let linking = linking_of(&executed, ctx, wallet_built, signatures_released);
    if linking != Linking::Direct {
        crate::option::guarantee(&mut executed, linking);
    }
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
        // Other keys are allowed only when the dApp brings their signature.
        partial: completes_other,
    };
    let plan = policy::plan(&executed, ctx.keys, &opts)?;
    refuse_sealed(&plan, ctx)?;
    refuse_expiring_collateral(&summary, ctx.now)?;
    let binding = bind(
        &mut a,
        &spends,
        &executed,
        ctx.ownership,
        &summary,
        completes_other,
        linking,
    )?;
    let report = intent
        .map(|i| i.verify(&summary, ctx.now))
        .transpose()
        .map_err(intent_error)?;
    let loss = permissions::check_spend(ctx.permissions, method, &summary, ctx.limits, ctx.now)?;
    let prompt = Prompt::SubmitCoinSpends {
        dapp: ctx.dapp,
        method,
        wallet_built,
        summary: &summary,
        plan: &plan,
        binding: binding.as_ref(),
        intent: report.as_ref(),
        linking,
    };
    if !approver.approve(&prompt) {
        return Err(user_rejected());
    }
    let mut aggregate = sign_batch(signer, &plan)?;
    if let Some(other) = &other_signature {
        aggregate.aggregate(other);
    }
    // The whole bundle, every party's requirement: what the mempool will check.
    let required = plan.all_requirements();
    let complete =
        chia_bls::aggregate_verify(&aggregate, required.iter().map(|(pk, msg)| (*pk, *msg)));
    if !complete {
        return Err(invalid_params().with_reason("signature_incomplete"));
    }
    // What leaves the wallet is recorded before it leaves (spec 11.2): the coins, and for a
    // sealed request each of its signatures, which the wallet never makes again.
    let record = BroadcastRecord {
        coins: spends.iter().map(|cs| cs.coin.coin_id()).collect(),
        sealed: if linking == Linking::Sealed {
            plan.ours
                .iter()
                .filter_map(|r| {
                    let coin = spends.get(r.spend)?.coin.coin_id();
                    Some((coin, sealed_digest(r.public_key(), r.message_bytes())))
                })
                .collect()
        } else {
            Vec::new()
        },
    };
    store_record(broadcaster, &record)?;
    let bundle = SpendBundle::new(spends, aggregate);
    let broadcast = broadcaster.submit(&bundle).map_err(|message| RpcError {
        code: codes::INVALID_PARAMS,
        message: format!("the network refused the transaction: {message}"),
        data: Some(json!({ "reason": "broadcast_failed" }).to_string()),
    })?;
    // Only a transaction that left the wallet counts towards the limits.
    permissions::commit_spend(ctx.limits, &loss, ctx.now)?;
    Ok(Submitted { broadcast, bundle })
}

/// Store what leaves the wallet before it leaves; 4000 `"record_failed"` otherwise.
fn store_record(recorder: &dyn Broadcaster, record: &BroadcastRecord) -> Result<(), RpcError> {
    recorder.record(record).map_err(|message| RpcError {
        code: codes::INVALID_PARAMS,
        message: format!("the wallet could not record the signatures: {message}"),
        data: Some(json!({ "reason": "record_failed" }).to_string()),
    })
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
    if ctx
        .signed_coins
        .is_sealed(&pk, &signed_message_hash(&message))
    {
        return Err(unauthorized().with_reason("sealed_signature"));
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
        signed: SignedCoins,
    }

    fn fixture_for(who: BlsPair) -> Fixture {
        Fixture {
            perms: DappPermissions::new_default(who.pk),
            own: owned(who.puzzle_hash),
            keys: [who.pk].into_iter().collect(),
            limits: Mem::default(),
            signer: KeySigner(who.sk.clone(), Cell::new(0), false),
            signed: SignedCoins::default(),
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
                signed_coins: &self.signed,
            };
            let ui = Ui(approve, RefCell::default());
            let out = handle(method, params, &ctx, &self.signer, &ui);
            (out, ui.1.into_inner())
        }
    }

    /// Broadcasts into a simulator, as a full node would, and records each bundle.
    struct Chain(RefCell<Simulator>, RefCell<Vec<SpendBundle>>);
    impl Broadcaster for Chain {
        fn record(&self, _record: &BroadcastRecord) -> Result<(), String> {
            Ok(())
        }
        fn submit(&self, bundle: &SpendBundle) -> Result<Broadcast, String> {
            self.0
                .borrow_mut()
                .new_transaction(bundle.clone())
                .map_err(|e| e.to_string())?;
            self.1.borrow_mut().push(bundle.clone());
            Ok(Broadcast {
                transaction_id: format!("0x{}", hex::encode(bundle.name())),
                status: "submitted".to_owned(),
            })
        }
    }

    /// Counts how often the host is asked for a batch.
    struct BatchSigner(SecretKey, Cell<usize>, Cell<usize>);
    impl Signer for BatchSigner {
        fn sign(&self, _pk: &PublicKey, msg: &[u8]) -> Result<Signature, SignerError> {
            self.1.set(self.1.get() + 1);
            Ok(chia_bls::sign(&self.0, msg))
        }
        fn sign_all(&self, r: &[(&PublicKey, &[u8])]) -> Result<Vec<Signature>, SignerError> {
            self.2.set(self.2.get() + 1);
            r.iter().map(|(pk, msg)| self.sign(pk, msg)).collect()
        }
    }

    impl Fixture {
        fn ctx(&self) -> RequestContext<'_> {
            RequestContext {
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
                signed_coins: &self.signed,
            }
        }

        /// `xchonnect_submitCoinSpends` against a chain; returns outcome, prompts, chain.
        fn submit(
            &self,
            sim: Simulator,
            params: &str,
            approve: bool,
        ) -> (Result<String, RpcError>, Vec<String>, Chain) {
            let ui = Ui(approve, RefCell::default());
            let chain = Chain(RefCell::new(sim), RefCell::default());
            let out = handle_with_host(
                SUBMIT_COIN_SPENDS,
                params,
                &self.ctx(),
                &Host {
                    signer: &self.signer,
                    approver: &ui,
                    broadcaster: Some(&chain),
                },
            );
            (out, ui.1.into_inner(), chain)
        }
    }

    /// Alice pays `amount` to Bob from one coin of `coin`, change back, `fee` reserved.
    fn pay(
        sim: &mut Simulator,
        alice: &BlsPair,
        coin: u64,
        amount: u64,
        fee: u64,
    ) -> Vec<CoinSpend> {
        let bob = BlsPair::new(2);
        let c = sim.new_coin(alice.puzzle_hash, coin);
        let mut sc = SpendContext::new();
        let conds = Conditions::new()
            .create_coin(bob.puzzle_hash, amount, Memos::None)
            .create_coin(alice.puzzle_hash, coin - amount - fee, Memos::None)
            .reserve_fee(fee);
        StandardLayer::new(alice.pk)
            .spend(&mut sc, c, conds)
            .unwrap();
        sc.take()
    }

    fn with_intent(spends: &[CoinSpend], intent: serde_json::Value) -> String {
        let mut p: serde_json::Value = serde_json::from_str(&params(spends, false)).unwrap();
        p["intent"] = intent;
        p.to_string()
    }

    #[test]
    fn submit_signs_once_and_the_wallet_broadcasts_a_bundle_the_chain_accepts() {
        let f = fixture();
        let mut sim = Simulator::new();
        let spends = pay(&mut sim, &f.who, 1000, 700, 10);
        let bob = hex::encode(BlsPair::new(2).puzzle_hash);
        let intent = json!({
            "kind": "send",
            "recipients": [{ "puzzleHash": bob, "amount": "700" }],
            "fee": "10",
            "netChange": [{ "assetId": null, "amount": "-710" }],
        });
        let (out, prompts, chain) = f.submit(sim, &with_intent(&spends, intent), true);
        let out: Value = serde_json::from_str(&out.unwrap()).unwrap();
        assert_eq!(out["status"], "submitted");
        assert!(out["transactionId"].as_str().unwrap().starts_with("0x"));
        // The wallet broadcast it, and the chain took it.
        assert_eq!(chain.1.borrow().len(), 1);
        let p: Value = serde_json::from_str(&prompts[0]).unwrap();
        assert_eq!(p["type"], "submit_coin_spends");
        assert_eq!(p["intent"]["kind"], "send");
        assert_eq!(p["intent"]["verified"].as_array().unwrap().len(), 3);
        assert_eq!(p["intent"]["recipients_complete"], true);
        assert_eq!(f.limits.0.borrow().spent.get(&AssetId::Xch), Some(&710));
    }

    #[test]
    fn a_five_coin_request_asks_the_host_for_one_batch() {
        let f = fixture();
        let mut sim = Simulator::new();
        let mut spends = pay(&mut sim, &f.who, 1_000_000, 900_000, 1);
        // Four more coins that only contribute their value.
        for _ in 0..4 {
            let c = sim.new_coin(f.who.puzzle_hash, 1000);
            let mut sc = SpendContext::new();
            StandardLayer::new(f.who.pk)
                .spend(&mut sc, c, Conditions::new())
                .unwrap();
            spends.extend(sc.take());
        }
        let signer = BatchSigner(f.who.sk.clone(), Cell::new(0), Cell::new(0));
        let ui = Ui(true, RefCell::default());
        let chain = Chain(RefCell::new(sim), RefCell::default());
        let out = handle_with_host(
            SUBMIT_COIN_SPENDS,
            &params(&spends, false),
            &f.ctx(),
            &Host {
                signer: &signer,
                approver: &ui,
                broadcaster: Some(&chain),
            },
        );
        out.unwrap();
        assert_eq!(ui.1.borrow().len(), 1, "one prompt for the whole request");
        assert_eq!(signer.2.get(), 1, "one batch: one authentication");
        assert_eq!(signer.1.get(), 5, "five signatures inside it");
        assert_eq!(chain.1.borrow().len(), 1);
    }

    #[test]
    fn an_intent_that_does_not_match_is_refused_before_any_prompt() {
        let f = fixture();
        let mut sim = Simulator::new();
        let spends = pay(&mut sim, &f.who, 1000, 700, 10);
        let bob = hex::encode(BlsPair::new(2).puzzle_hash);
        let mallory = hex::encode(BlsPair::new(9).puzzle_hash);
        for intent in [
            // Wrong amount.
            json!({ "recipients": [{ "puzzleHash": bob, "amount": "70" }] }),
            // Wrong recipient.
            json!({ "recipients": [{ "puzzleHash": mallory, "amount": "700" }] }),
            // A payment not declared at all.
            json!({ "recipients": [] }),
            // Wrong fee, wrong net.
            json!({ "fee": "1" }),
            json!({ "netChange": [{ "amount": "-10" }] }),
        ] {
            let (out, prompts, chain) =
                f.submit(sim.clone(), &with_intent(&spends, intent.clone()), true);
            let error = out.unwrap_err();
            assert_eq!(error.code, codes::UNAUTHORIZED, "{intent}");
            assert!(error.data.unwrap().contains("intent_mismatch"));
            assert!(prompts.is_empty(), "never shown: {intent}");
            assert!(chain.1.borrow().is_empty());
        }
        // Free text cannot pose as a kind.
        let (out, _, _) = f.submit(
            sim,
            &with_intent(
                &spends,
                json!({ "kind": "Send 0.1 XCH (verified by Chia)" }),
            ),
            true,
        );
        assert!(out.unwrap_err().data.unwrap().contains("invalid_intent"));
    }

    #[test]
    fn nothing_is_signed_or_broadcast_without_approval() {
        let f = fixture();
        let mut sim = Simulator::new();
        let spends = pay(&mut sim, &f.who, 1000, 700, 10);
        let (out, prompts, chain) = f.submit(sim, &params(&spends, false), false);
        assert_eq!(out.unwrap_err().code, codes::USER_REJECTED);
        assert_eq!(prompts.len(), 1);
        assert_eq!(f.signer.1.get(), 0);
        assert!(chain.1.borrow().is_empty());
        assert!(f.limits.0.borrow().spent.is_empty());
    }

    #[test]
    fn a_bundle_the_chain_refuses_is_reported_and_not_counted() {
        let f = fixture();
        let mut sim = Simulator::new();
        let spends = pay(&mut sim, &f.who, 1000, 700, 10);
        // Spend the coin first: the wallet's broadcast is now a double spend.
        let chain_first = Chain(RefCell::new(sim), RefCell::default());
        let (first, _, chain) = {
            let ui = Ui(true, RefCell::default());
            let out = handle_with_host(
                SUBMIT_COIN_SPENDS,
                &params(&spends, false),
                &f.ctx(),
                &Host {
                    signer: &f.signer,
                    approver: &ui,
                    broadcaster: Some(&chain_first),
                },
            );
            (out, (), chain_first)
        };
        first.unwrap();
        let spent_once = f.limits.0.borrow().spent.get(&AssetId::Xch).copied();
        let ui = Ui(true, RefCell::default());
        let again = handle_with_host(
            SUBMIT_COIN_SPENDS,
            &params(&spends, false),
            &f.ctx(),
            &Host {
                signer: &f.signer,
                approver: &ui,
                broadcaster: Some(&chain),
            },
        );
        let error = again.unwrap_err();
        assert!(error.data.unwrap().contains("broadcast_failed"));
        assert_eq!(
            f.limits.0.borrow().spent.get(&AssetId::Xch).copied(),
            spent_once,
            "a refused broadcast does not count towards the limit"
        );
    }

    #[test]
    fn without_a_broadcaster_the_method_is_not_offered() {
        let f = fixture();
        let spends = send(&mut Simulator::new(), &f.who, 500);
        let (out, prompts) = f.call(SUBMIT_COIN_SPENDS, &params(&spends, false), true);
        assert_eq!(out.unwrap_err().code, codes::METHOD_NOT_FOUND);
        assert!(prompts.is_empty());
    }

    #[test]
    fn another_partys_key_needs_their_signature_to_be_submitted() {
        // A spend that also needs Bob's signature: without it nothing is signed or sent.
        let f = fixture();
        let mut sim = Simulator::new();
        let mut spends = pay(&mut sim, &f.who, 1000, 700, 10);
        let bob = BlsPair::new(2);
        let c = sim.new_coin(bob.puzzle_hash, 50);
        let mut sc = SpendContext::new();
        StandardLayer::new(bob.pk)
            .spend(&mut sc, c, Conditions::new())
            .unwrap();
        spends.extend(sc.take());
        let (out, prompts, chain) = f.submit(sim, &params(&spends, false), true);
        assert_eq!(out.unwrap_err().code, codes::NO_SECRET_KEY);
        assert!(prompts.is_empty());
        assert!(chain.1.borrow().is_empty());
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

    // --- option contracts (spec 11.1.1) ---

    use crate::option_fixture::{self as opt, MintSpec};

    /// An option expiry well after the handler tests' clock (`now: 1_790_000_000`).
    const LATER: u64 = 1_900_000_000;

    fn prompt_json(prompts: &[String]) -> Value {
        serde_json::from_str(&prompts[0]).unwrap()
    }

    #[test]
    fn an_option_mint_is_shown_verified_and_broadcast() {
        let f = fixture();
        let mut sim = Simulator::new();
        // An expiry after the wallet's clock (`now`) and its margin: a mint kind holds only
        // for an option that does not expire within an hour.
        let spec = MintSpec {
            seconds: LATER,
            ..MintSpec::simple(&f.who)
        };
        let m = opt::mint(&mut sim, &f.who, spec);
        // Every payment to others is declared: none, the collateral is a lock.
        let intent = json!({ "kind": "option.mint", "recipients": [], "fee": "7" });
        let (out, prompts, chain) = f.submit(sim, &with_intent(&m.spends, intent), true);
        out.unwrap();
        assert_eq!(chain.1.borrow().len(), 1, "the chain accepted the mint");
        let p = prompt_json(&prompts);
        assert_eq!(p["summary"]["options"][0]["action"], "mint");
        assert_eq!(p["summary"]["options"][0]["guaranteed"], true);
        assert_eq!(p["summary"]["unknown_puzzles"].as_array().unwrap().len(), 0);
        assert_eq!(p["intent"]["kind_verified"], true);
        assert_eq!(p["intent"]["recipients_complete"], true);
        // The locked collateral counts against the XCH limit.
        assert_eq!(f.limits.0.borrow().spent.get(&AssetId::Xch), Some(&1008));
    }

    #[test]
    fn a_declared_option_kind_that_does_not_hold_is_refused() {
        let f = fixture();
        let mut sim = Simulator::new();
        let bob = BlsPair::new(2);
        // A loan request: Bob is the creator (lender), the user holds the option.
        let spec = MintSpec {
            creator: bob.puzzle_hash,
            ..MintSpec::simple(&f.who)
        };
        // Expired by the wallet's clock: Bob could take the collateral as soon as it lands.
        // Refused whatever the dApp declares (re-audit N5).
        let expired = opt::mint(&mut sim, &f.who, spec);
        let (out, prompts) = f.call("signCoinSpends", &params(&expired.spends, false), true);
        assert_eq!(
            out.unwrap_err().data.as_deref(),
            Some(r#"{"reason":"option_expires"}"#)
        );
        assert!(prompts.is_empty());
        for intent in [json!({ "kind": "loan.request" }), json!({ "kind": "swap" })] {
            let (out, prompts, _) =
                f.submit(sim.clone(), &with_intent(&expired.spends, intent), true);
            assert_eq!(
                out.unwrap_err().data.as_deref(),
                Some(r#"{"reason":"option_expires"}"#)
            );
            assert!(prompts.is_empty());
        }
        let spec = MintSpec {
            seconds: LATER,
            ..spec
        };
        let m = opt::mint(&mut sim, &f.who, spec);
        for kind in ["option.mint", "option.exercise", "loan.take"] {
            let (out, prompts, _) = f.submit(
                sim.clone(),
                &with_intent(&m.spends, json!({ "kind": kind })),
                true,
            );
            assert!(
                out.unwrap_err().data.unwrap().contains("intent_mismatch"),
                "{kind}"
            );
            assert!(prompts.is_empty());
        }
        let (out, prompts, _) = f.submit(
            sim.clone(),
            &with_intent(&m.spends, json!({ "kind": "loan.request" })),
            true,
        );
        out.unwrap();
        assert_eq!(prompt_json(&prompts)["intent"]["kind_verified"], true);
        // Any other kind stays a description, not a verified claim.
        let (out, prompts, _) = f.submit(
            sim,
            &with_intent(&m.spends, json!({ "kind": "option.buy" })),
            true,
        );
        out.unwrap();
        assert_eq!(prompt_json(&prompts)["intent"]["kind_verified"], false);
    }

    #[test]
    fn an_exercise_is_signed_only_when_the_collateral_claim_is_bound() {
        let f = fixture();
        let mut sim = Simulator::new();
        let m = opt::minted(&mut sim, &f.who, MintSpec::simple(&f.who));
        // Unbound: anyone could claim the released collateral; refused before any prompt.
        let loose = opt::exercise(&mut sim, &f.who, &m, false, true);
        let (out, prompts, chain) = f.submit(sim.clone(), &params(&loose, false), true);
        assert_eq!(
            out.unwrap_err().data.as_deref(),
            Some(r#"{"reason":"unbound_exercise"}"#)
        );
        assert!(prompts.is_empty() && chain.1.borrow().is_empty());
        let (out, prompts) = f.call("signCoinSpends", &params(&loose, false), true);
        assert_eq!(
            out.unwrap_err().data.as_deref(),
            Some(r#"{"reason":"unbound_exercise"}"#)
        );
        assert!(prompts.is_empty());
        // Bound: shown with the binding report, signed, accepted by the chain.
        let bound = opt::exercise(&mut sim, &f.who, &m, true, true);
        let intent = json!({ "kind": "option.exercise" });
        let (out, prompts, chain) = f.submit(sim, &with_intent(&bound, intent), true);
        out.unwrap();
        assert_eq!(chain.1.borrow().len(), 1);
        let p = prompt_json(&prompts);
        assert_eq!(p["summary"]["options"][0]["action"], "exercise");
        assert_eq!(p["binding"]["all_bound"], true);
        assert_eq!(p["binding"]["bound_received"][0]["amount"], 1000);
        assert_eq!(p["intent"]["kind_verified"], true);
    }

    /// Spends of a new coin of `who`, through each delegated puzzle that is not a quoted
    /// program, all making the same conditions: everything back to the user.
    fn unquoted_spends(sim: &mut Simulator, who: &BlsPair) -> Vec<(&'static str, Vec<CoinSpend>)> {
        let mut sc = SpendContext::new();
        let conds = Conditions::new()
            .create_coin(who.puzzle_hash, 600, Memos::None)
            .create_coin(who.puzzle_hash, 400, Memos::None);
        crate::swap_fixture::non_quote_delegations(&mut sc, &conds)
            .into_iter()
            .map(|(name, delegated, solution)| {
                let coin = sim.new_coin(who.puzzle_hash, 1000);
                let spend = crate::swap_fixture::delegated_spend(
                    &mut sc, coin, who.pk, delegated, solution,
                );
                (name, vec![spend])
            })
            .collect()
    }

    fn assert_unsigned_conditions(out: Result<String, RpcError>, name: &str) {
        let err = out.expect_err(name);
        assert_eq!(
            (err.code, err.data.as_deref()),
            (
                codes::UNAUTHORIZED,
                Some(r#"{"reason":"unsigned_conditions"}"#)
            ),
            "{name}"
        );
    }

    #[test]
    fn a_standard_spend_whose_delegated_puzzle_is_not_quoted_is_never_signed() {
        let mut sim = Simulator::new();
        let who = fixture().who;
        let variants = unquoted_spends(&mut sim, &who);
        assert_eq!(variants.len(), 5);
        for (name, spends) in variants {
            // The simulation runs: the request is well formed and shows no loss.
            let s = crate::simulate::simulate(&spends, &owned(who.puzzle_hash), DEFAULT_MAX_COST)
                .expect(name);
            assert_eq!(s.asset(AssetId::Xch).unwrap().net, 0, "{name}");
            for partial in [false, true] {
                let f = fixture();
                let (out, prompts) = f.call("signCoinSpends", &params(&spends, partial), true);
                assert_unsigned_conditions(out, name);
                assert!(prompts.is_empty(), "{name}: never prompted");
                assert_eq!(f.signer.1.get(), 0, "{name}: signer never called");
            }
            let f = fixture();
            let (out, prompts, chain) = f.submit(sim.clone(), &params(&spends, false), true);
            assert_unsigned_conditions(out, name);
            assert!(prompts.is_empty(), "{name}: never prompted");
            assert_eq!(f.signer.1.get(), 0, "{name}: signer never called");
            assert!(chain.1.borrow().is_empty(), "{name}: nothing broadcast");
        }
    }

    #[test]
    fn a_second_signature_by_the_spends_own_key_is_never_signed() {
        // A quoted delegated puzzle whose conditions also ask the coin's key to sign the hash
        // of another delegated puzzle, revealed in the (ignored) delegated solution.
        let f = fixture();
        let mut sim = Simulator::new();
        let coin = sim.new_coin(f.who.puzzle_hash, 1000);
        let mut sc = SpendContext::new();
        let other = Conditions::new().create_coin(f.who.puzzle_hash, 1000, Memos::None);
        let other = sc.alloc(&clvm_traits::clvm_quote!(other)).unwrap();
        let other_hash: Bytes32 = sc.tree_hash(other).into();
        let conds = Conditions::new()
            .create_coin(f.who.puzzle_hash, 1000, Memos::None)
            .agg_sig_me(f.who.pk, other_hash.to_vec().into());
        let delegated = sc.alloc(&clvm_traits::clvm_quote!(conds)).unwrap();
        let revealed = sc.alloc(&(other, ())).unwrap();
        let spend =
            crate::swap_fixture::delegated_spend(&mut sc, coin, f.who.pk, delegated, revealed);
        let (out, _) = f.call("signCoinSpends", &params(&[spend], false), true);
        assert_unsigned_conditions(out, "second signature");
        assert_eq!(f.signer.1.get(), 0);
    }

    #[test]
    fn a_cat_whose_inner_delegated_puzzle_is_not_quoted_is_never_signed() {
        use chia_sdk_driver::{Cat, CatSpend, Layer, Spend};
        let f = fixture();
        let mut sim = Simulator::new();
        let cat = crate::option_fixture::issue_cat(&mut sim, &f.who, 1000);
        let build = |quoted: bool| {
            let mut sc = SpendContext::new();
            let hint = sc.hint(f.who.puzzle_hash).unwrap();
            let conds = Conditions::new().create_coin(f.who.puzzle_hash, 1000, hint);
            let (delegated, solution) = if quoted {
                let q = sc.alloc(&clvm_traits::clvm_quote!(conds)).unwrap();
                (q, clvmr::NodePtr::NIL)
            } else {
                (sc.alloc(&1u8).unwrap(), sc.alloc(&conds).unwrap())
            };
            let layer = StandardLayer::new(f.who.pk);
            let puzzle = layer.construct_puzzle(&mut sc).unwrap();
            let solution = layer
                .construct_solution(
                    &mut sc,
                    chia_puzzle_types::standard::StandardSolution {
                        original_public_key: None,
                        delegated_puzzle: delegated,
                        solution,
                    },
                )
                .unwrap();
            Cat::spend_all(&mut sc, &[CatSpend::new(cat, Spend::new(puzzle, solution))]).unwrap();
            sc.take()
        };
        let (out, _) = f.call("signCoinSpends", &params(&build(false), false), true);
        assert_unsigned_conditions(out, "CAT inner puzzle");
        assert_eq!(f.signer.1.get(), 0);
        let honest = build(true);
        let (out, _) = f.call("signCoinSpends", &params(&honest, false), true);
        sim.new_transaction(SpendBundle::new(honest, sig(&out.unwrap())))
            .unwrap();
    }
}
