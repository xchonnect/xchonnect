//! Wallet-side signing safety (`xchonnect-wallet-kit`) for Swift and Kotlin.
//!
//! The host implements three foreign interfaces: [`WalletSigner`] (keys in the Secure
//! Enclave / StrongBox, biometric-gated), [`WalletApprover`] (the approval UI) and
//! [`LimitStorage`] (daily totals per dApp). [`handle_wallet_request`] then runs the full
//! CHIP-0002 pipeline: simulation, signature policy, permissions and limits, approval of
//! the exact effect, signing.

use crate::XchonnectError;
use crate::session::RpcOutcome;
use chia_bls::{PublicKey, Signature};
use chia_protocol::Bytes32;
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use xchonnect_wallet_kit::permissions::{
    AssetLimit, DailySpend, DappPermissions, LimitStore, PermissionError,
};
use xchonnect_wallet_kit::{AssetId, Network, Ownership, Prompt, RequestContext, handle};

/// Signs with wallet keys held by the platform. Return `None` if the user cancelled or
/// the key is unavailable.
#[uniffi::export(with_foreign)]
pub trait WalletSigner: Send + Sync {
    /// BLS augmented-scheme signature (96 bytes) of `message` with the key `public_key`
    /// (48-byte G1, hex without 0x).
    fn sign(&self, public_key: String, message: Vec<u8>) -> Option<Vec<u8>>;
}

/// Approval UI. `prompt_json` describes exactly what will be signed (see
/// `xchonnect_wallet_kit::Prompt`); return `true` only on explicit approval.
#[uniffi::export(with_foreign)]
pub trait WalletApprover: Send + Sync {
    /// Show the prompt and return the user's decision.
    fn approve(&self, prompt_json: String) -> bool;
}

/// Storage for one dApp's daily spending totals (opaque JSON).
#[uniffi::export(with_foreign)]
pub trait LimitStorage: Send + Sync {
    /// Stored JSON, or `None` if nothing was stored yet.
    fn load(&self) -> Option<String>;
    /// Persist the JSON; return `false` on failure (the request is then refused).
    fn save(&self, json: String) -> bool;
}

/// Everything the wallet knows about the session for one request.
#[derive(Debug, Clone, uniffi::Record)]
pub struct WalletRequestContext {
    /// Verified dApp domain.
    pub dapp: String,
    /// Wallet network: `"mainnet"` or `"testnet11"`.
    pub network: String,
    /// Chain the session was approved for.
    pub session_chain_id: String,
    /// Allowed CHIP-0002 methods.
    pub methods: Vec<String>,
    /// Keys exposed to this dApp (hex G1).
    pub exposed_keys: Vec<String>,
    /// XCH limit per request in mojos (decimal), if any.
    pub xch_per_request: Option<String>,
    /// XCH limit per UTC day in mojos (decimal), if any.
    pub xch_per_day: Option<String>,
    /// The user enabled AGG_SIG_UNSAFE for this dApp.
    pub allow_agg_sig_unsafe: bool,
    /// The user allows unknown contracts.
    pub allow_unknown_contracts: bool,
    /// Puzzle hashes the wallet owns (hex).
    pub owned_puzzle_hashes: Vec<String>,
    /// Public keys the wallet can sign with (hex G1).
    pub keys: Vec<String>,
    /// Current unix time.
    pub now: u64,
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).ok()
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    unhex(s)?.try_into().ok()
}

fn pk(s: &str) -> crate::Result<PublicKey> {
    unhex(s)
        .and_then(|b| <[u8; 48]>::try_from(b).ok())
        .and_then(|b| PublicKey::from_bytes(&b).ok())
        .ok_or_else(|| XchonnectError::input("public key"))
}

fn amount(s: Option<&String>) -> crate::Result<Option<u128>> {
    s.map(|v| v.parse().map_err(|_| XchonnectError::input("limit")))
        .transpose()
}

struct SignerAdapter(Arc<dyn WalletSigner>);
impl xchonnect_wallet_kit::Signer for SignerAdapter {
    fn sign(
        &self,
        public_key: &PublicKey,
        message: &[u8],
    ) -> Result<Signature, xchonnect_wallet_kit::SignerError> {
        let bytes = self
            .0
            .sign(hex::encode(public_key.to_bytes()), message.to_vec())
            .ok_or(xchonnect_wallet_kit::SignerError::Cancelled)?;
        let arr: [u8; 96] = bytes
            .try_into()
            .map_err(|_| xchonnect_wallet_kit::SignerError::KeyUnavailable)?;
        let sig = Signature::from_bytes(&arr)
            .map_err(|_| xchonnect_wallet_kit::SignerError::KeyUnavailable)?;
        // Never trust the platform blindly: the signature must verify for this key.
        if !chia_bls::verify(&sig, public_key, message) {
            return Err(xchonnect_wallet_kit::SignerError::KeyUnavailable);
        }
        Ok(sig)
    }
}

struct ApproverAdapter(Arc<dyn WalletApprover>);
impl xchonnect_wallet_kit::Approver for ApproverAdapter {
    fn approve(&self, prompt: &Prompt<'_>) -> bool {
        serde_json::to_string(prompt).is_ok_and(|json| self.0.approve(json))
    }
}

struct StoreAdapter(Arc<dyn LimitStorage>);
impl LimitStore for StoreAdapter {
    fn load(&self) -> Result<DailySpend, PermissionError> {
        let Some(json) = self.0.load() else {
            return Ok(DailySpend::default());
        };
        let v: serde_json::Value =
            serde_json::from_str(&json).map_err(|_| PermissionError::Storage)?;
        let mut spent = BTreeMap::new();
        for (k, amount) in v
            .get("spent")
            .and_then(|s| s.as_object())
            .ok_or(PermissionError::Storage)?
        {
            let asset = if k == "xch" {
                AssetId::Xch
            } else {
                let id = k.strip_prefix("cat:").and_then(hex32);
                AssetId::Cat(Bytes32::from(id.ok_or(PermissionError::Storage)?))
            };
            spent.insert(
                asset,
                amount
                    .as_str()
                    .and_then(|a| a.parse().ok())
                    .ok_or(PermissionError::Storage)?,
            );
        }
        Ok(DailySpend {
            day: v
                .get("day")
                .and_then(serde_json::Value::as_u64)
                .ok_or(PermissionError::Storage)?,
            spent,
        })
    }

    fn save(&self, record: &DailySpend) -> Result<(), PermissionError> {
        let spent: serde_json::Map<String, serde_json::Value> = record
            .spent
            .iter()
            .map(|(a, v)| {
                let k = match a {
                    AssetId::Xch => "xch".to_owned(),
                    AssetId::Cat(id) => format!("cat:{}", hex::encode(id)),
                };
                (k, serde_json::Value::String(v.to_string()))
            })
            .collect();
        let json = serde_json::json!({ "day": record.day, "spent": spent }).to_string();
        self.0
            .save(json)
            .then_some(())
            .ok_or(PermissionError::Storage)
    }
}

/// Run a CHIP-0002 request through the wallet-kit pipeline. The returned outcome goes
/// straight into `Session::respond` / `Session::respond_error`.
#[uniffi::export]
pub fn handle_wallet_request(
    method: String,
    params_json: String,
    context: WalletRequestContext,
    signer: Arc<dyn WalletSigner>,
    approver: Arc<dyn WalletApprover>,
    limits: Arc<dyn LimitStorage>,
) -> crate::Result<RpcOutcome> {
    let network = match context.network.as_str() {
        "mainnet" => Network::Mainnet,
        "testnet11" => Network::Testnet11,
        _ => return Err(XchonnectError::input("network")),
    };
    let mut permissions = DappPermissions::new_default(
        pk(context.exposed_keys.first().map_or("", String::as_str)).unwrap_or_default(),
    );
    permissions.methods = context.methods.clone();
    permissions.exposed_keys = context
        .exposed_keys
        .iter()
        .map(|k| pk(k))
        .collect::<crate::Result<_>>()?;
    let (per_request, per_day) = (
        amount(context.xch_per_request.as_ref())?,
        amount(context.xch_per_day.as_ref())?,
    );
    if per_request.is_some() || per_day.is_some() {
        permissions.limits.insert(
            AssetId::Xch,
            AssetLimit {
                per_request,
                per_day,
            },
        );
    }
    let ownership = Ownership {
        p2_puzzle_hashes: context
            .owned_puzzle_hashes
            .iter()
            .map(|h| {
                hex32(h)
                    .map(Bytes32::from)
                    .ok_or_else(|| XchonnectError::input("puzzle hash"))
            })
            .collect::<crate::Result<_>>()?,
    };
    let keys: HashSet<PublicKey> = context
        .keys
        .iter()
        .map(|k| pk(k))
        .collect::<crate::Result<_>>()?;
    let store = StoreAdapter(limits);
    let ctx = RequestContext {
        dapp: &context.dapp,
        network,
        session_chain_id: &context.session_chain_id,
        permissions: &permissions,
        allow_agg_sig_unsafe: context.allow_agg_sig_unsafe,
        allow_unknown_contracts: context.allow_unknown_contracts,
        ownership: &ownership,
        keys: &keys,
        limits: &store,
        now: context.now,
    };
    Ok(
        match handle(
            &method,
            &params_json,
            &ctx,
            &SignerAdapter(signer),
            &ApproverAdapter(approver),
        ) {
            Ok(result_json) => RpcOutcome::Success { result_json },
            Err(e) => RpcOutcome::Failure {
                code: e.code,
                message: e.message,
                data_json: e.data,
            },
        },
    )
}
