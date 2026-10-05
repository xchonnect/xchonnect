//! Per-dApp permissions and spending limits (spec 9.3, 11.1 item 5).
//!
//! Limits are enforced on the **guaranteed** effect from [`crate::simulate()`]: what leaves
//! the user's coins minus what comes back through the user's own spends, plus fees the
//! user's own spends reserve. Conditional receipts (from coins the user does not sign) never
//! offset a loss.

use crate::simulate::{AssetId, Summary};
use chia_bls::PublicKey;
use core::fmt;
use std::collections::BTreeMap;
use xchonnect_core::message::{Limits, Permissions};
use xchonnect_core::rpc::canonical_method;

/// Methods a new dApp may call by default (spec 9.1 required set).
pub const DEFAULT_METHODS: [&str; 5] = [
    "chainId",
    "connect",
    "getPublicKeys",
    "signCoinSpends",
    "signMessage",
];

/// The optional CHIP-0002 methods (spec 9.1) this crate answers when the wallet supplies
/// [`crate::ChainData`]. Not granted by default: a wallet adds them to a dApp's methods.
pub const OPTIONAL_METHODS: [&str; 5] = [
    "getAssetCoins",
    "getAssetBalance",
    "filterUnlockedCoins",
    "sendTransaction",
    "walletSwitchChain",
];

/// Seconds per limit day (UTC days).
const DAY_S: u64 = 86_400;

/// Limit for one asset.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AssetLimit {
    /// Maximum guaranteed loss per request.
    pub per_request: Option<u128>,
    /// Maximum guaranteed loss per UTC day.
    pub per_day: Option<u128>,
}

/// What a dApp may do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DappPermissions {
    /// Allowed CHIP-0002 methods (bare names).
    pub methods: Vec<String>,
    /// Public keys exposed to the dApp (`getPublicKeys`).
    pub exposed_keys: Vec<PublicKey>,
    /// Limits per asset (XCH in mojos, CATs in their smallest unit).
    pub limits: BTreeMap<AssetId, AssetLimit>,
}

impl DappPermissions {
    /// Spec default: the required methods and a single fresh key; no limits configured
    /// (every request still needs explicit approval).
    pub fn new_default(fresh_key: PublicKey) -> Self {
        DappPermissions {
            methods: DEFAULT_METHODS.iter().map(|m| (*m).to_owned()).collect(),
            exposed_keys: vec![fresh_key],
            limits: BTreeMap::new(),
        }
    }

    /// Whether `method` (bare or `chip0002_`-prefixed) is allowed.
    pub fn allows_method(&self, method: &str) -> bool {
        let m = canonical_method(method);
        self.methods.iter().any(|x| x == m)
    }

    /// The `session.permissions` message for the dApp (XCH limits only on the wire).
    pub fn to_message(&self) -> Permissions {
        let xch = self.limits.get(&AssetId::Xch).copied().unwrap_or_default();
        let limits = (xch.per_request.is_some() || xch.per_day.is_some()).then(|| Limits {
            per_request_mojos: xch.per_request.map(|v| v.to_string()),
            per_day_mojos: xch.per_day.map(|v| v.to_string()),
        });
        Permissions {
            methods: self.methods.clone(),
            keys: self
                .exposed_keys
                .iter()
                .map(|k| format!("0x{}", hex::encode(k.to_bytes())))
                .collect(),
            limits,
        }
    }
}

/// Why a request exceeds the permissions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionError {
    /// Method not allowed for this dApp (CHIP-0002 4001).
    MethodNotAllowed,
    /// Per-request limit exceeded for an asset (CHIP-0002 4029).
    PerRequestLimit(AssetId),
    /// Daily limit exceeded for an asset (CHIP-0002 4029).
    DailyLimit(AssetId),
    /// The host's limit storage failed; refuse rather than sign unaccounted.
    Storage,
}

impl fmt::Display for PermissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PermissionError::MethodNotAllowed => "method not allowed for this dApp",
            PermissionError::PerRequestLimit(_) => "per-request spending limit exceeded",
            PermissionError::DailyLimit(_) => "daily spending limit exceeded",
            PermissionError::Storage => "spending limit storage unavailable",
        })
    }
}

impl std::error::Error for PermissionError {}

/// Guaranteed loss per asset for a simulated request (fees count against XCH).
pub fn guaranteed_loss(summary: &Summary) -> BTreeMap<AssetId, u128> {
    let mut out: BTreeMap<AssetId, u128> = summary
        .assets
        .iter()
        .map(|d| (d.asset, d.sent.saturating_sub(d.received)))
        .filter(|&(_, loss)| loss > 0)
        .collect();
    if summary.owned_reserve_fee > 0
        && summary
            .assets
            .iter()
            .any(|d| d.asset == AssetId::Xch && d.sent > 0)
    {
        // A fee the user's own spends reserve is part of what leaves the user's XCH coins;
        // already inside `sent - received` when the user funds it. Count it only beyond
        // that. Fees reserved by counterparty spends are not the user's loss.
        let entry = out.entry(AssetId::Xch).or_insert(0);
        *entry = (*entry).max(u128::from(summary.owned_reserve_fee));
    }
    out
}

/// Daily totals persisted by the host (per dApp).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DailySpend {
    /// UTC day number of the totals.
    pub day: u64,
    /// Committed loss per asset on that day.
    pub spent: BTreeMap<AssetId, u128>,
}

/// Host storage for daily totals (one record per dApp session).
pub trait LimitStore {
    /// Load the record (default if none).
    fn load(&self) -> Result<DailySpend, PermissionError>;
    /// Persist the record.
    fn save(&self, record: &DailySpend) -> Result<(), PermissionError>;
}

/// Check a simulated request against method permission and limits. Does not record it;
/// call [`commit_spend`] after the signature was produced and returned.
pub fn check_spend(
    perms: &DappPermissions,
    method: &str,
    summary: &Summary,
    store: &dyn LimitStore,
    now: u64,
) -> Result<BTreeMap<AssetId, u128>, PermissionError> {
    if !perms.allows_method(method) {
        return Err(PermissionError::MethodNotAllowed);
    }
    let loss = guaranteed_loss(summary);
    let record = current_day(store.load()?, now);
    for (asset, amount) in &loss {
        let Some(limit) = perms.limits.get(asset) else {
            continue;
        };
        if limit.per_request.is_some_and(|max| *amount > max) {
            return Err(PermissionError::PerRequestLimit(*asset));
        }
        let today = record.spent.get(asset).copied().unwrap_or(0);
        if limit
            .per_day
            .is_some_and(|max| today.saturating_add(*amount) > max)
        {
            return Err(PermissionError::DailyLimit(*asset));
        }
    }
    Ok(loss)
}

/// Record a signed request's loss in today's totals.
pub fn commit_spend(
    store: &dyn LimitStore,
    loss: &BTreeMap<AssetId, u128>,
    now: u64,
) -> Result<(), PermissionError> {
    let mut record = current_day(store.load()?, now);
    for (asset, amount) in loss {
        let e = record.spent.entry(*asset).or_insert(0);
        *e = e.saturating_add(*amount);
    }
    store.save(&record)
}

/// Roll the record to `now`'s day. A clock that moves backwards keeps the stored day and
/// its totals (never resets them), so changing the device clock cannot raise the limit.
fn current_day(record: DailySpend, now: u64) -> DailySpend {
    let day = now / DAY_S;
    if day > record.day {
        DailySpend {
            day,
            spent: BTreeMap::new(),
        }
    } else {
        record
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::simulate::{AssetDelta, TimeLocks};
    use crate::swap_fixture::Mem;

    fn summary(sent: u128, received: u128, conditional: u128, fee: u64) -> Summary {
        Summary {
            assets: vec![AssetDelta {
                asset: AssetId::Xch,
                sent,
                received,
                conditional_received: conditional,
                net: received as i128 - sent as i128,
            }],
            implied_fee: None,
            reserve_fee: fee,
            owned_reserve_fee: fee,
            time_locks: TimeLocks::default(),
            unknown_puzzles: vec![],
            cost: 0,
            spends: vec![],
        }
    }

    fn perms(per_request: Option<u128>, per_day: Option<u128>) -> DappPermissions {
        let mut p = DappPermissions::new_default(PublicKey::default());
        p.limits.insert(
            AssetId::Xch,
            AssetLimit {
                per_request,
                per_day,
            },
        );
        p
    }

    const NOW: u64 = 1_790_000_000;

    #[test]
    fn default_permissions_follow_the_spec() {
        let p = DappPermissions::new_default(PublicKey::default());
        assert_eq!(p.exposed_keys.len(), 1);
        assert!(p.allows_method("signCoinSpends") && p.allows_method("chip0002_getPublicKeys"));
        assert!(!p.allows_method("sendTransaction") && !p.allows_method("chia_takeOffer"));
        let store = Mem::default();
        assert_eq!(
            check_spend(&p, "chia_send", &summary(1, 0, 0, 0), &store, NOW),
            Err(PermissionError::MethodNotAllowed)
        );
    }

    #[test]
    fn per_request_limit_uses_guaranteed_loss_only() {
        let p = perms(Some(1000), None);
        let store = Mem::default();
        let check = |s: Summary| check_spend(&p, "signCoinSpends", &s, &store, NOW);
        assert!(check(summary(1500, 600, 0, 0)).is_ok(), "loss 900");
        let over = Err(PermissionError::PerRequestLimit(AssetId::Xch));
        assert_eq!(check(summary(1500, 400, 0, 0)), over);
        // A conditional receipt (unsigned counterparty coin) must not offset the loss.
        assert_eq!(check(summary(5000, 0, 5000, 0)), over);
    }

    #[test]
    fn fees_reserved_by_counterparty_spends_are_not_the_users_loss() {
        let mut s = summary(100, 100, 0, 500);
        s.owned_reserve_fee = 0;
        assert!(guaranteed_loss(&s).is_empty());
        s.owned_reserve_fee = 500;
        assert_eq!(guaranteed_loss(&s).get(&AssetId::Xch), Some(&500));
    }

    #[test]
    fn daily_limit_accumulates_and_resets_next_day_only() {
        let p = perms(None, Some(1000));
        let store = Mem::default();
        let check =
            |sent, now| check_spend(&p, "signCoinSpends", &summary(sent, 0, 0, 0), &store, now);
        let over = Err(PermissionError::DailyLimit(AssetId::Xch));
        commit_spend(&store, &check(700, NOW).unwrap(), NOW).unwrap();
        assert_eq!(check(400, NOW), over);
        // Unsigned (only checked) requests do not count.
        assert!(check(300, NOW).is_ok());
        // Clock moved back a day: totals are kept, not reset.
        assert_eq!(check(400, NOW - DAY_S), over);
        // Next day: fresh budget.
        assert!(check(900, NOW + DAY_S).is_ok());
    }

    #[test]
    fn session_permissions_message() {
        let p = perms(Some(10), Some(20));
        let m = p.to_message();
        assert_eq!(m.methods.len(), 5);
        assert_eq!(m.keys.len(), 1);
        assert!(
            m.keys[0].starts_with("0xc0"),
            "infinity key placeholder encodes as c0…"
        );
        let l = m.limits.unwrap();
        assert_eq!(
            (l.per_request_mojos.as_deref(), l.per_day_mojos.as_deref()),
            (Some("10"), Some("20"))
        );
        assert!(
            DappPermissions::new_default(PublicKey::default())
                .to_message()
                .limits
                .is_none()
        );
    }
}
