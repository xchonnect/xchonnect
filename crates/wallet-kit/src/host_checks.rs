//! Checks a wallet host runs against its own storage and request processing (spec 11.2,
//! "Host obligations").
//!
//! The kit cannot see how a host keeps [`SignedCoins`] or whether it runs two signing
//! requests at once, and a dApp cannot reach a sealed request (only the wallet builds one),
//! so the wallet conformance suite cannot check these through the wallet's interface. A
//! host implements [`HostRecord`] over its real storage and [`RequestGate`] over its real
//! request lock, and calls [`check_sealed_record`] and [`check_one_at_a_time`] from its own
//! tests. Both use a test key and made-up coins; nothing is broadcast.
//!
//! - [`check_sealed_record`]: what [`Broadcaster::record`] reports is stored durably before
//!   the bundle is handed to the network; a sealed signature is refused afterwards in a
//!   fresh request built from the host's storage (`sealed_signature`); it stays refused
//!   until every coin the wallet signed for in its bundle is spent (pruning is per bundle);
//!   and a storage failure stops the broadcast (`record_failed`).
//! - [`check_one_at_a_time`]: two requests run through the host's gate never overlap.

use crate::handlers::{
    Approver, Broadcast, BroadcastRecord, Broadcaster, Prompt, RequestContext, RpcError,
    SUBMIT_COIN_SPENDS, SignedCoins, Signer, SignerError, SubmitRequest, handle, submit,
};
use crate::permissions::{DailySpend, DappPermissions, LimitStore, PermissionError};
use crate::policy::Network;
use crate::simulate::Ownership;
use chia_bls::{PublicKey, SecretKey, Signature};
use chia_protocol::{Bytes32, Coin, CoinSpend, SpendBundle};
use chia_puzzle_types::Memos;
use chia_puzzle_types::standard::StandardArgs;
use chia_sdk_driver::{SpendContext, StandardLayer};
use chia_sdk_types::Conditions;
use serde_json::Value;
use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// The host's record of signatures that left the wallet ([`SignedCoins`]), as the host keeps
/// it: the same storage and code paths its wallet uses.
pub trait HostRecord {
    /// The record as the host loads it for a new request.
    fn load(&self) -> Result<SignedCoins, String>;
    /// What the host's [`Broadcaster::record`] does: store `record` durably
    /// ([`SignedCoins::add`]); an error if it could not.
    fn record(&self, record: &BroadcastRecord) -> Result<(), String>;
    /// What the host does when its own verified sync holds `coin_id` spent at its reorg-safe
    /// depth ([`SignedCoins::spent`]). A host that never prunes does nothing here.
    fn spent(&self, coin_id: Bytes32) -> Result<(), String>;
    /// Make the host's storage fail (`true`) or work again (`false`), if the host can
    /// simulate that; `false` when it cannot (that part of the check is then skipped).
    fn set_failing(&self, failing: bool) -> bool;
}

/// The host's way of running one signing request at a time (spec 11.2).
pub trait RequestGate: Sync {
    /// Run `request` the way the host runs one signing request: holding whatever keeps any
    /// other signing request of the wallet from running until it returns.
    fn exclusive(&self, request: &mut dyn FnMut());
}

/// What a failed check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCheckFailure(pub String);

impl core::fmt::Display for HostCheckFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for HostCheckFailure {}

fn fail<T>(what: impl Into<String>) -> Result<T, HostCheckFailure> {
    Err(HostCheckFailure(what.into()))
}

/// The test wallet: one key, its standard puzzle hash.
struct Wallet {
    sk: SecretKey,
    pk: PublicKey,
    puzzle_hash: Bytes32,
}

impl Wallet {
    fn new() -> Self {
        let sk = SecretKey::from_seed(b"xchonnect wallet-kit host checks, not a real wallet");
        let pk = sk.public_key();
        let puzzle_hash = Bytes32::from(StandardArgs::curry_tree_hash(pk));
        Wallet {
            sk,
            pk,
            puzzle_hash,
        }
    }

    fn coin(&self, n: u8) -> Coin {
        Coin::new(Bytes32::new([n; 32]), self.puzzle_hash, 1000 + u64::from(n))
    }

    /// Two of the wallet's coins spent together, each requiring the other: what a wallet
    /// builds for one payment from two coins, read as sealed.
    fn pair(&self, a: Coin, b: Coin) -> Result<Vec<CoinSpend>, HostCheckFailure> {
        let mut ctx = SpendContext::new();
        let layer = StandardLayer::new(self.pk);
        let to_self = a.amount + b.amount;
        let first = Conditions::new()
            .create_coin(self.puzzle_hash, to_self, Memos::None)
            .assert_concurrent_spend(b.coin_id());
        let second = Conditions::new().assert_concurrent_spend(a.coin_id());
        layer
            .spend(&mut ctx, a, first)
            .and_then(|()| layer.spend(&mut ctx, b, second))
            .or_else(|e| fail(format!("building the test spends: {e}")))?;
        Ok(ctx.take())
    }
}

struct KeySigner<'a>(&'a SecretKey);
impl Signer for KeySigner<'_> {
    fn sign(&self, _pk: &PublicKey, message: &[u8]) -> Result<Signature, SignerError> {
        Ok(chia_bls::sign(self.0, message))
    }
}

struct Yes;
impl Approver for Yes {
    fn approve(&self, _prompt: &Prompt<'_>) -> bool {
        true
    }
}

struct NoLimits(RefCell<DailySpend>);
impl LimitStore for NoLimits {
    fn load(&self) -> Result<DailySpend, PermissionError> {
        Ok(self.0.borrow().clone())
    }
    fn save(&self, record: &DailySpend) -> Result<(), PermissionError> {
        *self.0.borrow_mut() = record.clone();
        Ok(())
    }
}

/// Records through the host and, at broadcast, checks that the host already holds the
/// record: the bundle never leaves before its signatures are stored.
struct TestNetwork<'a> {
    host: &'a dyn HostRecord,
    submitted: Cell<usize>,
    stored_first: Cell<bool>,
    last: RefCell<Option<BroadcastRecord>>,
}

impl Broadcaster for TestNetwork<'_> {
    fn record(&self, record: &BroadcastRecord) -> Result<(), String> {
        self.host.record(record)?;
        *self.last.borrow_mut() = Some(record.clone());
        Ok(())
    }

    fn submit(&self, bundle: &SpendBundle) -> Result<Broadcast, String> {
        self.submitted.set(self.submitted.get() + 1);
        let stored = self.host.load().is_ok_and(|kept| {
            let last = self.last.borrow();
            last.as_ref().is_some_and(|r| {
                r.coins.iter().all(|c| kept.released.contains(c))
                    && r.sealed
                        .as_ref()
                        .is_none_or(|s| s.digests.iter().all(|d| kept.sealed.contains_key(d)))
            })
        });
        self.stored_first.set(stored);
        Ok(Broadcast {
            transaction_id: format!("0x{}", hex::encode(bundle.name())),
            status: "not_sent".to_owned(),
        })
    }
}

struct Run<'a> {
    wallet: &'a Wallet,
    perms: DappPermissions,
    own: Ownership,
    keys: HashSet<PublicKey>,
    limits: NoLimits,
}

impl<'a> Run<'a> {
    fn new(wallet: &'a Wallet) -> Self {
        Run {
            wallet,
            perms: DappPermissions::new_default(wallet.pk),
            own: Ownership {
                p2_puzzle_hashes: [wallet.puzzle_hash].into_iter().collect(),
            },
            keys: [wallet.pk].into_iter().collect(),
            limits: NoLimits(RefCell::default()),
        }
    }

    fn ctx<'b>(&'b self, signed: &'b SignedCoins) -> RequestContext<'b> {
        RequestContext {
            dapp: "host-checks.invalid",
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
            signed_coins: signed,
        }
    }

    /// A wallet-built, sealed request, through the host's record. The prompt's linking, or
    /// the error.
    fn sealed(
        &self,
        host: &dyn HostRecord,
        spends: Vec<CoinSpend>,
        network: &TestNetwork<'_>,
    ) -> Result<(), RpcError> {
        let signed = host.load().map_err(|e| RpcError {
            code: 0,
            message: e,
            data: None,
        })?;
        submit(
            SubmitRequest {
                method: SUBMIT_COIN_SPENDS,
                spends,
                other_signature: None,
                intent: None,
                wallet_built: true,
                wallet_fee: 0,
                signatures_released: false,
            },
            &self.ctx(&signed),
            &KeySigner(&self.wallet.sk),
            &Yes,
            network,
        )
        .map(|_| ())
    }

    /// `signCoinSpends` of `spends` against the host's record.
    fn sign(&self, host: &dyn HostRecord, spends: &[CoinSpend]) -> Result<String, RpcError> {
        let signed = host.load().map_err(|e| RpcError {
            code: 0,
            message: e,
            data: None,
        })?;
        handle(
            "signCoinSpends",
            &params(spends),
            &self.ctx(&signed),
            &KeySigner(&self.wallet.sk),
            &Yes,
        )
    }
}

fn params(spends: &[CoinSpend]) -> String {
    let list: Vec<Value> = spends
        .iter()
        .map(|cs| {
            serde_json::json!({
                "coin": {
                    "parent_coin_info": format!("0x{}", hex::encode(cs.coin.parent_coin_info)),
                    "puzzle_hash": format!("0x{}", hex::encode(cs.coin.puzzle_hash)),
                    "amount": cs.coin.amount,
                },
                "puzzle_reveal": format!("0x{}", hex::encode(cs.puzzle_reveal.as_ref())),
                "solution": format!("0x{}", hex::encode(cs.solution.as_ref())),
            })
        })
        .collect();
    serde_json::json!({ "coinSpends": list }).to_string()
}

fn reason(e: &RpcError) -> String {
    e.data.clone().unwrap_or_default()
}

/// Check the host's [`SignedCoins`] storage against the sealed rules of spec 11.2. Run it
/// on an empty record (a fresh test store).
pub fn check_sealed_record(host: &dyn HostRecord) -> Result<(), HostCheckFailure> {
    let wallet = Wallet::new();
    let run = Run::new(&wallet);
    let (a, b) = (wallet.coin(1), wallet.coin(2));
    let bundle = wallet.pair(a, b)?;
    let network = |host| TestNetwork {
        host,
        submitted: Cell::new(0),
        stored_first: Cell::new(false),
        last: RefCell::new(None),
    };

    // 1. A sealed bundle: recorded before it is handed to the network.
    let first = network(host);
    if let Err(e) = run.sealed(host, bundle.clone(), &first) {
        return fail(format!("the sealed test bundle was refused: {e:?}"));
    }
    if first.submitted.get() != 1 {
        return fail("the sealed test bundle was not handed to the network");
    }
    if !first.stored_first.get() {
        return fail("the bundle reached the network before the host stored its record");
    }
    if first
        .last
        .borrow()
        .as_ref()
        .is_none_or(|r| r.sealed.is_none())
    {
        return fail("the test bundle was not read as sealed");
    }

    // 2. A fresh request from the host's storage: the same messages are never signed again.
    for (what, spends) in [
        ("the same bundle", bundle.clone()),
        (
            "one of its spends",
            bundle.iter().take(1).cloned().collect(),
        ),
    ] {
        let again = network(host);
        let out = run.sealed(host, spends.clone(), &again);
        if !out
            .as_ref()
            .is_err_and(|e| reason(e).contains("sealed_signature"))
        {
            return fail(format!(
                "{what} was signed again in a sealed request after a reload: {out:?}"
            ));
        }
        let out = run.sign(host, &spends);
        if !out
            .as_ref()
            .is_err_and(|e| reason(e).contains("sealed_signature"))
        {
            return fail(format!(
                "{what} was signed again by signCoinSpends after a reload: {out:?}"
            ));
        }
    }

    // 3. Pruning is per bundle: one coin spent leaves every signature of the bundle refused.
    host.spent(a.coin_id())
        .or_else(|e| fail(format!("spent: {e}")))?;
    let rest: Vec<CoinSpend> = bundle.iter().skip(1).cloned().collect();
    let out = run.sign(host, &rest);
    if !out
        .as_ref()
        .is_err_and(|e| reason(e).contains("sealed_signature"))
    {
        return fail(format!(
            "a signature of the bundle was made again after only one of its coins was spent: \
             {out:?}"
        ));
    }
    host.spent(b.coin_id())
        .or_else(|e| fail(format!("spent: {e}")))?;

    // 4. Storage that fails stops the broadcast.
    if host.set_failing(true) {
        let failing = network(host);
        let out = run.sealed(host, wallet.pair(wallet.coin(3), wallet.coin(4))?, &failing);
        host.set_failing(false);
        if !out
            .as_ref()
            .is_err_and(|e| reason(e).contains("record_failed"))
        {
            return fail(format!(
                "a bundle whose record could not be stored was not refused: {out:?}"
            ));
        }
        if failing.submitted.get() != 0 {
            return fail("a bundle whose record could not be stored was handed to the network");
        }
    }
    Ok(())
}

/// Check that two signing requests run through the host's [`RequestGate`] never overlap
/// (spec 11.2): from two threads, `rounds` times each.
pub fn check_one_at_a_time(gate: &dyn RequestGate, rounds: usize) -> Result<(), HostCheckFailure> {
    let active = AtomicUsize::new(0);
    let overlap = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..2 {
            scope.spawn(|| {
                for _ in 0..rounds {
                    gate.exclusive(&mut || {
                        if active.fetch_add(1, Ordering::SeqCst) > 0 {
                            overlap.fetch_add(1, Ordering::SeqCst);
                        }
                        std::thread::sleep(Duration::from_millis(2));
                        active.fetch_sub(1, Ordering::SeqCst);
                    });
                }
            });
        }
    });
    match overlap.load(Ordering::SeqCst) {
        0 => Ok(()),
        n => fail(format!(
            "{n} signing requests ran while another was running"
        )),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A host that keeps the record in memory, as a reference.
    #[derive(Default)]
    struct Memory {
        kept: RefCell<SignedCoins>,
        failing: Cell<bool>,
        /// Forget sealed bundles (a host that does not persist them).
        forget_sealed: bool,
        /// Prune a coin's own signatures only (per coin, not per bundle).
        per_coin: bool,
    }

    impl HostRecord for Memory {
        fn load(&self) -> Result<SignedCoins, String> {
            Ok(self.kept.borrow().clone())
        }
        fn record(&self, record: &BroadcastRecord) -> Result<(), String> {
            if self.failing.get() {
                return Err("disk full".to_owned());
            }
            let mut record = record.clone();
            if self.forget_sealed {
                record.sealed = None;
            }
            if self.per_coin
                && let Some(bundle) = &mut record.sealed
            {
                // Wrong: keeps each digest only for the first coin.
                bundle.coins.truncate(1);
            }
            self.kept.borrow_mut().add(&record);
            Ok(())
        }
        fn spent(&self, coin_id: Bytes32) -> Result<(), String> {
            self.kept.borrow_mut().spent(&coin_id);
            Ok(())
        }
        fn set_failing(&self, failing: bool) -> bool {
            self.failing.set(failing);
            true
        }
    }

    #[test]
    fn a_host_that_keeps_the_record_passes() {
        let host = Memory::default();
        check_sealed_record(&host).unwrap();
        assert_eq!(*host.kept.borrow(), {
            // Both coins of the sealed bundle spent: its digests are gone; the coins of the
            // refused bundle were never recorded.
            SignedCoins::default()
        });
    }

    #[test]
    fn a_host_that_forgets_sealed_bundles_fails() {
        let host = Memory {
            forget_sealed: true,
            ..Memory::default()
        };
        let e = check_sealed_record(&host).unwrap_err();
        assert!(
            e.0.contains("before the host stored") || e.0.contains("signed again"),
            "{e}"
        );
    }

    #[test]
    fn a_host_that_prunes_per_coin_fails() {
        let host = Memory {
            per_coin: true,
            ..Memory::default()
        };
        let e = check_sealed_record(&host).unwrap_err();
        assert!(e.0.contains("only one of its coins"), "{e}");
    }

    struct Locked(Mutex<()>);
    impl RequestGate for Locked {
        fn exclusive(&self, request: &mut dyn FnMut()) {
            let _held = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            request();
        }
    }

    struct Open;
    impl RequestGate for Open {
        fn exclusive(&self, request: &mut dyn FnMut()) {
            request();
        }
    }

    #[test]
    fn requests_one_at_a_time() {
        check_one_at_a_time(&Locked(Mutex::new(())), 20).unwrap();
        assert!(check_one_at_a_time(&Open, 20).is_err());
    }
}
