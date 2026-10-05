//! Black-box conformance suite for wallets (spec Sections 5.3, 6, 9 and 11).
//!
//! The suite plays the dApp. It publishes an origin document, shows the wallet a pairing
//! URI, and then judges the wallet only by what it does on the relay: whether it replies,
//! what it signs, and what it refuses. Nothing about the wallet's internals is assumed,
//! so the same run works against the example CLI wallet, a wallet in another repository,
//! or a phone wallet paired by hand.
//!
//! The negative checks are the point of the suite: a wallet that accepts a forged origin
//! document, answers a replayed or expired message, signs for a key it was never given,
//! ignores a spending limit or produces a partial signature for an unbound spend fails
//! here. See `conformance/README.md` for how to run it.

mod checks;
mod dapp;
mod driver;
mod origin;
mod spends;

pub use crate::report::{CheckInfo, CheckResult, Report, Status};
use crate::report::{DEFAULT_TIER, Fail};
use dapp::{Live, Pairing, Relay, UriSpec};
use driver::{Driver, Running, Variant};
use origin::{Origin, OriginServer, Served};
use spends::WalletKey;
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Checks that wait for a protocol timeout of several minutes (`--slow`).
pub(crate) const SLOW: &str = "slow";

/// Suite options.
#[derive(Debug, Clone)]
pub struct Options {
    /// Relay both sides meet on, e.g. `http://127.0.0.1:8787`.
    pub relay: String,
    /// Shell command that pairs the wallet; `{uri}` is replaced by the pairing URI.
    pub wallet: String,
    /// Command for a wallet whose user reports that the codes do not match.
    pub wallet_sas_mismatch: Option<String>,
    /// Command for a wallet whose user declines signing requests.
    pub wallet_reject: Option<String>,
    /// Pair by hand instead of running a command (phone wallets).
    pub manual: bool,
    /// Domain the suite claims. Default: `localhost:<port>` of its own origin server,
    /// which needs the wallet's developer mode.
    pub domain: Option<String>,
    /// Address the origin-document server binds, e.g. `0.0.0.0:8099` when a TLS reverse
    /// proxy in front of it serves `--domain`.
    pub listen: String,
    /// Per-request XCH spending limit (mojos) configured in the wallet for this dApp.
    /// The suite also reads it from `session.permissions` when the wallet sends it.
    pub xch_per_request_limit: Option<u128>,
    /// Seconds to wait for a pairing reply, `session.ready` or an `rpc.response`.
    pub timeout_s: u64,
    /// Seconds to wait before concluding that the wallet will *not* answer. Every
    /// negative check costs this much, so it trades run time for certainty.
    pub refusal_timeout_s: u64,
    /// Run only these check ids (case-insensitive). Empty = all.
    pub only: Vec<String>,
    /// Run checks that wait for multi-minute protocol timeouts.
    pub slow: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            relay: String::new(),
            wallet: String::new(),
            wallet_sas_mismatch: None,
            wallet_reject: None,
            manual: false,
            domain: None,
            listen: "127.0.0.1:0".to_owned(),
            xch_per_request_limit: None,
            timeout_s: 30,
            refusal_timeout_s: 8,
            only: Vec::new(),
            slow: false,
        }
    }
}

/// dApp name the suite publishes in its origin document.
const DAPP_NAME: &str = "Xchonnect Conformance";

/// What the suite learned about the wallet, shared by the signing checks.
#[derive(Debug)]
pub(crate) struct Profile {
    /// `chainId` the wallet reported.
    pub(crate) chain_id: String,
    /// First key from `getPublicKeys`, and the standard puzzle hash for it.
    pub(crate) key: WalletKey,
    /// The wallet signed the control request with exactly the expected signature.
    pub(crate) signs: bool,
    /// How the control request was answered.
    pub(crate) control: String,
}

/// Suite context: everything a check needs to put a wallet through one session.
pub(crate) struct Ctx {
    pub(crate) opts: Options,
    pub(crate) relay: Relay,
    pub(crate) origin: OriginServer,
    pub(crate) dapp: Origin,
    pub(crate) domain: String,
    pub(crate) developer_mode: bool,
    driver: Driver,
    profile: OnceLock<Result<Profile, Fail>>,
}

impl std::fmt::Debug for Ctx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ctx")
            .field("relay", &self.opts.relay)
            .field("domain", &self.domain)
            .finish_non_exhaustive()
    }
}

/// Unix seconds.
pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Ctx {
    fn new(opts: &Options) -> Result<Self, String> {
        let relay = Relay::connect(&opts.relay)?;
        let dapp = Origin::random(DAPP_NAME)?;
        let origin = OriginServer::start(&opts.listen, dapp.good())?;
        let domain = opts
            .domain
            .clone()
            .unwrap_or_else(|| format!("localhost:{}", origin.addr().port()));
        let developer_mode = xchonnect_core::uri::is_localhost_domain(&domain);
        let driver = if opts.manual {
            Driver::Manual
        } else {
            Driver::Exec {
                normal: opts.wallet.clone(),
                sas_mismatch: opts.wallet_sas_mismatch.clone(),
                reject: opts.wallet_reject.clone(),
            }
        };
        Ok(Ctx {
            opts: opts.clone(),
            relay,
            origin,
            dapp,
            domain,
            developer_mode,
            driver,
            profile: OnceLock::new(),
        })
    }

    pub(crate) fn timeout(&self) -> Duration {
        Duration::from_secs(self.opts.timeout_s)
    }

    pub(crate) fn refusal_timeout(&self) -> Duration {
        Duration::from_secs(self.opts.refusal_timeout_s)
    }

    /// Show the wallet a URI built from `spec` while `served` is the published document.
    pub(crate) fn offer(
        &self,
        variant: Variant,
        served: Served,
        spec: &UriSpecTweak,
        hint: &str,
    ) -> Result<(Pairing, Running), Fail> {
        self.origin.serve(served);
        let issued_at = now().saturating_sub(spec.issued_secs_ago);
        let pairing = Pairing::publish(
            &self.relay,
            &UriSpec {
                signer: &self.dapp.signer,
                domain: &self.domain,
                developer_mode: self.developer_mode,
                issued_at,
                lifetime_s: spec.lifetime_s,
                tamper: spec.tamper,
            },
        )?;
        let wallet = self.driver.start(variant, &pairing.uri, hint)?;
        Ok((pairing, wallet))
    }

    /// Pair and reach an active session, the way a dApp normally would.
    pub(crate) fn session(&self, variant: Variant) -> Result<(Live, Running), Fail> {
        let (mut pairing, wallet) = self.offer(
            variant,
            self.dapp.good(),
            &UriSpecTweak::default(),
            "pair with the dApp and confirm the code",
        )?;
        let accepted = pairing
            .wait_for_reply(&self.relay, now, self.timeout())?
            .ok_or_else(|| {
                Fail::Fail(format!(
                    "the wallet did not reply to a correctly signed pairing URI within {:?} \
                     (spec 6.3 step 4); wallet output: {}",
                    self.timeout(),
                    tail(&wallet.output())
                ))
            })?;
        let mut live = dapp::confirm(&self.relay, pairing, accepted, now)?;
        live.await_ready(&self.relay, &now, self.timeout())
            .map_err(|e| e.context(format!("wallet output: {}", tail(&wallet.output()))))?;
        Ok((live, wallet))
    }

    /// What the wallet reported about itself, and whether it signs at all. Computed once
    /// per run, in its own session.
    pub(crate) fn profile(&self) -> Result<&Profile, Fail> {
        self.profile
            .get_or_init(|| checks::discover(self))
            .as_ref()
            .map_err(Clone::clone)
    }
}

/// Deviations from a correct pairing URI.
#[derive(Debug, Clone, Copy)]
pub(crate) struct UriSpecTweak {
    /// Build the URI as if it had been issued this many seconds ago.
    pub(crate) issued_secs_ago: u64,
    /// URI lifetime.
    pub(crate) lifetime_s: u64,
    /// Rewrite the URI text after signing.
    pub(crate) tamper: Option<fn(&str) -> String>,
}

impl Default for UriSpecTweak {
    fn default() -> Self {
        UriSpecTweak {
            issued_secs_ago: 0,
            lifetime_s: 300,
            tamper: None,
        }
    }
}

/// Last part of the wallet's output, for failure messages.
pub(crate) fn tail(output: &str) -> String {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return "<nothing>".to_owned();
    }
    let start = trimmed.len().saturating_sub(400);
    let shown: String = trimmed.get(start..).unwrap_or(trimmed).replace('\n', " | ");
    format!("…{shown}")
}

/// All checks in suite order.
pub fn checks() -> Vec<CheckInfo> {
    checks::CHECKS.iter().map(|c| c.info).collect()
}

/// Run the suite against the wallet described by `opts`.
pub fn run(opts: &Options) -> Report {
    let only: Vec<String> = opts.only.iter().map(|s| s.to_ascii_uppercase()).collect();
    let subject = if opts.manual {
        "manual (operator-driven wallet)".to_owned()
    } else {
        opts.wallet.clone()
    };
    let ctx = match Ctx::new(opts) {
        Ok(c) => c,
        Err(e) => {
            // Without a relay or an origin server there is nothing to test; report every
            // selected check as skipped with the reason rather than passing silently.
            let results = checks::CHECKS
                .iter()
                .filter(|c| only.is_empty() || only.iter().any(|o| *o == c.info.id))
                .map(|c| CheckResult::of(c.info, Err(Fail::Skip(e.clone())), Instant::now()))
                .collect();
            return Report {
                kind: "wallet",
                subject,
                results,
            };
        }
    };
    let mut results = Vec::new();
    for check in checks::CHECKS {
        let info = check.info;
        let named = only.iter().any(|o| *o == info.id);
        if !only.is_empty() && !named {
            continue;
        }
        let started = Instant::now();
        let outcome = if !named && info.tier == SLOW && !opts.slow {
            Err(Fail::Skip("opt-in: pass --slow".to_owned()))
        } else {
            (check.run)(&ctx)
        };
        results.push(CheckResult::of(info, outcome, started));
    }
    Report {
        kind: "wallet",
        subject,
        results,
    }
}

/// Tier of a check that always runs.
pub(crate) const DEFAULT: &str = DEFAULT_TIER;
