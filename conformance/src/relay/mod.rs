//! Black-box conformance suite for relays (`docs/spec/wire/relay-api.md`, spec 7.1–7.5).
//!
//! The suite talks to a relay only over HTTP. It discovers the relay's limits and
//! mailbox creation methods from `GET /v1/info` and skips checks that need something
//! the relay does not offer.

mod checks;
mod ctx;
mod envelope;

use crate::report::Fail;
pub use crate::report::{CheckInfo, CheckResult, Report, Status};
use std::time::Instant;

/// Checks that burn rate-limit quota (`--aggressive`).
pub(crate) const AGGRESSIVE: &str = "aggressive";
/// Checks that wait for timeouts above a minute (`--slow`).
pub(crate) const SLOW: &str = "slow";

/// Suite options.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Relay base URL, e.g. `https://relay.example.com` (no trailing `/v1`).
    pub base_url: String,
    /// Run only these check ids (case-insensitive). Empty = all. Naming an opt-in
    /// check here runs it even without its opt-in flag.
    pub only: Vec<String>,
    /// Business API key (`Xchonnect-Api-Key`) for ticket and API-key checks.
    pub api_key: Option<String>,
    /// Run checks that deliberately exhaust rate limits.
    pub aggressive: bool,
    /// Run checks that take more than a minute (message expiry, long-poll clamping).
    pub slow: bool,
}

/// All checks in suite order.
pub fn checks() -> Vec<CheckInfo> {
    checks::CHECKS.iter().map(|c| c.info).collect()
}

/// Run the suite against `opts.base_url`.
pub fn run(opts: &Options) -> Report {
    let only: Vec<String> = opts.only.iter().map(|s| s.to_ascii_uppercase()).collect();
    let ctx = ctx::Ctx::new(opts);
    let mut results = Vec::new();
    for check in checks::CHECKS {
        let info = check.info;
        let named = only.iter().any(|o| o == info.id);
        if !only.is_empty() && !named {
            continue;
        }
        let started = Instant::now();
        let enabled = named
            || match info.tier {
                AGGRESSIVE => opts.aggressive,
                SLOW => opts.slow,
                _ => true,
            };
        let outcome = if !enabled {
            Err(Fail::Skip(format!("opt-in: pass --{}", info.tier)))
        } else if ctx.info.is_null() && info.id != "R-INFO-01" {
            Err(Fail::Skip(
                "GET /v1/info did not return a JSON object".to_owned(),
            ))
        } else {
            (check.run)(&ctx)
        };
        results.push(CheckResult::of(info, outcome, started));
    }
    Report {
        kind: "relay",
        subject: opts.base_url.clone(),
        results,
    }
}
