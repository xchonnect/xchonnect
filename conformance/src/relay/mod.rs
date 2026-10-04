//! Black-box conformance suite for relays (`docs/spec/wire/relay-api.md`, spec 7.1–7.5).
//!
//! The suite talks to a relay only over HTTP. It discovers the relay's limits and
//! mailbox creation methods from `GET /v1/info` and skips checks that need something
//! the relay does not offer.

mod checks;
mod client;
mod ctx;
mod envelope;

use serde_json::{Value, json};
use std::time::Instant;

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

/// When a check runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Always.
    Default,
    /// Only with `--aggressive` (burns rate-limit quota).
    Aggressive,
    /// Only with `--slow` (waits for timeouts above a minute).
    Slow,
}

/// Static description of a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckInfo {
    /// Stable id, e.g. `R-AUTH-01`.
    pub id: &'static str,
    /// What the check verifies.
    pub title: &'static str,
    /// Normative reference.
    pub spec: &'static str,
    /// Opt-in tier.
    pub tier: Tier,
}

/// Outcome of a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Requirement met.
    Pass,
    /// Requirement violated.
    Fail,
    /// Not applicable to this relay or not enabled.
    Skip,
}

impl Status {
    fn label(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Fail => "FAIL",
            Status::Skip => "SKIP",
        }
    }
}

/// Result of one check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    /// The check.
    pub info: CheckInfo,
    /// Outcome.
    pub status: Status,
    /// Failure or skip reason, or a note on a pass.
    pub detail: Option<String>,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u128,
}

/// Results of a suite run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Relay under test.
    pub base_url: String,
    /// One entry per selected check, in suite order.
    pub results: Vec<CheckResult>,
}

impl Report {
    fn count(&self, s: Status) -> usize {
        self.results.iter().filter(|r| r.status == s).count()
    }

    /// Number of failed checks.
    pub fn failures(&self) -> usize {
        self.count(Status::Fail)
    }

    /// True when no check failed.
    pub fn is_success(&self) -> bool {
        self.failures() == 0
    }

    /// Human-readable report, one line per check.
    pub fn to_text(&self) -> String {
        let mut out = format!("Xchonnect relay conformance: {}\n", self.base_url);
        for r in &self.results {
            let CheckInfo {
                id, title, spec, ..
            } = r.info;
            out += &format!("[{}] {id} {title} ({spec})\n", r.status.label());
            if let Some(d) = &r.detail {
                out += &format!("       -> {d}\n");
            }
        }
        let [pass, fail, skip] = [Status::Pass, Status::Fail, Status::Skip].map(|s| self.count(s));
        out + &format!("\n{pass} passed, {fail} failed, {skip} skipped\n")
    }

    /// Machine-readable report.
    pub fn to_json(&self) -> Value {
        json!({
            "relay": self.base_url,
            "summary": {
                "pass": self.count(Status::Pass),
                "fail": self.count(Status::Fail),
                "skip": self.count(Status::Skip),
            },
            "results": self.results.iter().map(|r| json!({
                "id": r.info.id,
                "title": r.info.title,
                "spec": r.info.spec,
                "tier": match r.info.tier { Tier::Default => "default", Tier::Aggressive => "aggressive", Tier::Slow => "slow" },
                "status": r.status.label().to_ascii_lowercase(),
                "detail": r.detail,
                "duration_ms": r.duration_ms,
            })).collect::<Vec<_>>(),
        })
    }
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
                Tier::Default => true,
                Tier::Aggressive => opts.aggressive,
                Tier::Slow => opts.slow,
            };
        let (status, detail) = if !enabled {
            let flag = if info.tier == Tier::Slow {
                "--slow"
            } else {
                "--aggressive"
            };
            (Status::Skip, Some(format!("opt-in: pass {flag}")))
        } else if ctx.info.is_null() && info.id != "R-INFO-01" {
            (
                Status::Skip,
                Some("GET /v1/info did not return a JSON object".to_owned()),
            )
        } else {
            match (check.run)(&ctx) {
                Ok(note) => (Status::Pass, note),
                Err(ctx::Fail::Fail(m)) => (Status::Fail, Some(m)),
                Err(ctx::Fail::Skip(m)) => (Status::Skip, Some(m)),
            }
        };
        results.push(CheckResult {
            info,
            status,
            detail,
            duration_ms: started.elapsed().as_millis(),
        });
    }
    Report {
        base_url: opts.base_url.clone(),
        results,
    }
}
