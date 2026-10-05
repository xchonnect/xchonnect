//! Result types shared by the conformance suites.
//!
//! A suite is a list of independent checks. Each one passes, fails or is skipped
//! because it does not apply to the implementation under test, and carries the
//! normative reference it is derived from so a failure can be looked up.

use serde_json::{Value, json};

/// Why a check did not pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Fail {
    /// Requirement violated (or the implementation could not be reached).
    Fail(String),
    /// Not applicable.
    Skip(String),
}

impl From<String> for Fail {
    fn from(s: String) -> Self {
        Fail::Fail(s)
    }
}

impl Fail {
    /// Prefix a failure message with `what`; skips pass through unchanged.
    pub(crate) fn context(self, what: impl std::fmt::Display) -> Self {
        match self {
            Fail::Fail(m) => Fail::Fail(format!("{what}: {m}")),
            s @ Fail::Skip(_) => s,
        }
    }
}

/// Check result: `Ok(None)` pass, `Ok(Some(note))` pass with a note.
pub(crate) type CheckRes = Result<Option<String>, Fail>;

/// Fail the check unless `cond` holds.
macro_rules! ensure {
    ($cond:expr, $($arg:tt)+) => {
        if !$cond {
            return Err($crate::report::Fail::Fail(format!($($arg)+)));
        }
    };
}
pub(crate) use ensure;

/// Skip the check.
macro_rules! skip {
    ($($arg:tt)+) => {
        return Err($crate::report::Fail::Skip(format!($($arg)+)))
    };
}
pub(crate) use skip;

/// Static description of a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckInfo {
    /// Stable id, e.g. `R-AUTH-01`.
    pub id: &'static str,
    /// What the check verifies.
    pub title: &'static str,
    /// Normative reference.
    pub spec: &'static str,
    /// Tier: `"default"`, or the name of the opt-in group it belongs to.
    pub tier: &'static str,
}

/// Tier of a check that always runs.
pub(crate) const DEFAULT_TIER: &str = "default";

impl CheckInfo {
    /// Suffix for listings: nothing for default checks, the opt-in flag otherwise.
    pub fn tier_suffix(&self) -> String {
        if self.tier == DEFAULT_TIER {
            String::new()
        } else {
            format!(" [--{}]", self.tier)
        }
    }
}

/// Outcome of a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Requirement met.
    Pass,
    /// Requirement violated.
    Fail,
    /// Not applicable to this implementation or not enabled.
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

impl CheckResult {
    /// Build a result from what a check returned.
    pub(crate) fn of(info: CheckInfo, outcome: CheckRes, started: std::time::Instant) -> Self {
        let (status, detail) = match outcome {
            Ok(note) => (Status::Pass, note),
            Err(Fail::Fail(m)) => (Status::Fail, Some(m)),
            Err(Fail::Skip(m)) => (Status::Skip, Some(m)),
        };
        CheckResult {
            info,
            status,
            detail,
            duration_ms: started.elapsed().as_millis(),
        }
    }
}

/// Results of a suite run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// What was tested: `"relay"` or `"wallet"`.
    pub kind: &'static str,
    /// Identifies the implementation under test (a URL, or the wallet command).
    pub subject: String,
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

    /// Ids of the checks with `status`.
    pub fn ids_with(&self, status: Status) -> Vec<&'static str> {
        self.results
            .iter()
            .filter(|r| r.status == status)
            .map(|r| r.info.id)
            .collect()
    }

    /// Human-readable report, one line per check.
    pub fn to_text(&self) -> String {
        let mut out = format!(
            "Xchonnect {} conformance: {}\n",
            self.kind,
            redact(&self.subject)
        );
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
            self.kind: redact(&self.subject),
            "summary": {
                "pass": self.count(Status::Pass),
                "fail": self.count(Status::Fail),
                "skip": self.count(Status::Skip),
            },
            "results": self.results.iter().map(|r| json!({
                "id": r.info.id,
                "title": r.info.title,
                "spec": r.info.spec,
                "tier": r.info.tier,
                "status": r.status.label().to_ascii_lowercase(),
                "detail": r.detail,
                "duration_ms": r.duration_ms,
            })).collect::<Vec<_>>(),
        })
    }
}

/// The wallet suite's subject is an operator-supplied shell command, which may well
/// contain a development seed or an API key. Keep it out of reports.
fn redact(subject: &str) -> String {
    const SECRETS: [&str; 6] = [
        "--dev-key",
        "--api-key",
        "--seed",
        "--key",
        "--secret",
        "--password",
    ];
    let mut out: Vec<&str> = Vec::new();
    let mut hiding: Option<char> = None;
    for word in subject.split_whitespace() {
        // A shell-quoted value may run over several whitespace-separated words; keep
        // hiding until the quote closes.
        if let Some(quote) = hiding {
            if word.ends_with(quote) {
                hiding = None;
            }
            continue;
        }
        if out.last().is_some_and(|w| SECRETS.contains(w)) {
            hiding = word.strip_prefix(['\'', '"']).and_then(|rest| {
                let quote = word.chars().next()?;
                (!rest.ends_with(quote) || rest.is_empty()).then_some(quote)
            });
            out.push("<redacted>");
            continue;
        }
        out.push(word);
    }
    out.join(" ")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]
mod tests {
    use super::*;

    #[test]
    fn secrets_in_the_subject_are_not_printed() {
        let report = |subject: &str| Report {
            kind: "wallet",
            subject: subject.to_owned(),
            results: vec![],
        };
        for subject in [
            "wallet pair {uri} --dev-key hunter2hunter2 --auto-approve",
            "wallet pair {uri} --dev-key 'hunter2hunter2' --auto-approve",
            // A quoted seed with spaces must be hidden to its closing quote.
            "wallet pair {uri} --dev-key 'hunter2 and hunter2' --auto-approve",
            "wallet pair {uri} --api-key \"hunter2 hunter2\"",
        ] {
            let r = report(subject);
            assert!(!r.to_text().contains("hunter2"), "{}", r.to_text());
            assert!(!r.to_json().to_string().contains("hunter2"));
            assert!(r.to_text().contains("<redacted>"), "{}", r.to_text());
            assert!(
                r.to_text().contains("--auto-approve") || subject.contains("--api-key"),
                "the rest of the command is still shown: {}",
                r.to_text()
            );
        }
    }

    #[test]
    fn json_names_the_subject_after_its_kind() {
        let r = Report {
            kind: "relay",
            subject: "http://127.0.0.1:1".to_owned(),
            results: vec![CheckResult {
                info: CheckInfo {
                    id: "X-1",
                    title: "t",
                    spec: "s",
                    tier: DEFAULT_TIER,
                },
                status: Status::Fail,
                detail: None,
                duration_ms: 0,
            }],
        };
        assert_eq!(r.to_json()["relay"], "http://127.0.0.1:1");
        assert_eq!(r.to_json()["summary"]["fail"], 1);
        assert!(!r.is_success() && r.ids_with(Status::Fail) == vec!["X-1"]);
    }
}
