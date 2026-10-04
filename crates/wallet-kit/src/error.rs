//! Errors. Messages describe the problem without echoing request contents.

use core::fmt;

/// Wallet-kit failures. Every variant means "do not sign".
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KitError {
    /// The request JSON does not match CHIP-0002 (`what` names the field).
    InvalidRequest(&'static str),
    /// A coin's puzzle reveal does not hash to its puzzle hash.
    PuzzleHashMismatch {
        /// Index of the spend in the request.
        spend: usize,
    },
    /// Running a puzzle failed (it raised, or its output is not a condition list).
    Execution {
        /// Index of the spend.
        spend: usize,
    },
    /// The request exceeds the configured CLVM cost limit.
    CostExceeded,
    /// A condition is malformed (for example an infinity public key in an AGG_SIG).
    InvalidCondition {
        /// Index of the spend.
        spend: usize,
    },
    /// An amount overflowed.
    Overflow,
}

impl fmt::Display for KitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KitError::InvalidRequest(w) => write!(f, "invalid request: {w}"),
            KitError::PuzzleHashMismatch { spend } => write!(
                f,
                "spend {spend}: puzzle reveal does not match the coin's puzzle hash"
            ),
            KitError::Execution { spend } => write!(f, "spend {spend}: puzzle failed to run"),
            KitError::CostExceeded => f.write_str("spend cost exceeds the limit"),
            KitError::InvalidCondition { spend } => write!(f, "spend {spend}: malformed condition"),
            KitError::Overflow => f.write_str("amount overflow"),
        }
    }
}

impl std::error::Error for KitError {}
