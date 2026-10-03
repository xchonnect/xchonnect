//! Error type for all core operations.
//!
//! Errors never carry secret material, tokens, mailbox ids or plaintext.

use core::fmt;

/// All failures reported by `xchonnect-core`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Input is not valid canonical CBOR as defined by spec Section 5.4.
    Cbor(&'static str),
    /// A structure decoded but violates the wire definition (missing/invalid field).
    Malformed(&'static str),
    /// Unknown protocol version.
    UnsupportedVersion,
    /// Authenticated decryption failed (wrong key, tampered data or AAD).
    Decrypt,
    /// Message is too large for the largest padding bucket.
    TooLarge,
    /// Replay or reordering: `seq` not greater than the last accepted value.
    Replay,
    /// Message `exp` is in the past.
    Expired,
    /// `exp - iat` exceeds 7 days.
    LifetimeTooLong,
    /// `iat` lies too far in the future.
    ClockSkew,
    /// Pairing URI is malformed.
    InvalidUri(&'static str),
    /// Pairing URI expired or its lifetime exceeds 5 minutes.
    UriExpired,
    /// Origin document is invalid or does not authorise the key.
    InvalidOrigin(&'static str),
    /// Origin signature verification failed.
    BadSignature,
    /// Operation is not valid in the current protocol state.
    State(&'static str),
    /// A second pairing reply after one was accepted (spec 6.3 step 5).
    AlreadyPaired,
    /// Key agreement produced an all-zero shared secret.
    WeakKey,
    /// Proof-of-work does not meet the target or is malformed.
    PowInvalid,
    /// Underlying primitive failed unexpectedly.
    Crypto(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Cbor(m) => write!(f, "invalid CBOR: {m}"),
            Error::Malformed(m) => write!(f, "malformed message: {m}"),
            Error::UnsupportedVersion => f.write_str("unsupported protocol version"),
            Error::Decrypt => f.write_str("decryption failed"),
            Error::TooLarge => f.write_str("message too large"),
            Error::Replay => f.write_str("replayed or reordered message"),
            Error::Expired => f.write_str("message expired"),
            Error::LifetimeTooLong => f.write_str("message lifetime exceeds 7 days"),
            Error::ClockSkew => f.write_str("message issued in the future"),
            Error::InvalidUri(m) => write!(f, "invalid pairing URI: {m}"),
            Error::UriExpired => f.write_str("pairing URI expired"),
            Error::InvalidOrigin(m) => write!(f, "invalid origin document: {m}"),
            Error::BadSignature => f.write_str("origin signature invalid"),
            Error::State(m) => write!(f, "invalid state: {m}"),
            Error::AlreadyPaired => f.write_str("pairing already completed"),
            Error::WeakKey => f.write_str("weak key"),
            Error::PowInvalid => f.write_str("proof-of-work invalid"),
            Error::Crypto(m) => write!(f, "cryptographic failure: {m}"),
        }
    }
}

impl std::error::Error for Error {}

/// Result alias.
pub type Result<T> = core::result::Result<T, Error>;
