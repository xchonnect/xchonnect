//! Typed error crossing the FFI boundary.

use core::fmt;
use xchonnect_core::Error as CoreError;

/// Every failure of the bindings. Variants mirror the kinds of the core error; the
/// message is the core's description and never contains secrets, tokens, mailbox ids
/// or plaintext.
///
/// Swift: `XchonnectError.Decrypt(message:)`; Kotlin: `XchonnectException.Decrypt`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Error)]
#[uniffi(flat_error)]
pub enum XchonnectError {
    /// Input is not valid canonical CBOR.
    Cbor(String),
    /// A structure decoded but violates the wire definition.
    Malformed(String),
    /// Unknown protocol version.
    UnsupportedVersion(String),
    /// Authenticated decryption failed (wrong key, tampered data). Ignore the envelope.
    Decrypt(String),
    /// Message is too large for the largest padding bucket.
    TooLarge(String),
    /// Replayed or reordered message. Ignore the envelope.
    Replay(String),
    /// Message expired.
    Expired(String),
    /// Message lifetime exceeds 7 days.
    LifetimeTooLong(String),
    /// Message issued too far in the future (check the device clock).
    ClockSkew(String),
    /// Pairing URI is malformed.
    InvalidUri(String),
    /// Pairing URI expired.
    UriExpired(String),
    /// Origin document invalid or does not authorise the URI's key.
    InvalidOrigin(String),
    /// Origin signature verification failed: do not pair.
    BadSignature(String),
    /// Operation not valid in the current protocol state.
    State(String),
    /// A second pairing reply after one was accepted.
    AlreadyPaired(String),
    /// Key agreement produced a weak key.
    WeakKey(String),
    /// Proof-of-work invalid, or the difficulty is above the client limit.
    PowInvalid(String),
    /// Underlying primitive failed unexpectedly.
    Crypto(String),
    /// The OHTTP gateway's key configuration no longer contains the pinned key: hard
    /// error, the app needs an updated pin (spec 10).
    OhttpKeyMismatch(String),
    /// An argument passed by the host is invalid (e.g. not base64url, wrong length).
    /// The message names the parameter, never its value.
    InvalidInput(String),
    /// A core error kind this binding version does not know yet.
    Other(String),
}

impl XchonnectError {
    pub(crate) fn input(param: &str) -> Self {
        XchonnectError::InvalidInput(format!("invalid {param}"))
    }
}

impl fmt::Display for XchonnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let m = match self {
            XchonnectError::Cbor(m)
            | XchonnectError::Malformed(m)
            | XchonnectError::UnsupportedVersion(m)
            | XchonnectError::Decrypt(m)
            | XchonnectError::TooLarge(m)
            | XchonnectError::Replay(m)
            | XchonnectError::Expired(m)
            | XchonnectError::LifetimeTooLong(m)
            | XchonnectError::ClockSkew(m)
            | XchonnectError::InvalidUri(m)
            | XchonnectError::UriExpired(m)
            | XchonnectError::InvalidOrigin(m)
            | XchonnectError::BadSignature(m)
            | XchonnectError::State(m)
            | XchonnectError::AlreadyPaired(m)
            | XchonnectError::WeakKey(m)
            | XchonnectError::PowInvalid(m)
            | XchonnectError::Crypto(m)
            | XchonnectError::OhttpKeyMismatch(m)
            | XchonnectError::InvalidInput(m)
            | XchonnectError::Other(m) => m,
        };
        f.write_str(m)
    }
}

impl std::error::Error for XchonnectError {}

impl From<CoreError> for XchonnectError {
    fn from(e: CoreError) -> Self {
        let m = e.to_string();
        match e {
            CoreError::Cbor(_) => XchonnectError::Cbor(m),
            CoreError::Malformed(_) => XchonnectError::Malformed(m),
            CoreError::UnsupportedVersion => XchonnectError::UnsupportedVersion(m),
            CoreError::Decrypt => XchonnectError::Decrypt(m),
            CoreError::TooLarge => XchonnectError::TooLarge(m),
            CoreError::Replay => XchonnectError::Replay(m),
            CoreError::Expired => XchonnectError::Expired(m),
            CoreError::LifetimeTooLong => XchonnectError::LifetimeTooLong(m),
            CoreError::ClockSkew => XchonnectError::ClockSkew(m),
            CoreError::InvalidUri(_) => XchonnectError::InvalidUri(m),
            CoreError::UriExpired => XchonnectError::UriExpired(m),
            CoreError::InvalidOrigin(_) => XchonnectError::InvalidOrigin(m),
            CoreError::BadSignature => XchonnectError::BadSignature(m),
            CoreError::State(_) => XchonnectError::State(m),
            CoreError::AlreadyPaired => XchonnectError::AlreadyPaired(m),
            CoreError::WeakKey => XchonnectError::WeakKey(m),
            CoreError::PowInvalid => XchonnectError::PowInvalid(m),
            CoreError::Crypto(_) => XchonnectError::Crypto(m),
            CoreError::OhttpKeyMismatch => XchonnectError::OhttpKeyMismatch(m),
            _ => XchonnectError::Other(m),
        }
    }
}

/// Result alias used by every exported function.
pub type Result<T> = core::result::Result<T, XchonnectError>;
