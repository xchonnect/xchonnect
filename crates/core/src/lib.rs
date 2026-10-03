//! Xchonnect protocol core: canonical CBOR, envelopes, pairing and sessions.
//!
//! This crate implements the transport defined in `docs/spec/xchonnect-spec.md`. It is
//! transport-agnostic (bytes in, bytes out), has no Chia dependency and no `unsafe` code.
//! Randomness and time are injected so that behaviour is deterministic under test.

pub mod b64;
pub mod crypto;
pub mod error;

pub use error::{Error, Result};
