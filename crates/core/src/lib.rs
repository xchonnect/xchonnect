//! Xchonnect protocol core: canonical CBOR, envelopes, pairing and sessions.
//!
//! This crate implements the transport defined in `docs/spec/xchonnect-spec.md`. It is
//! transport-agnostic (bytes in, bytes out), has no Chia dependency and no `unsafe` code.
//! Randomness and time are injected so that behaviour is deterministic under test.

pub mod b64;
pub mod cbor;
pub mod crypto;
pub mod domain;
pub mod envelope;
pub mod error;
pub mod keys;
pub mod message;
pub mod origin;
pub mod pairing;
pub mod session;
pub mod uri;

pub use error::{Error, Result};
