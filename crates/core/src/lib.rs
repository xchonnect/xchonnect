//! Xchonnect protocol core: canonical CBOR, envelopes, pairing and sessions.
//!
//! This crate implements the transport defined in `docs/spec/xchonnect-spec.md`. It is
//! transport-agnostic (bytes in, bytes out), has no Chia dependency and no `unsafe` code.
//! Randomness and time are injected so that behaviour is deterministic under test.

pub mod b64;
pub mod cbor;
pub mod crypto;
#[cfg(feature = "idna")]
pub mod domain;
pub mod envelope;
pub mod error;
pub mod keys;
pub mod message;
#[cfg(feature = "ohttp")]
pub mod ohttp;
pub mod origin;
pub mod pairing;
pub mod pow;
pub mod push;
pub mod rpc;
pub mod session;
pub mod uri;

pub use error::{Error, Result};

#[cfg(all(test, not(target_arch = "wasm32")))]
mod fuzz_seeds;
#[cfg(all(test, not(target_arch = "wasm32")))]
mod prop_tests;
#[cfg(all(test, not(target_arch = "wasm32")))]
mod vectors;
