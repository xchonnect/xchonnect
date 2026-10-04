//! Black-box conformance suites for Xchonnect relays and wallets.
//!
//! - [`relay`]: checks a relay's HTTP API against `docs/spec/wire/relay-api.md`.
//!
//! The command-line front end is the `xchonnect-conformance` binary; see
//! `conformance/README.md`.

pub mod relay;
