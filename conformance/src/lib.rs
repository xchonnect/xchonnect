//! Black-box conformance suites for Xchonnect relays and wallets.
//!
//! - [`relay`]: checks a relay's HTTP API against `docs/spec/wire/relay-api.md`.
//! - [`wallet`]: drives a wallet through the protocol as a dApp would and checks the
//!   wallet requirements of spec Sections 6, 9 and 11.
//!
//! The command-line front end is the `xchonnect-conformance` binary; see
//! `conformance/README.md`.

mod http;
pub mod relay;
pub mod report;
pub mod wallet;
