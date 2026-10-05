//! Automated verification of the Xchonnect privacy invariants.
//!
//! The project makes concrete, public promises: the relay cannot read messages and
//! stores no Chia addresses, public keys, device push tokens or client IPs (spec 13.4
//! invariants 2 and 5); its logs carry no IPs, user agents, mailbox ids, token values or
//! ciphertext (spec 13.5); the wake-up that reaches a vendor gateway is content-free
//! (spec 7.3); Apple and Google learn only that a device received a push (spec 13.6).
//!
//! This crate turns those sentences into checks that run on every commit:
//!
//! * [`flow`] drives a full pairing, signing and push session through the real relay and
//!   gateway code, planting a client IP, a user agent, a device token, a Chia address, a
//!   public key, an amount and a unique plaintext marker along the way.
//! * [`record`] observes what the services *do* with data — every value handed to
//!   storage, every wake-up request, everything handed to a push platform — rather than
//!   a hand-picked struct.
//! * [`capture`] collects every log line, at `TRACE`, from every task.
//! * [`scan`] searches those artefacts for each planted value in every plausible
//!   encoding, plus for sensitive *shapes* (IPv4 literals, bech32m addresses, key-length
//!   hex runs, user agents, bearer tokens) whose value the fixture never saw.
//! * [`inventory`] enforces the published data inventory both ways: a forbidden class
//!   that appears is a leak, and a declared class that is missing means the run proved
//!   nothing.
//!
//! The negative direction is the point. `tests/negative_controls.rs` plants leaks and
//! requires every check to fail; a check that cannot fail is not a check.

pub mod capture;
pub mod flow;
pub mod harness;
pub mod inventory;
pub mod live;
pub mod record;
pub mod scan;
pub mod sources;
