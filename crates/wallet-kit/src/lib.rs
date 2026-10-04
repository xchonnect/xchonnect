//! Wallet-side signing safety for Xchonnect wallets on Chia (spec Section 11).
//!
//! A wallet must never trust what a dApp says a spend does. This crate runs every
//! requested spend locally with the same CLVM interpreter the chain uses and derives
//! what actually happens to the user's assets ([`simulate`]), which signatures would be
//! produced and whether they are allowed (`policy`), and whether a request fits the
//! dApp's permissions and limits (`permissions`). Keys never enter this crate: signing
//! goes through a host-provided signer.

pub mod error;
pub mod policy;
pub mod simulate;
pub mod spend;

pub use error::KitError;
pub use policy::{Network, PolicyOptions, Refusal, SigningPlan, plan};
pub use simulate::{
    AssetDelta, AssetId, ExecutedSpend, Ownership, SpendKind, Summary, TimeLocks, execute, simulate,
};
pub use spend::parse_coin_spends;
