//! Wallet-side signing safety for Xchonnect wallets on Chia (spec Section 11).
//!
//! A wallet must never trust what a dApp says a spend does. This crate runs every
//! requested spend locally with the same CLVM interpreter the chain uses and derives
//! what actually happens to the user's assets ([`simulate()`]), which signatures would be
//! produced and whether they are allowed (`policy`), and whether a request fits the
//! dApp's permissions and limits (`permissions`). Keys never enter this crate: signing
//! goes through a host-provided signer.

pub mod binding;
pub mod error;
pub mod handlers;
pub mod intent;
#[cfg(test)]
mod multiparty_vectors;
pub mod permissions;
pub mod policy;
pub mod simulate;
pub mod spend;
#[cfg(test)]
pub(crate) mod swap_fixture;

pub use binding::{BindingReport, BoundPayment, verify_binding};
pub use error::KitError;
pub use handlers::{
    Approver, Broadcast, Broadcaster, Host, Prompt, RequestContext, RpcError, SUBMIT_COIN_SPENDS,
    Signer, SignerError, SubmitRequest, Submitted, handle, handle_with_host, signed_message_hash,
    submit,
};
pub use intent::{Intent, IntentError, IntentReport, NetClaim, RecipientClaim, VerifiedFact};
pub use permissions::{
    AssetLimit, DailySpend, DappPermissions, LimitStore, PermissionError, check_spend, commit_spend,
};
pub use policy::{Network, PolicyOptions, Refusal, SigningPlan, plan};
pub use simulate::{
    AssetDelta, AssetId, ExecutedSpend, Ownership, SpendKind, Summary, TimeLocks, execute, simulate,
};
pub use spend::parse_coin_spends;
