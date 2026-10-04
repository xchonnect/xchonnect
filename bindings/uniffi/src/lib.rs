//! Xchonnect core bindings for native wallets (Swift and Kotlin via UniFFI).
//!
//! This crate is FFI glue only: every protocol rule lives in `xchonnect-core`.
//!
//! Conventions at the boundary:
//! - Protocol values (mailbox ids, tokens, message ids, envelopes, PoW challenges and
//!   nonces, public keys) are **base64url strings without padding**, exactly as the
//!   relay HTTP API carries them (`env`, path segments, bearer tokens).
//! - The only raw bytes are the session persistence blob ([`Session::to_bytes`]), which
//!   the wallet stores in the platform keychain / encrypted storage, and the OHTTP
//!   bodies and key configurations ([`OhttpClient`]), which are HTTP bodies.
//! - Times are unix seconds passed in by the caller (`now`); the bindings never read the
//!   clock.
//! - CHIP-0002 `params` / `result` / error `data` stay JSON text.
//! - Every failure is an [`XchonnectError`] whose message never contains secrets.

mod error;
mod ohttp;
mod pairing;
mod session;
#[cfg(feature = "test-helpers")]
mod test_helpers;
#[cfg(feature = "wallet-kit")]
mod wallet_kit;

pub use error::{Result, XchonnectError};
pub use ohttp::{
    HttpHeader, OhttpClient, OhttpEncapsulated, OhttpRequest, OhttpResponse, OhttpResponseContext,
    ohttp_rotate_key, ohttp_select_key,
};
pub use pairing::{VerifiedPairingUri, WalletPairing, WalletReply};
pub use session::{
    IncomingMessage, Limits, MessageBody, RotationAccept, RotationOffer, RpcOutcome, Session,
    SessionRole,
};
#[cfg(feature = "test-helpers")]
pub use test_helpers::TestDapp;
#[cfg(feature = "wallet-kit")]
pub use wallet_kit::{
    LimitStorage, WalletApprover, WalletRequestContext, WalletSigner, handle_wallet_request,
};

use xchonnect_core::b64;
use xchonnect_core::crypto::{MailboxId, OsEntropy, Token};
use xchonnect_core::domain::{self as core_domain, DomainWarning as CoreDomainWarning};
use xchonnect_core::message::{self as core_message};
use xchonnect_core::origin::OriginDocument;
use xchonnect_core::session as core_session;
use xchonnect_core::uri::{PairingUri, ParseOptions};

uniffi::setup_scaffolding!("xchonnect");

// ---------------------------------------------------------------------------
// Boundary helpers
// ---------------------------------------------------------------------------

pub(crate) fn mailbox(param: &str, s: &str) -> Result<MailboxId> {
    MailboxId::from_b64(s).map_err(|_| XchonnectError::input(param))
}

pub(crate) fn token(param: &str, s: &str) -> Result<Token> {
    b64::decode_array::<32>(s)
        .map(Token::from_bytes)
        .map_err(|_| XchonnectError::input(param))
}

pub(crate) fn array<const N: usize>(param: &str, s: &str) -> Result<[u8; N]> {
    b64::decode_array::<N>(s).map_err(|_| XchonnectError::input(param))
}

pub(crate) fn bytes(param: &str, s: &str) -> Result<Vec<u8>> {
    b64::decode(s).map_err(|_| XchonnectError::input(param))
}

pub(crate) fn tok(t: &Token) -> String {
    b64::encode(t.expose())
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

/// An envelope to post to the relay: `POST /v1/mailboxes/{mailbox}/messages` with
/// `Authorization: Bearer {write_token}` and body `{"env": envelope}`.
///
/// Persist the session **before** posting (spec 12.1).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Outgoing {
    /// Destination mailbox id.
    pub mailbox: String,
    /// Write token for the destination mailbox.
    pub write_token: String,
    /// Encoded envelope.
    pub envelope: String,
    /// Inner message id (the `request_id` of any response).
    pub id: String,
}

impl From<core_session::Outgoing> for Outgoing {
    fn from(o: core_session::Outgoing) -> Self {
        Outgoing {
            mailbox: o.mailbox.to_b64(),
            write_token: tok(&o.write_token),
            envelope: b64::encode(&o.envelope),
            id: b64::encode(&o.id),
        }
    }
}

/// A mailbox and its read token (to read, or to `DELETE` after a rotation drained it).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MailboxCredentials {
    /// Mailbox id.
    pub mailbox: String,
    /// Read token.
    pub read_token: String,
}

impl MailboxCredentials {
    pub(crate) fn new(m: MailboxId, t: &Token) -> Self {
        MailboxCredentials {
            mailbox: m.to_b64(),
            read_token: tok(t),
        }
    }
}

/// A mailbox the wallet created on the relay, with both tokens (the write token is
/// handed to the peer).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct NewMailbox {
    /// Mailbox id.
    pub mailbox: String,
    /// Read token (kept by the wallet).
    pub read_token: String,
    /// Write token (sent to the peer).
    pub write_token: String,
}

impl NewMailbox {
    pub(crate) fn parse(&self) -> Result<(MailboxId, Token, Token)> {
        Ok((
            mailbox("mailbox", &self.mailbox)?,
            token("read_token", &self.read_token)?,
            token("write_token", &self.write_token)?,
        ))
    }
}

/// Optional wallet metadata shared with the dApp during pairing.
#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct WalletMetadata {
    /// Display name.
    #[uniffi(default = None)]
    pub name: Option<String>,
    /// Icon URL (https).
    #[uniffi(default = None)]
    pub icon: Option<String>,
    /// Universal-link base for same-device requests.
    #[uniffi(default = None)]
    pub link: Option<String>,
}

impl From<WalletMetadata> for core_message::WalletMeta {
    fn from(m: WalletMetadata) -> Self {
        core_message::WalletMeta {
            name: m.name,
            icon: m.icon,
            link: m.link,
        }
    }
}

impl From<core_message::WalletMeta> for WalletMetadata {
    fn from(m: core_message::WalletMeta) -> Self {
        WalletMetadata {
            name: m.name,
            icon: m.icon,
            link: m.link,
        }
    }
}

/// Public fields of a pairing URI, available before verification so the wallet knows
/// where to fetch the origin document. Nothing here is trusted until
/// [`VerifiedPairingUri`] succeeds.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct UriInfo {
    /// Relay base URL.
    pub relay: String,
    /// Claimed dApp domain (A-label).
    pub domain: String,
    /// URL of the origin document to fetch (HTTPS, no redirects, at most 16 KiB).
    pub origin_document_url: String,
    /// Expiry (unix seconds).
    pub expires_at: u64,
    /// Origin key id.
    pub kid: String,
    /// Optional sponsorship ticket (base64url).
    pub ticket: Option<String>,
}

/// One key of an origin document.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OriginKeyInfo {
    /// Key id.
    pub kid: String,
    /// Ed25519 public key (base64url).
    pub public_key: String,
    /// Last valid instant (unix seconds).
    pub not_after: u64,
}

/// A validated origin document.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OriginInfo {
    /// dApp display name.
    pub name: String,
    /// Optional icon URL.
    pub icon: Option<String>,
    /// Optional same-device return URL.
    pub return_url: Option<String>,
    /// Origin keys.
    pub keys: Vec<OriginKeyInfo>,
}

/// Warning the wallet must surface next to a displayed domain (spec 6.3 step 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum DomainWarning {
    /// Internationalised labels: also show the ASCII form.
    NonAscii,
    /// A label mixes scripts (e.g. Latin and Cyrillic): likely homograph.
    MixedScript,
    /// Not a valid IDN: show only the ASCII form.
    InvalidIdn,
}

/// Domain prepared for display.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DomainDisplay {
    /// The domain as received (A-labels).
    pub ascii: String,
    /// Unicode form (equals `ascii` when nothing is decoded).
    pub unicode: String,
    /// Warnings to show.
    pub warnings: Vec<DomainWarning>,
}

impl From<core_domain::DomainDisplay> for DomainDisplay {
    fn from(d: core_domain::DomainDisplay) -> Self {
        DomainDisplay {
            ascii: d.ascii,
            unicode: d.unicode,
            warnings: d
                .warnings
                .into_iter()
                .map(|w| match w {
                    CoreDomainWarning::NonAscii => DomainWarning::NonAscii,
                    CoreDomainWarning::MixedScript => DomainWarning::MixedScript,
                    CoreDomainWarning::InvalidIdn => DomainWarning::InvalidIdn,
                })
                .collect(),
        }
    }
}

/// CHIP-0002 / Xchonnect error codes for [`Session::respond_error`] (spec 9.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum RpcErrorCode {
    /// 4000: malformed params.
    InvalidParams,
    /// 4001: not permitted or refused by policy.
    Unauthorized,
    /// 4002: the user declined.
    UserRejected,
    /// 4003: spendable balance exceeded.
    SpendableBalanceExceeded,
    /// 4004: unknown or unsupported method.
    MethodNotFound,
    /// 4005: required key not held.
    NoSecretKey,
    /// 4029: prompt rate limit or spending limit.
    LimitExceeded,
    /// 4100: request expired before the user decided.
    RequestExpired,
    /// 4101: spend could not be decoded.
    UnsupportedContent,
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/// Protocol version implemented by this build.
#[uniffi::export]
pub fn protocol_version() -> u32 {
    1
}

/// Numeric value of an RPC error code.
#[uniffi::export]
pub fn rpc_error_code_value(code: RpcErrorCode) -> i64 {
    use xchonnect_core::rpc::codes;
    match code {
        RpcErrorCode::InvalidParams => codes::INVALID_PARAMS,
        RpcErrorCode::Unauthorized => codes::UNAUTHORIZED,
        RpcErrorCode::UserRejected => codes::USER_REJECTED,
        RpcErrorCode::SpendableBalanceExceeded => codes::SPENDABLE_BALANCE_EXCEEDED,
        RpcErrorCode::MethodNotFound => codes::METHOD_NOT_FOUND,
        RpcErrorCode::NoSecretKey => codes::NO_SECRET_KEY,
        RpcErrorCode::LimitExceeded => codes::LIMIT_EXCEEDED,
        RpcErrorCode::RequestExpired => codes::REQUEST_EXPIRED,
        RpcErrorCode::UnsupportedContent => codes::UNSUPPORTED_CONTENT,
    }
}

/// Strip a `chip0002_` alias prefix (wallets accept both method forms).
#[uniffi::export]
pub fn canonical_method(method: String) -> String {
    xchonnect_core::rpc::canonical_method(&method).to_owned()
}

/// New random 32-byte capability token (base64url), e.g. for a new mailbox.
#[uniffi::export]
pub fn generate_token() -> String {
    tok(&Token::random(&mut OsEntropy))
}

/// Token hash sent to the relay when creating a mailbox (base64url).
#[uniffi::export]
pub fn token_hash(token: String) -> Result<String> {
    Ok(b64::encode(&self::token("token", &token)?.hash()))
}

/// Fresh token pair for creating a mailbox: send the hashes in
/// `POST /v1/mailboxes`, keep the tokens. Combine with the returned `mailbox_id` into a
/// [`NewMailbox`].
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MailboxTokens {
    /// Read token (secret; kept by the wallet).
    pub read_token: String,
    /// Write token (secret; handed to the peer).
    pub write_token: String,
    /// `read_token_hash` for the relay.
    pub read_token_hash: String,
    /// `write_token_hash` for the relay.
    pub write_token_hash: String,
}

/// Generate a [`MailboxTokens`] pair.
#[uniffi::export]
pub fn generate_mailbox_tokens() -> MailboxTokens {
    let r = Token::random(&mut OsEntropy);
    let w = Token::random(&mut OsEntropy);
    MailboxTokens {
        read_token: tok(&r),
        write_token: tok(&w),
        read_token_hash: b64::encode(&r.hash()),
        write_token_hash: b64::encode(&w.hash()),
    }
}

/// Solve a relay proof-of-work challenge (spec 7.4); returns the nonce (base64url).
/// CPU-bound (up to seconds): call it off the main thread.
#[uniffi::export]
pub fn solve_pow(challenge: String) -> Result<String> {
    let c = bytes("challenge", &challenge)?;
    Ok(b64::encode(&xchonnect_core::pow::solve(&c)?))
}

/// Push platform of a device token (spec 7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PushPlatform {
    /// APNs production.
    Apns,
    /// APNs sandbox (development builds).
    ApnsSandbox,
    /// Firebase Cloud Messaging.
    Fcm,
}

/// A push registration to send to the relay (`push_reg` in `POST /v1/mailboxes` or
/// `PUT /v1/mailboxes/{id}/push`).
#[derive(Debug, Clone, uniffi::Record)]
pub struct PushRegistration {
    /// Gateway wake URL (as given).
    pub gateway_url: String,
    /// Sealed token, base64url.
    pub sealed_token: String,
    /// Mailbox hint key for encrypted previews, base64url (keep it with the session).
    pub hint_key: String,
    /// Expiry (unix seconds); re-register before it.
    pub expires_at: u64,
}

/// Seal a device push token to the push gateway's public key (spec 7.3). Use a fresh
/// registration per session so the relay cannot link sessions. `lifetime_s` is capped at
/// 90 days.
#[uniffi::export]
pub fn seal_push_token(
    gateway_url: String,
    gateway_public_key: String,
    platform: PushPlatform,
    device_token: String,
    now: u64,
    lifetime_s: u64,
) -> Result<PushRegistration> {
    use xchonnect_core::push::{MAX_LIFETIME_S, Platform, PushToken};
    let pk = array::<32>("gateway_public_key", &gateway_public_key)?;
    let hint_key: [u8; 32] = xchonnect_core::crypto::random_array(&mut OsEntropy);
    let exp = now.saturating_add(lifetime_s.clamp(60, MAX_LIFETIME_S));
    let platform = match platform {
        PushPlatform::Apns => Platform::Apns,
        PushPlatform::ApnsSandbox => Platform::ApnsSandbox,
        PushPlatform::Fcm => Platform::Fcm,
    };
    let sealed = PushToken {
        platform,
        device_token,
        hint_key,
        exp,
    }
    .seal(&mut OsEntropy, &pk, now)?;
    Ok(PushRegistration {
        gateway_url,
        sealed_token: b64::encode(&sealed),
        hint_key: b64::encode(&hint_key),
        expires_at: exp,
    })
}

/// Parse a pairing URI (or universal link payload) without verifying it.
/// `developer_mode` permits loopback `http` relays and `localhost:<port>` domains;
/// never enable it in production builds.
#[uniffi::export]
pub fn inspect_uri(uri: String, developer_mode: bool) -> Result<UriInfo> {
    let u = PairingUri::parse(&uri, ParseOptions { developer_mode })?;
    let scheme = if developer_mode && u.domain.starts_with("localhost") {
        "http"
    } else {
        "https"
    };
    Ok(UriInfo {
        origin_document_url: format!("{scheme}://{}/.well-known/xchonnect.json", u.domain),
        relay: u.relay,
        domain: u.domain,
        expires_at: u.expires_at,
        kid: u.kid,
        ticket: u.ticket.map(|t| b64::encode(&t)),
    })
}

/// Parse and validate an origin document body (`/.well-known/xchonnect.json`).
#[uniffi::export]
pub fn parse_origin_document(json: String) -> Result<OriginInfo> {
    let d = OriginDocument::parse(json.as_bytes())?;
    Ok(OriginInfo {
        name: d.name,
        icon: d.icon,
        return_url: d.return_url,
        keys: d
            .keys
            .into_iter()
            .map(|k| OriginKeyInfo {
                kid: k.kid,
                public_key: b64::encode(&k.pk),
                not_after: k.not_after,
            })
            .collect(),
    })
}

/// Decode an A-label domain for display and compute homograph warnings.
#[uniffi::export]
pub fn display_domain(ascii: String) -> DomainDisplay {
    core_domain::display_domain(&ascii).into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn errors_map_kinds_without_secrets() {
        let e: XchonnectError = xchonnect_core::Error::Decrypt.into();
        assert_eq!(e, XchonnectError::Decrypt("decryption failed".into()));
        let e = token_hash("not base64!".into()).unwrap_err();
        assert_eq!(e, XchonnectError::InvalidInput("invalid token".into()));
        assert!(!e.to_string().contains("not base64"));
    }

    #[test]
    fn token_helpers() {
        let t = generate_token();
        assert_eq!(b64::decode(&t).unwrap().len(), 32);
        assert_eq!(b64::decode(&token_hash(t).unwrap()).unwrap().len(), 32);
        assert_ne!(generate_token(), generate_token());
        let p = generate_mailbox_tokens();
        assert_eq!(token_hash(p.read_token.clone()).unwrap(), p.read_token_hash);
        assert_eq!(
            token_hash(p.write_token.clone()).unwrap(),
            p.write_token_hash
        );
        assert_ne!(p.read_token, p.write_token);
    }

    #[test]
    fn domain_and_codes() {
        let d = display_domain("xn--pngui-3ve.xyz".into());
        assert!(d.warnings.contains(&DomainWarning::NonAscii));
        assert_eq!(display_domain("pengui.xyz".into()).warnings, vec![]);
        assert_eq!(rpc_error_code_value(RpcErrorCode::UserRejected), 4002);
        assert_eq!(
            canonical_method("chip0002_signMessage".into()),
            "signMessage"
        );
    }

    #[test]
    fn pow_solves_relay_challenge() {
        let c = xchonnect_core::pow::issue(&[3; 32], &mut OsEntropy, 1000, 8).unwrap();
        let n = solve_pow(b64::encode(&c)).unwrap();
        let n = b64::decode_array::<8>(&n).unwrap();
        assert!(xchonnect_core::pow::verify(&[&[3; 32]], &c, &n, 1000).is_ok());
        assert!(matches!(
            solve_pow("@@".into()),
            Err(XchonnectError::InvalidInput(_))
        ));
    }
}
