//! Wallet side of the pairing handshake (spec 6.3).

use std::sync::Arc;

use xchonnect_core::b64;
use xchonnect_core::crypto::OsEntropy;
use xchonnect_core::domain as core_domain;
use xchonnect_core::origin::OriginDocument;
use xchonnect_core::pairing as core_pairing;
use xchonnect_core::uri::{PairingUri, ParseOptions};

use crate::session::Session;
use crate::{DomainDisplay, NewMailbox, Outgoing, Result, WalletMetadata};

/// A pairing URI whose expiry and origin signature were verified against the origin
/// document fetched from its domain. Show [`VerifiedPairingUri::domain_display`] and
/// [`VerifiedPairingUri::dapp_name`] and ask the user before calling
/// [`VerifiedPairingUri::reply`].
#[derive(Debug, uniffi::Object)]
pub struct VerifiedPairingUri {
    inner: core_pairing::VerifiedUri,
    icon: Option<String>,
    return_url: Option<String>,
}

#[uniffi::export]
impl VerifiedPairingUri {
    /// Parse `uri` and verify it against the origin document body fetched from
    /// [`crate::UriInfo::origin_document_url`] (spec 6.3 step 2).
    #[uniffi::constructor]
    pub fn new(
        uri: String,
        origin_document_json: String,
        now: u64,
        developer_mode: bool,
    ) -> Result<Arc<Self>> {
        let parsed = PairingUri::parse(&uri, ParseOptions { developer_mode })?;
        let doc = OriginDocument::parse(origin_document_json.as_bytes())?;
        let inner = core_pairing::VerifiedUri::new(parsed, &doc, now)?;
        Ok(Arc::new(VerifiedPairingUri {
            inner,
            icon: doc.icon,
            return_url: doc.return_url,
        }))
    }

    /// Verified dApp domain (A-label).
    pub fn domain(&self) -> String {
        self.inner.uri().domain.clone()
    }

    /// The domain prepared for display, with homograph warnings.
    pub fn domain_display(&self) -> DomainDisplay {
        core_domain::display_domain(&self.inner.uri().domain).into()
    }

    /// dApp name from the origin document.
    pub fn dapp_name(&self) -> String {
        self.inner.dapp_name().to_owned()
    }

    /// dApp icon URL from the origin document, if any.
    pub fn dapp_icon(&self) -> Option<String> {
        self.icon.clone()
    }

    /// Same-device return URL from the origin document, if any.
    pub fn return_url(&self) -> Option<String> {
        self.return_url.clone()
    }

    /// Relay base URL; the wallet creates its own mailbox W there.
    pub fn relay(&self) -> String {
        self.inner.uri().relay.clone()
    }

    /// URI expiry (unix seconds).
    pub fn expires_at(&self) -> u64 {
        self.inner.uri().expires_at
    }

    /// Sponsorship ticket (base64url) to use when creating mailbox W, if any.
    pub fn ticket(&self) -> Option<String> {
        self.inner.uri().ticket.map(|t| b64::encode(&t))
    }

    /// The user approved: build the pairing reply. `own_mailbox` is mailbox W, which
    /// the wallet created on [`VerifiedPairingUri::relay`] first. Post
    /// [`WalletReply::outgoing`], then poll W for `session.confirm`.
    pub fn reply(
        &self,
        now: u64,
        own_mailbox: NewMailbox,
        meta: Option<WalletMetadata>,
    ) -> Result<WalletReply> {
        let (m, r, w) = own_mailbox.parse()?;
        let (p, out) = core_pairing::WalletPairing::reply(
            &mut OsEntropy,
            now,
            &self.inner,
            m,
            r,
            w,
            meta.map(Into::into),
        )?;
        Ok(WalletReply {
            pairing: Arc::new(WalletPairing { inner: p }),
            outgoing: out.into(),
        })
    }
}

/// Result of [`VerifiedPairingUri::reply`].
#[derive(Debug, uniffi::Record)]
pub struct WalletReply {
    /// Pairing state waiting for `session.confirm`.
    pub pairing: Arc<WalletPairing>,
    /// The pairing reply to post to the dApp's pairing mailbox.
    pub outgoing: Outgoing,
}

/// Wallet waiting for `session.confirm` on mailbox W.
#[derive(Debug, uniffi::Object)]
pub struct WalletPairing {
    inner: core_pairing::WalletPairing,
}

#[cfg(feature = "test-helpers")]
impl WalletPairing {
    pub(crate) fn wrap(inner: core_pairing::WalletPairing) -> Self {
        WalletPairing { inner }
    }
}

#[uniffi::export]
impl WalletPairing {
    /// SAS to display, formatted as `"042 917"`.
    pub fn sas(&self) -> String {
        self.inner.sas().to_string()
    }

    /// SAS as six digits without separator (`"042917"`), e.g. for accessibility.
    pub fn sas_digits(&self) -> String {
        self.inner.sas().digits()
    }

    /// Mailbox W to poll, with its read token.
    pub fn own_mailbox(&self) -> crate::MailboxCredentials {
        (self.inner.own_mailbox(), self.inner.own_read_token()).into()
    }

    /// The confirm timeout (300 s after replying) has passed: abort, delete W and warn
    /// the user that the code may have been used by another device.
    pub fn timed_out(&self, now: u64) -> bool {
        self.inner.timed_out(now)
    }

    /// Process an envelope from W. Returns the session (not yet active): show the SAS
    /// and call [`Session::confirm_sas`] or [`Session::reject_sas`]. Errors (e.g.
    /// `Decrypt`) mean "ignore this envelope and keep polling".
    pub fn on_confirm(&self, now: u64, envelope: String) -> Result<Arc<Session>> {
        let env = crate::bytes("envelope", &envelope)?;
        Ok(Arc::new(Session::wrap(self.inner.on_confirm(now, &env)?)))
    }
}
