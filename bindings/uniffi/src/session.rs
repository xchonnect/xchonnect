//! Established sessions (spec 5.3, 6.3, 6.4, 9.2).

use std::sync::{Arc, Mutex, MutexGuard};

use xchonnect_core::b64;
use xchonnect_core::crypto::OsEntropy;
use xchonnect_core::message::{self as m, Message, RotatePhase};
use xchonnect_core::session as core_session;

use crate::{
    MailboxCredentials, NewMailbox, Outgoing, Result, WalletMetadata, XchonnectError, mailbox, tok,
    token,
};

/// Time-to-live of responses and receipts sealed by the wallet.
const RESPONSE_TTL_S: u64 = 3600;
/// Time-to-live of `session.ping` / `session.pong`.
const PING_TTL_S: u64 = 300;

/// This side's role in a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SessionRole {
    /// The dApp.
    Dapp,
    /// The wallet.
    Wallet,
}

/// A peer's `session.rotate` offer; pass it back unchanged to
/// [`Session::accept_rotation`].
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RotationOffer {
    /// The new epoch.
    pub epoch: u64,
    /// Peer's fresh X25519 public key (base64url).
    pub epk: String,
    /// Peer's new mailbox.
    pub mailbox: String,
    /// Write token for the peer's new mailbox.
    pub write_token: String,
}

/// Outcome of an `rpc.response`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum RpcOutcome {
    /// JSON text result.
    Success {
        /// Result as JSON text.
        result_json: String,
    },
    /// Error object.
    Failure {
        /// Numeric code (see [`crate::RpcErrorCode`]).
        code: i64,
        /// Human-readable message.
        message: String,
        /// Optional data as JSON text.
        data_json: Option<String>,
    },
}

/// Spending limits in `session.permissions` (decimal mojo strings).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Limits {
    /// Per request.
    pub per_request_mojos: Option<String>,
    /// Per day.
    pub per_day_mojos: Option<String>,
}

/// Typed body of a decoded message.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum MessageBody {
    /// `rpc.request`: show it to the user, then [`Session::respond`] or
    /// [`Session::respond_error`] with the message `id` as `request_id`.
    RpcRequest {
        /// Method as sent (may carry the `chip0002_` prefix).
        method: String,
        /// Method without the `chip0002_` alias prefix.
        canonical_method: String,
        /// CHIP-0002 params as JSON text.
        params_json: String,
    },
    /// `rpc.response` (received by dApps).
    RpcResponse {
        /// Id of the request.
        request_id: String,
        /// Result or error.
        outcome: RpcOutcome,
    },
    /// `rpc.received` delivery receipt (received by dApps).
    RpcReceived {
        /// Id of the request.
        request_id: String,
    },
    /// `session.ready` (received by dApps).
    SessionReady {
        /// Wallet metadata, if shared.
        meta: Option<WalletMetadata>,
    },
    /// The peer offers a key rotation: create a new mailbox and call
    /// [`Session::accept_rotation`].
    RotationOffered {
        /// The offer.
        offer: RotationOffer,
    },
    /// The peer accepted this side's rotation; the session switched epochs. Keep
    /// draining [`Session::draining_mailbox`] and call [`Session::finish_drain`].
    RotationAccepted {
        /// The new epoch.
        epoch: u64,
    },
    /// `session.permissions`.
    Permissions {
        /// Allowed CHIP-0002 methods.
        methods: Vec<String>,
        /// Exposed public keys (lowercase hex).
        keys: Vec<String>,
        /// Optional limits.
        limits: Option<Limits>,
    },
    /// `session.end`: the session has ended; delete its state and mailboxes.
    SessionEnd {
        /// Optional reason.
        reason: Option<String>,
    },
    /// `session.ping`: answer with [`Session::pong`].
    Ping,
    /// `session.pong`.
    Pong,
    /// A type this version does not know; ignore it.
    Unknown {
        /// Wire type string.
        type_name: String,
    },
}

/// A decoded, authenticated message.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct IncomingMessage {
    /// Message id (base64url): the `request_id` for responses.
    pub id: String,
    /// Sequence number.
    pub seq: u64,
    /// Issued at (unix seconds).
    pub iat: u64,
    /// Expiry (unix seconds); do not answer requests after it.
    pub exp: u64,
    /// Typed body.
    pub body: MessageBody,
}

impl From<m::Inner> for IncomingMessage {
    fn from(i: m::Inner) -> Self {
        let type_name = i.message.type_name().to_owned();
        let body = match i.message {
            Message::RpcRequest { method, params } => MessageBody::RpcRequest {
                canonical_method: xchonnect_core::rpc::canonical_method(&method).to_owned(),
                method,
                params_json: params,
            },
            Message::RpcResponse {
                request_id,
                outcome,
            } => MessageBody::RpcResponse {
                request_id: b64::encode(&request_id),
                outcome: match outcome {
                    m::RpcOutcome::Result(r) => RpcOutcome::Success { result_json: r },
                    m::RpcOutcome::Error(e) => RpcOutcome::Failure {
                        code: e.code,
                        message: e.message,
                        data_json: e.data,
                    },
                },
            },
            Message::RpcReceived { request_id } => MessageBody::RpcReceived {
                request_id: b64::encode(&request_id),
            },
            Message::SessionReady { meta } => MessageBody::SessionReady {
                meta: meta.map(Into::into),
            },
            Message::SessionRotate(r) => match r.phase {
                RotatePhase::Offer => MessageBody::RotationOffered {
                    offer: RotationOffer {
                        epoch: r.epoch,
                        epk: b64::encode(&r.epk),
                        mailbox: r.mailbox.to_b64(),
                        write_token: tok(&r.write_token),
                    },
                },
                RotatePhase::Accept => MessageBody::RotationAccepted { epoch: r.epoch },
            },
            Message::SessionPermissions(p) => MessageBody::Permissions {
                methods: p.methods,
                keys: p.keys,
                limits: p.limits.map(|l| Limits {
                    per_request_mojos: l.per_request_mojos,
                    per_day_mojos: l.per_day_mojos,
                }),
            },
            Message::SessionEnd { reason } => MessageBody::SessionEnd { reason },
            Message::SessionPing => MessageBody::Ping,
            Message::SessionPong => MessageBody::Pong,
            // `session.confirm` never reaches the host (the core rejects it in `open`).
            _ => MessageBody::Unknown { type_name },
        };
        IncomingMessage {
            id: b64::encode(&i.id),
            seq: i.seq,
            iat: i.iat,
            exp: i.exp,
            body,
        }
    }
}

/// Result of [`Session::accept_rotation`].
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RotationAccept {
    /// The accept to post (to the peer's **old** mailbox).
    pub outgoing: Outgoing,
    /// This side's own abandoned rotation offer mailbox, to delete on the relay.
    pub abandoned: Option<MailboxCredentials>,
}

/// A paired session. Thread-safe; calls are serialised internally.
///
/// **Persist [`Session::to_bytes`] after every mutating call and before posting the
/// returned envelope** (spec 12.1). The persisted bytes contain secrets: keep them in
/// the keychain / encrypted storage.
#[derive(Debug, uniffi::Object)]
pub struct Session {
    inner: Mutex<core_session::Session>,
}

impl Session {
    pub(crate) fn wrap(s: core_session::Session) -> Self {
        Session {
            inner: Mutex::new(s),
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, core_session::Session>> {
        self.inner
            .lock()
            .map_err(|_| XchonnectError::State("session lock poisoned".into()))
    }

    /// Read-only access. A poisoned lock (a panic during an earlier call) still holds a
    /// memory-safe state, and reading it cannot make anything worse; mutating calls
    /// refuse it instead (see `lock`).
    fn peek(&self) -> MutexGuard<'_, core_session::Session> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn seal(&self, now: u64, msg: Message, ttl_s: u64) -> Result<Outgoing> {
        Ok(self.lock()?.seal(&mut OsEntropy, now, msg, ttl_s)?.into())
    }
}

#[uniffi::export]
impl Session {
    /// Restore a session persisted with [`Session::to_bytes`].
    #[uniffi::constructor]
    pub fn from_bytes(state: Vec<u8>) -> Result<Arc<Self>> {
        let s = core_session::Session::from_bytes(&state)?;
        Ok(Arc::new(Session::wrap(s)))
    }

    /// Serialise for secure storage. Contains secrets.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.lock()?.to_bytes()?)
    }

    /// This side's role.
    pub fn role(&self) -> SessionRole {
        match self.peek().role() {
            core_session::Role::Dapp => SessionRole::Dapp,
            core_session::Role::Wallet => SessionRole::Wallet,
        }
    }

    /// Requests may be exchanged (the user confirmed the SAS and the session has not
    /// ended).
    pub fn is_active(&self) -> bool {
        self.peek().is_active()
    }

    /// The session has ended.
    pub fn is_ended(&self) -> bool {
        self.peek().is_ended()
    }

    /// Current key epoch.
    pub fn epoch(&self) -> u64 {
        self.peek().epoch()
    }

    /// Mailbox to poll (current epoch).
    pub fn own_mailbox(&self) -> MailboxCredentials {
        let s = self.peek();
        (s.own_mailbox(), s.own_read_token()).into()
    }

    /// Previous-epoch mailbox to drain **before** the current one, if a rotation
    /// happened recently.
    pub fn draining_mailbox(&self) -> Option<MailboxCredentials> {
        self.peek().draining_mailbox().map(Into::into)
    }

    /// Mailbox of a rotation this side offered that the peer has not accepted yet.
    pub fn pending_rotation_mailbox(&self) -> Option<MailboxCredentials> {
        self.peek().pending_rotation_mailbox().map(Into::into)
    }

    /// The rotation thresholds (30 days or 10 000 messages) are reached.
    pub fn needs_rotation(&self, now: u64) -> bool {
        self.peek().needs_rotation(now)
    }

    /// Open an envelope fetched from `from_mailbox` (one of this side's mailboxes).
    /// Errors such as `Decrypt` or `Replay` mean "drop this envelope".
    pub fn open(
        &self,
        now: u64,
        from_mailbox: String,
        envelope: String,
    ) -> Result<IncomingMessage> {
        let mbx = mailbox("from_mailbox", &from_mailbox)?;
        let env = crate::bytes("envelope", &envelope)?;
        Ok(self.lock()?.open(now, &mbx, &env)?.into())
    }

    /// The user confirmed matching codes. Wallet: returns `session.ready` to post.
    pub fn confirm_sas(&self, now: u64, meta: Option<WalletMetadata>) -> Result<Option<Outgoing>> {
        Ok(self
            .lock()?
            .confirm_sas(&mut OsEntropy, now, meta.map(Into::into))?
            .map(Into::into))
    }

    /// The user reported mismatching codes: returns `session.end` to post.
    pub fn reject_sas(&self, now: u64) -> Result<Outgoing> {
        Ok(self.lock()?.reject_sas(&mut OsEntropy, now)?.into())
    }

    /// End the session: returns `session.end` to post; then delete the state.
    pub fn end(&self, now: u64, reason: Option<String>) -> Result<Outgoing> {
        Ok(self.lock()?.end(&mut OsEntropy, now, reason)?.into())
    }

    /// Answer a request with a JSON result.
    pub fn respond(&self, now: u64, request_id: String, result_json: String) -> Result<Outgoing> {
        let id = crate::array::<16>("request_id", &request_id)?;
        let msg = xchonnect_core::rpc::result(id, &result_json)?;
        self.seal(now, msg, RESPONSE_TTL_S)
    }

    /// Answer a request with an error (`code` e.g. from [`crate::rpc_error_code_value`]).
    pub fn respond_error(
        &self,
        now: u64,
        request_id: String,
        code: i64,
        message: String,
        data_json: Option<String>,
    ) -> Result<Outgoing> {
        let id = crate::array::<16>("request_id", &request_id)?;
        let msg = xchonnect_core::rpc::error(id, code, &message, data_json.as_deref())?;
        self.seal(now, msg, RESPONSE_TTL_S)
    }

    /// Declare the granted scopes to the dApp (`session.permissions`, spec 9.3): the
    /// allowed CHIP-0002 methods, the public keys this session exposes (lowercase hex)
    /// and optional spending limits. Send it after [`Session::confirm_sas`], and again
    /// whenever the user changes the grant.
    pub fn permissions(
        &self,
        now: u64,
        methods: Vec<String>,
        keys: Vec<String>,
        limits: Option<Limits>,
    ) -> Result<Outgoing> {
        let msg = Message::SessionPermissions(m::Permissions {
            methods,
            keys,
            limits: limits.map(|l| m::Limits {
                per_request_mojos: l.per_request_mojos,
                per_day_mojos: l.per_day_mojos,
            }),
        });
        self.seal(now, msg, RESPONSE_TTL_S)
    }

    /// Delivery receipt (`rpc.received`) for a request the user has not decided yet.
    pub fn received(&self, now: u64, request_id: String) -> Result<Outgoing> {
        let id = crate::array::<16>("request_id", &request_id)?;
        self.seal(now, Message::RpcReceived { request_id: id }, RESPONSE_TTL_S)
    }

    /// Seal a `session.ping`.
    pub fn ping(&self, now: u64) -> Result<Outgoing> {
        self.seal(now, Message::SessionPing, PING_TTL_S)
    }

    /// Seal a `session.pong` (answer to [`MessageBody::Ping`]).
    pub fn pong(&self, now: u64) -> Result<Outgoing> {
        self.seal(now, Message::SessionPong, PING_TTL_S)
    }

    /// Start a rotation (spec 9.2) with a mailbox the wallet just created.
    pub fn begin_rotation(&self, now: u64, new_mailbox: NewMailbox) -> Result<Outgoing> {
        let (mbx, r, w) = new_mailbox.parse()?;
        Ok(self
            .lock()?
            .begin_rotation(&mut OsEntropy, now, mbx, r, w)?
            .into())
    }

    /// Accept a peer's [`MessageBody::RotationOffered`] with a mailbox the wallet just
    /// created. Afterwards drain [`Session::draining_mailbox`] before the new one.
    pub fn accept_rotation(
        &self,
        now: u64,
        offer: RotationOffer,
        new_mailbox: NewMailbox,
    ) -> Result<RotationAccept> {
        let core_offer = m::Rotate {
            phase: RotatePhase::Offer,
            epoch: offer.epoch,
            epk: crate::array::<32>("offer.epk", &offer.epk)?,
            mailbox: mailbox("offer.mailbox", &offer.mailbox)?,
            write_token: token("offer.write_token", &offer.write_token)?,
        };
        let (mbx, r, w) = new_mailbox.parse()?;
        let (out, abandoned) =
            self.lock()?
                .accept_rotation(&mut OsEntropy, now, &core_offer, mbx, r, w)?;
        Ok(RotationAccept {
            outgoing: out.into(),
            abandoned: abandoned.map(Into::into),
        })
    }

    /// The draining mailbox is empty: returns it for deletion on the relay, or `None`
    /// while the peer may still post to it.
    pub fn finish_drain(&self) -> Result<Option<MailboxCredentials>> {
        Ok(self.lock()?.finish_drain().map(Into::into))
    }
}
