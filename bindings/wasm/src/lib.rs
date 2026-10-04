//! WebAssembly bindings of `xchonnect-core` for the dApp SDK.
//!
//! Conventions: binary values cross the boundary as base64url strings (no padding);
//! times are unix seconds passed in by the caller; decoded messages are returned as
//! JSON text; every error becomes a JS `Error` whose message never contains secrets.

use serde_json::{Value, json};
use wasm_bindgen::prelude::*;
use xchonnect_core::b64;
use xchonnect_core::crypto::{self, Ed25519Seed, MailboxId, OsEntropy, Token};
use xchonnect_core::message::{Inner, Message, RpcOutcome};
use xchonnect_core::pairing::{self as core_pairing, DappPairingParams};
use xchonnect_core::session::{self as core_session};
use xchonnect_core::uri::ParseOptions;

fn err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

fn mailbox(s: &str) -> Result<MailboxId, JsError> {
    MailboxId::from_b64(s).map_err(err)
}

fn token(s: &str) -> Result<Token, JsError> {
    Ok(Token::from_bytes(b64::decode_array::<32>(s).map_err(err)?))
}

/// Protocol version implemented by this build.
#[wasm_bindgen(js_name = protocolVersion)]
pub fn protocol_version() -> u32 {
    1
}

/// New random 32-byte capability token (base64url).
#[wasm_bindgen(js_name = generateToken)]
pub fn generate_token() -> String {
    b64::encode(Token::random(&mut OsEntropy).expose())
}

/// `SHA-256("xchonnect v1 token" || token)` as sent to the relay (base64url).
#[wasm_bindgen(js_name = tokenHash)]
pub fn token_hash(token_b64: &str) -> Result<String, JsError> {
    Ok(b64::encode(&token(token_b64)?.hash()))
}

/// Solve a relay proof-of-work challenge (spec 7.4). Returns the nonce (base64url).
#[wasm_bindgen(js_name = solvePow)]
pub fn solve_pow(challenge_b64: &str) -> Result<String, JsError> {
    let c = b64::decode(challenge_b64).map_err(err)?;
    Ok(b64::encode(&xchonnect_core::pow::solve(&c).map_err(err)?))
}

/// Development only: sign with an in-browser origin seed. Production dApps sign on
/// their backend or KMS.
#[wasm_bindgen(js_name = devSign)]
pub fn dev_sign(seed_b64: &str, msg_b64: &str) -> Result<String, JsError> {
    let seed = Ed25519Seed::from_bytes(b64::decode_array::<32>(seed_b64).map_err(err)?);
    Ok(b64::encode(&seed.sign(&b64::decode(msg_b64).map_err(err)?)))
}

/// Development only: Ed25519 public key for a seed.
#[wasm_bindgen(js_name = devPublicKey)]
pub fn dev_public_key(seed_b64: &str) -> Result<String, JsError> {
    let seed = Ed25519Seed::from_bytes(b64::decode_array::<32>(seed_b64).map_err(err)?);
    Ok(b64::encode(&seed.public_key()))
}

/// An envelope to post: `mailbox`, `writeToken`, `envelope` (base64url) and `id`.
#[wasm_bindgen(getter_with_clone)]
pub struct Outgoing {
    /// Destination mailbox id.
    pub mailbox: String,
    /// Write token for the destination.
    #[wasm_bindgen(js_name = writeToken)]
    pub write_token: String,
    /// Encoded envelope.
    pub envelope: String,
    /// Inner message id (base64url).
    pub id: String,
}

impl From<core_session::Outgoing> for Outgoing {
    fn from(o: core_session::Outgoing) -> Self {
        Outgoing {
            mailbox: o.mailbox.to_b64(),
            write_token: b64::encode(o.write_token.expose()),
            envelope: b64::encode(&o.envelope),
            id: b64::encode(&o.id),
        }
    }
}

// ---------------------------------------------------------------------------
// Pairing
// ---------------------------------------------------------------------------

/// dApp pairing waiting for its origin signature.
#[wasm_bindgen]
pub struct UnsignedPairing {
    inner: Option<core_pairing::UnsignedPairing>,
}

#[wasm_bindgen]
impl UnsignedPairing {
    /// Generate the pairing key and secret (spec 6.2). `developer_mode` permits a
    /// loopback `http` relay and a `localhost:<port>` domain.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        relay: &str,
        domain: &str,
        pairing_mailbox: &str,
        pairing_write_token: &str,
        lifetime_s: u32,
        now: f64,
        kid: &str,
        ticket: Option<String>,
        developer_mode: bool,
    ) -> Result<UnsignedPairing, JsError> {
        let ticket = ticket
            .map(|t| b64::decode_array::<32>(&t))
            .transpose()
            .map_err(err)?;
        let p = DappPairingParams {
            relay,
            domain,
            pairing_mailbox: mailbox(pairing_mailbox)?,
            pairing_write: token(pairing_write_token)?,
            lifetime_s: u64::from(lifetime_s),
            ticket,
            options: ParseOptions { developer_mode },
        };
        let inner =
            core_pairing::DappPairing::prepare(&mut OsEntropy, now as u64, kid, p).map_err(err)?;
        Ok(UnsignedPairing { inner: Some(inner) })
    }

    /// Bytes to sign with the origin key (base64url).
    #[wasm_bindgen(js_name = sigInput)]
    pub fn sig_input(&self) -> Result<String, JsError> {
        let u = self.inner.as_ref().ok_or_else(|| err("already finished"))?;
        Ok(b64::encode(&u.sig_input().map_err(err)?))
    }

    /// Insert the signature; verifies it first when `origin_pk` is given.
    pub fn finish(
        &mut self,
        signature_b64: &str,
        origin_pk: Option<String>,
    ) -> Result<DappPairing, JsError> {
        let u = self.inner.take().ok_or_else(|| err("already finished"))?;
        let sig = b64::decode_array::<64>(signature_b64).map_err(err)?;
        let pk = origin_pk
            .map(|p| b64::decode_array::<32>(&p))
            .transpose()
            .map_err(err)?;
        Ok(DappPairing {
            inner: u.finish(sig, pk.as_ref()).map_err(err)?,
        })
    }
}

/// dApp waiting for the wallet's pairing reply.
#[wasm_bindgen]
pub struct DappPairing {
    inner: core_pairing::DappPairing,
}

#[wasm_bindgen]
impl DappPairing {
    /// `xchonnect:v1?…` URI for the QR code.
    pub fn uri(&self) -> String {
        self.inner.uri().to_uri()
    }

    /// Universal-link form for a wallet's link base (e.g. `https://klimper.app/pair`).
    #[wasm_bindgen(js_name = universalLink)]
    pub fn universal_link(&self, base: &str) -> String {
        self.inner.uri().to_universal_link(base)
    }

    /// Expiry of the URI (unix seconds).
    #[wasm_bindgen(js_name = expiresAt)]
    pub fn expires_at(&self) -> f64 {
        self.inner.uri().expires_at as f64
    }

    /// Process one envelope from the pairing mailbox. Throws for replies to ignore.
    #[wasm_bindgen(js_name = onReply)]
    pub fn on_reply(&mut self, now: f64, envelope_b64: &str) -> Result<AcceptedPairing, JsError> {
        let env = b64::decode(envelope_b64).map_err(err)?;
        Ok(AcceptedPairing {
            inner: Some(self.inner.on_reply(now as u64, &env).map_err(err)?),
        })
    }
}

/// Accepted pairing reply: show the SAS, then confirm with the new session mailbox.
#[wasm_bindgen]
pub struct AcceptedPairing {
    inner: Option<core_pairing::AcceptedPairing>,
}

/// Result of [`AcceptedPairing::confirm`].
#[wasm_bindgen]
pub struct Confirmed {
    session: Option<Session>,
    outgoing: Option<Outgoing>,
}

#[wasm_bindgen]
impl Confirmed {
    /// The new session (call once).
    #[wasm_bindgen(js_name = takeSession)]
    pub fn take_session(&mut self) -> Result<Session, JsError> {
        self.session.take().ok_or_else(|| err("already taken"))
    }

    /// The `session.confirm` envelope to post (call once).
    #[wasm_bindgen(js_name = takeOutgoing)]
    pub fn take_outgoing(&mut self) -> Result<Outgoing, JsError> {
        self.outgoing.take().ok_or_else(|| err("already taken"))
    }
}

#[wasm_bindgen]
impl AcceptedPairing {
    /// SAS as `"042 917"`.
    pub fn sas(&self) -> Result<String, JsError> {
        Ok(self
            .inner
            .as_ref()
            .ok_or_else(|| err("already confirmed"))?
            .sas()
            .to_string())
    }

    /// Wallet name from the pairing reply, if any.
    #[wasm_bindgen(js_name = walletName)]
    pub fn wallet_name(&self) -> Option<String> {
        self.inner.as_ref()?.wallet_meta()?.name.clone()
    }

    /// Wallet universal-link base for same-device requests, if any.
    #[wasm_bindgen(js_name = walletLink)]
    pub fn wallet_link(&self) -> Option<String> {
        self.inner.as_ref()?.wallet_meta()?.link.clone()
    }

    /// Create the session with the freshly created session mailbox D.
    pub fn confirm(
        &mut self,
        now: f64,
        session_mailbox: &str,
        read_token: &str,
        write_token: &str,
    ) -> Result<Confirmed, JsError> {
        let a = self.inner.take().ok_or_else(|| err("already confirmed"))?;
        let (s, out) = a
            .confirm(
                &mut OsEntropy,
                now as u64,
                mailbox(session_mailbox)?,
                token(read_token)?,
                token(write_token)?,
            )
            .map_err(err)?;
        Ok(Confirmed {
            session: Some(Session { inner: s }),
            outgoing: Some(out.into()),
        })
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// A paired session (dApp side in the browser).
#[wasm_bindgen]
pub struct Session {
    inner: core_session::Session,
}

fn message_json(inner: &Inner) -> Value {
    let id = b64::encode(&inner.id);
    let mut v = match &inner.message {
        Message::RpcRequest { method, params } => json!({ "method": method, "params": params }),
        Message::RpcResponse {
            request_id,
            outcome,
        } => match outcome {
            RpcOutcome::Result(r) => json!({ "requestId": b64::encode(request_id), "result": r }),
            RpcOutcome::Error(e) => {
                json!({ "requestId": b64::encode(request_id), "error": { "code": e.code, "message": e.message, "data": e.data } })
            }
        },
        Message::RpcReceived { request_id } => json!({ "requestId": b64::encode(request_id) }),
        Message::SessionReady { meta } => {
            json!({ "walletName": meta.as_ref().and_then(|m| m.name.clone()) })
        }
        Message::SessionRotate(r) => {
            json!({
                "phase": if r.phase == xchonnect_core::message::RotatePhase::Offer { "offer" } else { "accept" },
                "epoch": r.epoch,
                "epk": b64::encode(&r.epk),
                "mailbox": r.mailbox.to_b64(),
                "writeToken": b64::encode(r.write_token.expose()),
            })
        }
        Message::SessionPermissions(p) => json!({ "methods": p.methods, "keys": p.keys }),
        Message::SessionEnd { reason } => json!({ "reason": reason }),
        _ => json!({}),
    };
    if let Some(o) = v.as_object_mut() {
        o.insert("type".into(), json!(inner.message.type_name()));
        o.insert("id".into(), json!(id));
        o.insert("seq".into(), json!(inner.seq));
        o.insert("exp".into(), json!(inner.exp));
    }
    v
}

#[wasm_bindgen]
impl Session {
    /// Restore from [`Session::to_bytes`] (base64url).
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(state_b64: &str) -> Result<Session, JsError> {
        Ok(Session {
            inner: core_session::Session::from_bytes(&b64::decode(state_b64).map_err(err)?)
                .map_err(err)?,
        })
    }

    /// Serialise (base64url). Contains secrets: store encrypted (spec 12.1).
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Result<String, JsError> {
        Ok(b64::encode(&self.inner.to_bytes().map_err(err)?))
    }

    /// Requests may be exchanged.
    #[wasm_bindgen(js_name = isActive)]
    pub fn is_active(&self) -> bool {
        self.inner.is_active()
    }

    /// Wallet sent `session.ready`.
    #[wasm_bindgen(js_name = peerReady)]
    pub fn peer_ready(&self) -> bool {
        self.inner.peer_ready()
    }

    /// Session ended.
    #[wasm_bindgen(js_name = isEnded)]
    pub fn is_ended(&self) -> bool {
        self.inner.is_ended()
    }

    /// Current epoch.
    pub fn epoch(&self) -> f64 {
        self.inner.epoch() as f64
    }

    /// Mailbox to read.
    #[wasm_bindgen(js_name = ownMailbox)]
    pub fn own_mailbox(&self) -> String {
        self.inner.own_mailbox().to_b64()
    }

    /// Read token for [`Session::own_mailbox`].
    #[wasm_bindgen(js_name = ownReadToken)]
    pub fn own_read_token(&self) -> String {
        b64::encode(self.inner.own_read_token().expose())
    }

    /// Previous-epoch mailbox to drain first, as `[mailbox, readToken]`, if any.
    #[wasm_bindgen(js_name = drainingMailbox)]
    pub fn draining_mailbox(&self) -> Option<Vec<String>> {
        self.inner
            .draining_mailbox()
            .map(|(m, t)| vec![m.to_b64(), b64::encode(t.expose())])
    }

    /// A rotation offered by this side awaits the peer's accept.
    #[wasm_bindgen(js_name = rotationPending)]
    pub fn rotation_pending(&self) -> bool {
        self.inner.pending_rotation_mailbox().is_some()
    }

    /// Whether rotation thresholds are reached.
    #[wasm_bindgen(js_name = needsRotation)]
    pub fn needs_rotation(&self, now: f64) -> bool {
        self.inner.needs_rotation(now as u64)
    }

    /// The user confirmed the SAS on the dApp.
    #[wasm_bindgen(js_name = confirmSas)]
    pub fn confirm_sas(&mut self, now: f64) -> Result<Option<Outgoing>, JsError> {
        Ok(self
            .inner
            .confirm_sas(&mut OsEntropy, now as u64, None)
            .map_err(err)?
            .map(Outgoing::from))
    }

    /// Wallet: answer a request with a JSON result.
    pub fn respond(
        &mut self,
        now: f64,
        request_id_b64: &str,
        result_json: &str,
    ) -> Result<Outgoing, JsError> {
        let id = b64::decode_array::<16>(request_id_b64).map_err(err)?;
        let m = xchonnect_core::rpc::result(id, result_json).map_err(err)?;
        Ok(self
            .inner
            .seal(&mut OsEntropy, now as u64, m, 3600)
            .map_err(err)?
            .into())
    }

    /// Wallet: answer a request with an error.
    #[wasm_bindgen(js_name = respondError)]
    pub fn respond_error(
        &mut self,
        now: f64,
        request_id_b64: &str,
        code: i32,
        message: &str,
    ) -> Result<Outgoing, JsError> {
        let id = b64::decode_array::<16>(request_id_b64).map_err(err)?;
        let m = xchonnect_core::rpc::error(id, i64::from(code), message, None).map_err(err)?;
        Ok(self
            .inner
            .seal(&mut OsEntropy, now as u64, m, 3600)
            .map_err(err)?
            .into())
    }

    /// Wallet: delivery receipt for a request.
    pub fn received(&mut self, now: f64, request_id_b64: &str) -> Result<Outgoing, JsError> {
        let id = b64::decode_array::<16>(request_id_b64).map_err(err)?;
        Ok(self
            .inner
            .seal(
                &mut OsEntropy,
                now as u64,
                Message::RpcReceived { request_id: id },
                3600,
            )
            .map_err(err)?
            .into())
    }

    /// Accept a peer's rotation offer (fields from the opened `session.rotate`). The
    /// caller created `new_mailbox` first. Returns the accept to post.
    #[wasm_bindgen(js_name = acceptRotation)]
    #[allow(clippy::too_many_arguments)]
    pub fn accept_rotation(
        &mut self,
        now: f64,
        epoch: f64,
        epk_b64: &str,
        offer_mailbox: &str,
        offer_write_token: &str,
        new_mailbox: &str,
        read_token: &str,
        write_token: &str,
    ) -> Result<Outgoing, JsError> {
        let offer = xchonnect_core::message::Rotate {
            phase: xchonnect_core::message::RotatePhase::Offer,
            epoch: epoch as u64,
            epk: b64::decode_array::<32>(epk_b64).map_err(err)?,
            mailbox: mailbox(offer_mailbox)?,
            write_token: token(offer_write_token)?,
        };
        let (out, _abandoned) = self
            .inner
            .accept_rotation(
                &mut OsEntropy,
                now as u64,
                &offer,
                mailbox(new_mailbox)?,
                token(read_token)?,
                token(write_token)?,
            )
            .map_err(err)?;
        Ok(out.into())
    }

    /// The user reported mismatching codes: returns `session.end` to post.
    #[wasm_bindgen(js_name = rejectSas)]
    pub fn reject_sas(&mut self, now: f64) -> Result<Outgoing, JsError> {
        Ok(self
            .inner
            .reject_sas(&mut OsEntropy, now as u64)
            .map_err(err)?
            .into())
    }

    /// End the session: returns `session.end` to post.
    pub fn end(&mut self, now: f64, reason: Option<String>) -> Result<Outgoing, JsError> {
        Ok(self
            .inner
            .end(&mut OsEntropy, now as u64, reason)
            .map_err(err)?
            .into())
    }

    /// Seal an `rpc.request` (params as JSON text).
    pub fn request(
        &mut self,
        now: f64,
        method: &str,
        params_json: &str,
        ttl_s: u32,
    ) -> Result<Outgoing, JsError> {
        let m = xchonnect_core::rpc::request(method, params_json).map_err(err)?;
        Ok(self
            .inner
            .seal(&mut OsEntropy, now as u64, m, u64::from(ttl_s))
            .map_err(err)?
            .into())
    }

    /// Seal a `session.ping`.
    pub fn ping(&mut self, now: f64) -> Result<Outgoing, JsError> {
        Ok(self
            .inner
            .seal(&mut OsEntropy, now as u64, Message::SessionPing, 300)
            .map_err(err)?
            .into())
    }

    /// Open an envelope fetched from `mailbox`; returns the message as JSON text.
    pub fn open(
        &mut self,
        now: f64,
        mailbox_b64: &str,
        envelope_b64: &str,
    ) -> Result<String, JsError> {
        let env = b64::decode(envelope_b64).map_err(err)?;
        let inner = self
            .inner
            .open(now as u64, &mailbox(mailbox_b64)?, &env)
            .map_err(err)?;
        Ok(message_json(&inner).to_string())
    }

    /// Start a rotation; the caller created `new_mailbox` first.
    #[wasm_bindgen(js_name = beginRotation)]
    pub fn begin_rotation(
        &mut self,
        now: f64,
        new_mailbox: &str,
        read_token: &str,
        write_token: &str,
    ) -> Result<Outgoing, JsError> {
        Ok(self
            .inner
            .begin_rotation(
                &mut OsEntropy,
                now as u64,
                mailbox(new_mailbox)?,
                token(read_token)?,
                token(write_token)?,
            )
            .map_err(err)?
            .into())
    }

    /// Finish draining after rotation: returns `[mailbox, readToken]` to delete, if any.
    #[wasm_bindgen(js_name = finishDrain)]
    pub fn finish_drain(&mut self) -> Option<Vec<String>> {
        self.inner
            .finish_drain()
            .map(|r| vec![r.mailbox.to_b64(), b64::encode(r.read_token.expose())])
    }
}

/// Mailbox id helper for tests: SHA-256 of a token, used to check token hashing in JS.
#[wasm_bindgen(js_name = sha256)]
pub fn sha256(data_b64: &str) -> Result<String, JsError> {
    Ok(b64::encode(&crypto::sha256_parts(&[&b64::decode(
        data_b64,
    )
    .map_err(err)?])))
}

// ---------------------------------------------------------------------------
// Wallet side (tests, web wallets)
// ---------------------------------------------------------------------------

/// Wallet pairing waiting for `session.confirm`.
#[wasm_bindgen]
pub struct WalletPairing {
    inner: core_pairing::WalletPairing,
}

/// Result of [`WalletPairing::reply`].
#[wasm_bindgen]
pub struct WalletReply {
    pairing: Option<WalletPairing>,
    outgoing: Option<Outgoing>,
    domain: String,
    dapp_name: String,
}

#[wasm_bindgen]
impl WalletReply {
    /// The pairing state (call once).
    #[wasm_bindgen(js_name = takePairing)]
    pub fn take_pairing(&mut self) -> Result<WalletPairing, JsError> {
        self.pairing.take().ok_or_else(|| err("already taken"))
    }
    /// The pairing reply envelope (call once).
    #[wasm_bindgen(js_name = takeOutgoing)]
    pub fn take_outgoing(&mut self) -> Result<Outgoing, JsError> {
        self.outgoing.take().ok_or_else(|| err("already taken"))
    }
    /// Verified dApp domain.
    #[wasm_bindgen(getter)]
    pub fn domain(&self) -> String {
        self.domain.clone()
    }
    /// dApp name from the origin document.
    #[wasm_bindgen(getter, js_name = dappName)]
    pub fn dapp_name(&self) -> String {
        self.dapp_name.clone()
    }
}

/// Parse a pairing URI without verifying it; returns JSON with `relay`, `domain`,
/// `expiresAt` so the wallet knows where to fetch the origin document.
#[wasm_bindgen(js_name = inspectUri)]
pub fn inspect_uri(uri: &str, developer_mode: bool) -> Result<String, JsError> {
    let u = xchonnect_core::uri::PairingUri::parse(uri, ParseOptions { developer_mode })
        .map_err(err)?;
    Ok(json!({ "relay": u.relay, "domain": u.domain, "expiresAt": u.expires_at, "ticket": u.ticket.map(|t| b64::encode(&t)) }).to_string())
}

#[wasm_bindgen]
impl WalletPairing {
    /// Verify the URI against the fetched origin document and build the pairing reply.
    #[allow(clippy::too_many_arguments)]
    pub fn reply(
        uri: &str,
        origin_document_json: &str,
        now: f64,
        own_mailbox: &str,
        read_token: &str,
        write_token: &str,
        wallet_name: Option<String>,
        developer_mode: bool,
        wallet_link: Option<String>,
    ) -> Result<WalletReply, JsError> {
        let parsed = xchonnect_core::uri::PairingUri::parse(uri, ParseOptions { developer_mode })
            .map_err(err)?;
        let doc = xchonnect_core::origin::OriginDocument::parse(origin_document_json.as_bytes())
            .map_err(err)?;
        let domain = parsed.domain.clone();
        let verified = core_pairing::VerifiedUri::new(parsed, &doc, now as u64).map_err(err)?;
        let meta = (wallet_name.is_some() || wallet_link.is_some()).then(|| {
            xchonnect_core::message::WalletMeta {
                name: wallet_name,
                link: wallet_link,
                ..Default::default()
            }
        });
        let (p, out) = core_pairing::WalletPairing::reply(
            &mut OsEntropy,
            now as u64,
            &verified,
            mailbox(own_mailbox)?,
            token(read_token)?,
            token(write_token)?,
            meta,
        )
        .map_err(err)?;
        Ok(WalletReply {
            pairing: Some(WalletPairing { inner: p }),
            outgoing: Some(out.into()),
            domain,
            dapp_name: verified.dapp_name().to_owned(),
        })
    }

    /// SAS as `"042 917"`.
    pub fn sas(&self) -> String {
        self.inner.sas().to_string()
    }

    /// Process `session.confirm`; returns the wallet session (not yet active).
    #[wasm_bindgen(js_name = onConfirm)]
    pub fn on_confirm(&self, now: f64, envelope_b64: &str) -> Result<Session, JsError> {
        let env = b64::decode(envelope_b64).map_err(err)?;
        Ok(Session {
            inner: self.inner.on_confirm(now as u64, &env).map_err(err)?,
        })
    }
}
