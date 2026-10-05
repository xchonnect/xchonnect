//! WebAssembly bindings of `xchonnect-core` for the dApp SDK.
//!
//! Conventions: binary values cross the boundary as base64url strings (no padding);
//! times are unix seconds passed in by the caller; decoded messages are returned as
//! JSON text; every error becomes a JS `Error` whose message never contains secrets
//! (core errors convert through `JsError: From<E: Error>`, i.e. their `Display` text).

use serde_json::{Value, json};
use wasm_bindgen::prelude::*;
use xchonnect_core::b64;
use xchonnect_core::crypto::{self, Ed25519Seed, Entropy, MailboxId, OsEntropy, Token};
use xchonnect_core::message::{
    Inner, Limits, Message, Permissions, RotatePhase, RpcOutcome, WalletMeta,
};
use xchonnect_core::origin::OriginDocument;
use xchonnect_core::pairing::{self as core_pairing, DappPairingParams};
use xchonnect_core::session::{self as core_session};
use xchonnect_core::uri::{PairingUri, ParseOptions};

mod vectors;

fn err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

fn mailbox(s: &str) -> Result<MailboxId, JsError> {
    Ok(MailboxId::from_b64(s)?)
}

fn token(s: &str) -> Result<Token, JsError> {
    Ok(Token::from_bytes(b64::decode_array::<32>(s)?))
}

fn opt_bytes32(s: Option<String>) -> Result<Option<[u8; 32]>, JsError> {
    Ok(s.map(|t| b64::decode_array::<32>(&t)).transpose()?)
}

fn creds(m: MailboxId, t: &Token) -> Vec<String> {
    vec![m.to_b64(), b64::encode(t.expose())]
}

/// Shared by [`UnsignedPairing::prepare`] and the test-vector entry point.
#[allow(clippy::too_many_arguments)]
fn prepare_pairing(
    rng: &mut dyn Entropy,
    relay: &str,
    domain: &str,
    pairing_mailbox: &str,
    pairing_write_token: &str,
    lifetime_s: u32,
    now: f64,
    kid: &str,
    ticket: Option<String>,
    options: ParseOptions,
) -> Result<core_pairing::UnsignedPairing, JsError> {
    let ticket = opt_bytes32(ticket)?;
    let p = DappPairingParams {
        relay,
        domain,
        pairing_mailbox: mailbox(pairing_mailbox)?,
        pairing_write: token(pairing_write_token)?,
        lifetime_s: u64::from(lifetime_s),
        ticket,
        options,
    };
    Ok(core_pairing::DappPairing::prepare(rng, now as u64, kid, p)?)
}

/// Shared by [`WalletPairing::reply`] and the test-vector entry point.
#[allow(clippy::too_many_arguments)]
fn wallet_reply(
    rng: &mut dyn Entropy,
    uri: &str,
    origin_document_json: &str,
    now: f64,
    own_mailbox: &str,
    read_token: &str,
    write_token: &str,
    wallet_name: Option<String>,
    wallet_link: Option<String>,
    developer_mode: bool,
) -> Result<WalletReply, JsError> {
    let parsed = PairingUri::parse(uri, ParseOptions { developer_mode })?;
    let doc = OriginDocument::parse(origin_document_json.as_bytes())?;
    let domain = parsed.domain.clone();
    let verified = core_pairing::VerifiedUri::new(parsed, &doc, now as u64)?;
    let meta = (wallet_name.is_some() || wallet_link.is_some()).then(|| WalletMeta {
        name: wallet_name,
        link: wallet_link,
        ..Default::default()
    });
    let (p, out) = core_pairing::WalletPairing::reply(
        rng,
        now as u64,
        &verified,
        mailbox(own_mailbox)?,
        token(read_token)?,
        token(write_token)?,
        meta,
    )?;
    Ok(WalletReply {
        pairing: Some(WalletPairing { inner: p }),
        outgoing: Some(out.into()),
        domain,
        dapp_name: verified.dapp_name().to_owned(),
    })
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
    let c = b64::decode(challenge_b64)?;
    Ok(b64::encode(&xchonnect_core::pow::solve(&c)?))
}

/// Development only: sign with an in-browser origin seed. Production dApps sign on
/// their backend or KMS.
#[wasm_bindgen(js_name = devSign)]
pub fn dev_sign(seed_b64: &str, msg_b64: &str) -> Result<String, JsError> {
    let seed = Ed25519Seed::from_bytes(b64::decode_array::<32>(seed_b64)?);
    Ok(b64::encode(&seed.sign(&b64::decode(msg_b64)?)))
}

/// Development only: Ed25519 public key for a seed.
#[wasm_bindgen(js_name = devPublicKey)]
pub fn dev_public_key(seed_b64: &str) -> Result<String, JsError> {
    let seed = Ed25519Seed::from_bytes(b64::decode_array::<32>(seed_b64)?);
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
        let inner = prepare_pairing(
            &mut OsEntropy,
            relay,
            domain,
            pairing_mailbox,
            pairing_write_token,
            lifetime_s,
            now,
            kid,
            ticket,
            ParseOptions { developer_mode },
        )?;
        Ok(UnsignedPairing { inner: Some(inner) })
    }

    /// Bytes to sign with the origin key (base64url).
    #[wasm_bindgen(js_name = sigInput)]
    pub fn sig_input(&self) -> Result<String, JsError> {
        let u = self.inner.as_ref().ok_or_else(|| err("already finished"))?;
        Ok(b64::encode(&u.sig_input()?))
    }

    /// Insert the signature; verifies it first when `origin_pk` is given.
    pub fn finish(
        &mut self,
        signature_b64: &str,
        origin_pk: Option<String>,
    ) -> Result<DappPairing, JsError> {
        let u = self.inner.take().ok_or_else(|| err("already finished"))?;
        let sig = b64::decode_array::<64>(signature_b64)?;
        let pk = opt_bytes32(origin_pk)?;
        Ok(DappPairing {
            inner: u.finish(sig, pk.as_ref())?,
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

    /// Universal-link form for a wallet's link base (e.g. `https://wallet.example/pair`).
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
        let env = b64::decode(envelope_b64)?;
        Ok(AcceptedPairing {
            inner: Some(self.inner.on_reply(now as u64, &env)?),
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
        let a = self
            .inner
            .as_ref()
            .ok_or_else(|| err("already confirmed"))?;
        Ok(a.sas().to_string())
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
        let (s, out) = a.confirm(
            &mut OsEntropy,
            now as u64,
            mailbox(session_mailbox)?,
            token(read_token)?,
            token(write_token)?,
        )?;
        Ok(Confirmed {
            session: Some(Session {
                inner: s,
                abandoned: None,
            }),
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
    /// Set by `acceptRotation`, taken by `takeAbandonedMailbox`.
    abandoned: Option<Vec<String>>,
}

fn message_json(inner: &Inner) -> Value {
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
        Message::RpcReceived { request_id } | Message::RpcCancel { request_id } => {
            json!({ "requestId": b64::encode(request_id) })
        }
        Message::RpcStatus {
            request_id,
            state,
            tx_id,
        } => json!({
            "requestId": b64::encode(request_id),
            "state": state,
            "txId": tx_id.map(|id| format!("0x{}", hex::encode(id))),
        }),
        Message::SessionReady { meta } => {
            json!({ "walletName": meta.as_ref().and_then(|m| m.name.clone()) })
        }
        Message::SessionRotate(r) => {
            json!({
                "phase": if r.phase == RotatePhase::Offer { "offer" } else { "accept" },
                "epoch": r.epoch,
                "epk": b64::encode(&r.epk),
                "mailbox": r.mailbox.to_b64(),
                "writeToken": b64::encode(r.write_token.expose()),
            })
        }
        Message::SessionPermissions(p) => json!({
            "methods": p.methods,
            "keys": p.keys,
            "limits": p.limits.as_ref().map(|l| json!({
                "perRequestMojos": l.per_request_mojos,
                "perDayMojos": l.per_day_mojos,
            })),
        }),
        Message::SessionEnd { reason } => json!({ "reason": reason }),
        _ => json!({}),
    };
    if let Some(o) = v.as_object_mut() {
        o.insert("type".into(), json!(inner.message.type_name()));
        o.insert("id".into(), json!(b64::encode(&inner.id)));
        o.insert("seq".into(), json!(inner.seq));
        o.insert("exp".into(), json!(inner.exp));
    }
    v
}

impl Session {
    fn seal(&mut self, now: f64, msg: Message, ttl_s: u64) -> Result<Outgoing, JsError> {
        Ok(self
            .inner
            .seal(&mut OsEntropy, now as u64, msg, ttl_s)?
            .into())
    }
}

#[wasm_bindgen]
impl Session {
    /// Restore from [`Session::to_bytes`] (base64url).
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(state_b64: &str) -> Result<Session, JsError> {
        let inner = core_session::Session::from_bytes(&b64::decode(state_b64)?)?;
        Ok(Session {
            inner,
            abandoned: None,
        })
    }

    /// Serialise (base64url). Contains secrets: store encrypted (spec 12.1).
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Result<String, JsError> {
        Ok(b64::encode(&self.inner.to_bytes()?))
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
        self.inner.draining_mailbox().map(|(m, t)| creds(m, t))
    }

    /// A rotation offered by this side awaits the peer's accept.
    #[wasm_bindgen(js_name = rotationPending)]
    pub fn rotation_pending(&self) -> bool {
        self.inner.pending_rotation_mailbox().is_some()
    }

    /// Mailbox this side created for its pending rotation offer, as `[mailbox,
    /// readToken]`: poll it for the peer's accept (also after a restore).
    #[wasm_bindgen(js_name = pendingRotationMailbox)]
    pub fn pending_rotation_mailbox(&self) -> Option<Vec<String>> {
        self.inner
            .pending_rotation_mailbox()
            .map(|(m, t)| creds(m, t))
    }

    /// Mailbox abandoned by the last [`Self::accept_rotation`] (concurrent offers: the
    /// wallet drops its own offer), as `[mailbox, readToken]`; delete it on the relay.
    /// Cleared by the next call.
    #[wasm_bindgen(js_name = takeAbandonedMailbox)]
    pub fn take_abandoned_mailbox(&mut self) -> Option<Vec<String>> {
        self.abandoned.take()
    }

    /// Whether rotation thresholds are reached.
    #[wasm_bindgen(js_name = needsRotation)]
    pub fn needs_rotation(&self, now: f64) -> bool {
        self.inner.needs_rotation(now as u64)
    }

    /// The user confirmed the SAS on the dApp.
    #[wasm_bindgen(js_name = confirmSas)]
    pub fn confirm_sas(&mut self, now: f64) -> Result<Option<Outgoing>, JsError> {
        let out = self.inner.confirm_sas(&mut OsEntropy, now as u64, None)?;
        Ok(out.map(Outgoing::from))
    }

    /// Wallet: answer a request with a JSON result.
    pub fn respond(
        &mut self,
        now: f64,
        request_id_b64: &str,
        result_json: &str,
    ) -> Result<Outgoing, JsError> {
        let id = b64::decode_array::<16>(request_id_b64)?;
        self.seal(now, xchonnect_core::rpc::result(id, result_json)?, 3600)
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
        let id = b64::decode_array::<16>(request_id_b64)?;
        let m = xchonnect_core::rpc::error(id, i64::from(code), message, None)?;
        self.seal(now, m, 3600)
    }

    /// Wallet: declare the granted scopes (`session.permissions`, spec 9.3). The limits
    /// are decimal mojo strings; pass `undefined` for "no limit of this kind".
    pub fn permissions(
        &mut self,
        now: f64,
        methods: Vec<String>,
        keys: Vec<String>,
        per_request_mojos: Option<String>,
        per_day_mojos: Option<String>,
    ) -> Result<Outgoing, JsError> {
        let declared = per_request_mojos.is_some() || per_day_mojos.is_some();
        let limits = declared.then_some(Limits {
            per_request_mojos,
            per_day_mojos,
        });
        let m = Message::SessionPermissions(Permissions {
            methods,
            keys,
            limits,
        });
        self.seal(now, m, 3600)
    }

    /// Wallet: delivery receipt for a request.
    pub fn received(&mut self, now: f64, request_id_b64: &str) -> Result<Outgoing, JsError> {
        let request_id = b64::decode_array::<16>(request_id_b64)?;
        self.seal(now, Message::RpcReceived { request_id }, 3600)
    }

    /// dApp: withdraw a request the user has not decided yet (`rpc.cancel`, spec 9.1).
    pub fn cancel(&mut self, now: f64, request_id_b64: &str) -> Result<Outgoing, JsError> {
        let request_id = b64::decode_array::<16>(request_id_b64)?;
        self.seal(now, Message::RpcCancel { request_id }, 3600)
    }

    /// Wallet: report where a request is (`rpc.status`): `shown`, `approved` or
    /// `broadcast`, the last with the transaction id (hex, `0x` optional).
    pub fn status(
        &mut self,
        now: f64,
        request_id_b64: &str,
        state: &str,
        tx_id_hex: Option<String>,
    ) -> Result<Outgoing, JsError> {
        let request_id = b64::decode_array::<16>(request_id_b64)?;
        if !xchonnect_core::message::RPC_STATUS_STATES.contains(&state) {
            return Err(JsError::new("unknown status state"));
        }
        let tx_id = match tx_id_hex {
            None => None,
            Some(hex_id) => {
                let bytes = hex::decode(hex_id.trim_start_matches("0x"))
                    .map_err(|_| JsError::new("txId is not hex"))?;
                Some(
                    <[u8; 32]>::try_from(bytes.as_slice())
                        .map_err(|_| JsError::new("txId is not 32 bytes"))?,
                )
            }
        };
        self.seal(
            now,
            Message::RpcStatus {
                request_id,
                state: state.to_owned(),
                tx_id,
            },
            3600,
        )
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
            phase: RotatePhase::Offer,
            epoch: epoch as u64,
            epk: b64::decode_array::<32>(epk_b64)?,
            mailbox: mailbox(offer_mailbox)?,
            write_token: token(offer_write_token)?,
        };
        let (out, abandoned) = self.inner.accept_rotation(
            &mut OsEntropy,
            now as u64,
            &offer,
            mailbox(new_mailbox)?,
            token(read_token)?,
            token(write_token)?,
        )?;
        self.abandoned = abandoned.map(|r| creds(r.mailbox, &r.read_token));
        Ok(out.into())
    }

    /// The user reported mismatching codes: returns `session.end` to post.
    #[wasm_bindgen(js_name = rejectSas)]
    pub fn reject_sas(&mut self, now: f64) -> Result<Outgoing, JsError> {
        Ok(self.inner.reject_sas(&mut OsEntropy, now as u64)?.into())
    }

    /// End the session: returns `session.end` to post.
    pub fn end(&mut self, now: f64, reason: Option<String>) -> Result<Outgoing, JsError> {
        Ok(self.inner.end(&mut OsEntropy, now as u64, reason)?.into())
    }

    /// Seal an `rpc.request` (params as JSON text).
    pub fn request(
        &mut self,
        now: f64,
        method: &str,
        params_json: &str,
        ttl_s: u32,
    ) -> Result<Outgoing, JsError> {
        let m = xchonnect_core::rpc::request(method, params_json)?;
        self.seal(now, m, u64::from(ttl_s))
    }

    /// Seal a `session.ping`.
    pub fn ping(&mut self, now: f64) -> Result<Outgoing, JsError> {
        self.seal(now, Message::SessionPing, 300)
    }

    /// Open an envelope fetched from `mailbox`; returns the message as JSON text.
    pub fn open(
        &mut self,
        now: f64,
        mailbox_b64: &str,
        envelope_b64: &str,
    ) -> Result<String, JsError> {
        let env = b64::decode(envelope_b64)?;
        let inner = self.inner.open(now as u64, &mailbox(mailbox_b64)?, &env)?;
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
        let out = self.inner.begin_rotation(
            &mut OsEntropy,
            now as u64,
            mailbox(new_mailbox)?,
            token(read_token)?,
            token(write_token)?,
        )?;
        Ok(out.into())
    }

    /// Finish draining after rotation: returns `[mailbox, readToken]` to delete, if any.
    #[wasm_bindgen(js_name = finishDrain)]
    pub fn finish_drain(&mut self) -> Option<Vec<String>> {
        self.inner
            .finish_drain()
            .map(|r| creds(r.mailbox, &r.read_token))
    }
}

/// Mailbox id helper for tests: SHA-256 of a token, used to check token hashing in JS.
#[wasm_bindgen(js_name = sha256)]
pub fn sha256(data_b64: &str) -> Result<String, JsError> {
    Ok(b64::encode(&crypto::sha256_parts(&[&b64::decode(
        data_b64,
    )?])))
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
    let u = PairingUri::parse(uri, ParseOptions { developer_mode })?;
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
        wallet_reply(
            &mut OsEntropy,
            uri,
            origin_document_json,
            now,
            own_mailbox,
            read_token,
            write_token,
            wallet_name,
            wallet_link,
            developer_mode,
        )
    }

    /// SAS as `"042 917"`.
    pub fn sas(&self) -> String {
        self.inner.sas().to_string()
    }

    /// Process `session.confirm`; returns the wallet session (not yet active).
    #[wasm_bindgen(js_name = onConfirm)]
    pub fn on_confirm(&self, now: f64, envelope_b64: &str) -> Result<Session, JsError> {
        let env = b64::decode(envelope_b64)?;
        Ok(Session {
            inner: self.inner.on_confirm(now as u64, &env)?,
            abandoned: None,
        })
    }
}

// ---------------------------------------------------------------------------
// Oblivious HTTP client (spec 10, TASK-52)
//
// Encapsulated messages and key configurations cross the boundary as raw bytes
// (`Uint8Array`), since they are HTTP bodies; the host's `fetch` sends them.
// ---------------------------------------------------------------------------

/// The configuration to pin from an `application/ohttp-keys` list obtained out of band
/// (the newest usable entry). Returns the encoded key configuration.
#[wasm_bindgen(js_name = ohttpSelectKey)]
pub fn ohttp_select_key(list: &[u8]) -> Result<Vec<u8>, JsError> {
    Ok(xchonnect_core::ohttp::select(list)?.encoded().to_vec())
}

/// OHTTP client for one pinned gateway key configuration.
#[wasm_bindgen]
pub struct OhttpClient {
    inner: xchonnect_core::ohttp::Client,
}

#[wasm_bindgen]
impl OhttpClient {
    /// Client for an encoded key configuration (from `ohttpSelectKey`/`decapsulateKeyRotation`).
    #[wasm_bindgen(constructor)]
    pub fn new(config: &[u8]) -> Result<OhttpClient, JsError> {
        let config = xchonnect_core::ohttp::KeyConfig::decode(config)?;
        Ok(OhttpClient {
            inner: xchonnect_core::ohttp::Client::new(config),
        })
    }

    /// Key identifier of the pinned configuration.
    #[wasm_bindgen(getter, js_name = keyId)]
    pub fn key_id(&self) -> u8 {
        self.inner.config().key_id()
    }

    /// Encapsulate an inner request. `headers_json` is `[[name, value], ...]`.
    pub fn encapsulate(
        &self,
        method: &str,
        scheme: &str,
        authority: &str,
        path: &str,
        headers_json: &str,
        body: Option<Vec<u8>>,
    ) -> Result<OhttpPending, JsError> {
        let headers: Vec<(String, String)> = serde_json::from_str(headers_json)?;
        let body = body.unwrap_or_default();
        let req = xchonnect_core::ohttp::Request {
            method,
            scheme,
            authority,
            path,
            headers: &headers,
            body: &body,
        };
        let (request, ctx) = self.inner.encapsulate(&mut OsEntropy, &req)?;
        Ok(OhttpPending {
            request,
            ctx: Some(ctx),
        })
    }
}

/// An encapsulated request waiting for its response (single use).
#[wasm_bindgen]
pub struct OhttpPending {
    request: Vec<u8>,
    ctx: Option<xchonnect_core::ohttp::ResponseContext>,
}

impl OhttpPending {
    fn take(&mut self) -> Result<xchonnect_core::ohttp::ResponseContext, JsError> {
        self.ctx
            .take()
            .ok_or_else(|| err("OHTTP response already decapsulated"))
    }
}

#[wasm_bindgen]
impl OhttpPending {
    /// The `message/ohttp-req` body to POST to the OHTTP relay.
    #[wasm_bindgen(getter)]
    pub fn request(&self) -> Vec<u8> {
        self.request.clone()
    }

    /// Decapsulate the answer to an encapsulated `GET /.well-known/ohttp-keys` and return
    /// the new pin (newest entry). Throws unless the pinned key's holder produced it, for
    /// a non-200 answer, or when the list no longer contains the pinned key (a hard
    /// error: the app needs an updated pin). Can be called once (instead of
    /// `decapsulate`).
    #[wasm_bindgen(js_name = decapsulateKeyRotation)]
    pub fn decapsulate_key_rotation(&mut self, response: &[u8]) -> Result<Vec<u8>, JsError> {
        let pin = self.take()?.decapsulate_key_rotation(response)?;
        Ok(pin.encoded().to_vec())
    }

    /// Decapsulate the `message/ohttp-res` body. Can be called once.
    pub fn decapsulate(&mut self, response: &[u8]) -> Result<OhttpResponse, JsError> {
        let r = self.take()?.decapsulate(response)?;
        Ok(OhttpResponse {
            status: r.status,
            headers: serde_json::to_string(&r.headers)?,
            body: r.body,
        })
    }
}

/// A decapsulated inner response.
#[wasm_bindgen]
pub struct OhttpResponse {
    status: u16,
    headers: String,
    body: Vec<u8>,
}

#[wasm_bindgen]
impl OhttpResponse {
    /// Status code.
    #[wasm_bindgen(getter)]
    pub fn status(&self) -> u16 {
        self.status
    }

    /// Header fields as JSON `[[name, value], ...]` (lowercase names).
    #[wasm_bindgen(getter)]
    pub fn headers(&self) -> String {
        self.headers.clone()
    }

    /// Content.
    #[wasm_bindgen(getter)]
    pub fn body(&self) -> Vec<u8> {
        self.body.clone()
    }
}

// ---------------------------------------------------------------------------
// Multi-party signing helpers (TASK-57)
// ---------------------------------------------------------------------------

/// Aggregate BLS signatures (hex, compressed G2, optional `0x`). Used by dApps that
/// collect `partialSign` results from several wallets.
pub fn aggregate_signatures_hex(signatures: &[String]) -> Result<String, String> {
    use bls12_381::{G2Affine, G2Projective};
    let mut acc = G2Projective::identity();
    for s in signatures {
        let raw = hex::decode(s.strip_prefix("0x").unwrap_or(s))
            .map_err(|_| "signature is not hex".to_owned())?;
        let bytes: [u8; 96] = raw
            .try_into()
            .map_err(|_| "signature must be 96 bytes".to_owned())?;
        let point = Option::<G2Affine>::from(G2Affine::from_compressed(&bytes))
            .ok_or_else(|| "invalid signature point".to_owned())?;
        acc += G2Projective::from(point);
    }
    Ok(format!(
        "0x{}",
        hex::encode(G2Affine::from(acc).to_compressed())
    ))
}

/// Aggregate BLS signatures from several wallets (hex strings) into one.
#[wasm_bindgen(js_name = aggregateSignatures)]
pub fn aggregate_signatures(signatures: Vec<String>) -> Result<String, JsError> {
    aggregate_signatures_hex(&signatures).map_err(err)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod aggregate_tests {
    use super::aggregate_signatures_hex;

    #[test]
    fn matches_chia_bls_aggregation() {
        let sk1 = chia_bls::SecretKey::from_seed(&[1; 32]);
        let sk2 = chia_bls::SecretKey::from_seed(&[2; 32]);
        let s1 = chia_bls::sign(&sk1, b"one");
        let s2 = chia_bls::sign(&sk2, b"two");
        let mut expected = s1.clone();
        expected.aggregate(&s2);
        let got = aggregate_signatures_hex(&[
            hex::encode(s1.to_bytes()),
            format!("0x{}", hex::encode(s2.to_bytes())),
        ])
        .unwrap();
        assert_eq!(got, format!("0x{}", hex::encode(expected.to_bytes())));
        assert_eq!(
            aggregate_signatures_hex(&[]).unwrap(),
            format!(
                "0x{}",
                hex::encode(chia_bls::Signature::default().to_bytes())
            )
        );
        assert!(aggregate_signatures_hex(&["00".repeat(96)]).is_err());
    }
}
