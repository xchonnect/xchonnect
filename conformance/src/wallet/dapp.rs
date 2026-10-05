//! The dApp half of the protocol, as the suite plays it: relay calls, the pairing
//! handshake and a live session (spec 6.3, 7.1, 9).
//!
//! This is deliberately a thin layer over `xchonnect-core`: the suite must speak the
//! protocol correctly so that every failure it reports is the wallet's.

use crate::http::{Client, Req};
use crate::report::{Fail, ensure};
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use xchonnect_core::crypto::{MailboxId, OsEntropy, Token};
use xchonnect_core::message::{Inner, Message, Permissions, RpcOutcome, WalletMeta};
use xchonnect_core::pairing::{AcceptedPairing, DappPairing, DappPairingParams};
use xchonnect_core::session::{Outgoing, Session};
use xchonnect_core::uri::{OriginSigner, ParseOptions};
use xchonnect_core::{b64, pow};

/// How long a single relay long-poll waits.
const POLL_WAIT_S: u64 = 2;
/// Longest `Retry-After` the suite waits out when the relay rate-limits it.
const MAX_PACING_SLEEP_S: u64 = 15;
/// Total time one relay call may spend waiting out rate limits.
const PACING_BUDGET: Duration = Duration::from_secs(60);

// --- relay ---------------------------------------------------------------------------

/// A mailbox the suite owns on the relay.
pub(crate) struct Mailbox {
    pub(crate) id: MailboxId,
    pub(crate) read: Token,
    pub(crate) write: Token,
}

impl std::fmt::Debug for Mailbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Mailbox({}, [redacted])", self.id.to_b64())
    }
}

/// Relay the suite and the wallet meet on.
#[derive(Debug)]
pub(crate) struct Relay {
    client: Client,
    pub(crate) base_url: String,
    info: Value,
}

impl Relay {
    /// Connect and read `GET /v1/info`.
    pub(crate) fn connect(base_url: &str) -> Result<Self, String> {
        let client = Client::new(base_url);
        let r = client
            .send(&Req::new("GET", "/v1/info"))
            .map_err(|e| format!("relay {base_url}: {e}"))?;
        if r.status != 200 {
            return Err(format!("relay {base_url}: GET /v1/info: {}", r.describe()));
        }
        Ok(Relay {
            client,
            base_url: base_url.trim_end_matches('/').to_owned(),
            info: r.json(),
        })
    }

    fn offers(&self, method: &str) -> bool {
        self.info
            .get("mailbox_creation")
            .and_then(Value::as_array)
            .is_some_and(|a| a.iter().any(|m| m.as_str() == Some(method)))
    }

    /// Send a request, waiting out a short `Retry-After` so the relay's rate limits do
    /// not look like wallet failures.
    fn call(&self, req: &Req, what: &str) -> Result<Value, Fail> {
        let started = Instant::now();
        loop {
            let r = self.client.send(req)?;
            if (200..300).contains(&r.status) {
                return Ok(r.json());
            }
            let retry_after = (r.status == 429)
                .then(|| r.header("retry-after").and_then(|v| v.trim().parse().ok()))
                .flatten()
                .filter(|s: &u64| *s <= MAX_PACING_SLEEP_S);
            match retry_after {
                Some(s) if started.elapsed() < PACING_BUDGET => {
                    std::thread::sleep(Duration::from_secs(s.max(1)));
                }
                _ => return Err(Fail::Fail(format!("relay {what}: {}", r.describe()))),
            }
        }
    }

    /// Create a mailbox, solving the proof-of-work if the relay asks for one.
    pub(crate) fn create_mailbox(&self) -> Result<Mailbox, Fail> {
        let (read, write) = (Token::random(&mut OsEntropy), Token::random(&mut OsEntropy));
        let mut body = json!({
            "read_token_hash": b64::encode(&read.hash()),
            "write_token_hash": b64::encode(&write.hash()),
        });
        if !self.offers("open") {
            if !self.offers("pow") {
                return Err(Fail::Skip(
                    "the relay offers neither open nor proof-of-work mailbox creation; the \
                     wallet suite needs a relay it can create mailboxes on"
                        .to_owned(),
                ));
            }
            let c = self.call(&Req::new("POST", "/v1/challenge"), "POST /v1/challenge")?;
            let challenge = c
                .get("challenge")
                .and_then(Value::as_str)
                .and_then(|s| b64::decode(s).ok())
                .ok_or_else(|| Fail::Fail("relay: no base64url challenge".to_owned()))?;
            let nonce = pow::solve(&challenge)
                .map_err(|e| Fail::Fail(format!("cannot solve the challenge: {e}")))?;
            if let Some(o) = body.as_object_mut() {
                o.insert(
                    "pow".into(),
                    json!({ "challenge": b64::encode(&challenge), "nonce": b64::encode(&nonce) }),
                );
            }
        }
        let v = self.call(
            &Req::new("POST", "/v1/mailboxes").json(&body),
            "POST /v1/mailboxes",
        )?;
        let id = v
            .get("mailbox_id")
            .and_then(Value::as_str)
            .and_then(|s| MailboxId::from_b64(s).ok())
            .ok_or_else(|| Fail::Fail("relay: no mailbox_id in the 201".to_owned()))?;
        Ok(Mailbox { id, read, write })
    }

    /// Post a raw envelope to a mailbox the suite has the write token for.
    pub(crate) fn post_raw(
        &self,
        mailbox: &MailboxId,
        write: &Token,
        envelope: &[u8],
    ) -> Result<(), Fail> {
        let req = Req::new(
            "POST",
            format!("/v1/mailboxes/{}/messages", mailbox.to_b64()),
        )
        .bearer(write.expose())
        .json(&json!({ "env": b64::encode(envelope) }));
        self.call(&req, "POST messages")?;
        Ok(())
    }

    /// Post what a session sealed.
    pub(crate) fn post(&self, out: &Outgoing) -> Result<(), Fail> {
        self.post_raw(&out.mailbox, &out.write_token, &out.envelope)
    }

    /// Fetch and acknowledge everything in a mailbox, waiting up to `wait` seconds.
    pub(crate) fn drain(
        &self,
        mailbox: &MailboxId,
        read: &Token,
        wait: u64,
    ) -> Result<Vec<Vec<u8>>, Fail> {
        let path = format!("/v1/mailboxes/{}/messages?wait={wait}", mailbox.to_b64());
        let v = self.call(&Req::new("GET", path).bearer(read.expose()), "GET messages")?;
        let mut ids = Vec::new();
        let mut envelopes = Vec::new();
        for m in v
            .get("messages")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let (Some(id), Some(env)) = (
                m.get("msg_id").and_then(Value::as_str),
                m.get("env").and_then(Value::as_str),
            ) else {
                return Err(Fail::Fail(format!("relay: malformed message entry {m}")));
            };
            ids.push(id.to_owned());
            envelopes.push(
                b64::decode(env)
                    .map_err(|_| Fail::Fail("relay: env is not base64url".to_owned()))?,
            );
        }
        if !ids.is_empty() {
            let req = Req::new("POST", format!("/v1/mailboxes/{}/ack", mailbox.to_b64()))
                .bearer(read.expose())
                .json(&json!({ "msg_ids": ids }));
            self.call(&req, "POST ack")?;
        }
        Ok(envelopes)
    }

    /// Delete a mailbox, best effort.
    pub(crate) fn delete(&self, mailbox: &MailboxId, read: &Token) {
        let req =
            Req::new("DELETE", format!("/v1/mailboxes/{}", mailbox.to_b64())).bearer(read.expose());
        let _ = self.client.send(&req);
    }
}

// --- pairing -------------------------------------------------------------------------

/// A pairing the suite has published and is waiting on.
pub(crate) struct Pairing {
    /// The URI as the wallet receives it (possibly tampered with on purpose).
    pub(crate) uri: String,
    dapp: DappPairing,
    /// Pairing mailbox P.
    pub(crate) mailbox: Mailbox,
}

impl std::fmt::Debug for Pairing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pairing").finish_non_exhaustive()
    }
}

/// Inputs for one pairing URI.
pub(crate) struct UriSpec<'a> {
    pub(crate) signer: &'a dyn OriginSigner,
    pub(crate) domain: &'a str,
    pub(crate) developer_mode: bool,
    /// The time the URI is built at: in the past for an already-expired URI.
    pub(crate) issued_at: u64,
    pub(crate) lifetime_s: u64,
    /// Applied to the URI text after signing, to produce a URI the signature no longer
    /// covers.
    pub(crate) tamper: Option<fn(&str) -> String>,
}

impl Pairing {
    /// Create the pairing mailbox and build the URI to show.
    pub(crate) fn publish(relay: &Relay, spec: &UriSpec<'_>) -> Result<Self, Fail> {
        let mailbox = relay.create_mailbox()?;
        let dapp = DappPairing::new(
            &mut OsEntropy,
            spec.issued_at,
            spec.signer,
            DappPairingParams {
                relay: &relay.base_url,
                domain: spec.domain,
                pairing_mailbox: mailbox.id,
                pairing_write: mailbox.write.clone(),
                lifetime_s: spec.lifetime_s,
                ticket: None,
                options: ParseOptions {
                    developer_mode: spec.developer_mode,
                },
            },
        )
        .map_err(|e| Fail::Fail(format!("the suite could not build a pairing URI: {e}")))?;
        let uri = dapp.uri().to_uri();
        Ok(Pairing {
            uri: spec.tamper.map_or(uri.clone(), |f| f(&uri)),
            dapp,
            mailbox,
        })
    }

    /// Poll the pairing mailbox until the wallet replies or `timeout` passes.
    ///
    /// A reply the dApp cannot open is reported as a failure: spec 6.3 step 5 requires
    /// the wallet's reply to be a canonical `PairingReply` sealed to the URI's key.
    pub(crate) fn wait_for_reply(
        &mut self,
        relay: &Relay,
        now: impl Fn() -> u64,
        timeout: Duration,
    ) -> Result<Option<AcceptedPairing>, Fail> {
        let deadline = Instant::now() + timeout;
        let mut rejected: Vec<String> = Vec::new();
        while Instant::now() < deadline {
            let wait = POLL_WAIT_S.min(remaining_secs(deadline));
            for env in relay.drain(&self.mailbox.id, &self.mailbox.read, wait)? {
                match self.dapp.on_reply(now(), &env) {
                    Ok(a) => return Ok(Some(a)),
                    // A dApp ignores junk in the pairing mailbox and keeps waiting; here
                    // only the wallet under test has the write token, so it is reported
                    // once the wait is over.
                    Err(e) => rejected.push(format!("{} bytes: {e}", env.len())),
                }
            }
        }
        if rejected.is_empty() {
            return Ok(None);
        }
        Err(Fail::Fail(format!(
            "the wallet posted {} message(s) to the pairing mailbox that are not a valid \
             pairing reply for this URI (spec 6.3 step 5): {}",
            rejected.len(),
            rejected.join("; ")
        )))
    }
}

fn remaining_secs(deadline: Instant) -> u64 {
    deadline
        .saturating_duration_since(Instant::now())
        .as_secs()
        .max(1)
}

// --- live session --------------------------------------------------------------------

/// A session the suite drives as the dApp.
#[derive(Debug)]
pub(crate) struct Live {
    pub(crate) session: Session,
    /// Every mailbox the suite created for this session, to delete when it is over. The
    /// one being read is always the session's current own mailbox, which changes with a
    /// key rotation.
    created: Vec<(MailboxId, Token)>,
    /// The code the suite would show the user.
    pub(crate) sas: String,
    /// Name the wallet gave in its pairing reply or `session.ready`.
    pub(crate) wallet_name: Option<String>,
    /// Permissions the wallet announced, if it sent `session.permissions` (spec 9.3).
    pub(crate) permissions: Option<Permissions>,
    /// Messages received but not consumed by a request, newest last.
    pub(crate) seen: Vec<Inner>,
}

/// Delete P, create D, send `session.confirm` and confirm the SAS on the dApp side
/// (spec 6.3 steps 6–8). The session is not active until `session.ready` arrives, which
/// is what [`Live::await_ready`] waits for.
pub(crate) fn confirm(
    relay: &Relay,
    pairing: Pairing,
    accepted: AcceptedPairing,
    now: impl Fn() -> u64,
) -> Result<Live, Fail> {
    let sas = accepted.sas().digits();
    let wallet_name = accepted.wallet_meta().and_then(|m| m.name.clone());
    // Single-use pairing mailbox (spec 6.3 step 6): it must be gone before anything else.
    relay.delete(&pairing.mailbox.id, &pairing.mailbox.read);
    let mailbox = relay.create_mailbox()?;
    let (mut session, confirm) = accepted
        .confirm(
            &mut OsEntropy,
            now(),
            mailbox.id,
            mailbox.read.clone(),
            mailbox.write.clone(),
        )
        .map_err(|e| Fail::Fail(format!("the suite could not confirm the pairing: {e}")))?;
    relay.post(&confirm)?;
    // The user compared the codes on both devices and they matched.
    session
        .confirm_sas(&mut OsEntropy, now(), None)
        .map_err(|e| Fail::Fail(format!("the suite could not confirm the SAS: {e}")))?;
    Ok(Live {
        session,
        created: vec![(mailbox.id, mailbox.read)],
        sas,
        wallet_name,
        permissions: None,
        seen: Vec::new(),
    })
}

impl Live {
    /// The mailbox the dApp currently reads, and its read token.
    fn own(&self) -> (MailboxId, Token) {
        (
            self.session.own_mailbox(),
            self.session.own_read_token().clone(),
        )
    }

    /// Remember a mailbox the suite created for this session (a rotation target), so it
    /// is deleted with the rest.
    pub(crate) fn track(&mut self, mailbox: &Mailbox) {
        self.created.push((mailbox.id, mailbox.read.clone()));
    }

    /// Wait for `session.ready`, after which requests may be exchanged (spec 6.3 step 8).
    pub(crate) fn await_ready(
        &mut self,
        relay: &Relay,
        now: &impl Fn() -> u64,
        timeout: Duration,
    ) -> Result<(), Fail> {
        self.pump(relay, now, timeout, &|l: &Live| l.session.peer_ready())?;
        ensure!(
            self.session.peer_ready(),
            "no session.ready within {timeout:?} after session.confirm (spec 6.3 step 8); \
             messages received: [{}]",
            self.types().join(", ")
        );
        Ok(())
    }

    /// Whether the wallet told us the session is over.
    pub(crate) fn ended_by_wallet(&self) -> bool {
        self.seen
            .iter()
            .any(|i| matches!(i.message, Message::SessionEnd { .. }))
    }

    /// Fetch, open and record messages until `done` holds or `timeout` passes.
    ///
    /// Envelopes the session refuses (replays, tampered ciphertexts, wrong epoch) are
    /// counted, not an error: the suite posts some of those on purpose.
    pub(crate) fn pump(
        &mut self,
        relay: &Relay,
        now: &impl Fn() -> u64,
        timeout: Duration,
        done: &dyn Fn(&Live) -> bool,
    ) -> Result<(), Fail> {
        let deadline = Instant::now() + timeout;
        while !done(self) && Instant::now() < deadline {
            let wait = POLL_WAIT_S.min(remaining_secs(deadline));
            // A mailbox retired by a rotation is read before the current one
            // (spec 9.2.1); a mailbox the wallet has not accepted yet cannot be opened,
            // so it is not consumed.
            let mut boxes = vec![self.own()];
            if let Some((m, t)) = self.session.draining_mailbox() {
                boxes.insert(0, (m, t.clone()));
            }
            for (id, read) in boxes {
                for env in relay.drain(&id, &read, wait)? {
                    match self.session.open(now(), &id, &env) {
                        Ok(inner) => self.record(inner),
                        Err(_) => continue,
                    }
                }
            }
        }
        Ok(())
    }

    fn record(&mut self, inner: Inner) {
        if let Message::SessionPermissions(p) = &inner.message {
            self.permissions = Some(p.clone());
        }
        if let Message::SessionReady {
            meta: Some(WalletMeta { name: Some(n), .. }),
        } = &inner.message
        {
            self.wallet_name = Some(n.clone());
        }
        if self.seen.len() < 256 {
            self.seen.push(inner);
        }
    }

    /// Send a `rpc.request` and wait for its `rpc.response` (spec 9.1).
    pub(crate) fn request(
        &mut self,
        relay: &Relay,
        now: &impl Fn() -> u64,
        method: &str,
        params: &str,
        timeout: Duration,
    ) -> Result<RpcOutcome, Fail> {
        let msg = xchonnect_core::rpc::request(method, params)
            .map_err(|e| Fail::Fail(format!("the suite built an invalid request: {e}")))?;
        let out = self
            .session
            .seal(&mut OsEntropy, now(), msg, 300)
            .map_err(|e| Fail::Fail(format!("the suite could not seal the request: {e}")))?;
        let id = out.id;
        relay.post(&out)?;
        self.pump(relay, now, timeout, &|l: &Live| l.response(&id).is_some())?;
        self.response(&id).ok_or_else(|| {
            Fail::Fail(format!(
                "no rpc.response to {method} within {timeout:?} (spec 9.1); messages received: \
                 [{}]",
                self.types().join(", ")
            ))
        })
    }

    /// The response to `id`, if it arrived.
    pub(crate) fn response(&self, id: &[u8; 16]) -> Option<RpcOutcome> {
        self.seen.iter().find_map(|i| match &i.message {
            Message::RpcResponse {
                request_id,
                outcome,
            } if request_id == id => Some(outcome.clone()),
            _ => None,
        })
    }

    /// Wire types received so far, for failure messages.
    pub(crate) fn types(&self) -> Vec<String> {
        self.seen
            .iter()
            .map(|i| i.message.type_name().to_owned())
            .collect()
    }

    /// Send `session.end` without giving up the mailbox, so a check can still see what
    /// the wallet does afterwards.
    pub(crate) fn end(&mut self, relay: &Relay, now: u64, reason: &str) {
        if let Ok(out) = self
            .session
            .end(&mut OsEntropy, now, Some(reason.to_owned()))
        {
            let _ = relay.post(&out);
        }
    }

    /// Everything the wallet has posted to the dApp mailbox since the last drain, without
    /// opening it: usable after the session has ended.
    pub(crate) fn raw_backlog(&self, relay: &Relay) -> usize {
        let (id, read) = self.own();
        relay.drain(&id, &read, 0).map_or(0, |v| v.len())
    }

    /// End the session and delete every mailbox the suite created for it.
    pub(crate) fn finish(&mut self, relay: &Relay, now: u64, reason: &str) {
        self.end(relay, now, reason);
        self.cleanup(relay);
    }

    /// Delete every mailbox the suite created for this session.
    pub(crate) fn cleanup(&self, relay: &Relay) {
        for (id, read) in &self.created {
            relay.delete(id, read);
        }
    }
}
