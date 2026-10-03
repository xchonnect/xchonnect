//! Established sessions: sealing and opening messages, activation, replay protection,
//! rotation and persistence (spec 5.2, 5.3, 6.3, 6.4, 9.2).
//!
//! The session is transport-agnostic. The host fetches envelopes from the relay and
//! passes them to [`Session::open`] together with the mailbox they came from, and posts
//! the [`Outgoing`] values returned by the sealing methods. **The host MUST persist the
//! session after every call that mutates it and before posting the resulting envelope**
//! (spec 12.1, sender state-loss rule in 5.3).

use crate::cbor::{self, Value};
use crate::crypto::RootKey;
use crate::crypto::{self, ChainKey, DirectionKey, Entropy, MailboxId, Token, X25519Secret};
use crate::envelope::{self, Direction, Envelope};
use crate::error::{Error, Result};
use crate::keys::{self, EpochKeys};
use crate::message::{Inner, Message, Rotate, RotatePhase};

/// Maximum lifetime `exp - iat` of a message (7 days).
pub const MAX_LIFETIME_S: u64 = 7 * 24 * 3600;
/// Tolerated future skew of `iat`.
pub const MAX_SKEW_S: u64 = 300;
/// Rotate after this many days in one epoch.
pub const ROTATE_AFTER_S: u64 = 30 * 24 * 3600;
/// Rotate after this many messages sent in one epoch.
pub const ROTATE_AFTER_MESSAGES: u64 = 10_000;
const STATE_VERSION: u64 = 1;

/// Which side of the session this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The dApp.
    Dapp,
    /// The wallet.
    Wallet,
}

/// An envelope to post to the relay.
#[derive(Debug, Clone)]
pub struct Outgoing {
    /// Destination mailbox.
    pub mailbox: MailboxId,
    /// Write token for the destination mailbox.
    pub write_token: Token,
    /// Encoded envelope.
    pub envelope: Vec<u8>,
    /// Inner message id (the `request_id` of any response).
    pub id: [u8; 16],
}

#[derive(Debug, Clone)]
struct PrevEpoch {
    keys: EpochKeys,
    own_mailbox: MailboxId,
    own_read: Token,
}

#[derive(Debug, Clone)]
struct PendingRotation {
    secret: X25519Secret,
    epoch: u64,
    new_mailbox: MailboxId,
    new_read: Token,
}

/// Mailbox the host should delete after a rotation has drained it.
#[derive(Debug, Clone)]
pub struct RetiredMailbox {
    /// Mailbox id.
    pub mailbox: MailboxId,
    /// Its read token (authorises `DELETE`).
    pub read_token: Token,
}

/// A paired session.
#[derive(Debug, Clone)]
pub struct Session {
    role: Role,
    keys: EpochKeys,
    own_mailbox: MailboxId,
    own_read: Token,
    peer_mailbox: MailboxId,
    peer_write: Token,
    send_seq: u64,
    recv_seq: u64,
    sas_confirmed: bool,
    peer_ready: bool,
    ended: bool,
    epoch_started: u64,
    epoch_sent: u64,
    prev: Option<PrevEpoch>,
    rotation: Option<PendingRotation>,
}

/// Parameters for creating a session (used by pairing).
pub(crate) struct NewSession {
    pub(crate) role: Role,
    pub(crate) root0: RootKey,
    pub(crate) own_mailbox: MailboxId,
    pub(crate) own_read: Token,
    pub(crate) peer_mailbox: MailboxId,
    pub(crate) peer_write: Token,
    pub(crate) now: u64,
}

impl Session {
    pub(crate) fn new(p: NewSession) -> Result<Session> {
        Ok(Session {
            role: p.role,
            keys: keys::epoch_keys(&p.root0, 0)?,
            own_mailbox: p.own_mailbox,
            own_read: p.own_read,
            peer_mailbox: p.peer_mailbox,
            peer_write: p.peer_write,
            send_seq: 0,
            recv_seq: 0,
            sas_confirmed: false,
            peer_ready: false,
            ended: false,
            epoch_started: p.now,
            epoch_sent: 0,
            prev: None,
            rotation: None,
        })
    }

    /// Record a `seq` already consumed during pairing.
    pub(crate) fn mark_received(&mut self, seq: u64) {
        self.recv_seq = seq;
    }

    /// This side's role.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Current epoch.
    pub fn epoch(&self) -> u64 {
        self.keys.epoch
    }

    /// Mailbox this side reads (current epoch).
    pub fn own_mailbox(&self) -> MailboxId {
        self.own_mailbox
    }

    /// Read token for [`Session::own_mailbox`].
    pub fn own_read_token(&self) -> &Token {
        &self.own_read
    }

    /// Mailbox of the previous epoch that must still be drained (read it **before**
    /// the current one), if a rotation happened recently.
    pub fn draining_mailbox(&self) -> Option<(MailboxId, &Token)> {
        self.prev.as_ref().map(|p| (p.own_mailbox, &p.own_read))
    }

    /// Mailbox created for a rotation this side offered and that the peer has not
    /// accepted yet. The host should also read it after the accept arrives.
    pub fn pending_rotation_mailbox(&self) -> Option<(MailboxId, &Token)> {
        self.rotation.as_ref().map(|r| (r.new_mailbox, &r.new_read))
    }

    /// Whether requests may be exchanged (spec 6.3 step 8).
    pub fn is_active(&self) -> bool {
        !self.ended
            && match self.role {
                Role::Dapp => self.sas_confirmed && self.peer_ready,
                Role::Wallet => self.sas_confirmed,
            }
    }

    /// Whether the dApp has received `session.ready`.
    pub fn peer_ready(&self) -> bool {
        self.peer_ready
    }

    /// Whether this session has ended.
    pub fn is_ended(&self) -> bool {
        self.ended
    }

    /// Whether the rotation thresholds are reached (30 days or 10 000 messages).
    pub fn needs_rotation(&self, now: u64) -> bool {
        now.saturating_sub(self.epoch_started) >= ROTATE_AFTER_S
            || self.epoch_sent >= ROTATE_AFTER_MESSAGES
    }

    fn send_key(&self) -> (&DirectionKey, Direction) {
        match self.role {
            Role::Dapp => (&self.keys.d2w, Direction::DappToWallet),
            Role::Wallet => (&self.keys.w2d, Direction::WalletToDapp),
        }
    }

    fn recv_key<'a>(&self, keys: &'a EpochKeys) -> (&'a DirectionKey, Direction) {
        match self.role {
            Role::Dapp => (&keys.w2d, Direction::WalletToDapp),
            Role::Wallet => (&keys.d2w, Direction::DappToWallet),
        }
    }

    /// The user confirmed that both devices show the same SAS.
    ///
    /// Wallet: returns the `session.ready` message to post. dApp: returns `None`; the
    /// session becomes active once `session.ready` has also arrived.
    pub fn confirm_sas(
        &mut self,
        rng: &mut dyn Entropy,
        now: u64,
        meta: Option<crate::message::WalletMeta>,
    ) -> Result<Option<Outgoing>> {
        if self.ended {
            return Err(Error::State("session ended"));
        }
        self.sas_confirmed = true;
        match self.role {
            Role::Wallet => Ok(Some(self.seal(
                rng,
                now,
                Message::SessionReady { meta },
                3600,
            )?)),
            Role::Dapp => Ok(None),
        }
    }

    /// The user reported that the codes do not match: end the session (spec 6.3 step 8).
    pub fn reject_sas(&mut self, rng: &mut dyn Entropy, now: u64) -> Result<Outgoing> {
        self.end(rng, now, Some("sas mismatch".to_owned()))
    }

    /// End the session; returns `session.end` to post. Keys must be deleted by the host
    /// after posting.
    pub fn end(
        &mut self,
        rng: &mut dyn Entropy,
        now: u64,
        reason: Option<String>,
    ) -> Result<Outgoing> {
        let out = self.seal_unchecked(rng, now, Message::SessionEnd { reason }, 86_400)?;
        self.ended = true;
        Ok(out)
    }

    /// Seal a message to the peer. `ttl_s` is clamped to 7 days.
    pub fn seal(
        &mut self,
        rng: &mut dyn Entropy,
        now: u64,
        message: Message,
        ttl_s: u64,
    ) -> Result<Outgoing> {
        if self.ended {
            return Err(Error::State("session ended"));
        }
        let is_rpc = matches!(
            message,
            Message::RpcRequest { .. } | Message::RpcResponse { .. } | Message::RpcReceived { .. }
        );
        if is_rpc && !self.is_active() {
            return Err(Error::State("session not active"));
        }
        if matches!(message, Message::SessionRotate(_)) {
            return Err(Error::State("use begin_rotation / accept_rotation"));
        }
        self.seal_unchecked(rng, now, message, ttl_s)
    }

    fn seal_unchecked(
        &mut self,
        rng: &mut dyn Entropy,
        now: u64,
        message: Message,
        ttl_s: u64,
    ) -> Result<Outgoing> {
        let seq = self
            .send_seq
            .checked_add(1)
            .filter(|s| *s <= crate::message::MAX_SEQ)
            .ok_or(Error::State("seq exhausted"))?;
        let id: [u8; 16] = crypto::random_array(rng);
        let inner = Inner {
            seq,
            iat: now,
            exp: now + ttl_s.clamp(1, MAX_LIFETIME_S),
            id,
            message,
        };
        let (key, dir) = self.send_key();
        let env = envelope::seal_session(rng, key, dir, &self.peer_mailbox, &inner.encode()?)?;
        self.send_seq = seq;
        self.epoch_sent += 1;
        Ok(Outgoing {
            mailbox: self.peer_mailbox,
            write_token: self.peer_write.clone(),
            envelope: env,
            id,
        })
    }

    /// Open an envelope fetched from `from_mailbox` (one of this side's mailboxes).
    ///
    /// Enforces spec 5.3 receive rules and session state. Handles `session.ready`,
    /// `session.end` and rotation accepts internally; returns the decoded message for
    /// the host in every success case.
    pub fn open(
        &mut self,
        now: u64,
        from_mailbox: &MailboxId,
        envelope_bytes: &[u8],
    ) -> Result<Inner> {
        if self.ended {
            return Err(Error::State("session ended"));
        }
        let env = Envelope::decode(envelope_bytes)?;
        let keys = if *from_mailbox == self.own_mailbox {
            &self.keys
        } else if let Some(prev) = self
            .prev
            .as_ref()
            .filter(|p| p.own_mailbox == *from_mailbox)
        {
            &prev.keys
        } else if self
            .rotation
            .as_ref()
            .is_some_and(|r| r.new_mailbox == *from_mailbox)
        {
            // Messages for our offered mailbox need keys we derive when the accept arrives.
            return Err(Error::State(
                "rotation pending: process the current mailbox first",
            ));
        } else {
            return Err(Error::State("unknown mailbox"));
        };
        let (key, dir) = self.recv_key(keys);
        let value = envelope::open_session(key, dir, from_mailbox, &env)?;
        let inner = Inner::from_value(&value)?;
        check_times(&inner, now)?;
        if inner.seq <= self.recv_seq {
            return Err(Error::Replay);
        }
        match &inner.message {
            Message::RpcRequest { .. }
            | Message::RpcResponse { .. }
            | Message::RpcReceived { .. }
                if !self.is_active() =>
            {
                return Err(Error::State("session not active"));
            }
            Message::RpcRequest { .. } if self.role == Role::Dapp => {
                return Err(Error::State("dApps do not accept requests"));
            }
            Message::SessionReady { .. } if self.role != Role::Dapp => {
                return Err(Error::State("unexpected session.ready"));
            }
            Message::SessionConfirm { .. } => {
                return Err(Error::State("unexpected session.confirm"));
            }
            _ => {}
        }
        self.recv_seq = inner.seq;
        match &inner.message {
            Message::SessionReady { .. } => self.peer_ready = true,
            Message::SessionEnd { .. } => self.ended = true,
            Message::SessionRotate(r) if r.phase == RotatePhase::Accept => {
                self.complete_rotation(r, now)?
            }
            _ => {}
        }
        Ok(inner)
    }

    /// Start a rotation (spec 9.2). The host first creates `new_mailbox` on the relay.
    pub fn begin_rotation(
        &mut self,
        rng: &mut dyn Entropy,
        now: u64,
        new_mailbox: MailboxId,
        new_read: Token,
        new_write: Token,
    ) -> Result<Outgoing> {
        if !self.is_active() {
            return Err(Error::State("session not active"));
        }
        if self.rotation.is_some() || self.prev.is_some() {
            return Err(Error::State("rotation already in progress"));
        }
        let secret = X25519Secret::random(rng);
        let epoch = self.keys.epoch + 1;
        let msg = Message::SessionRotate(Rotate {
            phase: RotatePhase::Offer,
            epoch,
            epk: secret.public_key(),
            mailbox: new_mailbox,
            write_token: new_write,
        });
        let out = self.seal_unchecked(rng, now, msg, 86_400)?;
        self.rotation = Some(PendingRotation {
            secret,
            epoch,
            new_mailbox,
            new_read,
        });
        Ok(out)
    }

    /// Accept a peer's rotation offer received through [`Session::open`]. The host first
    /// creates `new_mailbox`. Returns the accept message (sealed under the old epoch).
    ///
    /// Concurrent offers: the dApp's offer wins. A wallet with its own pending offer
    /// abandons it (returned as a mailbox to delete); a dApp refuses the wallet's offer.
    pub fn accept_rotation(
        &mut self,
        rng: &mut dyn Entropy,
        now: u64,
        offer: &Rotate,
        new_mailbox: MailboxId,
        new_read: Token,
        new_write: Token,
    ) -> Result<(Outgoing, Option<RetiredMailbox>)> {
        if offer.phase != RotatePhase::Offer || offer.epoch != self.keys.epoch + 1 {
            return Err(Error::State("unexpected rotation offer"));
        }
        if self.prev.is_some() {
            return Err(Error::State("previous rotation still draining"));
        }
        let abandoned = match (self.role, self.rotation.take()) {
            (Role::Dapp, Some(own)) => {
                self.rotation = Some(own);
                return Err(Error::State("concurrent rotation: the dApp offer wins"));
            }
            (_, Some(own)) => Some(RetiredMailbox {
                mailbox: own.new_mailbox,
                read_token: own.new_read.clone(),
            }),
            (_, None) => None,
        };
        let b = X25519Secret::random(rng);
        let b_pub = b.public_key();
        let dh = b.diffie_hellman(&offer.epk)?;
        let root = keys::rotation_root(&self.keys.chain, &dh, offer.epoch, &offer.epk, &b_pub)?;
        let accept = Message::SessionRotate(Rotate {
            phase: RotatePhase::Accept,
            epoch: offer.epoch,
            epk: b_pub,
            mailbox: new_mailbox,
            write_token: new_write,
        });
        let out = self.seal_unchecked(rng, now, accept, 86_400)?;
        self.switch_epoch(
            &root,
            offer.epoch,
            new_mailbox,
            new_read,
            offer.mailbox,
            offer.write_token.clone(),
            now,
        )?;
        Ok((out, abandoned))
    }

    fn complete_rotation(&mut self, accept: &Rotate, now: u64) -> Result<()> {
        let pending = self
            .rotation
            .take()
            .ok_or(Error::State("no rotation pending"))?;
        if accept.epoch != pending.epoch {
            self.rotation = Some(pending);
            return Err(Error::State("rotation epoch mismatch"));
        }
        let dh = pending.secret.diffie_hellman(&accept.epk)?;
        let root = keys::rotation_root(
            &self.keys.chain,
            &dh,
            pending.epoch,
            &pending.secret.public_key(),
            &accept.epk,
        )?;
        self.switch_epoch(
            &root,
            pending.epoch,
            pending.new_mailbox,
            pending.new_read.clone(),
            accept.mailbox,
            accept.write_token.clone(),
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn switch_epoch(
        &mut self,
        root: &RootKey,
        epoch: u64,
        own_mailbox: MailboxId,
        own_read: Token,
        peer_mailbox: MailboxId,
        peer_write: Token,
        now: u64,
    ) -> Result<()> {
        let new_keys = keys::epoch_keys(root, epoch)?;
        let old_keys = core::mem::replace(&mut self.keys, new_keys);
        let old_mailbox = core::mem::replace(&mut self.own_mailbox, own_mailbox);
        let old_read = core::mem::replace(&mut self.own_read, own_read);
        self.prev = Some(PrevEpoch {
            keys: old_keys,
            own_mailbox: old_mailbox,
            own_read: old_read,
        });
        self.peer_mailbox = peer_mailbox;
        self.peer_write = peer_write;
        self.epoch_started = now;
        self.epoch_sent = 0;
        Ok(())
    }

    /// The previous epoch's mailbox is empty: erase its keys and return it so the host
    /// can delete it on the relay.
    pub fn finish_drain(&mut self) -> Option<RetiredMailbox> {
        self.prev.take().map(|p| RetiredMailbox {
            mailbox: p.own_mailbox,
            read_token: p.own_read,
        })
    }

    // -----------------------------------------------------------------------
    // Persistence
    // -----------------------------------------------------------------------

    /// Serialise for host storage (versioned canonical CBOR). The output contains
    /// secrets: store it in the platform keychain or encrypted storage (spec 12.1).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let keys_v = |k: &EpochKeys| {
            Value::text_map(vec![
                ("e", Value::Uint(k.epoch)),
                ("d2w", Value::bytes(k.d2w.expose())),
                ("w2d", Value::bytes(k.w2d.expose())),
                ("ck", Value::bytes(k.chain.expose())),
            ])
        };
        let mut e = vec![
            ("v", Value::Uint(STATE_VERSION)),
            (
                "role",
                Value::text(if self.role == Role::Dapp {
                    "dapp"
                } else {
                    "wallet"
                }),
            ),
            ("keys", keys_v(&self.keys)),
            ("own_mbx", Value::bytes(&self.own_mailbox.0)),
            ("own_r", Value::bytes(self.own_read.expose())),
            ("peer_mbx", Value::bytes(&self.peer_mailbox.0)),
            ("peer_w", Value::bytes(self.peer_write.expose())),
            ("send_seq", Value::Uint(self.send_seq)),
            ("recv_seq", Value::Uint(self.recv_seq)),
            ("sas_ok", Value::Bool(self.sas_confirmed)),
            ("peer_ready", Value::Bool(self.peer_ready)),
            ("ended", Value::Bool(self.ended)),
            ("epoch_started", Value::Uint(self.epoch_started)),
            ("epoch_sent", Value::Uint(self.epoch_sent)),
        ];
        if let Some(p) = &self.prev {
            e.push((
                "prev",
                Value::text_map(vec![
                    ("keys", keys_v(&p.keys)),
                    ("mbx", Value::bytes(&p.own_mailbox.0)),
                    ("r", Value::bytes(p.own_read.expose())),
                ]),
            ));
        }
        if let Some(r) = &self.rotation {
            e.push((
                "rot",
                Value::text_map(vec![
                    ("sk", Value::bytes(r.secret.expose())),
                    ("e", Value::Uint(r.epoch)),
                    ("mbx", Value::bytes(&r.new_mailbox.0)),
                    ("r", Value::bytes(r.new_read.expose())),
                ]),
            ));
        }
        cbor::encode(&Value::text_map(e))
    }

    /// Restore from [`Session::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Session> {
        let v = cbor::decode(bytes)?;
        if v.get("v").and_then(Value::as_u64) != Some(STATE_VERSION) {
            return Err(Error::Malformed("session state version"));
        }
        let u = |k: &'static str| v.get(k).and_then(Value::as_u64).ok_or(Error::Malformed(k));
        let b = |k: &'static str| v.get(k).and_then(Value::as_bool).ok_or(Error::Malformed(k));
        let role = match v.get("role").and_then(Value::as_text) {
            Some("dapp") => Role::Dapp,
            Some("wallet") => Role::Wallet,
            _ => return Err(Error::Malformed("role")),
        };
        let prev = match v.get("prev") {
            None => None,
            Some(p) => Some(PrevEpoch {
                keys: keys_from(p.get("keys").ok_or(Error::Malformed("prev.keys"))?)?,
                own_mailbox: MailboxId(arr(p, "mbx")?),
                own_read: Token::from_bytes(arr(p, "r")?),
            }),
        };
        let rotation = match v.get("rot") {
            None => None,
            Some(r) => Some(PendingRotation {
                secret: X25519Secret::from_bytes(arr(r, "sk")?),
                epoch: r
                    .get("e")
                    .and_then(Value::as_u64)
                    .ok_or(Error::Malformed("rot.e"))?,
                new_mailbox: MailboxId(arr(r, "mbx")?),
                new_read: Token::from_bytes(arr(r, "r")?),
            }),
        };
        Ok(Session {
            role,
            keys: keys_from(v.get("keys").ok_or(Error::Malformed("keys"))?)?,
            own_mailbox: MailboxId(arr(&v, "own_mbx")?),
            own_read: Token::from_bytes(arr(&v, "own_r")?),
            peer_mailbox: MailboxId(arr(&v, "peer_mbx")?),
            peer_write: Token::from_bytes(arr(&v, "peer_w")?),
            send_seq: u("send_seq")?,
            recv_seq: u("recv_seq")?,
            sas_confirmed: b("sas_ok")?,
            peer_ready: b("peer_ready")?,
            ended: b("ended")?,
            epoch_started: u("epoch_started")?,
            epoch_sent: u("epoch_sent")?,
            prev,
            rotation,
        })
    }
}

fn arr<const N: usize>(v: &Value, key: &'static str) -> Result<[u8; N]> {
    v.get(key)
        .and_then(Value::as_bytes)
        .and_then(|b| b.try_into().ok())
        .ok_or(Error::Malformed(key))
}

fn keys_from(v: &Value) -> Result<EpochKeys> {
    Ok(EpochKeys {
        epoch: v
            .get("e")
            .and_then(Value::as_u64)
            .ok_or(Error::Malformed("keys.e"))?,
        d2w: DirectionKey::from_bytes(arr(v, "d2w")?),
        w2d: DirectionKey::from_bytes(arr(v, "w2d")?),
        chain: ChainKey::from_bytes(arr(v, "ck")?),
    })
}

/// Spec 5.3 time rules.
pub(crate) fn check_times(inner: &Inner, now: u64) -> Result<()> {
    if inner.exp < now {
        return Err(Error::Expired);
    }
    if inner.exp.saturating_sub(inner.iat) > MAX_LIFETIME_S {
        return Err(Error::LifetimeTooLong);
    }
    if inner.iat > now + MAX_SKEW_S {
        return Err(Error::ClockSkew);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::pairing::tests::{fixture, paired};

    const NOW: u64 = 1_790_000_100;

    /// Seal an arbitrary inner message as `sender` would (bypassing `seal`'s checks).
    fn craft(sender: &Session, seq: u64, iat: u64, exp: u64) -> Vec<u8> {
        let inner = Inner {
            seq,
            iat,
            exp,
            id: [7; 16],
            message: Message::SessionPing,
        };
        let (key, dir) = sender.send_key();
        envelope::seal_session_with_nonce(
            &[1; 24],
            key,
            dir,
            &sender.peer_mailbox,
            &inner.encode().unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn receive_rules_have_distinct_errors() {
        let mut f = fixture();
        let (ds, mut ws) = paired(&mut f);
        let mbx = ws.own_mailbox();
        let base = ws.recv_seq;
        assert_eq!(
            ws.open(NOW, &mbx, &craft(&ds, base + 1, NOW, NOW - 1))
                .unwrap_err(),
            Error::Expired
        );
        assert_eq!(
            ws.open(
                NOW,
                &mbx,
                &craft(&ds, base + 1, NOW, NOW + MAX_LIFETIME_S + 1)
            )
            .unwrap_err(),
            Error::LifetimeTooLong
        );
        assert_eq!(
            ws.open(
                NOW,
                &mbx,
                &craft(&ds, base + 1, NOW + MAX_SKEW_S + 1, NOW + 1000)
            )
            .unwrap_err(),
            Error::ClockSkew
        );
        // Valid, then replay and reorder.
        let m5 = craft(&ds, base + 5, NOW, NOW + 60);
        let m3 = craft(&ds, base + 3, NOW, NOW + 60);
        ws.open(NOW, &mbx, &m5).unwrap();
        assert_eq!(ws.open(NOW, &mbx, &m5).unwrap_err(), Error::Replay);
        assert_eq!(ws.open(NOW, &mbx, &m3).unwrap_err(), Error::Replay);
        // Gaps are allowed.
        ws.open(NOW, &mbx, &craft(&ds, base + 9, NOW, NOW + 60))
            .unwrap();
        // Wrong mailbox / reflected own message fail.
        assert_eq!(
            ws.open(NOW, &MailboxId([0xee; 16]), &m5).unwrap_err(),
            Error::State("unknown mailbox")
        );
    }

    #[test]
    fn reflection_is_rejected() {
        let mut f = fixture();
        let (mut ds, mut ws) = paired(&mut f);
        let out = ws.seal(&mut f.rng, NOW, Message::SessionPing, 60).unwrap();
        // Posting the wallet's own message back into the wallet's mailbox fails (direction key + AAD).
        let own = ws.own_mailbox();
        assert_eq!(
            ws.open(NOW, &own, &out.envelope).unwrap_err(),
            Error::Decrypt
        );
        assert!(ds.open(NOW, &ds.own_mailbox(), &out.envelope).is_ok());
    }

    #[test]
    fn restore_preserves_replay_protection() {
        let mut f = fixture();
        let (mut ds, mut ws) = paired(&mut f);
        let m1 = ds.seal(&mut f.rng, NOW, Message::SessionPing, 60).unwrap();
        ws.open(NOW, &ws.own_mailbox(), &m1.envelope).unwrap();
        let bytes = ws.to_bytes().unwrap();
        let mut restored = Session::from_bytes(&bytes).unwrap();
        assert_eq!(restored.to_bytes().unwrap(), bytes);
        assert_eq!(
            restored
                .open(NOW, &restored.own_mailbox(), &m1.envelope)
                .unwrap_err(),
            Error::Replay
        );
        let m2 = ds.seal(&mut f.rng, NOW, Message::SessionPing, 60).unwrap();
        assert!(
            restored
                .open(NOW, &restored.own_mailbox(), &m2.envelope)
                .is_ok()
        );
        assert!(restored.is_active());
        // Unknown version rejected.
        let mut v = cbor::decode(&bytes).unwrap();
        if let Value::Map(m) = &mut v {
            for (k, val) in m.iter_mut() {
                if k.as_text() == Some("v") {
                    *val = Value::Uint(99);
                }
            }
        }
        assert!(Session::from_bytes(&cbor::encode(&v).unwrap()).is_err());
    }

    #[test]
    fn rotation_thresholds_reported() {
        let mut f = fixture();
        let (mut ds, _ws) = paired(&mut f);
        assert!(!ds.needs_rotation(NOW));
        assert!(ds.needs_rotation(ds.epoch_started + ROTATE_AFTER_S));
        ds.epoch_sent = ROTATE_AFTER_MESSAGES;
        assert!(ds.needs_rotation(NOW));
    }

    #[test]
    fn wallet_refuses_requests_before_sas_confirmation() {
        let mut f = fixture();
        let (ds, mut ws) = paired(&mut f);
        ws.sas_confirmed = false;
        let inner = Inner {
            seq: 99,
            iat: NOW,
            exp: NOW + 60,
            id: [1; 16],
            message: Message::RpcRequest {
                method: "chainId".into(),
                params: "{}".into(),
            },
        };
        let (key, dir) = ds.send_key();
        let env = envelope::seal_session_with_nonce(
            &[2; 24],
            key,
            dir,
            &ds.peer_mailbox,
            &inner.encode().unwrap(),
        )
        .unwrap();
        assert_eq!(
            ws.open(NOW, &ws.own_mailbox(), &env).unwrap_err(),
            Error::State("session not active")
        );
    }
}
