//! Pairing handshake state machines (spec 6.3).
//!
//! ```text
//! dApp                                   wallet
//! DappPairing::new  ── URI (QR) ───────▶ PairingUri::parse
//!                                        VerifiedUri::new (expiry + origin signature)
//!                   ◀── pairing reply ── WalletPairing::reply
//! DappPairing::on_reply (first valid wins)
//! AcceptedPairing::confirm ─ session.confirm ▶ WalletPairing::on_confirm
//! Session::confirm_sas (user)            Session::confirm_sas (user) ─ session.ready ▶
//! ```
//! Both state machines are deterministic given entropy and time.

use crate::crypto::{
    self, Entropy, HpkeReceiver, HpkeSender, MailboxId, PairingSecret, Psk, RootKey, Token,
    X25519Secret,
};
use crate::envelope::{self, Envelope, Kind, PAIRING_CT_LEN};
use crate::error::{Error, Result};
use crate::keys::{self, Sas};
use crate::message::{Inner, Message, PairingReply, WalletMeta};
use crate::origin::OriginDocument;
use crate::session::{self, NewSession, Outgoing, Role, Session};
use crate::uri::{OriginSigner, PairingUri, ParseOptions, UriParams};

/// Time the wallet waits for `session.confirm` after replying (spec 6.3 step 7).
pub const CONFIRM_TIMEOUT_S: u64 = 300;

fn hpke_info(h_uri: &[u8; 32]) -> Vec<u8> {
    [keys::LABEL_PAIRING_INFO, h_uri.as_slice()].concat()
}

fn pairing_aad(mbx_p: &MailboxId) -> Vec<u8> {
    [keys::LABEL_PAIRING_AAD, mbx_p.0.as_slice()].concat()
}

fn psk(secret: &PairingSecret) -> Psk<'_> {
    Psk {
        psk: secret.expose(),
        psk_id: keys::LABEL_PSK_ID,
    }
}

// ---------------------------------------------------------------------------
// dApp side
// ---------------------------------------------------------------------------

/// Inputs for [`DappPairing::new`]. The host has already created the pairing mailbox.
#[derive(Debug)]
pub struct DappPairingParams<'a> {
    /// Relay base URL.
    pub relay: &'a str,
    /// dApp domain (A-label).
    pub domain: &'a str,
    /// Pairing mailbox P.
    pub pairing_mailbox: MailboxId,
    /// Write token for P (goes into the URI).
    pub pairing_write: Token,
    /// URI lifetime in seconds (at most 300).
    pub lifetime_s: u64,
    /// Optional sponsorship ticket.
    pub ticket: Option<[u8; 32]>,
    /// Developer mode (loopback relay, localhost domain).
    pub options: ParseOptions,
}

/// dApp waiting for a pairing reply.
#[derive(Debug)]
pub struct DappPairing {
    uri: PairingUri,
    dsk: X25519Secret,
    h_uri: [u8; 32],
    accepted: bool,
}

/// A pairing reply the dApp accepted. The host MUST now delete the pairing mailbox,
/// create the session mailbox and call [`AcceptedPairing::confirm`].
#[derive(Debug)]
pub struct AcceptedPairing {
    root0: RootKey,
    sas: Sas,
    reply: PairingReply,
}

impl DappPairing {
    /// Generate the pairing key and secret and build the signed URI.
    pub fn new(
        rng: &mut dyn Entropy,
        now: u64,
        signer: &dyn OriginSigner,
        p: DappPairingParams<'_>,
    ) -> Result<Self> {
        let dsk = X25519Secret::random(rng);
        let secret = PairingSecret::random(rng);
        let uri = PairingUri::build(
            signer,
            now,
            UriParams {
                relay: p.relay,
                mailbox: p.pairing_mailbox,
                write_token: p.pairing_write,
                dapp_pk: dsk.public_key(),
                secret,
                domain: p.domain,
                expires_at: now.saturating_add(p.lifetime_s),
                ticket: p.ticket,
            },
            p.options,
        )?;
        let h_uri = uri.h_uri()?;
        Ok(DappPairing {
            uri,
            dsk,
            h_uri,
            accepted: false,
        })
    }

    /// The URI to show as QR code / universal link.
    pub fn uri(&self) -> &PairingUri {
        &self.uri
    }

    /// Process one envelope from the pairing mailbox, in relay order.
    ///
    /// Returns [`Error::Decrypt`] (or another error) for replies to ignore; the dApp
    /// keeps waiting. The first valid reply is accepted; every later call returns
    /// [`Error::AlreadyPaired`].
    pub fn on_reply(&mut self, now: u64, envelope_bytes: &[u8]) -> Result<AcceptedPairing> {
        if self.accepted {
            return Err(Error::AlreadyPaired);
        }
        if now > self.uri.expires_at {
            return Err(Error::UriExpired);
        }
        let env = Envelope::decode(envelope_bytes)?;
        if env.kind != Kind::Pairing {
            return Err(Error::Malformed("expected a pairing reply"));
        }
        let enc: [u8; 32] = env
            .n
            .as_slice()
            .try_into()
            .map_err(|_| Error::Malformed("enc"))?;
        let mut ctx = HpkeReceiver::setup(
            &self.dsk,
            &enc,
            &hpke_info(&self.h_uri),
            Some(psk(&self.uri.secret)),
        )?;
        let padded = ctx.open(&pairing_aad(&self.uri.mailbox), &env.ct)?;
        let reply = PairingReply::from_value(&envelope::unpad(&padded)?)?;
        let th = keys::pairing_transcript(&self.h_uri, &enc, &env.ct);
        let root0 = RootKey::from_bytes(ctx.export(&keys::root_export_context(&th))?);
        let sas = Sas::derive(&root0)?;
        self.accepted = true;
        Ok(AcceptedPairing { root0, sas, reply })
    }
}

impl AcceptedPairing {
    /// SAS to display.
    pub fn sas(&self) -> Sas {
        self.sas
    }

    /// Wallet metadata from the reply.
    pub fn wallet_meta(&self) -> Option<&WalletMeta> {
        self.reply.meta.as_ref()
    }

    /// Create the session and the `session.confirm` message carrying the new session
    /// mailbox D. The session becomes active after the user confirms the SAS on the
    /// dApp ([`Session::confirm_sas`]) and `session.ready` arrives.
    pub fn confirm(
        self,
        rng: &mut dyn Entropy,
        now: u64,
        session_mailbox: MailboxId,
        session_read: Token,
        session_write: Token,
    ) -> Result<(Session, Outgoing)> {
        let mut s = Session::new(NewSession {
            role: Role::Dapp,
            root0: self.root0,
            own_mailbox: session_mailbox,
            own_read: session_read,
            peer_mailbox: self.reply.mailbox,
            peer_write: self.reply.write_token.clone(),
            now,
        })?;
        let out = s.seal(
            rng,
            now,
            Message::SessionConfirm {
                mailbox: session_mailbox,
                write_token: session_write,
            },
            CONFIRM_TIMEOUT_S,
        )?;
        Ok((s, out))
    }
}

// ---------------------------------------------------------------------------
// Wallet side
// ---------------------------------------------------------------------------

/// A pairing URI whose expiry and origin signature were verified against the origin
/// document fetched from `uri.domain`. The wallet shows the verified domain and asks
/// the user before calling [`WalletPairing::reply`].
#[derive(Debug, Clone)]
pub struct VerifiedUri {
    uri: PairingUri,
    dapp_name: String,
}

impl VerifiedUri {
    /// Verify expiry, then the origin signature (spec 6.3 step 2).
    pub fn new(uri: PairingUri, doc: &OriginDocument, now: u64) -> Result<Self> {
        uri.check_time(now)?;
        uri.verify(doc, now)?;
        Ok(VerifiedUri {
            uri,
            dapp_name: doc.name.clone(),
        })
    }

    /// The verified URI.
    pub fn uri(&self) -> &PairingUri {
        &self.uri
    }

    /// dApp name from the origin document.
    pub fn dapp_name(&self) -> &str {
        &self.dapp_name
    }
}

/// Wallet waiting for `session.confirm`.
#[derive(Debug)]
pub struct WalletPairing {
    root0: RootKey,
    sas: Sas,
    own_mailbox: MailboxId,
    own_read: Token,
    replied_at: u64,
}

impl WalletPairing {
    /// Build the pairing reply to post to the pairing mailbox (`uri.mailbox` with
    /// `uri.write_token`). The host has created mailbox W first.
    pub fn reply(
        rng: &mut dyn Entropy,
        now: u64,
        verified: &VerifiedUri,
        own_mailbox: MailboxId,
        own_read: Token,
        own_write: Token,
        meta: Option<WalletMeta>,
    ) -> Result<(WalletPairing, Outgoing)> {
        let uri = &verified.uri;
        uri.check_time(now)?;
        let h_uri = uri.h_uri()?;
        let (enc, mut ctx) = HpkeSender::setup(
            rng,
            &uri.dapp_pk,
            &hpke_info(&h_uri),
            Some(psk(&uri.secret)),
        )?;
        let reply = PairingReply {
            mailbox: own_mailbox,
            write_token: own_write,
            meta,
        };
        let padded = envelope::pad_to(&reply.encode()?, PAIRING_CT_LEN)?;
        let ct = ctx.seal(&pairing_aad(&uri.mailbox), &padded)?;
        let th = keys::pairing_transcript(&h_uri, &enc, &ct);
        let root0 = RootKey::from_bytes(ctx.export(&keys::root_export_context(&th))?);
        let sas = Sas::derive(&root0)?;
        let envelope = Envelope {
            kind: Kind::Pairing,
            n: enc.to_vec(),
            ct,
        }
        .encode()?;
        let out = Outgoing {
            mailbox: uri.mailbox,
            write_token: uri.write_token.clone(),
            envelope,
            id: crypto::random_array(rng),
        };
        Ok((
            WalletPairing {
                root0,
                sas,
                own_mailbox,
                own_read,
                replied_at: now,
            },
            out,
        ))
    }

    /// SAS to display.
    pub fn sas(&self) -> Sas {
        self.sas
    }

    /// Mailbox W to poll for `session.confirm`.
    pub fn own_mailbox(&self) -> MailboxId {
        self.own_mailbox
    }

    /// Read token for W.
    pub fn own_read_token(&self) -> &Token {
        &self.own_read
    }

    /// Whether the confirm timeout has passed; the wallet must then abort and warn that
    /// the code may have been used by another device.
    pub fn timed_out(&self, now: u64) -> bool {
        now > self.replied_at.saturating_add(CONFIRM_TIMEOUT_S)
    }

    /// Process `session.confirm` from mailbox W and create the session. The session is
    /// active once the user confirms the SAS ([`Session::confirm_sas`], which yields
    /// `session.ready`).
    pub fn on_confirm(&self, now: u64, envelope_bytes: &[u8]) -> Result<Session> {
        if self.timed_out(now) {
            return Err(Error::State("pairing timed out"));
        }
        let keys0 = keys::epoch_keys(&self.root0, 0)?;
        let env = Envelope::decode(envelope_bytes)?;
        let value = envelope::open_session(
            &keys0.d2w,
            envelope::Direction::DappToWallet,
            &self.own_mailbox,
            &env,
        )?;
        let inner = Inner::from_value(&value)?;
        session::check_times(&inner, now)?;
        let Message::SessionConfirm {
            mailbox,
            write_token,
        } = inner.message
        else {
            return Err(Error::State("expected session.confirm"));
        };
        let mut s = Session::new(NewSession {
            role: Role::Wallet,
            root0: self.root0.clone(),
            own_mailbox: self.own_mailbox,
            own_read: self.own_read.clone(),
            peer_mailbox: mailbox,
            peer_write: write_token,
            now,
        })?;
        s.mark_received(inner.seq);
        Ok(s)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
pub(crate) mod tests {
    use super::*;
    use crate::crypto::{Ed25519Seed, TestEntropy};
    use crate::message::RpcOutcome;
    use crate::uri::LocalSigner;

    const NOW: u64 = 1_790_000_000;

    pub(crate) struct Fixture {
        pub rng: TestEntropy,
        pub signer: LocalSigner,
        pub doc: OriginDocument,
    }

    pub(crate) fn fixture() -> Fixture {
        let signer = LocalSigner::new(Ed25519Seed::from_bytes([1; 32]), "k1").unwrap();
        let json = format!(
            r#"{{"v":1,"name":"Pengui","origin_keys":[{{"kid":"k1","pk":"{}","not_after":"2030-01-01"}}]}}"#,
            crate::b64::encode(&signer.public_key())
        );
        Fixture {
            rng: TestEntropy::new([42; 32]),
            signer,
            doc: OriginDocument::parse(json.as_bytes()).unwrap(),
        }
    }

    fn new_dapp(f: &mut Fixture) -> DappPairing {
        DappPairing::new(
            &mut f.rng,
            NOW,
            &f.signer,
            DappPairingParams {
                relay: "https://relay.example",
                domain: "pengui.xyz",
                pairing_mailbox: MailboxId([1; 16]),
                pairing_write: Token::from_bytes([2; 32]),
                lifetime_s: 300,
                ticket: None,
                options: ParseOptions::default(),
            },
        )
        .unwrap()
    }

    fn wallet_reply(f: &mut Fixture, uri: &str, mbx: u8) -> (WalletPairing, Outgoing) {
        let parsed = PairingUri::parse(uri, ParseOptions::default()).unwrap();
        let verified = VerifiedUri::new(parsed, &f.doc, NOW + 5).unwrap();
        WalletPairing::reply(
            &mut f.rng,
            NOW + 5,
            &verified,
            MailboxId([mbx; 16]),
            Token::from_bytes([mbx; 32]),
            Token::from_bytes([mbx + 1; 32]),
            None,
        )
        .unwrap()
    }

    /// Full handshake; returns (dapp session, wallet session).
    pub(crate) fn paired(f: &mut Fixture) -> (Session, Session) {
        let mut dapp = new_dapp(f);
        let (wallet, reply) = wallet_reply(f, &dapp.uri().to_uri(), 10);
        let accepted = dapp.on_reply(NOW + 6, &reply.envelope).unwrap();
        assert_eq!(accepted.sas(), wallet.sas());
        let (mut ds, confirm) = accepted
            .confirm(
                &mut f.rng,
                NOW + 7,
                MailboxId([20; 16]),
                Token::from_bytes([21; 32]),
                Token::from_bytes([22; 32]),
            )
            .unwrap();
        assert_eq!(confirm.mailbox, MailboxId([10; 16]));
        let mut ws = wallet.on_confirm(NOW + 8, &confirm.envelope).unwrap();
        assert!(!ws.is_active() && !ds.is_active());
        let ready = ws.confirm_sas(&mut f.rng, NOW + 9, None).unwrap().unwrap();
        assert!(ws.is_active());
        assert_eq!(ready.mailbox, MailboxId([20; 16]));
        ds.open(NOW + 10, &MailboxId([20; 16]), &ready.envelope)
            .unwrap();
        assert!(
            !ds.is_active(),
            "dApp needs the user's SAS confirmation too"
        );
        assert!(
            ds.confirm_sas(&mut f.rng, NOW + 10, None)
                .unwrap()
                .is_none()
        );
        assert!(ds.is_active());
        (ds, ws)
    }

    #[test]
    fn handshake_and_rpc_roundtrip() {
        let mut f = fixture();
        let (mut ds, mut ws) = paired(&mut f);
        let req = ds
            .seal(
                &mut f.rng,
                NOW + 20,
                Message::RpcRequest {
                    method: "chainId".into(),
                    params: "{}".into(),
                },
                600,
            )
            .unwrap();
        let got = ws.open(NOW + 21, &ws.own_mailbox(), &req.envelope).unwrap();
        assert_eq!(got.id, req.id);
        let resp = ws
            .seal(
                &mut f.rng,
                NOW + 22,
                Message::RpcResponse {
                    request_id: got.id,
                    outcome: RpcOutcome::Result("\"mainnet\"".into()),
                },
                600,
            )
            .unwrap();
        let back = ds
            .open(NOW + 23, &ds.own_mailbox(), &resp.envelope)
            .unwrap();
        assert!(
            matches!(back.message, Message::RpcResponse { request_id, .. } if request_id == req.id)
        );
    }

    #[test]
    fn first_reply_wins() {
        let mut f = fixture();
        let mut dapp = new_dapp(&mut f);
        let uri = dapp.uri().to_uri();
        let (_attacker, r1) = wallet_reply(&mut f, &uri, 30);
        let (victim, r2) = wallet_reply(&mut f, &uri, 40);
        let accepted = dapp.on_reply(NOW + 6, &r1.envelope).unwrap();
        assert_eq!(
            dapp.on_reply(NOW + 6, &r2.envelope).unwrap_err(),
            Error::AlreadyPaired
        );
        // The victim's wallet never gets a confirm it can open and times out.
        let (_ds, confirm) = accepted
            .confirm(
                &mut f.rng,
                NOW + 7,
                MailboxId([20; 16]),
                Token::from_bytes([21; 32]),
                Token::from_bytes([22; 32]),
            )
            .unwrap();
        assert!(victim.on_confirm(NOW + 8, &confirm.envelope).is_err());
        assert!(victim.timed_out(NOW + 5 + CONFIRM_TIMEOUT_S + 1));
    }

    #[test]
    fn invalid_replies_do_not_consume_pairing() {
        let mut f = fixture();
        let mut dapp = new_dapp(&mut f);
        // Reply built with a different pairing secret (attacker without the QR secret).
        let mut forged = PairingUri::parse(&dapp.uri().to_uri(), ParseOptions::default()).unwrap();
        forged.secret = PairingSecret::from_bytes([99; 32]);
        let verified = VerifiedUri {
            uri: forged,
            dapp_name: "x".into(),
        };
        let (_w, bad) = WalletPairing::reply(
            &mut f.rng,
            NOW + 5,
            &verified,
            MailboxId([7; 16]),
            Token::from_bytes([7; 32]),
            Token::from_bytes([8; 32]),
            None,
        )
        .unwrap();
        assert_eq!(
            dapp.on_reply(NOW + 6, &bad.envelope).unwrap_err(),
            Error::Decrypt
        );
        // Tampered ciphertext.
        let (_w, good) = wallet_reply(&mut f, &dapp.uri().to_uri(), 50);
        let mut env = Envelope::decode(&good.envelope).unwrap();
        env.ct[3] ^= 1;
        assert_eq!(
            dapp.on_reply(NOW + 6, &env.encode().unwrap()).unwrap_err(),
            Error::Decrypt
        );
        // The genuine reply still pairs.
        assert!(dapp.on_reply(NOW + 6, &good.envelope).is_ok());
    }

    #[test]
    fn reply_after_expiry_rejected() {
        let mut f = fixture();
        let mut dapp = new_dapp(&mut f);
        let (_w, r) = wallet_reply(&mut f, &dapp.uri().to_uri(), 10);
        assert_eq!(
            dapp.on_reply(NOW + 301, &r.envelope).unwrap_err(),
            Error::UriExpired
        );
    }

    #[test]
    fn transcript_binding_changes_keys() {
        // A different URI (e.g. other relay) for the same keys yields a different SAS.
        let mut f = fixture();
        let dapp = new_dapp(&mut f);
        let mut other = PairingUri::parse(&dapp.uri().to_uri(), ParseOptions::default()).unwrap();
        other.relay = "https://other.example".into();
        assert_ne!(other.h_uri().unwrap(), dapp.uri().h_uri().unwrap());
        let verified = VerifiedUri {
            uri: other,
            dapp_name: "x".into(),
        };
        let mut dapp = dapp;
        let (_w, r) = WalletPairing::reply(
            &mut f.rng,
            NOW + 5,
            &verified,
            MailboxId([7; 16]),
            Token::from_bytes([7; 32]),
            Token::from_bytes([8; 32]),
            None,
        )
        .unwrap();
        // HPKE info differs, so the dApp cannot open it.
        assert_eq!(
            dapp.on_reply(NOW + 6, &r.envelope).unwrap_err(),
            Error::Decrypt
        );
    }

    #[test]
    fn sas_mismatch_aborts() {
        let mut f = fixture();
        let mut dapp = new_dapp(&mut f);
        let (wallet, reply) = wallet_reply(&mut f, &dapp.uri().to_uri(), 10);
        let accepted = dapp.on_reply(NOW + 6, &reply.envelope).unwrap();
        let (mut ds, confirm) = accepted
            .confirm(
                &mut f.rng,
                NOW + 7,
                MailboxId([20; 16]),
                Token::from_bytes([21; 32]),
                Token::from_bytes([22; 32]),
            )
            .unwrap();
        let mut ws = wallet.on_confirm(NOW + 8, &confirm.envelope).unwrap();
        let end = ws.reject_sas(&mut f.rng, NOW + 9).unwrap();
        assert!(ws.is_ended());
        assert!(
            ws.seal(&mut f.rng, NOW + 9, Message::SessionPing, 60)
                .is_err()
        );
        let got = ds
            .open(NOW + 10, &MailboxId([20; 16]), &end.envelope)
            .unwrap();
        assert!(matches!(got.message, Message::SessionEnd { .. }));
        assert!(ds.is_ended());
    }

    #[test]
    fn verified_uri_rejects_bad_signature() {
        let mut f = fixture();
        let dapp = new_dapp(&mut f);
        let mut tampered =
            PairingUri::parse(&dapp.uri().to_uri(), ParseOptions::default()).unwrap();
        tampered.domain = "evil.example".into();
        assert_eq!(
            VerifiedUri::new(tampered, &f.doc, NOW).unwrap_err(),
            Error::BadSignature
        );
    }
}
