//! dApp side driven from Swift/Kotlin round-trip tests (`test-helpers` feature only).
//!
//! Uses a fixed, public origin key: never enable this feature in wallet builds.

use std::sync::{Arc, Mutex, MutexGuard};

use xchonnect_core::b64;
use xchonnect_core::crypto::{Ed25519Seed, MailboxId, OsEntropy, Token};
use xchonnect_core::pairing::{AcceptedPairing, DappPairing, DappPairingParams};
use xchonnect_core::rpc;
use xchonnect_core::session::Session as CoreSession;
use xchonnect_core::uri::{LocalSigner, ParseOptions};

use crate::session::IncomingMessage;
use crate::{Outgoing, Result, XchonnectError, mailbox};

const SEED: [u8; 32] = [7; 32];

#[derive(Debug)]
struct State {
    pairing: DappPairing,
    accepted: Option<AcceptedPairing>,
    session: Option<CoreSession>,
}

/// A dApp built from the core's dApp-side state machines, for binding tests.
#[derive(Debug, uniffi::Object)]
pub struct TestDapp {
    origin_json: String,
    state: Mutex<State>,
}

fn st(e: &'static str) -> XchonnectError {
    XchonnectError::State(e.into())
}

fn random_mailbox() -> MailboxId {
    MailboxId(xchonnect_core::crypto::random_array(&mut OsEntropy))
}

impl TestDapp {
    fn lock(&self) -> Result<MutexGuard<'_, State>> {
        self.state.lock().map_err(|_| st("poisoned"))
    }

    fn with_session<T>(
        &self,
        f: impl FnOnce(&mut CoreSession) -> xchonnect_core::Result<T>,
    ) -> Result<T> {
        Ok(f(self
            .lock()?
            .session
            .as_mut()
            .ok_or_else(|| st("no session"))?)?)
    }
}

#[uniffi::export]
impl TestDapp {
    /// Create a pairing on `https://relay.example` for `pengui.xyz`.
    #[uniffi::constructor]
    pub fn new(now: u64) -> Result<Arc<Self>> {
        let signer = LocalSigner::new(Ed25519Seed::from_bytes(SEED), "k1")?;
        let origin_json = format!(
            r#"{{"v":1,"name":"Pengui","origin_keys":[{{"kid":"k1","pk":"{}","not_after":"2099-12-31"}}]}}"#,
            b64::encode(&signer.public_key())
        );
        let pairing = DappPairing::new(
            &mut OsEntropy,
            now,
            &signer,
            DappPairingParams {
                relay: "https://relay.example",
                domain: "pengui.xyz",
                pairing_mailbox: random_mailbox(),
                pairing_write: Token::random(&mut OsEntropy),
                lifetime_s: 300,
                ticket: None,
                options: ParseOptions::default(),
            },
        )?;
        Ok(Arc::new(TestDapp {
            origin_json,
            state: Mutex::new(State {
                pairing,
                accepted: None,
                session: None,
            }),
        }))
    }

    /// Test vectors only: the dApp of a published pairing case, rebuilt from its
    /// explicit `dsk` and pairing secret so that [`TestDapp::on_reply`] can be driven
    /// with the vector's envelopes. `signature` and `origin_pk` are the case's published
    /// origin signature and key.
    #[uniffi::constructor]
    #[allow(clippy::too_many_arguments)]
    pub fn from_vector(
        now: u64,
        relay: String,
        domain: String,
        pairing_mailbox: String,
        pairing_write_token: String,
        lifetime_s: u64,
        kid: String,
        ticket: Option<String>,
        dsk: String,
        pairing_secret: String,
        signature: String,
        origin_pk: String,
    ) -> Result<Arc<Self>> {
        let mut rng = crate::vectors::vector_entropy(
            [
                crate::array::<32>("dsk", &dsk)?,
                crate::array::<32>("pairing_secret", &pairing_secret)?,
            ]
            .concat(),
        );
        let unsigned = DappPairing::prepare(
            &mut rng,
            now,
            &kid,
            DappPairingParams {
                relay: &relay,
                domain: &domain,
                pairing_mailbox: mailbox("pairing_mailbox", &pairing_mailbox)?,
                pairing_write: crate::token("pairing_write_token", &pairing_write_token)?,
                lifetime_s,
                ticket: ticket
                    .as_deref()
                    .map(|t| crate::array::<32>("ticket", t))
                    .transpose()?,
                options: ParseOptions::default(),
            },
        )?;
        let pairing = unsigned.finish(
            crate::array::<64>("signature", &signature)?,
            Some(&crate::array::<32>("origin_pk", &origin_pk)?),
        )?;
        Ok(Arc::new(TestDapp {
            origin_json: String::new(),
            state: Mutex::new(State {
                pairing,
                accepted: None,
                session: None,
            }),
        }))
    }

    /// A random mailbox id, standing in for the one a relay assigns.
    pub fn fake_mailbox_id(&self) -> String {
        random_mailbox().to_b64()
    }

    /// Body of the dApp's `/.well-known/xchonnect.json`.
    pub fn origin_document_json(&self) -> String {
        self.origin_json.clone()
    }

    /// The pairing URI (QR code content).
    pub fn pairing_uri(&self) -> Result<String> {
        Ok(self.lock()?.pairing.uri().to_uri())
    }

    /// Process the wallet's pairing reply; returns the SAS.
    pub fn on_reply(&self, now: u64, envelope: String) -> Result<String> {
        let env = crate::bytes("envelope", &envelope)?;
        let mut s = self.lock()?;
        let a = s.pairing.on_reply(now, &env)?;
        let sas = a.sas().to_string();
        s.accepted = Some(a);
        Ok(sas)
    }

    /// Create the session (fresh mailbox D) and return `session.confirm`.
    pub fn confirm(&self, now: u64) -> Result<Outgoing> {
        let mut s = self.lock()?;
        let a = s.accepted.take().ok_or_else(|| st("no accepted reply"))?;
        let (session, out) = a.confirm(
            &mut OsEntropy,
            now,
            random_mailbox(),
            Token::random(&mut OsEntropy),
            Token::random(&mut OsEntropy),
        )?;
        s.session = Some(session);
        Ok(out.into())
    }

    /// The dApp user confirmed the SAS.
    pub fn confirm_sas(&self, now: u64) -> Result<()> {
        self.with_session(|x| x.confirm_sas(&mut OsEntropy, now, None))
            .map(|_| ())
    }

    /// Whether the dApp session is active.
    pub fn is_active(&self) -> Result<bool> {
        Ok(self
            .lock()?
            .session
            .as_ref()
            .is_some_and(CoreSession::is_active))
    }

    /// Current epoch of the dApp session.
    pub fn epoch(&self) -> Result<u64> {
        self.with_session(|x| Ok(x.epoch()))
    }

    /// Open an envelope the wallet posted to `mailbox`.
    pub fn open(&self, now: u64, mailbox_id: String, envelope: String) -> Result<IncomingMessage> {
        let mbx = mailbox("mailbox", &mailbox_id)?;
        let env = crate::bytes("envelope", &envelope)?;
        Ok(self.with_session(|x| x.open(now, &mbx, &env))?.into())
    }

    /// Seal an `rpc.request`.
    pub fn request(&self, now: u64, method: String, params_json: String) -> Result<Outgoing> {
        let msg = rpc::request(&method, &params_json)?;
        Ok(self
            .with_session(|x| x.seal(&mut OsEntropy, now, msg, 600))?
            .into())
    }

    /// Offer a rotation with a fresh mailbox.
    pub fn begin_rotation(&self, now: u64) -> Result<Outgoing> {
        Ok(self
            .with_session(|x| {
                x.begin_rotation(
                    &mut OsEntropy,
                    now,
                    random_mailbox(),
                    Token::random(&mut OsEntropy),
                    Token::random(&mut OsEntropy),
                )
            })?
            .into())
    }

    /// Seal `session.end`.
    pub fn end(&self, now: u64, reason: Option<String>) -> Result<Outgoing> {
        Ok(self
            .with_session(|x| x.end(&mut OsEntropy, now, reason))?
            .into())
    }
}
