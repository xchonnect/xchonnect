//! Test-vector entry points (`docs/spec/vectors/`). **Not part of the wallet API.**
//!
//! Only compiled with the `test-helpers` feature, which release wallet builds never
//! enable. The production constructors draw keys, pairing secrets, HPKE ephemerals and
//! nonces from the OS CSPRNG, so they cannot reproduce published vectors; these
//! functions take those values explicitly instead and exist only so the Swift and Kotlin
//! round-trip programs can check the generated bindings against the vectors
//! (`scripts/test-bindings-native.sh`). Never call them in applications: supplying your
//! own key material or nonces defeats the protocol's guarantees.

use std::sync::Arc;

use serde_json::json;
use xchonnect_core::b64;
use xchonnect_core::cbor;
use xchonnect_core::crypto::{ChainKey, DirectionKey, Entropy, RootKey, X25519Secret};
use xchonnect_core::envelope::{self, Direction, Envelope, Kind};
use xchonnect_core::keys::{self, Sas};
use xchonnect_core::origin::OriginDocument;
use xchonnect_core::pairing as core_pairing;
use xchonnect_core::uri::{PairingUri, ParseOptions};

use crate::error::{Result, XchonnectError};
use crate::pairing::{WalletPairing, WalletReply};
use crate::{NewMailbox, WalletMetadata, array, mailbox};

/// Replays explicit bytes, then zeros (only for values that never reach the wire).
struct Replay {
    bytes: Vec<u8>,
    pos: usize,
}

impl Entropy for Replay {
    fn fill(&mut self, dst: &mut [u8]) {
        for b in dst {
            *b = self.bytes.get(self.pos).copied().unwrap_or(0);
            self.pos = self.pos.saturating_add(1);
        }
    }
}

/// Entropy source that replays `bytes` and then zeros. Test vectors only.
pub(crate) fn vector_entropy(bytes: Vec<u8>) -> impl Entropy {
    Replay { bytes, pos: 0 }
}

fn direction(dir: u8) -> Result<Direction> {
    match dir {
        1 => Ok(Direction::DappToWallet),
        2 => Ok(Direction::WalletToDapp),
        _ => Err(XchonnectError::input("direction")),
    }
}

/// Test vectors only: epoch keys and SAS from a root key. Returns JSON
/// `{"d2w","w2d","ck","sas"}` (base64url, SAS as six digits).
#[uniffi::export]
pub fn vector_epoch_keys(root: String) -> Result<String> {
    let root = RootKey::from_bytes(array::<32>("root", &root)?);
    let k = keys::epoch_keys(&root, 0)?;
    Ok(json!({
        "d2w": b64::encode(k.d2w.expose()),
        "w2d": b64::encode(k.w2d.expose()),
        "ck": b64::encode(k.chain.expose()),
        "sas": Sas::derive(&root)?.digits(),
    })
    .to_string())
}

/// Test vectors only: rotation from chaining key `ck` with ephemeral secrets `a` and `b`.
/// Returns JSON `{"aPub","bPub","root"}` (base64url).
#[uniffi::export]
pub fn vector_rotate(ck: String, a: String, b: String, new_epoch: u64) -> Result<String> {
    let a = X25519Secret::from_bytes(array::<32>("a", &a)?);
    let b = X25519Secret::from_bytes(array::<32>("b", &b)?);
    let (a_pub, b_pub) = (a.public_key(), b.public_key());
    let dh = a.diffie_hellman(&b_pub)?;
    let root = keys::rotation_root(
        &ChainKey::from_bytes(array::<32>("ck", &ck)?),
        &dh,
        new_epoch,
        &a_pub,
        &b_pub,
    )?;
    Ok(json!({
        "aPub": b64::encode(&a_pub),
        "bPub": b64::encode(&b_pub),
        "root": b64::encode(root.expose()),
    })
    .to_string())
}

/// Test vectors only: the 28-byte session AAD (base64url).
#[uniffi::export]
pub fn vector_aad(dir: u8, recipient_mailbox: String) -> Result<String> {
    Ok(b64::encode(&envelope::aad(
        Kind::Session,
        direction(dir)?,
        &mailbox("recipient_mailbox", &recipient_mailbox)?,
    )))
}

/// Test vectors only: seal an inner plaintext with an explicit nonce (base64url
/// envelope).
#[uniffi::export]
pub fn vector_seal_session(
    key: String,
    nonce: String,
    dir: u8,
    recipient_mailbox: String,
    inner: String,
) -> Result<String> {
    let nonce = array::<24>("nonce", &nonce)?;
    let inner = crate::bytes("inner", &inner)?;
    Ok(b64::encode(&envelope::seal_session_with_nonce(
        &nonce,
        &DirectionKey::from_bytes(array::<32>("key", &key)?),
        direction(dir)?,
        &mailbox("recipient_mailbox", &recipient_mailbox)?,
        &inner,
    )?))
}

/// Test vectors only: decode and open a session envelope; returns the inner CBOR
/// (canonical, unpadded, base64url).
#[uniffi::export]
pub fn vector_open_session(
    key: String,
    dir: u8,
    recipient_mailbox: String,
    envelope_b64: String,
) -> Result<String> {
    let env = Envelope::decode(&crate::bytes("envelope", &envelope_b64)?)?;
    let v = envelope::open_session(
        &DirectionKey::from_bytes(array::<32>("key", &key)?),
        direction(dir)?,
        &mailbox("recipient_mailbox", &recipient_mailbox)?,
        &env,
    )?;
    Ok(b64::encode(&cbor::encode(&v)?))
}

/// Test vectors only: seal a notification preview (the dApp side of spec 7.3.3) with
/// explicit entropy, so the Swift and Kotlin runners can drive
/// `open_notification_preview`. Returns the sealed blob (base64url, always
/// [`xchonnect_core::preview::SEALED_LEN`] bytes).
#[uniffi::export]
pub fn vector_seal_preview(
    hint_key: String,
    kind: u8,
    detail: Option<String>,
    now: u64,
    ttl_s: u64,
    entropy: String,
) -> Result<String> {
    use xchonnect_core::preview;
    let kind = match kind {
        0 => preview::Kind::Generic,
        1 => preview::Kind::SigningRequest,
        2 => preview::Kind::MessageSignature,
        3 => preview::Kind::SessionEvent,
        _ => return Err(XchonnectError::input("kind")),
    };
    let sealed = preview::seal(
        &mut vector_entropy(crate::bytes("entropy", &entropy)?),
        &array::<32>("hint_key", &hint_key)?,
        &preview::Preview { kind, detail },
        now,
        ttl_s,
    )?;
    Ok(b64::encode(&sealed))
}

/// Test vectors only: structural envelope decoding as a relay performs it.
#[uniffi::export]
pub fn vector_decode_envelope(envelope_b64: String) -> Result<()> {
    Envelope::decode(&crate::bytes("envelope", &envelope_b64)?)?;
    Ok(())
}

/// Test vectors only: a wallet pairing reply with an explicit HPKE `ikmE`, reproducing
/// the published reply envelope byte for byte.
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn vector_wallet_reply(
    uri: String,
    origin_document_json: String,
    now: u64,
    own_mailbox: NewMailbox,
    meta: Option<WalletMetadata>,
    ikm_e: String,
) -> Result<WalletReply> {
    let parsed = PairingUri::parse(&uri, ParseOptions::default())?;
    let doc = OriginDocument::parse(origin_document_json.as_bytes())?;
    let verified = core_pairing::VerifiedUri::new(parsed, &doc, now)?;
    let (m, r, w) = own_mailbox.parse()?;
    let (pairing, out) = core_pairing::WalletPairing::reply(
        &mut vector_entropy(array::<32>("ikm_e", &ikm_e)?.to_vec()),
        now,
        &verified,
        m,
        r,
        w,
        meta.map(Into::into),
    )?;
    Ok(WalletReply {
        pairing: Arc::new(WalletPairing::wrap(pairing)),
        outgoing: out.into(),
    })
}
