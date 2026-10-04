//! Test-vector entry points (`docs/spec/vectors/`). **Not part of the SDK API.**
//!
//! The production constructors draw keys, pairing secrets, HPKE ephemerals and nonces
//! from the OS CSPRNG, so they cannot reproduce published vectors. These functions take
//! those values explicitly instead and exist only so the SDK test suite can check the
//! WASM build against the vectors. They are hidden from the generated docs, prefixed
//! `vector`, and not re-exported by `@xchonnect/dapp`. Never call them in applications:
//! supplying your own key material or nonces defeats the protocol's guarantees.

use crate::{DappPairing, WalletPairing, WalletReply, err, mailbox, token};
use serde_json::json;
use wasm_bindgen::prelude::*;
use xchonnect_core::b64;
use xchonnect_core::cbor;
use xchonnect_core::crypto::{ChainKey, DirectionKey, Entropy, RootKey, X25519Secret};
use xchonnect_core::envelope::{self, Direction, Envelope, Kind};
use xchonnect_core::keys::{self, Sas};
use xchonnect_core::pairing::{self as core_pairing, DappPairingParams};
use xchonnect_core::uri::ParseOptions;

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

fn bytes32(s: &str) -> Result<[u8; 32], JsError> {
    b64::decode_array::<32>(s).map_err(err)
}

fn direction(d: u8) -> Result<Direction, JsError> {
    match d {
        1 => Ok(Direction::DappToWallet),
        2 => Ok(Direction::WalletToDapp),
        _ => Err(err("direction must be 1 or 2")),
    }
}

/// Test vectors only: a dApp pairing with explicit `dsk` and pairing secret `s`.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen(js_name = vectorDappPairing)]
pub fn vector_dapp_pairing(
    relay: &str,
    domain: &str,
    pairing_mailbox: &str,
    pairing_write_token: &str,
    lifetime_s: u32,
    now: f64,
    kid: &str,
    ticket: Option<String>,
    dsk_b64: &str,
    secret_b64: &str,
    signature_b64: &str,
    origin_pk_b64: &str,
) -> Result<DappPairing, JsError> {
    let ticket = ticket
        .map(|t| b64::decode_array::<32>(&t))
        .transpose()
        .map_err(err)?;
    let mut rng = Replay {
        bytes: [bytes32(dsk_b64)?, bytes32(secret_b64)?].concat(),
        pos: 0,
    };
    let unsigned = core_pairing::DappPairing::prepare(
        &mut rng,
        now as u64,
        kid,
        DappPairingParams {
            relay,
            domain,
            pairing_mailbox: mailbox(pairing_mailbox)?,
            pairing_write: token(pairing_write_token)?,
            lifetime_s: u64::from(lifetime_s),
            ticket,
            options: ParseOptions::default(),
        },
    )
    .map_err(err)?;
    let sig = b64::decode_array::<64>(signature_b64).map_err(err)?;
    Ok(DappPairing {
        inner: unsigned
            .finish(sig, Some(&bytes32(origin_pk_b64)?))
            .map_err(err)?,
    })
}

/// Test vectors only: a wallet pairing reply with an explicit HPKE `ikmE`.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen(js_name = vectorWalletReply)]
pub fn vector_wallet_reply(
    uri: &str,
    origin_document_json: &str,
    now: f64,
    own_mailbox: &str,
    read_token: &str,
    write_token: &str,
    wallet_name: Option<String>,
    ikm_e_b64: &str,
) -> Result<WalletReply, JsError> {
    let parsed =
        xchonnect_core::uri::PairingUri::parse(uri, ParseOptions::default()).map_err(err)?;
    let doc = xchonnect_core::origin::OriginDocument::parse(origin_document_json.as_bytes())
        .map_err(err)?;
    let domain = parsed.domain.clone();
    let verified = core_pairing::VerifiedUri::new(parsed, &doc, now as u64).map_err(err)?;
    let meta = wallet_name.map(|n| xchonnect_core::message::WalletMeta {
        name: Some(n),
        ..Default::default()
    });
    let mut rng = Replay {
        bytes: bytes32(ikm_e_b64)?.to_vec(),
        pos: 0,
    };
    let (p, out) = core_pairing::WalletPairing::reply(
        &mut rng,
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

/// Test vectors only: epoch keys and SAS from a root key. Returns JSON
/// `{d2w, w2d, ck, sas}` (base64url, SAS as six digits).
#[doc(hidden)]
#[wasm_bindgen(js_name = vectorEpochKeys)]
pub fn vector_epoch_keys(root_b64: &str) -> Result<String, JsError> {
    let root = RootKey::from_bytes(bytes32(root_b64)?);
    let k = keys::epoch_keys(&root, 0).map_err(err)?;
    Ok(json!({
        "d2w": b64::encode(k.d2w.expose()),
        "w2d": b64::encode(k.w2d.expose()),
        "ck": b64::encode(k.chain.expose()),
        "sas": Sas::derive(&root).map_err(err)?.digits(),
    })
    .to_string())
}

/// Test vectors only: rotation from chaining key `ck` with ephemeral secrets `a`, `b`.
/// Returns JSON `{aPub, bPub, root}` (base64url).
#[doc(hidden)]
#[wasm_bindgen(js_name = vectorRotate)]
pub fn vector_rotate(
    ck_b64: &str,
    a_b64: &str,
    b_b64: &str,
    new_epoch: f64,
) -> Result<String, JsError> {
    let a = X25519Secret::from_bytes(bytes32(a_b64)?);
    let b = X25519Secret::from_bytes(bytes32(b_b64)?);
    let (a_pub, b_pub) = (a.public_key(), b.public_key());
    let dh = a.diffie_hellman(&b_pub).map_err(err)?;
    let root = keys::rotation_root(
        &ChainKey::from_bytes(bytes32(ck_b64)?),
        &dh,
        new_epoch as u64,
        &a_pub,
        &b_pub,
    )
    .map_err(err)?;
    Ok(json!({
        "aPub": b64::encode(&a_pub),
        "bPub": b64::encode(&b_pub),
        "root": b64::encode(root.expose()),
    })
    .to_string())
}

/// Test vectors only: the 28-byte session AAD (base64url).
#[doc(hidden)]
#[wasm_bindgen(js_name = vectorAad)]
pub fn vector_aad(dir: u8, recipient: &str) -> Result<String, JsError> {
    Ok(b64::encode(&envelope::aad(
        Kind::Session,
        direction(dir)?,
        &mailbox(recipient)?,
    )))
}

/// Test vectors only: seal an inner plaintext with an explicit nonce.
#[doc(hidden)]
#[wasm_bindgen(js_name = vectorSealSession)]
pub fn vector_seal_session(
    key_b64: &str,
    nonce_b64: &str,
    dir: u8,
    recipient: &str,
    inner_b64: &str,
) -> Result<String, JsError> {
    let nonce = b64::decode_array::<24>(nonce_b64).map_err(err)?;
    let inner = b64::decode(inner_b64).map_err(err)?;
    Ok(b64::encode(
        &envelope::seal_session_with_nonce(
            &nonce,
            &DirectionKey::from_bytes(bytes32(key_b64)?),
            direction(dir)?,
            &mailbox(recipient)?,
            &inner,
        )
        .map_err(err)?,
    ))
}

/// Test vectors only: decode and open a session envelope; returns the inner CBOR
/// (canonical, unpadded, base64url).
#[doc(hidden)]
#[wasm_bindgen(js_name = vectorOpenSession)]
pub fn vector_open_session(
    key_b64: &str,
    dir: u8,
    recipient: &str,
    envelope_b64: &str,
) -> Result<String, JsError> {
    let env = Envelope::decode(&b64::decode(envelope_b64).map_err(err)?).map_err(err)?;
    let v = envelope::open_session(
        &DirectionKey::from_bytes(bytes32(key_b64)?),
        direction(dir)?,
        &mailbox(recipient)?,
        &env,
    )
    .map_err(err)?;
    Ok(b64::encode(&cbor::encode(&v).map_err(err)?))
}

/// Test vectors only: structural envelope decoding as a relay performs it.
#[doc(hidden)]
#[wasm_bindgen(js_name = vectorDecodeEnvelope)]
pub fn vector_decode_envelope(envelope_b64: &str) -> Result<(), JsError> {
    Envelope::decode(&b64::decode(envelope_b64).map_err(err)?).map_err(err)?;
    Ok(())
}
