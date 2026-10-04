//! Throwaway spike: exercise every primitive the Xchonnect core needs.
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hpke::aead::ChaCha20Poly1305 as HpkeChaCha;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as _, OpModeR, OpModeS, PskBundle, Serializable};

pub fn run() -> Result<String, String> {
    let mut log = String::new();

    // CSPRNG
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).map_err(|e| format!("getrandom: {e}"))?;
    log += "getrandom ok\n";

    // X25519
    let a = x25519_dalek::StaticSecret::from(buf);
    let b = x25519_dalek::StaticSecret::from([7u8; 32]);
    let (pa, pb) = (x25519_dalek::PublicKey::from(&a), x25519_dalek::PublicKey::from(&b));
    let s1 = a.diffie_hellman(&pb);
    let s2 = b.diffie_hellman(&pa);
    if s1.as_bytes() != s2.as_bytes() || !s1.was_contributory() {
        return Err("x25519 mismatch".into());
    }
    log += "x25519 ok\n";

    // HPKE PSK seal/open + export
    let (sk_r, pk_r) = X25519HkdfSha256::gen_keypair();
    let psk = [9u8; 32];
    let bundle = PskBundle::new(&psk, b"xchonnect v1 psk").map_err(|e| e.to_string())?;
    let (enc, mut sctx) = hpke::setup_sender::<HpkeChaCha, HkdfSha256, X25519HkdfSha256>(
        &OpModeS::Psk(bundle),
        &pk_r,
        b"info",
    )
    .map_err(|e| e.to_string())?;
    let ct = sctx.seal(b"hello", b"aad").map_err(|e| e.to_string())?;
    let enc_bytes = enc.to_bytes();
    let enc2 = <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(&enc_bytes)
        .map_err(|e| e.to_string())?;
    let bundle = PskBundle::new(&psk, b"xchonnect v1 psk").map_err(|e| e.to_string())?;
    let mut rctx = hpke::setup_receiver::<HpkeChaCha, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Psk(bundle),
        &sk_r,
        &enc2,
        b"info",
    )
    .map_err(|e| e.to_string())?;
    let pt = rctx.open(&ct, b"aad").map_err(|e| e.to_string())?;
    let (mut e1, mut e2) = ([0u8; 32], [0u8; 32]);
    sctx.export(b"ctx", &mut e1).map_err(|e| e.to_string())?;
    rctx.export(b"ctx", &mut e2).map_err(|e| e.to_string())?;
    if pt != b"hello" || e1 != e2 {
        return Err("hpke mismatch".into());
    }
    log += "hpke psk ok\n";

    // XChaCha20-Poly1305
    let cipher = XChaCha20Poly1305::new(&[1u8; 32].into());
    let nonce = XNonce::from([2u8; 24]);
    let c = cipher
        .encrypt(&nonce, Payload { msg: b"m", aad: b"a" })
        .map_err(|_| "xchacha enc")?;
    let p = cipher
        .decrypt(&nonce, Payload { msg: &c, aad: b"a" })
        .map_err(|_| "xchacha dec")?;
    if p != b"m" {
        return Err("xchacha mismatch".into());
    }
    log += "xchacha ok\n";

    // Ed25519
    use ed25519_dalek::Signer;
    let sk = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
    let sig = sk.sign(b"msg");
    sk.verifying_key().verify_strict(b"msg", &sig).map_err(|e| e.to_string())?;
    log += "ed25519 ok\n";

    // HKDF / SHA-256
    use sha2::Digest;
    let h = sha2::Sha256::digest(b"abc");
    let hk = hkdf::Hkdf::<sha2::Sha256>::from_prk(&h).map_err(|_| "prk")?;
    let mut okm = [0u8; 32];
    hk.expand(b"label", &mut okm).map_err(|_| "expand")?;
    log += "hkdf ok\n";

    // OHTTP round trip
    let config = ohttp::KeyConfig::new(
        1,
        ohttp::hpke::Kem::X25519Sha256,
        vec![ohttp::SymmetricSuite::new(
            ohttp::hpke::Kdf::HkdfSha256,
            ohttp::hpke::Aead::ChaCha20Poly1305,
        )],
    )
    .map_err(|e| e.to_string())?;
    let server = ohttp::Server::new(config).map_err(|e| e.to_string())?;
    let encoded = server.config().encode().map_err(|e| e.to_string())?;
    let client = ohttp::ClientRequest::from_encoded_config(&encoded).map_err(|e| e.to_string())?;
    let (req, cresp) = client.encapsulate(b"GET /v1/info").map_err(|e| e.to_string())?;
    let (inner, sresp) = server.decapsulate(&req).map_err(|e| e.to_string())?;
    let enc_resp = sresp.encapsulate(&inner).map_err(|e| e.to_string())?;
    let out = cresp.decapsulate(&enc_resp).map_err(|e| e.to_string())?;
    if out != b"GET /v1/info" {
        return Err("ohttp mismatch".into());
    }
    log += "ohttp ok\n";
    Ok(log)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn spike() -> String {
    match run() {
        Ok(s) => s,
        Err(e) => format!("ERROR: {e}"),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn all() {
        println!("{}", super::run().unwrap());
    }
}
