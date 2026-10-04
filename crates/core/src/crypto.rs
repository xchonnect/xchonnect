//! Cryptographic primitives used by Xchonnect, wrapped in protocol-specific types.
//!
//! Every secret has its own type so that keys cannot be mixed up, is wiped from memory
//! on drop, never prints its contents through `Debug`, and is compared in constant
//! time. All primitives come from the crates listed in
//! `docs/design/crate-selection.md`; nothing here implements cryptography itself.

use crate::error::{Error, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use core::convert::Infallible;
use core::fmt;
use hpke::aead::{AeadCtxR, AeadCtxS, ChaCha20Poly1305 as HpkeChaCha};
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, OpModeR, OpModeS, PskBundle, Serializable};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

// --- Entropy -------------------------------------------------------------------------------

/// Source of cryptographically secure random bytes.
///
/// Production code uses [`OsEntropy`]. Implementations MUST be cryptographically
/// secure; the trait exists so that test vectors can be generated deterministically.
pub trait Entropy {
    /// Fill `dst` with random bytes.
    fn fill(&mut self, dst: &mut [u8]);
}

/// Operating-system CSPRNG (`getrandom`; `crypto.getRandomValues` on wasm32).
#[derive(Debug, Default, Clone, Copy)]
pub struct OsEntropy;

impl Entropy for OsEntropy {
    #[allow(clippy::expect_used)]
    fn fill(&mut self, dst: &mut [u8]) {
        // A failing OS RNG is unrecoverable: continuing would produce predictable keys.
        getrandom::fill(dst).expect("operating system random number generator failed");
    }
}

/// Deterministic entropy for test vectors only. Output is
/// `SHA-256("xchonnect test entropy" || seed || u64_be(counter))` blocks.
#[cfg(any(test, feature = "test-vectors"))]
#[derive(Debug, Clone)]
pub struct TestEntropy {
    seed: [u8; 32],
    counter: u64,
    buf: Vec<u8>,
}

#[cfg(any(test, feature = "test-vectors"))]
impl TestEntropy {
    /// Create a generator from a seed.
    pub fn new(seed: [u8; 32]) -> Self {
        TestEntropy {
            seed,
            counter: 0,
            buf: Vec::new(),
        }
    }
}

#[cfg(any(test, feature = "test-vectors"))]
impl Entropy for TestEntropy {
    fn fill(&mut self, dst: &mut [u8]) {
        for byte in dst {
            if self.buf.is_empty() {
                let ctr = self.counter.to_be_bytes();
                let block = sha256_parts(&[b"xchonnect test entropy", &self.seed, &ctr]);
                self.counter += 1;
                self.buf = block.into_iter().rev().collect();
            }
            *byte = self.buf.pop().unwrap_or(0);
        }
    }
}

/// Adapter so `hpke`/`x25519-dalek` can draw from an [`Entropy`].
pub(crate) struct RngAdapter<'a>(pub(crate) &'a mut dyn Entropy);

impl hpke::rand_core::TryRng for RngAdapter<'_> {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> core::result::Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.0.fill(&mut b);
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> core::result::Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.0.fill(&mut b);
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), Infallible> {
        self.0.fill(dst);
        Ok(())
    }
}

impl hpke::rand_core::TryCryptoRng for RngAdapter<'_> {}

/// Fill a fresh array with random bytes.
pub fn random_array<const N: usize>(rng: &mut dyn Entropy) -> [u8; N] {
    let mut out = [0u8; N];
    rng.fill(&mut out);
    out
}

// --- Secret newtypes -----------------------------------------------------------------------

macro_rules! secret_type {
    ($(#[$doc:meta])* $name:ident, $len:expr) => {
        $(#[$doc])*
        #[derive(Clone, Zeroize, ZeroizeOnDrop)]
        pub struct $name([u8; $len]);

        impl $name {
            /// Length in bytes.
            pub const LEN: usize = $len;

            /// Wrap raw bytes.
            pub fn from_bytes(bytes: [u8; $len]) -> Self {
                $name(bytes)
            }

            /// Parse from a slice of exactly the right length.
            pub fn from_slice(bytes: &[u8]) -> Result<Self> {
                let arr: [u8; $len] =
                    bytes.try_into().map_err(|_| Error::Malformed(concat!(stringify!($name), " length")))?;
                Ok($name(arr))
            }

            /// Generate from the given entropy source.
            pub fn random(rng: &mut dyn Entropy) -> Self {
                $name(random_array(rng))
            }

            /// Borrow the raw bytes. Callers must not log or persist them unprotected.
            pub fn expose(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.0.ct_eq(&other.0).into()
            }
        }

        impl Eq for $name {}

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
    };
}

secret_type!(
    /// Mailbox read or write capability token (spec 7.1).
    Token, 32
);
secret_type!(
    /// Pairing secret `s` from the pairing URI; used as the HPKE PSK.
    PairingSecret, 32
);
secret_type!(
    /// Epoch root key `root_e` (spec 5.2).
    RootKey, 32
);
secret_type!(
    /// Direction key (`k_d2w` or `k_w2d`).
    DirectionKey, 32
);
secret_type!(
    /// Rotation chaining key `ck_e`.
    ChainKey, 32
);
secret_type!(
    /// X25519 private key (pairing key `dsk` or rotation ephemeral).
    X25519Secret, 32
);
secret_type!(
    /// Ed25519 origin signing key seed. Production dApps keep this in an HSM/KMS and
    /// sign through [`crate::uri::OriginSigner`]; this type exists for tools and tests.
    Ed25519Seed, 32
);

/// Mailbox identifier (16 bytes, chosen by the relay). Not secret, but it must not
/// appear in logs (spec 13.5), so `Debug` does not print it.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MailboxId(pub [u8; 16]);

impl MailboxId {
    /// Parse from exactly 16 bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        Ok(MailboxId(
            bytes
                .try_into()
                .map_err(|_| Error::Malformed("mailbox id length"))?,
        ))
    }

    /// base64url without padding, as used in URLs and JSON.
    pub fn to_b64(&self) -> String {
        crate::b64::encode(&self.0)
    }

    /// Parse the base64url form.
    pub fn from_b64(s: &str) -> Result<Self> {
        Ok(MailboxId(crate::b64::decode_array(s)?))
    }
}

impl fmt::Debug for MailboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MailboxId([redacted])")
    }
}

impl Token {
    /// `SHA-256("xchonnect v1 token" || token)`: the only form the relay stores.
    pub fn hash(&self) -> [u8; 32] {
        token_hash(&self.0)
    }
}

/// Token hash over raw bytes (used by the relay for presented tokens).
pub fn token_hash(token: &[u8]) -> [u8; 32] {
    sha256_parts(&[b"xchonnect v1 token", token])
}

/// Constant-time equality for byte slices of equal length.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

// --- Hashing and KDF -----------------------------------------------------------------------

/// SHA-256 of the concatenation of `parts`.
pub fn sha256_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// HKDF-Expand(prk, info_parts concatenated, 32).
pub fn hkdf_expand32(prk: &[u8; 32], info_parts: &[&[u8]]) -> Result<[u8; 32]> {
    let hk = hkdf::Hkdf::<Sha256>::from_prk(prk).map_err(|_| Error::Crypto("hkdf prk"))?;
    let mut out = [0u8; 32];
    hk.expand_multi_info(info_parts, &mut out)
        .map_err(|_| Error::Crypto("hkdf expand"))?;
    Ok(out)
}

/// HKDF-Expand with an output of `N` bytes.
pub fn hkdf_expand<const N: usize>(prk: &[u8; 32], info: &[u8]) -> Result<[u8; N]> {
    let hk = hkdf::Hkdf::<Sha256>::from_prk(prk).map_err(|_| Error::Crypto("hkdf prk"))?;
    let mut out = [0u8; N];
    hk.expand(info, &mut out)
        .map_err(|_| Error::Crypto("hkdf expand"))?;
    Ok(out)
}

/// HKDF-Extract(salt, ikm) returning the 32-byte PRK.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let (prk, _) = hkdf::Hkdf::<Sha256>::extract(Some(salt), ikm);
    prk.into()
}

/// HMAC-SHA256.
pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Result<[u8; 32]> {
    use hmac::{KeyInit as _, Mac};
    let mut mac =
        hmac::Hmac::<Sha256>::new_from_slice(key).map_err(|_| Error::Crypto("hmac key"))?;
    for p in parts {
        mac.update(p);
    }
    Ok(mac.finalize().into_bytes().into())
}

// --- X25519 --------------------------------------------------------------------------------

impl X25519Secret {
    /// The corresponding public key.
    pub fn public_key(&self) -> [u8; 32] {
        let sk = x25519_dalek::StaticSecret::from(self.0);
        x25519_dalek::PublicKey::from(&sk).to_bytes()
    }

    /// X25519(self, peer). Rejects all-zero outputs (spec 5.2).
    pub fn diffie_hellman(&self, peer: &[u8; 32]) -> Result<[u8; 32]> {
        let sk = x25519_dalek::StaticSecret::from(self.0);
        let shared = sk.diffie_hellman(&x25519_dalek::PublicKey::from(*peer));
        if !shared.was_contributory() {
            return Err(Error::WeakKey);
        }
        Ok(shared.to_bytes())
    }
}

// --- XChaCha20-Poly1305 --------------------------------------------------------------------

/// Encrypt with XChaCha20-Poly1305. Output = ciphertext || 16-byte tag.
pub fn xchacha_seal(
    key: &DirectionKey,
    nonce: &[u8; 24],
    aad: &[u8],
    pt: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(&key.0.into());
    cipher
        .encrypt(&XNonce::from(*nonce), Payload { msg: pt, aad })
        .map_err(|_| Error::Crypto("aead seal"))
}

/// Decrypt with XChaCha20-Poly1305.
pub fn xchacha_open(
    key: &DirectionKey,
    nonce: &[u8; 24],
    aad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(&key.0.into());
    cipher
        .decrypt(&XNonce::from(*nonce), Payload { msg: ct, aad })
        .map_err(|_| Error::Decrypt)
}

// --- HPKE (RFC 9180): DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305 ---------

type Kem = X25519HkdfSha256;

/// HPKE sender context (kept to export a secret after sealing).
pub struct HpkeSender {
    ctx: AeadCtxS<HpkeChaCha, HkdfSha256, Kem>,
}

/// HPKE receiver context.
pub struct HpkeReceiver {
    ctx: AeadCtxR<HpkeChaCha, HkdfSha256, Kem>,
}

impl fmt::Debug for HpkeSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HpkeSender([redacted])")
    }
}

impl fmt::Debug for HpkeReceiver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HpkeReceiver([redacted])")
    }
}

/// Pre-shared key for HPKE PSK mode.
#[derive(Debug, Clone, Copy)]
pub struct Psk<'a> {
    /// The PSK (at least 32 bytes).
    pub psk: &'a [u8],
    /// The PSK identifier.
    pub psk_id: &'a [u8],
}

impl HpkeSender {
    /// `SetupBaseS` (no PSK) or `SetupPSKS` towards `pk_r`. Returns `(enc, ctx)`.
    pub fn setup(
        rng: &mut dyn Entropy,
        pk_r: &[u8; 32],
        info: &[u8],
        psk: Option<Psk<'_>>,
    ) -> Result<([u8; 32], Self)> {
        let pk = <Kem as hpke::Kem>::PublicKey::from_bytes(pk_r)
            .map_err(|_| Error::Malformed("hpke public key"))?;
        let mode = match psk {
            Some(p) => OpModeS::Psk(
                PskBundle::new(p.psk, p.psk_id).map_err(|_| Error::Crypto("psk bundle"))?,
            ),
            None => OpModeS::Base,
        };
        let (enc, ctx) = hpke::setup_sender_with_rng::<HpkeChaCha, HkdfSha256, Kem>(
            &mode,
            &pk,
            info,
            &mut RngAdapter(rng),
        )
        .map_err(|_| Error::Crypto("hpke setup"))?;
        let enc: [u8; 32] = enc.to_bytes().into();
        Ok((enc, HpkeSender { ctx }))
    }

    /// Seal one message.
    pub fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
        self.ctx
            .seal(pt, aad)
            .map_err(|_| Error::Crypto("hpke seal"))
    }

    /// Secret export (RFC 9180 §5.3) of 32 bytes.
    pub fn export(&self, exporter_context: &[u8]) -> Result<[u8; 32]> {
        let mut out = [0u8; 32];
        self.ctx
            .export(exporter_context, &mut out)
            .map_err(|_| Error::Crypto("hpke export"))?;
        Ok(out)
    }
}

impl HpkeReceiver {
    /// `SetupBaseR` or `SetupPSKR`.
    pub fn setup(
        sk_r: &X25519Secret,
        enc: &[u8; 32],
        info: &[u8],
        psk: Option<Psk<'_>>,
    ) -> Result<Self> {
        let sk = <Kem as hpke::Kem>::PrivateKey::from_bytes(&sk_r.0)
            .map_err(|_| Error::Malformed("hpke private key"))?;
        let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(enc)
            .map_err(|_| Error::Malformed("hpke enc"))?;
        let mode = match psk {
            Some(p) => OpModeR::Psk(
                PskBundle::new(p.psk, p.psk_id).map_err(|_| Error::Crypto("psk bundle"))?,
            ),
            None => OpModeR::Base,
        };
        let ctx = hpke::setup_receiver::<HpkeChaCha, HkdfSha256, Kem>(&mode, &sk, &enc, info)
            .map_err(|_| Error::Decrypt)?;
        Ok(HpkeReceiver { ctx })
    }

    /// Open one message.
    pub fn open(&mut self, aad: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
        self.ctx.open(ct, aad).map_err(|_| Error::Decrypt)
    }

    /// Secret export of 32 bytes.
    pub fn export(&self, exporter_context: &[u8]) -> Result<[u8; 32]> {
        let mut out = [0u8; 32];
        self.ctx
            .export(exporter_context, &mut out)
            .map_err(|_| Error::Crypto("hpke export"))?;
        Ok(out)
    }
}

// --- Ed25519 -------------------------------------------------------------------------------

impl Ed25519Seed {
    /// Public key for this seed.
    pub fn public_key(&self) -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(&self.0)
            .verifying_key()
            .to_bytes()
    }

    /// Sign `msg`.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        ed25519_dalek::SigningKey::from_bytes(&self.0)
            .sign(msg)
            .to_bytes()
    }
}

/// Strict Ed25519 verification (rejects non-canonical signatures and weak keys).
pub fn ed25519_verify(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<()> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(pk).map_err(|_| Error::BadSignature)?;
    if vk.is_weak() {
        return Err(Error::BadSignature);
    }
    let sig = ed25519_dalek::Signature::from_bytes(sig);
    vk.verify_strict(msg, &sig).map_err(|_| Error::BadSignature)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    fn h<const N: usize>(s: &str) -> [u8; N] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    #[test]
    fn x25519_rfc7748() {
        // RFC 7748 §6.1
        let a = X25519Secret::from_bytes(h(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        let b_pub = h("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        assert_eq!(
            a.public_key(),
            h("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        assert_eq!(
            a.diffie_hellman(&b_pub).unwrap(),
            h("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        );
    }

    #[test]
    fn x25519_rejects_low_order() {
        let a = X25519Secret::from_bytes([1u8; 32]);
        assert_eq!(a.diffie_hellman(&[0u8; 32]), Err(Error::WeakKey));
    }

    #[test]
    fn ed25519_rfc8032_test1() {
        let seed = Ed25519Seed::from_bytes(h(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        ));
        let pk = seed.public_key();
        assert_eq!(
            pk,
            h("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        );
        let sig = seed.sign(b"");
        assert_eq!(
            sig,
            h::<64>(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            )
        );
        ed25519_verify(&pk, b"", &sig).unwrap();
        let mut bad = sig;
        bad[0] ^= 1;
        assert_eq!(ed25519_verify(&pk, b"", &bad), Err(Error::BadSignature));
    }

    #[test]
    fn hkdf_rfc5869_case1_expand() {
        let prk = h("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        let okm: [u8; 42] = hkdf_expand(&prk, &h::<10>("f0f1f2f3f4f5f6f7f8f9")).unwrap();
        assert_eq!(
            okm.to_vec(),
            hex::decode("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865").unwrap()
        );
        let extracted = hkdf_extract(&h::<13>("000102030405060708090a0b0c"), &[0x0b; 22]);
        assert_eq!(extracted, prk);
    }

    #[test]
    fn xchacha_draft_vector() {
        // draft-irtf-cfrg-xchacha-03 §A.3.1
        let key = DirectionKey::from_bytes(h(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        ));
        let nonce = h("404142434445464748494a4b4c4d4e4f5051525354555657");
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let ct = xchacha_seal(&key, &nonce, &aad, pt).unwrap();
        let expected = "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e\
c0875924c1c7987947deafd8780acf49";
        assert_eq!(hex::encode(&ct), expected);
        assert_eq!(xchacha_open(&key, &nonce, &aad, &ct).unwrap(), pt.to_vec());
        assert_eq!(
            xchacha_open(&key, &nonce, b"other", &ct),
            Err(Error::Decrypt)
        );
    }

    #[test]
    fn hpke_psk_roundtrip_and_export() {
        let mut rng = TestEntropy::new([1; 32]);
        let skr = X25519Secret::random(&mut rng);
        let psk = Psk {
            psk: &[7u8; 32],
            psk_id: b"id",
        };
        let (enc, mut s) =
            HpkeSender::setup(&mut rng, &skr.public_key(), b"info", Some(psk)).unwrap();
        let ct = s.seal(b"aad", b"hello").unwrap();
        let mut r = HpkeReceiver::setup(&skr, &enc, b"info", Some(psk)).unwrap();
        assert_eq!(r.open(b"aad", &ct).unwrap(), b"hello");
        assert_eq!(s.export(b"x").unwrap(), r.export(b"x").unwrap());
        // Wrong PSK fails to open.
        let wrong = Psk {
            psk: &[8u8; 32],
            ..psk
        };
        let mut r2 = HpkeReceiver::setup(&skr, &enc, b"info", Some(wrong)).unwrap();
        assert_eq!(r2.open(b"aad", &ct), Err(Error::Decrypt));
    }

    /// Replays fixed bytes, then panics if more are requested.
    struct Fixed(Vec<u8>);
    impl Entropy for Fixed {
        fn fill(&mut self, dst: &mut [u8]) {
            dst.fill_with(|| self.0.remove(0));
        }
    }

    #[test]
    fn hpke_rfc9180_a22_psk() {
        // RFC 9180 A.2.2: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305, mode_psk
        let info = hex::decode("4f6465206f6e2061204772656369616e2055726e").unwrap();
        let psk_bytes =
            hex::decode("0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82")
                .unwrap();
        let psk_id = hex::decode("456e6e796e20447572696e206172616e204d6f726961").unwrap();
        let psk = Psk {
            psk: &psk_bytes,
            psk_id: &psk_id,
        };
        let sk_r = X25519Secret::from_bytes(h(
            "77d114e0212be51cb1d76fa99dd41cfd4d0166b08caa09074430a6c59ef17879",
        ));
        let pk_r = h("13640af826b722fc04feaa4de2f28fbd5ecc03623b317834e7ff4120dbe73062");
        assert_eq!(sk_r.public_key(), pk_r);
        let mut ikm_e = Fixed(
            hex::decode("35706a0b09fb26fb45c39c2f5079c709c7cf98e43afa973f14d88ece7e29c2e3")
                .unwrap(),
        );
        let (enc, mut sender) = HpkeSender::setup(&mut ikm_e, &pk_r, &info, Some(psk)).unwrap();
        assert_eq!(
            enc,
            h("2261299c3f40a9afc133b969a97f05e95be2c514e54f3de26cbe5644ac735b04")
        );
        let pt = hex::decode("4265617574792069732074727574682c20747275746820626561757479").unwrap();
        let ct = sender.seal(b"Count-0", &pt).unwrap();
        assert_eq!(
            hex::encode(&ct),
            "4a177f9c0d6f15cfdf533fb65bf84aecdc6ab16b8b85b4cf65a370e07fc1d78d28fb073214525276f4a89608ff"
        );
        let mut receiver = HpkeReceiver::setup(&sk_r, &enc, &info, Some(psk)).unwrap();
        assert_eq!(receiver.open(b"Count-0", &ct).unwrap(), pt);
        assert_eq!(
            receiver.export(b"TestContext").unwrap(),
            h("ad40e3ae14f21c99bfdebc20ae14ab86f4ca2dc9a4799d200f43a25f99fa78ae")
        );
        assert_eq!(
            sender.export(b"").unwrap(),
            h("813c1bfc516c99076ae0f466671f0ba5ff244a41699f7b2417e4c59d46d39f40")
        );
    }

    #[test]
    fn secrets_are_redacted_and_ct_compared() {
        let t = Token::from_bytes([5; 32]);
        assert_eq!(format!("{t:?}"), "Token([redacted])");
        assert_eq!(t, Token::from_bytes([5; 32]));
        assert_ne!(t, Token::from_bytes([6; 32]));
        assert_eq!(format!("{:?}", MailboxId([1; 16])), "MailboxId([redacted])");
    }

    #[test]
    fn test_entropy_is_deterministic() {
        let a: [u8; 50] = random_array(&mut TestEntropy::new([9; 32]));
        let b: [u8; 50] = random_array(&mut TestEntropy::new([9; 32]));
        assert_eq!(a, b);
    }
}
