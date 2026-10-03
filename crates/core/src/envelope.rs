//! Outer envelope, padding and session-message encryption (spec 5.3).

use crate::cbor::{self, Value};
use crate::crypto::{self, DirectionKey, Entropy, MailboxId};
use crate::error::{Error, Result};

/// Protocol version carried in every envelope.
pub const VERSION: u64 = 1;
/// AEAD tag length.
pub const TAG_LEN: usize = 16;
/// Allowed ciphertext sizes (plaintext + tag) for session messages.
pub const BUCKETS: [usize; 5] = [1024, 4096, 16384, 65536, 262144];
/// Ciphertext size of a pairing reply.
pub const PAIRING_CT_LEN: usize = 1024;
/// Largest encoded envelope accepted anywhere (relay limit in `/v1/info`).
pub const MAX_ENVELOPE_BYTES: usize = 262_400;

/// Envelope kind (spec 5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Session message: `n` is a 24-byte nonce.
    Session = 1,
    /// Pairing reply: `n` is the 32-byte HPKE `enc`.
    Pairing = 2,
}

/// Direction of a session message; part of the AAD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// dApp → wallet (`0x01`, key `k_d2w`).
    DappToWallet = 1,
    /// wallet → dApp (`0x02`, key `k_w2d`).
    WalletToDapp = 2,
}

/// A decoded, structurally valid outer envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Kind.
    pub kind: Kind,
    /// Nonce (session) or HPKE `enc` (pairing).
    pub n: Vec<u8>,
    /// Ciphertext including tag.
    pub ct: Vec<u8>,
}

impl Envelope {
    /// Canonical CBOR encoding.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.check()?;
        cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Uint(VERSION)),
            (Value::Uint(2), Value::Uint(self.kind as u64)),
            (Value::Uint(3), Value::Bytes(self.n.clone())),
            (Value::Uint(4), Value::Bytes(self.ct.clone())),
        ]))
    }

    /// Decode and validate exactly against the `Envelope` CDDL. This is what relays
    /// run on every posted message.
    pub fn decode(bytes: &[u8]) -> Result<Envelope> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(Error::TooLarge);
        }
        let v = cbor::decode(bytes)?;
        let Value::Map(entries) = &v else {
            return Err(Error::Malformed("envelope must be a map"));
        };
        if entries.len() != 4 {
            return Err(Error::Malformed("envelope must have exactly keys 1..4"));
        }
        if v.get_uint(1).and_then(Value::as_u64) != Some(VERSION) {
            return Err(Error::UnsupportedVersion);
        }
        let kind = match v.get_uint(2).and_then(Value::as_u64) {
            Some(1) => Kind::Session,
            Some(2) => Kind::Pairing,
            _ => return Err(Error::Malformed("envelope kind")),
        };
        let n = v
            .get_uint(3)
            .and_then(Value::as_bytes)
            .ok_or(Error::Malformed("envelope n"))?;
        let ct = v
            .get_uint(4)
            .and_then(Value::as_bytes)
            .ok_or(Error::Malformed("envelope ct"))?;
        let env = Envelope {
            kind,
            n: n.to_vec(),
            ct: ct.to_vec(),
        };
        env.check()?;
        Ok(env)
    }

    fn check(&self) -> Result<()> {
        match self.kind {
            Kind::Session => {
                if self.n.len() != 24 {
                    return Err(Error::Malformed("nonce length"));
                }
                if !BUCKETS.contains(&self.ct.len()) {
                    return Err(Error::Malformed("ciphertext length is not a bucket size"));
                }
            }
            Kind::Pairing => {
                if self.n.len() != 32 {
                    return Err(Error::Malformed("enc length"));
                }
                if self.ct.len() != PAIRING_CT_LEN {
                    return Err(Error::Malformed("pairing ciphertext length"));
                }
            }
        }
        Ok(())
    }
}

/// Pad `plaintext` with zeros so that plaintext + tag is exactly `target`.
pub fn pad_to(plaintext: &[u8], target: usize) -> Result<Vec<u8>> {
    let len = target.checked_sub(TAG_LEN).ok_or(Error::TooLarge)?;
    if plaintext.len() > len {
        return Err(Error::TooLarge);
    }
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(plaintext);
    out.resize(len, 0);
    Ok(out)
}

/// Pad to the smallest bucket that fits.
pub fn pad(plaintext: &[u8]) -> Result<Vec<u8>> {
    let bucket = BUCKETS
        .iter()
        .copied()
        .find(|b| plaintext.len() + TAG_LEN <= *b)
        .ok_or(Error::TooLarge)?;
    pad_to(plaintext, bucket)
}

/// Decode the single CBOR item at the start of a padded plaintext and require that
/// every following byte is zero.
pub fn unpad(padded: &[u8]) -> Result<Value> {
    let (v, used) = cbor::decode_prefix(padded)?;
    let rest = padded.get(used..).ok_or(Error::Malformed("padding"))?;
    if rest.iter().any(|b| *b != 0) {
        return Err(Error::Malformed("non-zero padding"));
    }
    Ok(v)
}

/// The 28-byte AAD: `"xchonnect" || v || kind || direction || recipient_mailbox_id`.
pub fn aad(kind: Kind, direction: Direction, recipient: &MailboxId) -> [u8; 28] {
    let mut a = [0u8; 28];
    let header = [VERSION as u8, kind as u8, direction as u8];
    for (dst, src) in a
        .iter_mut()
        .zip(b"xchonnect".iter().chain(&header).chain(&recipient.0))
    {
        *dst = *src;
    }
    a
}

/// Encrypt an inner plaintext (canonical CBOR) into an encoded session envelope.
pub fn seal_session(
    rng: &mut dyn Entropy,
    key: &DirectionKey,
    direction: Direction,
    recipient: &MailboxId,
    inner_cbor: &[u8],
) -> Result<Vec<u8>> {
    let nonce: [u8; 24] = crypto::random_array(rng);
    seal_session_with_nonce(&nonce, key, direction, recipient, inner_cbor)
}

/// [`seal_session`] with an explicit nonce (for test vectors).
pub fn seal_session_with_nonce(
    nonce: &[u8; 24],
    key: &DirectionKey,
    direction: Direction,
    recipient: &MailboxId,
    inner_cbor: &[u8],
) -> Result<Vec<u8>> {
    let padded = pad(inner_cbor)?;
    let ct = crypto::xchacha_seal(
        key,
        nonce,
        &aad(Kind::Session, direction, recipient),
        &padded,
    )?;
    Envelope {
        kind: Kind::Session,
        n: nonce.to_vec(),
        ct,
    }
    .encode()
}

/// Decrypt a session envelope; returns the inner CBOR value (canonical, unpadded).
pub fn open_session(
    key: &DirectionKey,
    direction: Direction,
    recipient: &MailboxId,
    env: &Envelope,
) -> Result<Value> {
    if env.kind != Kind::Session {
        return Err(Error::Malformed("not a session envelope"));
    }
    let nonce: [u8; 24] = env
        .n
        .as_slice()
        .try_into()
        .map_err(|_| Error::Malformed("nonce length"))?;
    let padded = crypto::xchacha_open(
        key,
        &nonce,
        &aad(Kind::Session, direction, recipient),
        &env.ct,
    )?;
    unpad(&padded)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::crypto::TestEntropy;

    fn key() -> DirectionKey {
        DirectionKey::from_bytes([1; 32])
    }

    #[test]
    fn seal_open_roundtrip_each_bucket() {
        let mut rng = TestEntropy::new([0; 32]);
        let mbx = MailboxId([9; 16]);
        for (size, bucket) in [(10, 1024), (1008, 1024), (1009, 4096), (200_000, 262_144)] {
            let inner = cbor::encode(&Value::Bytes(vec![0xaa; size])).unwrap();
            let bytes =
                seal_session(&mut rng, &key(), Direction::DappToWallet, &mbx, &inner).unwrap();
            let env = Envelope::decode(&bytes).unwrap();
            assert!(env.ct.len() >= bucket.min(1024));
            assert!(BUCKETS.contains(&env.ct.len()));
            let back = open_session(&key(), Direction::DappToWallet, &mbx, &env).unwrap();
            assert_eq!(cbor::encode(&back).unwrap(), inner);
        }
    }

    #[test]
    fn exact_bucket_sizes() {
        let p = pad(&[0u8; 1008]).unwrap();
        assert_eq!(p.len() + TAG_LEN, 1024);
        let p = pad(&[0u8; 1009]).unwrap();
        assert_eq!(p.len() + TAG_LEN, 4096);
        assert_eq!(pad(&vec![0u8; 262_144 - 15]), Err(Error::TooLarge));
    }

    #[test]
    fn aad_binds_direction_mailbox_kind() {
        let mut rng = TestEntropy::new([0; 32]);
        let mbx = MailboxId([9; 16]);
        let inner = cbor::encode(&Value::Uint(1)).unwrap();
        let env = Envelope::decode(
            &seal_session(&mut rng, &key(), Direction::DappToWallet, &mbx, &inner).unwrap(),
        )
        .unwrap();
        assert_eq!(
            open_session(&key(), Direction::WalletToDapp, &mbx, &env),
            Err(Error::Decrypt)
        );
        assert_eq!(
            open_session(&key(), Direction::DappToWallet, &MailboxId([8; 16]), &env),
            Err(Error::Decrypt)
        );
        let mut tampered = env.clone();
        tampered.ct[5] ^= 1;
        assert_eq!(
            open_session(&key(), Direction::DappToWallet, &mbx, &tampered),
            Err(Error::Decrypt)
        );
        assert_eq!(
            aad(Kind::Session, Direction::DappToWallet, &mbx)[..12],
            *b"xchonnect\x01\x01\x01"
        );
    }

    #[test]
    fn envelope_validation() {
        let ok = Envelope {
            kind: Kind::Session,
            n: vec![0; 24],
            ct: vec![0; 1024],
        };
        assert!(Envelope::decode(&ok.encode().unwrap()).is_ok());
        let bad_ct = cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Uint(1)),
            (Value::Uint(2), Value::Uint(1)),
            (Value::Uint(3), Value::Bytes(vec![0; 24])),
            (Value::Uint(4), Value::Bytes(vec![0; 1000])),
        ]))
        .unwrap();
        assert!(Envelope::decode(&bad_ct).is_err());
        let v2 = cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Uint(2)),
            (Value::Uint(2), Value::Uint(1)),
            (Value::Uint(3), Value::Bytes(vec![0; 24])),
            (Value::Uint(4), Value::Bytes(vec![0; 1024])),
        ]))
        .unwrap();
        assert_eq!(Envelope::decode(&v2), Err(Error::UnsupportedVersion));
        let extra = cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Uint(1)),
            (Value::Uint(2), Value::Uint(1)),
            (Value::Uint(3), Value::Bytes(vec![0; 24])),
            (Value::Uint(4), Value::Bytes(vec![0; 1024])),
            (Value::Uint(5), Value::Null),
        ]))
        .unwrap();
        assert!(Envelope::decode(&extra).is_err());
        let mut trailing = ok.encode().unwrap();
        trailing.push(0);
        assert!(Envelope::decode(&trailing).is_err());
    }

    #[test]
    fn non_zero_padding_rejected() {
        let mut p = pad(&cbor::encode(&Value::Uint(1)).unwrap()).unwrap();
        assert!(unpad(&p).is_ok());
        let last = p.len() - 1;
        p[last] = 1;
        assert!(unpad(&p).is_err());
    }
}
