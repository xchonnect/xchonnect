//! Sealed push tokens (spec 7.3, 7.3.2; `SealedTokenPlaintext` in
//! `docs/spec/wire/envelope.cddl`).
//!
//! The wallet seals its platform device token to the push gateway's X25519 key with HPKE
//! base mode, so the relay stores and forwards an opaque blob. Every seal uses a fresh
//! HPKE ephemeral key, so two registrations of the same device are unlinkable for the
//! relay (the gateway can still link them, spec 13.6).

use crate::cbor::{self, Value};
use crate::crypto::{Entropy, HpkeReceiver, HpkeSender, X25519Secret};
use crate::error::{Error, Result};

/// HPKE `info` for sealed push tokens.
pub const INFO: &[u8] = b"xchonnect v1 push";
/// Maximum lifetime of a sealed token (spec 7.3.2).
pub const MAX_LIFETIME_S: u64 = 90 * 24 * 3600;
/// Maximum device token length.
pub const MAX_DEVICE_TOKEN: usize = 4096;
/// Maximum sealed token size accepted anywhere.
pub const MAX_SEALED: usize = 8 * 1024;

/// Push platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// Apple Push Notification service (production).
    Apns,
    /// APNs sandbox (development builds).
    ApnsSandbox,
    /// Firebase Cloud Messaging.
    Fcm,
    /// Test platform for gateways under test; never delivers.
    Test,
}

impl Platform {
    /// Wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Platform::Apns => "apns",
            Platform::ApnsSandbox => "apns-sandbox",
            Platform::Fcm => "fcm",
            Platform::Test => "test",
        }
    }

    fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "apns" => Platform::Apns,
            "apns-sandbox" => Platform::ApnsSandbox,
            "fcm" => Platform::Fcm,
            "test" => Platform::Test,
            _ => return Err(Error::Malformed("push platform")),
        })
    }
}

/// Contents of a sealed token (only the gateway ever sees these).
#[derive(Clone, PartialEq, Eq)]
pub struct PushToken {
    /// Platform.
    pub platform: Platform,
    /// Platform device token.
    pub device_token: String,
    /// Mailbox hint key for encrypted notification previews.
    pub hint_key: [u8; 32],
    /// Expiry (unix seconds).
    pub exp: u64,
}

impl core::fmt::Debug for PushToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PushToken")
            .field("platform", &self.platform)
            .field("exp", &self.exp)
            .finish_non_exhaustive()
    }
}

impl PushToken {
    fn encode(&self) -> Result<Vec<u8>> {
        cbor::encode(&Value::text_map(vec![
            ("p", Value::text(self.platform.as_str())),
            ("t", Value::text(&self.device_token)),
            ("h", Value::bytes(&self.hint_key)),
            ("exp", Value::Uint(self.exp)),
        ]))
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let v = cbor::decode(bytes)?;
        let t = v
            .get("t")
            .and_then(Value::as_text)
            .ok_or(Error::Malformed("device token"))?;
        if t.is_empty() || t.len() > MAX_DEVICE_TOKEN {
            return Err(Error::Malformed("device token"));
        }
        Ok(PushToken {
            platform: Platform::parse(
                v.get("p")
                    .and_then(Value::as_text)
                    .ok_or(Error::Malformed("push platform"))?,
            )?,
            device_token: t.to_owned(),
            hint_key: v
                .get("h")
                .and_then(Value::as_bytes)
                .and_then(|b| b.try_into().ok())
                .ok_or(Error::Malformed("hint key"))?,
            exp: v
                .get("exp")
                .and_then(Value::as_u64)
                .ok_or(Error::Malformed("exp"))?,
        })
    }

    /// Seal to the gateway public key (wallet side). Output: `enc (32) || ciphertext`.
    pub fn seal(&self, rng: &mut dyn Entropy, gateway_pk: &[u8; 32], now: u64) -> Result<Vec<u8>> {
        if self.exp <= now || self.exp - now > MAX_LIFETIME_S {
            return Err(Error::Malformed("exp must be within 90 days"));
        }
        if self.device_token.is_empty() || self.device_token.len() > MAX_DEVICE_TOKEN {
            return Err(Error::Malformed("device token"));
        }
        let (enc, mut ctx) = HpkeSender::setup(rng, gateway_pk, INFO, None)?;
        let ct = ctx.seal(b"", &self.encode()?)?;
        Ok([enc.as_slice(), &ct].concat())
    }

    /// Open a sealed token (gateway side) and validate it at `now`.
    pub fn open(gateway_sk: &X25519Secret, sealed: &[u8], now: u64) -> Result<Self> {
        if sealed.len() <= 32 || sealed.len() > MAX_SEALED {
            return Err(Error::Malformed("sealed token length"));
        }
        let (enc, ct) = sealed.split_at(32);
        let enc: [u8; 32] = enc.try_into().map_err(|_| Error::Malformed("enc"))?;
        let mut ctx = HpkeReceiver::setup(gateway_sk, &enc, INFO, None)?;
        let token = PushToken::decode(&ctx.open(b"", ct)?)?;
        if token.exp < now {
            return Err(Error::Expired);
        }
        if token.exp - now > MAX_LIFETIME_S {
            return Err(Error::LifetimeTooLong);
        }
        Ok(token)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::crypto::TestEntropy;

    const NOW: u64 = 1_790_000_000;

    fn token(exp: u64) -> PushToken {
        PushToken {
            platform: Platform::Apns,
            device_token: "a1b2c3".repeat(10),
            hint_key: [7; 32],
            exp,
        }
    }

    #[test]
    fn seal_open_roundtrip_and_unlinkable() {
        let mut rng = TestEntropy::new([3; 32]);
        let gw = X25519Secret::random(&mut rng);
        let t = token(NOW + 86_400);
        let a = t.seal(&mut rng, &gw.public_key(), NOW).unwrap();
        let b = t.seal(&mut rng, &gw.public_key(), NOW).unwrap();
        assert_ne!(a, b, "fresh HPKE ephemeral per seal");
        assert_eq!(PushToken::open(&gw, &a, NOW).unwrap(), t);
        assert_eq!(PushToken::open(&gw, &b, NOW).unwrap(), t);
        assert!(
            !format!("{t:?}").contains("a1b2c3"),
            "Debug hides the device token"
        );
    }

    #[test]
    fn rejects_wrong_key_tamper_expiry() {
        let mut rng = TestEntropy::new([4; 32]);
        let gw = X25519Secret::random(&mut rng);
        let other = X25519Secret::random(&mut rng);
        let sealed = token(NOW + 100)
            .seal(&mut rng, &gw.public_key(), NOW)
            .unwrap();
        assert_eq!(PushToken::open(&other, &sealed, NOW), Err(Error::Decrypt));
        let mut t = sealed.clone();
        let last = t.len() - 1;
        t[last] ^= 1;
        assert_eq!(PushToken::open(&gw, &t, NOW), Err(Error::Decrypt));
        assert_eq!(
            PushToken::open(&gw, &sealed, NOW + 101),
            Err(Error::Expired)
        );
        assert!(PushToken::open(&gw, &sealed[..20], NOW).is_err());
        assert!(
            token(NOW + MAX_LIFETIME_S + 1)
                .seal(&mut rng, &gw.public_key(), NOW)
                .is_err()
        );
        assert!(token(NOW).seal(&mut rng, &gw.public_key(), NOW).is_err());
        let empty = PushToken {
            device_token: String::new(),
            ..token(NOW + 10)
        };
        assert!(empty.seal(&mut rng, &gw.public_key(), NOW).is_err());
    }

    #[test]
    fn deterministic_vector() {
        // Fixed entropy and keys: guards against accidental wire changes.
        let gw = X25519Secret::from_bytes([9; 32]);
        let t = PushToken {
            platform: Platform::Fcm,
            device_token: "device".into(),
            hint_key: [1; 32],
            exp: NOW + 60,
        };
        let sealed = t
            .seal(&mut TestEntropy::new([5; 32]), &gw.public_key(), NOW)
            .unwrap();
        assert_eq!(sealed.len(), 32 + t.encode().unwrap().len() + 16);
        let again = t
            .seal(&mut TestEntropy::new([5; 32]), &gw.public_key(), NOW)
            .unwrap();
        assert_eq!(sealed, again);
        assert_eq!(PushToken::open(&gw, &sealed, NOW).unwrap(), t);
        assert_eq!(
            hex::encode(t.encode().unwrap()),
            // {"h": h'01…01', "p": "fcm", "t": "device", "exp": 1790000060}, canonical key order
            "a461685820010101010101010101010101010101010101010101010101010101010101010161706366636d617466646576696365636578701a6ab13bbc"
        );
    }
}
