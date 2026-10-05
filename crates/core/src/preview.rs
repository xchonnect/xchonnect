//! Encrypted notification previews (spec 7.3.3; `NotificationPreview` in
//! `docs/spec/wire/envelope.cddl`).
//!
//! A wake-up carries no content, so by default the device shows a generic alert. A dApp
//! that knows the session's mailbox hint key may attach a tiny encrypted preview, which
//! the wallet decrypts on-device in an iOS Notification Service Extension or an Android
//! FCM data handler. Apple, Google, the relay and the push gateway only ever see a
//! fixed-size opaque blob (T11).
//!
//! Properties this module guarantees:
//!
//! * **Fixed size.** Every sealed preview is exactly [`SEALED_LEN`] bytes, so neither
//!   the push provider nor the gateway learns anything from the length.
//! * **Bounded work.** Opening allocates at most [`SEALED_LEN`] bytes plus the detail
//!   line, so a Notification Service Extension stays well inside its memory budget.
//! * **Never fails.** [`open`] returns [`Outcome::Generic`] for anything it cannot
//!   authenticate, decode or trust, so the handler always has something to show.
//! * **No amounts or addresses** unless the wallet opts in: the optional detail line is
//!   dropped unless [`Policy::allow_detail`] is set, and it is rejected outright if it
//!   contains control characters or bidirectional overrides (T12).
//!
//! The preview text never drives a signing decision; the wallet still fetches the
//! authenticated request from the mailbox (spec 7.3, T12).

use crate::cbor::{self, Value};
use crate::crypto::{self, DirectionKey, Entropy};
use crate::envelope::{self, TAG_LEN};
use crate::error::{Error, Result};
use zeroize::Zeroize;

/// HKDF info that separates the preview key from every other key in the schedule.
pub const KEY_INFO: &[u8] = b"xchonnect v1 preview key";
/// AEAD associated data for previews.
pub const AAD: &[u8] = b"xchonnect v1 preview";
/// Preview structure version.
pub const VERSION: u64 = 1;
/// Nonce length (XChaCha20-Poly1305, spec 5).
pub const NONCE_LEN: usize = 24;
/// Ciphertext length including the Poly1305 tag.
pub const CT_LEN: usize = 144;
/// Padded plaintext length. Every preview is padded to exactly this many bytes.
pub const PLAINTEXT_LEN: usize = CT_LEN - TAG_LEN;
/// Length of a sealed preview: `nonce || ciphertext`.
pub const SEALED_LEN: usize = NONCE_LEN + CT_LEN;
/// Maximum length of the optional detail line, in bytes.
pub const MAX_DETAIL: usize = 64;
/// How long a preview stays showable (spec 7.3.3). A replayed wake-up must not resurrect
/// an old preview.
pub const TTL_S: u64 = 120;
/// Maximum accepted `exp - now`, so a sender cannot mint a long-lived preview.
pub const MAX_LIFETIME_S: u64 = 600;

/// What the device is being woken up for. Deliberately coarse: a kind must not identify
/// the user, the dApp or the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Kind {
    /// Nothing more specific than "something is waiting".
    #[default]
    Generic,
    /// A transaction or spend bundle is waiting for a signature.
    SigningRequest,
    /// A message signature is waiting.
    MessageSignature,
    /// A session-level event that needs no user action (rotation, liveness).
    SessionEvent,
}

impl Kind {
    /// Wire value.
    pub fn as_u64(self) -> u64 {
        match self {
            Kind::Generic => 0,
            Kind::SigningRequest => 1,
            Kind::MessageSignature => 2,
            Kind::SessionEvent => 3,
        }
    }

    fn parse(v: u64) -> Option<Self> {
        Some(match v {
            0 => Kind::Generic,
            1 => Kind::SigningRequest,
            2 => Kind::MessageSignature,
            3 => Kind::SessionEvent,
            _ => return None,
        })
    }

    /// Localisation key the wallet looks up for the notification body. Wallets ship the
    /// strings, so the gateway and the push provider never carry user-visible text.
    pub fn loc_key(self) -> &'static str {
        match self {
            Kind::Generic => "xchonnect.preview.generic",
            Kind::SigningRequest => "xchonnect.preview.signing_request",
            Kind::MessageSignature => "xchonnect.preview.message_signature",
            Kind::SessionEvent => "xchonnect.preview.session_event",
        }
    }
}

/// Preview contents.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Preview {
    /// What is waiting.
    pub kind: Kind,
    /// Optional short detail line. Senders may put amounts or addresses here only with
    /// the user's consent; the on-device helper drops it unless the wallet opts in.
    pub detail: Option<String>,
}

/// What the wallet allows on the lock screen (spec 7.3: "MUST NOT contain amounts or
/// addresses unless the user opts in").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Policy {
    /// Show the sender's detail line. Off by default.
    pub allow_detail: bool,
}

impl Policy {
    /// Kind only; the detail line is discarded.
    pub fn kind_only() -> Self {
        Policy {
            allow_detail: false,
        }
    }

    /// The user opted in to seeing the sender's detail line.
    pub fn with_detail() -> Self {
        Policy { allow_detail: true }
    }
}

/// Result of opening a preview. There is no error case: a handler always has something
/// to render (spec 7.3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Authenticated and fresh.
    Decrypted(Preview),
    /// Missing, unauthenticated, malformed, stale or not allowed: show the generic
    /// alert.
    Generic,
}

impl Outcome {
    /// The preview if one was decrypted, else `None`.
    pub fn preview(&self) -> Option<&Preview> {
        match self {
            Outcome::Decrypted(p) => Some(p),
            Outcome::Generic => None,
        }
    }

    /// Localisation key to render: the decrypted kind, or the generic alert.
    pub fn loc_key(&self) -> &'static str {
        self.preview()
            .map_or(Kind::Generic.loc_key(), |p| p.kind.loc_key())
    }
}

/// Reject detail lines that could rewrite the lock screen: control characters, line
/// breaks and Unicode bidirectional overrides (T12).
fn detail_is_safe(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_DETAIL
        && !s.chars().any(|c| {
            c.is_control()
                || matches!(c, '\u{200e}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}')
        })
}

/// Derive the preview AEAD key from the mailbox hint key.
fn key(hint_key: &[u8; 32]) -> Result<DirectionKey> {
    let mut k = crypto::hkdf_expand32(hint_key, &[KEY_INFO])?;
    let out = DirectionKey::from_slice(&k);
    k.zeroize();
    out
}

fn encode(p: &Preview, exp: u64) -> Result<Vec<u8>> {
    let mut entries = vec![
        ("v", Value::Uint(VERSION)),
        ("k", Value::Uint(p.kind.as_u64())),
        ("x", Value::Uint(exp)),
    ];
    if let Some(d) = &p.detail {
        if !detail_is_safe(d) {
            return Err(Error::Malformed("preview detail"));
        }
        entries.push(("d", Value::text(d)));
    }
    cbor::encode(&Value::text_map(entries))
}

/// Seal a preview under the session's mailbox hint key (dApp side).
///
/// The output is always [`SEALED_LEN`] bytes. `exp` is `now + ttl_s`, with `ttl_s`
/// clamped to [`MAX_LIFETIME_S`].
pub fn seal(
    rng: &mut dyn Entropy,
    hint_key: &[u8; 32],
    p: &Preview,
    now: u64,
    ttl_s: u64,
) -> Result<Vec<u8>> {
    let exp = now.saturating_add(ttl_s.clamp(1, MAX_LIFETIME_S));
    let padded = envelope::pad_to(&encode(p, exp)?, CT_LEN)?;
    let nonce: [u8; NONCE_LEN] = crypto::random_array(rng);
    let ct = crypto::xchacha_seal(&key(hint_key)?, &nonce, AAD, &padded)?;
    debug_assert_eq!(ct.len(), CT_LEN);
    Ok([nonce.as_slice(), &ct].concat())
}

/// Open a sealed preview on the device (iOS Notification Service Extension or Android
/// FCM data handler).
///
/// Never fails: anything that does not authenticate, decode, parse or pass `policy`
/// yields [`Outcome::Generic`] so the handler falls back to the generic alert.
/// `sealed` is attacker-supplied; every path here is total.
pub fn open(hint_key: &[u8; 32], sealed: &[u8], now: u64, policy: Policy) -> Outcome {
    open_checked(hint_key, sealed, now, policy).unwrap_or(Outcome::Generic)
}

fn open_checked(hint_key: &[u8; 32], sealed: &[u8], now: u64, policy: Policy) -> Result<Outcome> {
    if sealed.len() != SEALED_LEN {
        return Err(Error::Malformed("preview length"));
    }
    let (nonce, ct) = sealed.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| Error::Malformed("nonce"))?;
    let mut padded = crypto::xchacha_open(&key(hint_key)?, &nonce, AAD, ct)?;
    let decoded = envelope::unpad(&padded);
    padded.zeroize();
    let v = decoded?;
    if v.field("v", "preview version", Value::as_u64)? != VERSION {
        return Err(Error::UnsupportedVersion);
    }
    let kind = Kind::parse(v.field("k", "preview kind", Value::as_u64)?)
        .ok_or(Error::Malformed("preview kind"))?;
    let exp = v.field("x", "preview exp", Value::as_u64)?;
    if exp < now {
        return Err(Error::Expired);
    }
    if exp - now > MAX_LIFETIME_S {
        return Err(Error::LifetimeTooLong);
    }
    let detail = match (policy.allow_detail, v.get("d")) {
        (true, Some(d)) => {
            let d = d.as_text().ok_or(Error::Malformed("preview detail"))?;
            if !detail_is_safe(d) {
                return Err(Error::Malformed("preview detail"));
            }
            Some(d.to_owned())
        }
        // Not opted in, or no detail sent: the lock screen shows the kind only.
        _ => None,
    };
    Ok(Outcome::Decrypted(Preview { kind, detail }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::crypto::TestEntropy;

    const NOW: u64 = 1_790_000_000;
    const HINT: [u8; 32] = [7; 32];

    fn sealed_of(p: &Preview) -> Vec<u8> {
        seal(&mut TestEntropy::new([1; 32]), &HINT, p, NOW, TTL_S).unwrap()
    }

    #[test]
    fn roundtrip_is_fixed_size_and_hides_the_kind() {
        let generic = sealed_of(&Preview::default());
        let signing = sealed_of(&Preview {
            kind: Kind::SigningRequest,
            detail: None,
        });
        let detailed = sealed_of(&Preview {
            kind: Kind::SigningRequest,
            detail: Some("1.25 XCH to xch1qq…".into()),
        });
        for s in [&generic, &signing, &detailed] {
            assert_eq!(s.len(), SEALED_LEN, "every preview is the same size");
        }
        assert_eq!(
            open(&HINT, &signing, NOW, Policy::kind_only()),
            Outcome::Decrypted(Preview {
                kind: Kind::SigningRequest,
                detail: None,
            })
        );
        assert_eq!(
            open(&HINT, &generic, NOW, Policy::kind_only()).loc_key(),
            "xchonnect.preview.generic"
        );
    }

    #[test]
    fn detail_needs_the_wallet_to_opt_in() {
        let p = Preview {
            kind: Kind::SigningRequest,
            detail: Some("1.25 XCH to xch1qq".into()),
        };
        let s = sealed_of(&p);
        // Default policy: amounts and addresses never reach the lock screen (spec 7.3).
        let out = open(&HINT, &s, NOW, Policy::default());
        assert_eq!(out.preview().unwrap().detail, None);
        assert!(!format!("{out:?}").contains("XCH"));
        // Opted in: shown verbatim.
        let out = open(&HINT, &s, NOW, Policy::with_detail());
        assert_eq!(
            out.preview().unwrap().detail.as_deref(),
            p.detail.as_deref()
        );
    }

    #[test]
    fn anything_untrusted_falls_back_to_the_generic_alert() {
        let s = sealed_of(&Preview {
            kind: Kind::SigningRequest,
            detail: None,
        });
        let other = [8; 32];
        let mut tampered = s.clone();
        tampered[SEALED_LEN - 1] ^= 1;
        let mut bad_nonce = s.clone();
        bad_nonce[0] ^= 1;
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty", Vec::new()),
            ("truncated", s[..SEALED_LEN - 1].to_vec()),
            ("one byte longer", [s.clone(), vec![0]].concat()),
            ("tampered tag", tampered),
            ("tampered nonce", bad_nonce),
            ("junk", vec![0xff; SEALED_LEN]),
        ];
        for (name, c) in cases {
            assert_eq!(
                open(&HINT, &c, NOW, Policy::with_detail()),
                Outcome::Generic,
                "{name}"
            );
        }
        assert_eq!(open(&other, &s, NOW, Policy::default()), Outcome::Generic);
        // Stale and future previews are dropped (a replayed wake-up shows the generic
        // alert, it does not resurrect old text).
        assert_eq!(
            open(&HINT, &s, NOW + TTL_S + 1, Policy::default()),
            Outcome::Generic
        );
        assert!(matches!(
            open(&HINT, &s, NOW, Policy::default()),
            Outcome::Decrypted(_)
        ));
    }

    #[test]
    fn unsafe_detail_lines_are_refused_on_both_sides() {
        let mut rng = TestEntropy::new([2; 32]);
        for bad in [
            "",
            "a\nb",
            "a\u{202e}b",
            "a\u{0000}",
            "a\u{2066}b",
            &"x".repeat(MAX_DETAIL + 1),
        ] {
            let p = Preview {
                kind: Kind::Generic,
                detail: Some(bad.to_owned()),
            };
            assert!(seal(&mut rng, &HINT, &p, NOW, TTL_S).is_err(), "{bad:?}");
        }
        // A sender that bypasses `seal` cannot smuggle one past `open` either.
        let body = cbor::encode(&Value::text_map(vec![
            ("v", Value::Uint(VERSION)),
            ("k", Value::Uint(0)),
            ("x", Value::Uint(NOW + 60)),
            ("d", Value::text("a\u{202e}b")),
        ]))
        .unwrap();
        let padded = envelope::pad_to(&body, CT_LEN).unwrap();
        let nonce: [u8; NONCE_LEN] = crypto::random_array(&mut rng);
        let ct = crypto::xchacha_seal(&key(&HINT).unwrap(), &nonce, AAD, &padded).unwrap();
        let s = [nonce.as_slice(), &ct].concat();
        assert_eq!(
            open(&HINT, &s, NOW, Policy::with_detail()),
            Outcome::Generic
        );
        // Same bytes are fine for a wallet that does not show details at all.
        assert!(matches!(
            open(&HINT, &s, NOW, Policy::kind_only()),
            Outcome::Decrypted(_)
        ));
    }

    #[test]
    fn unknown_kinds_and_versions_fall_back() {
        let mut rng = TestEntropy::new([3; 32]);
        for (v, k) in [(VERSION, 99), (2, 0)] {
            let body = cbor::encode(&Value::text_map(vec![
                ("v", Value::Uint(v)),
                ("k", Value::Uint(k)),
                ("x", Value::Uint(NOW + 60)),
            ]))
            .unwrap();
            let padded = envelope::pad_to(&body, CT_LEN).unwrap();
            let nonce: [u8; NONCE_LEN] = crypto::random_array(&mut rng);
            let ct = crypto::xchacha_seal(&key(&HINT).unwrap(), &nonce, AAD, &padded).unwrap();
            assert_eq!(
                open(
                    &HINT,
                    &[nonce.as_slice(), &ct].concat(),
                    NOW,
                    Policy::default()
                ),
                Outcome::Generic
            );
        }
    }

    #[test]
    fn fresh_nonce_per_seal_and_the_key_is_domain_separated() {
        let mut rng = TestEntropy::new([4; 32]);
        let p = Preview::default();
        let a = seal(&mut rng, &HINT, &p, NOW, TTL_S).unwrap();
        let b = seal(&mut rng, &HINT, &p, NOW, TTL_S).unwrap();
        assert_ne!(a, b, "fresh nonce per preview");
        assert_ne!(
            key(&HINT).unwrap().expose(),
            &HINT,
            "the hint key is never used as the AEAD key directly"
        );
    }

    #[test]
    fn lifetime_is_clamped() {
        let p = Preview::default();
        let long = seal(
            &mut TestEntropy::new([5; 32]),
            &HINT,
            &p,
            NOW,
            MAX_LIFETIME_S * 100,
        )
        .unwrap();
        assert!(matches!(
            open(&HINT, &long, NOW + MAX_LIFETIME_S, Policy::default()),
            Outcome::Decrypted(_)
        ));
        assert_eq!(
            open(&HINT, &long, NOW + MAX_LIFETIME_S + 1, Policy::default()),
            Outcome::Generic
        );
    }

    #[test]
    fn fits_the_apns_and_fcm_payload_budgets() {
        // APNs alert payloads are limited to 4 KiB and FCM messages to 4 KiB; a sealed
        // preview is carried base64url-encoded inside the JSON body.
        let b64_len = crate::b64::encode(&[0u8; SEALED_LEN]).len();
        assert_eq!((SEALED_LEN, b64_len), (168, 224));
        assert!(b64_len + 512 < 4096, "preview plus envelope fits 4 KiB");
    }

    #[test]
    fn deterministic_vector() {
        // Fixed entropy: guards against accidental wire changes.
        let p = Preview {
            kind: Kind::SigningRequest,
            detail: Some("needs your signature".into()),
        };
        let body = encode(&p, NOW + TTL_S).unwrap();
        assert_eq!(
            hex::encode(&body),
            // {"d": "needs your signature", "k": 1, "v": 1, "x": 1790000120},
            // canonical key order.
            "a46164746e6565647320796f7572207369676e6174757265616b0161760161781a6ab13bf8"
        );
        let s = seal(&mut TestEntropy::new([6; 32]), &HINT, &p, NOW, TTL_S).unwrap();
        assert_eq!(
            s,
            seal(&mut TestEntropy::new([6; 32]), &HINT, &p, NOW, TTL_S).unwrap()
        );
        assert_eq!(
            open(&HINT, &s, NOW, Policy::with_detail()),
            Outcome::Decrypted(p)
        );
    }
}
