//! dApp origin document `/.well-known/xchonnect.json` (spec 6.1,
//! `docs/spec/wire/xchonnect.schema.json`).
//!
//! Fetching is the host's job (wallets use their platform HTTP stack and MUST follow the
//! fetch rules: HTTPS, no redirects, at most [`MAX_DOCUMENT_BYTES`]); this module parses
//! and validates the document.

use crate::error::{Error, Result};
use serde::Deserialize;

/// Maximum accepted document size.
pub const MAX_DOCUMENT_BYTES: usize = 16 * 1024;

/// One origin signing key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginKey {
    /// Key id referenced by pairing URIs.
    pub kid: String,
    /// Ed25519 public key.
    pub pk: [u8; 32],
    /// Last valid day (inclusive, UTC) as unix seconds of 23:59:59.
    pub not_after: u64,
}

/// A validated origin document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginDocument {
    /// dApp display name.
    pub name: String,
    /// Origin keys.
    pub keys: Vec<OriginKey>,
    /// Optional icon URL.
    pub icon: Option<String>,
    /// Optional same-device return URL.
    pub return_url: Option<String>,
}

#[derive(Deserialize)]
struct RawDoc {
    v: u64,
    name: String,
    origin_keys: Vec<RawKey>,
    icon: Option<String>,
    return_url: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawKey {
    kid: String,
    pk: String,
    not_after: String,
}

/// Whether `kid` matches `^[A-Za-z0-9._-]{1,64}$`.
pub fn valid_kid(kid: &str) -> bool {
    (1..=64).contains(&kid.len())
        && kid
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

impl OriginDocument {
    /// Parse and validate a document body.
    pub fn parse(json: &[u8]) -> Result<Self> {
        if json.len() > MAX_DOCUMENT_BYTES {
            return Err(Error::InvalidOrigin("document too large"));
        }
        let raw: RawDoc = serde_json::from_slice(json)
            .map_err(|_| Error::InvalidOrigin("not valid JSON for schema"))?;
        if raw.v != 1 {
            return Err(Error::InvalidOrigin("unsupported version"));
        }
        if raw.name.is_empty() || raw.name.chars().count() > 64 {
            return Err(Error::InvalidOrigin("name"));
        }
        if raw.origin_keys.is_empty() || raw.origin_keys.len() > 8 {
            return Err(Error::InvalidOrigin("origin_keys count"));
        }
        for url in raw.icon.iter().chain(raw.return_url.iter()) {
            if !url.starts_with("https://") || url.len() > 256 {
                return Err(Error::InvalidOrigin("url"));
            }
        }
        let mut keys = Vec::with_capacity(raw.origin_keys.len());
        for k in raw.origin_keys {
            if !valid_kid(&k.kid) {
                return Err(Error::InvalidOrigin("kid"));
            }
            if keys.iter().any(|x: &OriginKey| x.kid == k.kid) {
                return Err(Error::InvalidOrigin("duplicate kid"));
            }
            let pk =
                crate::b64::decode_array::<32>(&k.pk).map_err(|_| Error::InvalidOrigin("pk"))?;
            let not_after = end_of_day(&k.not_after)?;
            keys.push(OriginKey {
                kid: k.kid,
                pk,
                not_after,
            });
        }
        Ok(OriginDocument {
            name: raw.name,
            keys,
            icon: raw.icon,
            return_url: raw.return_url,
        })
    }

    /// The key with `kid`, if it exists and is valid at `now`.
    pub fn key(&self, kid: &str, now: u64) -> Result<&OriginKey> {
        let k = self
            .keys
            .iter()
            .find(|k| k.kid == kid)
            .ok_or(Error::InvalidOrigin("unknown kid"))?;
        if now > k.not_after {
            return Err(Error::InvalidOrigin("key expired"));
        }
        Ok(k)
    }
}

/// Unix seconds of 23:59:59 UTC on a `YYYY-MM-DD` date.
fn end_of_day(date: &str) -> Result<u64> {
    let b = date.as_bytes();
    let digits = |r: core::ops::Range<usize>| -> Result<u64> {
        let s = date.get(r).ok_or(Error::InvalidOrigin("not_after"))?;
        if !s.bytes().all(|c| c.is_ascii_digit()) {
            return Err(Error::InvalidOrigin("not_after"));
        }
        s.parse().map_err(|_| Error::InvalidOrigin("not_after"))
    };
    if b.len() != 10 || b.get(4) != Some(&b'-') || b.get(7) != Some(&b'-') {
        return Err(Error::InvalidOrigin("not_after"));
    }
    let (y, m, d) = (digits(0..4)?, digits(5..7)?, digits(8..10)?);
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let feb = if leap { 29 } else { 28 };
    let mdays = [31, feb, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let max_day = mdays
        .get((m as usize).wrapping_sub(1))
        .ok_or(Error::InvalidOrigin("not_after"))?;
    if y < 1970 || d == 0 || d > *max_day {
        return Err(Error::InvalidOrigin("not_after"));
    }
    // Days from civil (H. Hinnant), restricted to years >= 1970.
    let (y, m) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Ok(days * 86_400 + 86_399)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn end_of_day_known_dates() {
        assert_eq!(end_of_day("1970-01-01").unwrap(), 86_399);
        assert_eq!(end_of_day("2000-03-01").unwrap(), 951_955_199);
        assert_eq!(end_of_day("2027-10-01").unwrap(), 1_822_435_199);
        assert!(end_of_day("2027-02-29").is_err());
        assert!(end_of_day("2028-02-29").is_ok());
        assert!(end_of_day("2027-13-01").is_err());
        assert!(end_of_day("2027-1-01").is_err());
        assert!(end_of_day("+027-10-01").is_err());
    }

    #[test]
    fn parse_and_select() {
        let pk = crate::b64::encode(&[7u8; 32]);
        let doc = format!(
            r#"{{"v":1,"name":"Pengui","origin_keys":[{{"kid":"2026-10","pk":"{pk}","not_after":"2027-10-01"}}],"icon":"https://pengui.xyz/i.png","extra":true}}"#
        );
        let d = OriginDocument::parse(doc.as_bytes()).unwrap();
        assert_eq!(d.name, "Pengui");
        assert!(d.key("2026-10", 1_800_000_000).is_ok());
        assert_eq!(
            d.key("2026-10", 1_822_435_200),
            Err(Error::InvalidOrigin("key expired"))
        );
        assert_eq!(d.key("other", 0), Err(Error::InvalidOrigin("unknown kid")));
    }

    #[test]
    fn rejects_invalid_documents() {
        let pk = crate::b64::encode(&[7u8; 32]);
        let cases = [
            format!(r#"{{"v":2,"name":"x","origin_keys":[{{"kid":"a","pk":"{pk}","not_after":"2027-10-01"}}]}}"#),
            r#"{"v":1,"name":"x","origin_keys":[]}"#.to_owned(),
            format!(r#"{{"v":1,"name":"x","origin_keys":[{{"kid":"a b","pk":"{pk}","not_after":"2027-10-01"}}]}}"#),
            r#"{"v":1,"name":"x","origin_keys":[{"kid":"a","pk":"AAAA","not_after":"2027-10-01"}]}"#.to_owned(),
            format!(r#"{{"v":1,"name":"","origin_keys":[{{"kid":"a","pk":"{pk}","not_after":"2027-10-01"}}]}}"#),
            format!(r#"{{"v":1,"name":"x","icon":"http://x","origin_keys":[{{"kid":"a","pk":"{pk}","not_after":"2027-10-01"}}]}}"#),
            format!(r#"{{"v":1,"name":"x","origin_keys":[{{"kid":"a","pk":"{pk}","not_after":"2027-10-01"}},{{"kid":"a","pk":"{pk}","not_after":"2027-10-01"}}]}}"#),
        ];
        for c in cases {
            assert!(OriginDocument::parse(c.as_bytes()).is_err(), "{c}");
        }
        assert!(OriginDocument::parse(&vec![b' '; MAX_DOCUMENT_BYTES + 1]).is_err());
    }
}
