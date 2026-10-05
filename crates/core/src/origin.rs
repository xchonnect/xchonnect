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

/// Whether `url` is `https://<domain>` with nothing between the scheme and the first
/// `/`, `?` or `#` but exactly `domain`.
///
/// The comparison is on the whole authority and byte-exact, which is what makes it
/// safe:
///
/// * a prefix or suffix match would accept `https://pengui.space.evil.com` and
///   `https://evil-pengui.space` for `pengui.space`;
/// * comparing a parsed "host" would accept `https://pengui.space@evil.com` (userinfo)
///   and `https://pengui.space:8443`;
/// * a subdomain is *not* accepted: the schema says "the same domain", and a dApp whose
///   origin key leaked must not be able to point the user at a host the pairing URI did
///   not name;
/// * a trailing dot (`pengui.space.`) is a different URL origin, so it is refused;
/// * `domain` as it reaches here is already lowercase ASCII A-labels
///   ([`crate::uri::validate_domain`]), and that same string is what the wallet shows
///   the user ([`crate::domain::display_domain`]). Requiring the `return_url` to repeat
///   it verbatim means the host that is checked and the host that is displayed are the
///   same bytes: there is no normalisation step in which the two could disagree. A host
///   written in any other form — uppercase, Unicode rather than its A-label — is
///   refused rather than normalised (T18, T3).
pub fn url_is_on_domain(url: &str, domain: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    !domain.is_empty() && authority == domain
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

    /// Bind the document to the domain the pairing URI claims (spec 6.1; `return_url`
    /// in `docs/spec/wire/xchonnect.schema.json`: "must be on the same domain").
    ///
    /// `return_url` is a navigation target the wallet opens after a same-device
    /// request, so a `return_url` on another host turns a dApp whose origin key leaked
    /// into a one-tap redirect and contradicts the domain the wallet just showed the
    /// user (T18, T3). The document is **rejected**, not silently stripped: origin
    /// verification has no continue-anyway path.
    ///
    /// Called by [`crate::pairing::VerifiedUri::new`], so every verified pairing has
    /// already passed it. `icon` is not covered: the schema puts no same-domain rule on
    /// it and an icon is fetched and drawn, not navigated to.
    pub fn check_bound_to(&self, domain: &str) -> Result<()> {
        match &self.return_url {
            Some(u) if !url_is_on_domain(u, domain) => Err(Error::InvalidOrigin(
                "return_url is not on the dApp's domain",
            )),
            _ => Ok(()),
        }
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

    /// `return_url` must be on the claimed domain, and the host comparison must not be
    /// foolable by a prefix, a suffix, userinfo, a port or a subdomain (T18, T3).
    #[test]
    fn return_url_must_be_on_the_claimed_domain() {
        let doc = |return_url: &str| {
            let pk = crate::b64::encode(&[7u8; 32]);
            let json = format!(
                r#"{{"v":1,"name":"Pengui","return_url":"{return_url}","origin_keys":[{{"kid":"k1","pk":"{pk}","not_after":"2030-01-01"}}]}}"#
            );
            OriginDocument::parse(json.as_bytes()).unwrap()
        };
        // Accepted: the host is exactly the claimed domain, with or without a path,
        // query or fragment.
        for ok in [
            "https://pengui.space",
            "https://pengui.space/",
            "https://pengui.space/back",
            "https://pengui.space/back?session=7#done",
            "https://pengui.space?x=1",
        ] {
            assert_eq!(doc(ok).check_bound_to("pengui.space"), Ok(()), "{ok}");
            assert_eq!(doc(ok).return_url.as_deref(), Some(ok));
        }
        // Refused. A prefix or suffix match, or comparing only a parsed host, would let
        // one of these through.
        for bad in [
            // Lookalike registrations.
            "https://evil-pengui.space/back",
            "https://pengui.space.evil.com/back",
            "https://pengui-space/back",
            "https://xpengui.space/back",
            // Subdomains: the schema says the same domain.
            "https://app.pengui.space/back",
            "https://pengui.space.",
            // Userinfo and port smuggling.
            "https://pengui.space@evil.com/back",
            "https://pengui.space:8443/back",
            "https://evil.com@pengui.space.evil.com/",
            // A different textual form of the same name is refused, not normalised, so
            // the checked host and the displayed host are always the same bytes.
            "https://PENGUI.SPACE/back",
            "https://xn--pengui-3ve.space/back",
            // No authority at all.
            "https:///back",
            "https:///back",
        ] {
            assert_eq!(
                doc(bad).check_bound_to("pengui.space"),
                Err(Error::InvalidOrigin(
                    "return_url is not on the dApp's domain"
                )),
                "{bad} was accepted"
            );
        }
        // A document without a `return_url` is bound to any domain.
        let pk = crate::b64::encode(&[7u8; 32]);
        let plain = format!(
            r#"{{"v":1,"name":"Pengui","origin_keys":[{{"kid":"k1","pk":"{pk}","not_after":"2030-01-01"}}]}}"#
        );
        let plain = OriginDocument::parse(plain.as_bytes()).unwrap();
        assert_eq!(plain.check_bound_to("pengui.space"), Ok(()));
        // An `icon` on a CDN stays allowed: the schema puts no same-domain rule on it.
        let icon = format!(
            r#"{{"v":1,"name":"Pengui","icon":"https://cdn.example/i.png","origin_keys":[{{"kid":"k1","pk":"{pk}","not_after":"2030-01-01"}}]}}"#
        );
        let icon = OriginDocument::parse(icon.as_bytes()).unwrap();
        assert_eq!(icon.check_bound_to("pengui.space"), Ok(()));
        // The predicate itself: an empty domain never matches, and the scheme is fixed.
        assert!(!url_is_on_domain("https://pengui.space", ""));
        assert!(!url_is_on_domain("http://pengui.space", "pengui.space"));
        assert!(!url_is_on_domain("pengui.space", "pengui.space"));
        assert!(!url_is_on_domain("", ""));
        // A developer-mode `localhost:<port>` domain still matches itself.
        assert!(url_is_on_domain(
            "https://localhost:5173/back",
            "localhost:5173"
        ));
    }
}
