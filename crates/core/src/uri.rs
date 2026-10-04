//! Pairing URI (spec 6.2, `docs/spec/wire/pairing-uri.md`).

use crate::cbor::{self, Value};
use crate::crypto::{self, Ed25519Seed, MailboxId, PairingSecret, Token};
use crate::error::{Error, Result};
use crate::origin::{self, OriginDocument};

/// Maximum URI lifetime chosen by a dApp.
pub const MAX_LIFETIME_S: u64 = 300;
/// Tolerated clock skew when checking expiry.
pub const CLOCK_SKEW_S: u64 = 60;
const SCHEME_PREFIX: &str = "xchonnect:v1?";

/// Signs pairing URIs with the dApp origin key. Production implementations call an
/// HSM or KMS so the key never sits in the dApp's web server.
pub trait OriginSigner {
    /// Key id published in the origin document.
    fn kid(&self) -> &str;
    /// Ed25519 signature over `msg`.
    fn sign(&self, msg: &[u8]) -> Result<[u8; 64]>;
}

/// In-process signer for development and tests.
#[derive(Debug)]
pub struct LocalSigner {
    seed: Ed25519Seed,
    kid: String,
}

impl LocalSigner {
    /// Create from a seed and key id.
    pub fn new(seed: Ed25519Seed, kid: &str) -> Result<Self> {
        if !origin::valid_kid(kid) {
            return Err(Error::InvalidUri("kid"));
        }
        Ok(LocalSigner {
            seed,
            kid: kid.to_owned(),
        })
    }

    /// The public key to publish in `/.well-known/xchonnect.json`.
    pub fn public_key(&self) -> [u8; 32] {
        self.seed.public_key()
    }
}

impl OriginSigner for LocalSigner {
    fn kid(&self) -> &str {
        &self.kid
    }
    fn sign(&self, msg: &[u8]) -> Result<[u8; 64]> {
        Ok(self.seed.sign(msg))
    }
}

/// Parse options.
#[derive(Debug, Clone, Copy, Default)]
pub struct ParseOptions {
    /// Explicit developer mode: allow `http` relays on loopback hosts and `localhost:<port>`
    /// domains. Never enable in production builds.
    pub developer_mode: bool,
}

/// A parsed pairing URI. Parsing checks syntax only; call [`PairingUri::check_time`]
/// and [`PairingUri::verify`] before trusting it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingUri {
    /// Relay base URL (`r`).
    pub relay: String,
    /// Pairing mailbox id (`m`).
    pub mailbox: MailboxId,
    /// Pairing mailbox write token (`w`).
    pub write_token: Token,
    /// dApp pairing public key (`k`).
    pub dapp_pk: [u8; 32],
    /// Pairing secret (`s`).
    pub secret: PairingSecret,
    /// dApp domain (`d`).
    pub domain: String,
    /// Expiry (`x`).
    pub expires_at: u64,
    /// Origin key id (`i`).
    pub kid: String,
    /// Origin signature (`o`).
    pub signature: [u8; 64],
    /// Optional sponsorship ticket (`t`).
    pub ticket: Option<[u8; 32]>,
}

/// Inputs for building a URI.
#[derive(Debug)]
pub struct UriParams<'a> {
    /// Relay base URL.
    pub relay: &'a str,
    /// Pairing mailbox id.
    pub mailbox: MailboxId,
    /// Pairing mailbox write token.
    pub write_token: Token,
    /// dApp pairing public key.
    pub dapp_pk: [u8; 32],
    /// Pairing secret.
    pub secret: PairingSecret,
    /// dApp domain (A-label form).
    pub domain: &'a str,
    /// Expiry.
    pub expires_at: u64,
    /// Optional ticket.
    pub ticket: Option<[u8; 32]>,
}

impl PairingUri {
    /// Build and sign a pairing URI.
    pub fn build(
        signer: &dyn OriginSigner,
        now: u64,
        p: UriParams<'_>,
        opts: ParseOptions,
    ) -> Result<Self> {
        if p.expires_at <= now || p.expires_at - now > MAX_LIFETIME_S {
            return Err(Error::InvalidUri("lifetime must be 1..=300 s"));
        }
        validate_relay(p.relay, opts)?;
        validate_domain(p.domain, opts)?;
        let kid = signer.kid().to_owned();
        if !origin::valid_kid(&kid) {
            return Err(Error::InvalidUri("kid"));
        }
        let input = sig_input(
            p.relay,
            &p.mailbox,
            &p.write_token,
            &p.dapp_pk,
            p.domain,
            p.expires_at,
            &kid,
        )?;
        let signature = signer.sign(&input)?;
        Ok(PairingUri {
            relay: p.relay.to_owned(),
            mailbox: p.mailbox,
            write_token: p.write_token,
            dapp_pk: p.dapp_pk,
            secret: p.secret,
            domain: p.domain.to_owned(),
            expires_at: p.expires_at,
            kid,
            signature,
            ticket: p.ticket,
        })
    }

    /// The canonical signature input `uri_sig_input`.
    pub fn sig_input(&self) -> Result<Vec<u8>> {
        sig_input(
            &self.relay,
            &self.mailbox,
            &self.write_token,
            &self.dapp_pk,
            &self.domain,
            self.expires_at,
            &self.kid,
        )
    }

    /// `h_uri = SHA-256(uri_sig_input)`.
    pub fn h_uri(&self) -> Result<[u8; 32]> {
        Ok(crypto::sha256_parts(&[&self.sig_input()?]))
    }

    fn params(&self) -> String {
        let mut s = format!(
            "r={}&m={}&w={}&k={}&s={}&d={}&x={}&i={}&o={}",
            percent_encode(&self.relay),
            self.mailbox.to_b64(),
            crate::b64::encode(self.write_token.expose()),
            crate::b64::encode(&self.dapp_pk),
            crate::b64::encode(self.secret.expose()),
            self.domain,
            self.expires_at,
            self.kid,
            crate::b64::encode(&self.signature),
        );
        if let Some(t) = &self.ticket {
            s.push_str("&t=");
            s.push_str(&crate::b64::encode(t));
        }
        s
    }

    /// `xchonnect:v1?...` form (QR codes).
    pub fn to_uri(&self) -> String {
        format!("{SCHEME_PREFIX}{}", self.params())
    }

    /// Universal-link form `<base>#<params>`, e.g. base `https://klimper.app/pair`.
    pub fn to_universal_link(&self, base: &str) -> String {
        format!("{base}#{}", self.params())
    }

    /// Parse either form.
    pub fn parse(s: &str, opts: ParseOptions) -> Result<Self> {
        if s.len() > 2048 {
            return Err(Error::InvalidUri("too long"));
        }
        let params = if let Some(rest) = s.strip_prefix(SCHEME_PREFIX) {
            rest
        } else if s.starts_with("https://") {
            s.split_once('#')
                .map(|(_, f)| f)
                .ok_or(Error::InvalidUri("universal link without fragment"))?
        } else {
            return Err(Error::InvalidUri("unknown scheme or version"));
        };
        let mut fields: [Option<&str>; 10] = [None; 10];
        const KEYS: [&str; 10] = ["r", "m", "w", "k", "s", "d", "x", "i", "o", "t"];
        for pair in params.split('&') {
            let (k, v) = pair
                .split_once('=')
                .ok_or(Error::InvalidUri("parameter without value"))?;
            if let Some(idx) = KEYS.iter().position(|key| *key == k) {
                let slot = fields.get_mut(idx).ok_or(Error::InvalidUri("parameter"))?;
                if slot.is_some() {
                    return Err(Error::InvalidUri("duplicate parameter"));
                }
                *slot = Some(v);
            } // unknown parameters are ignored
        }
        let get = |i: usize, name: &'static str| {
            fields
                .get(i)
                .copied()
                .flatten()
                .ok_or(Error::InvalidUri(name))
        };
        let relay = percent_decode(get(0, "missing r")?)?;
        validate_relay(&relay, opts)?;
        let domain = get(5, "missing d")?.to_owned();
        validate_domain(&domain, opts)?;
        let x = get(6, "missing x")?;
        if x.is_empty()
            || x.len() > 12
            || !x.bytes().all(|b| b.is_ascii_digit())
            || (x.len() > 1 && x.starts_with('0'))
        {
            return Err(Error::InvalidUri("x"));
        }
        let kid = get(7, "missing i")?.to_owned();
        if !origin::valid_kid(&kid) {
            return Err(Error::InvalidUri("i"));
        }
        let b = |i: usize, name: &'static str| -> Result<Vec<u8>> {
            crate::b64::decode(get(i, name)?).map_err(|_| Error::InvalidUri(name))
        };
        let arr = |i: usize, name: &'static str| -> Result<[u8; 32]> {
            b(i, name)?.try_into().map_err(|_| Error::InvalidUri(name))
        };
        let ticket = match fields.get(9).copied().flatten() {
            Some(_) => Some(arr(9, "t")?),
            None => None,
        };
        Ok(PairingUri {
            relay,
            mailbox: MailboxId(b(1, "m")?.try_into().map_err(|_| Error::InvalidUri("m"))?),
            write_token: Token::from_bytes(arr(2, "w")?),
            dapp_pk: arr(3, "k")?,
            secret: PairingSecret::from_bytes(arr(4, "s")?),
            domain,
            expires_at: x.parse().map_err(|_| Error::InvalidUri("x"))?,
            kid,
            signature: b(8, "o")?.try_into().map_err(|_| Error::InvalidUri("o"))?,
            ticket,
        })
    }

    /// Reject expired URIs and lifetimes above 300 s (plus skew).
    pub fn check_time(&self, now: u64) -> Result<()> {
        if self.expires_at < now
            || self.expires_at > now.saturating_add(MAX_LIFETIME_S + CLOCK_SKEW_S)
        {
            return Err(Error::UriExpired);
        }
        Ok(())
    }

    /// Verify the origin signature against a fetched origin document for `self.domain`.
    pub fn verify(&self, doc: &OriginDocument, now: u64) -> Result<()> {
        let key = doc.key(&self.kid, now)?;
        crypto::ed25519_verify(&key.pk, &self.sig_input()?, &self.signature)
    }
}

fn sig_input(
    relay: &str,
    mbx: &MailboxId,
    w: &Token,
    dpk: &[u8; 32],
    domain: &str,
    x: u64,
    kid: &str,
) -> Result<Vec<u8>> {
    cbor::encode(&Value::Array(vec![
        Value::text("xchonnect pairing uri v1"),
        Value::text(relay),
        Value::bytes(&mbx.0),
        Value::bytes(w.expose()),
        Value::bytes(dpk),
        Value::text(domain),
        Value::Uint(x),
        Value::text(kid),
    ]))
}

fn is_loopback_host(host: &str) -> bool {
    let h = host.rsplit_once(':').map_or(host, |(h, port)| {
        if port.bytes().all(|b| b.is_ascii_digit()) {
            h
        } else {
            host
        }
    });
    matches!(h, "localhost" | "127.0.0.1" | "[::1]")
}

/// Validate a relay base URL (`https`, no query/fragment/userinfo, no trailing slash).
pub fn validate_relay(relay: &str, opts: ParseOptions) -> Result<()> {
    if relay.len() > 200 || relay.ends_with('/') || relay.contains(['?', '#', '@', ' ']) {
        return Err(Error::InvalidUri("relay URL"));
    }
    let rest = if let Some(r) = relay.strip_prefix("https://") {
        r
    } else if let Some(r) = relay.strip_prefix("http://") {
        let host = r.split('/').next().unwrap_or_default();
        if !(opts.developer_mode && is_loopback_host(host)) {
            return Err(Error::InvalidUri("relay must use https"));
        }
        r
    } else {
        return Err(Error::InvalidUri("relay URL scheme"));
    };
    if rest.split('/').next().is_none_or(str::is_empty) {
        return Err(Error::InvalidUri("relay host"));
    }
    Ok(())
}

/// Validate a dApp domain (lowercase A-labels, no port unless developer mode localhost).
pub fn validate_domain(domain: &str, opts: ParseOptions) -> Result<()> {
    if opts.developer_mode {
        if let Some(port) = domain.strip_prefix("localhost:") {
            if !port.is_empty() && port.len() <= 5 && port.bytes().all(|b| b.is_ascii_digit()) {
                return Ok(());
            }
        }
        if domain == "localhost" {
            return Ok(());
        }
    }
    if domain.is_empty() || domain.len() > 253 || !domain.contains('.') {
        return Err(Error::InvalidUri("domain"));
    }
    for label in domain.split('.') {
        let ok = (1..=63).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-');
        if !ok {
            return Err(Error::InvalidUri("domain"));
        }
    }
    Ok(())
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn percent_decode(s: &str) -> Result<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        if b == b'%' {
            let hex = s
                .get(i + 1..i + 3)
                .ok_or(Error::InvalidUri("percent encoding"))?;
            out.push(
                u8::from_str_radix(hex, 16).map_err(|_| Error::InvalidUri("percent encoding"))?,
            );
            i += 3;
        } else if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b);
            i += 1;
        } else {
            return Err(Error::InvalidUri("unencoded character"));
        }
    }
    String::from_utf8(out).map_err(|_| Error::InvalidUri("relay URL encoding"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const NOW: u64 = 1_790_000_000;

    fn signer() -> LocalSigner {
        LocalSigner::new(Ed25519Seed::from_bytes([1; 32]), "2026-10").unwrap()
    }

    fn doc(pk: [u8; 32], not_after: &str) -> OriginDocument {
        let json = format!(
            r#"{{"v":1,"name":"Pengui","origin_keys":[{{"kid":"2026-10","pk":"{}","not_after":"{not_after}"}}]}}"#,
            crate::b64::encode(&pk)
        );
        OriginDocument::parse(json.as_bytes()).unwrap()
    }

    const DEV: ParseOptions = ParseOptions {
        developer_mode: true,
    };

    fn build(relay: &str, domain: &str, lifetime: u64, opts: ParseOptions) -> Result<PairingUri> {
        let p = UriParams {
            relay,
            mailbox: MailboxId([2; 16]),
            write_token: Token::from_bytes([3; 32]),
            dapp_pk: [4; 32],
            secret: PairingSecret::from_bytes([5; 32]),
            domain,
            expires_at: NOW + lifetime,
            ticket: None,
        };
        PairingUri::build(&signer(), NOW, p, opts)
    }

    fn sample() -> PairingUri {
        let u = build(
            "https://relay.example.org/xc",
            "pengui.xyz",
            300,
            Default::default(),
        );
        // The ticket is not covered by the signature.
        let ticket = Some([6; 32]);
        PairingUri {
            ticket,
            ..u.unwrap()
        }
    }

    #[test]
    fn build_parse_verify_both_forms() {
        let u = sample();
        let d = doc(signer().public_key(), "2027-10-01");
        for s in [u.to_uri(), u.to_universal_link("https://klimper.app/pair")] {
            let p = PairingUri::parse(&s, ParseOptions::default()).unwrap();
            assert_eq!(p, u);
            p.check_time(NOW).unwrap();
            p.verify(&d, NOW).unwrap();
        }
        assert!(u.to_uri().len() < 420, "QR budget: {}", u.to_uri().len());
    }

    #[test]
    fn verification_failures() {
        let u = sample();
        let good = doc(signer().public_key(), "2027-10-01");
        // Wrong key.
        let wrong_key = doc([9; 32], "2027-10-01");
        assert_eq!(u.verify(&wrong_key, NOW), Err(Error::BadSignature));
        // Expired key.
        let expired = doc(signer().public_key(), "2020-01-01");
        assert_eq!(
            u.verify(&expired, NOW),
            Err(Error::InvalidOrigin("key expired"))
        );
        // Unknown kid; domain substituted (signature covers d); pairing key substituted.
        type Edit = fn(&mut PairingUri);
        let edits: [(Edit, Error); 3] = [
            (
                |u| u.kid = "other".into(),
                Error::InvalidOrigin("unknown kid"),
            ),
            (|u| u.domain = "evil.example".into(), Error::BadSignature),
            (|u| u.dapp_pk = [8; 32], Error::BadSignature),
        ];
        for (edit, err) in edits {
            let mut changed = u.clone();
            edit(&mut changed);
            assert_eq!(changed.verify(&good, NOW), Err(err));
        }
    }

    #[test]
    fn time_checks() {
        let u = sample();
        assert_eq!(u.check_time(NOW + 301), Err(Error::UriExpired));
        assert_eq!(
            u.check_time(NOW - 100),
            Err(Error::UriExpired),
            "lifetime above 300 s + skew"
        );
        assert!(u.check_time(NOW - 50).is_ok());
        let long = build(
            "https://r.example",
            "pengui.xyz",
            301,
            ParseOptions::default(),
        );
        assert!(long.is_err());
    }

    #[test]
    fn malformed_uris_rejected() {
        let good = sample().to_uri();
        let cases = [
            good.replace("xchonnect:v1?", "xchonnect:v2?"),
            good.replace("&d=pengui.xyz", "&d=Pengui.xyz"),
            good.replace("&d=pengui.xyz", "&d=pengui.xyz:443"),
            good.replace("r=https", "r=http"),
            good.replace("&x=", "&x=0"),
            format!("{good}&m=AAAA"),
            good.replace("&i=2026-10", "&i=bad%20kid"),
            good.replacen("&w=", "&w=A", 1),
            good.replace("&o=", "&o=="),
            "https://klimper.app/pair".to_owned(),
        ];
        for c in cases {
            assert!(
                PairingUri::parse(&c, ParseOptions::default()).is_err(),
                "{c}"
            );
        }
    }

    #[test]
    fn developer_mode_allows_loopback() {
        let u = build("http://127.0.0.1:8787", "localhost:5173", 60, DEV).unwrap();
        assert!(PairingUri::parse(&u.to_uri(), ParseOptions::default()).is_err());
        assert!(PairingUri::parse(&u.to_uri(), DEV).is_ok());
    }
}
