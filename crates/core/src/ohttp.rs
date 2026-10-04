//! Oblivious HTTP client (spec 10; RFC 9458 with RFC 9292 binary HTTP).
//!
//! Bytes in, bytes out: the host sends the encapsulated request with its own HTTP stack
//! (`POST` to the OHTTP relay, `Content-Type: message/ohttp-req`) and passes the response
//! body back for decapsulation.
//!
//! Only DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305 is implemented, on
//! top of the HPKE suite the protocol already uses (no extra cryptographic dependency;
//! the generic `ohttp` crate would add about 65 KB gzip to the browser WASM). The
//! Xchonnect relay's gateway offers this suite; configurations without it are skipped.
//!
//! **Key pinning (spec 10).** Clients start from a pinned key configuration that ships
//! with the app (the relay operator publishes it); they never accept a configuration
//! merely because a server offered it. Rotation: encapsulate `GET /.well-known/ohttp-keys`
//! under the pinned key and decapsulate the answer with
//! [`ResponseContext::decapsulate_key_rotation`]. Only the holder of the pinned private
//! key can produce a response that decrypts, so the new list is authenticated by it; a
//! directly fetched list cannot be used (a TLS-terminating edge, spec 10.3, could
//! otherwise put its own key first). The list must still contain the pinned key (the
//! operator keeps it during the overlap); then the newest configuration becomes the new
//! pin. A list without the pinned key is a hard error ([`Error::OhttpKeyMismatch`]); the
//! app then needs an updated pin.

use crate::crypto::{Entropy, HpkeSender, hkdf_expand, hkdf_extract};
use crate::error::{Error, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use zeroize::Zeroizing;

/// `Content-Type` of encapsulated requests.
pub const REQUEST_MEDIA_TYPE: &str = "message/ohttp-req";
/// `Content-Type` of encapsulated responses.
pub const RESPONSE_MEDIA_TYPE: &str = "message/ohttp-res";
/// `Content-Type` of key configuration lists.
pub const KEYS_MEDIA_TYPE: &str = "application/ohttp-keys";
/// RFC 9458 section 5.3 problem type: the gateway does not accept the key configuration.
pub const KEY_PROBLEM_TYPE: &str = "https://iana.org/assignments/http-problem-types#ohttp-key";

const KEM_X25519_SHA256: u16 = 0x0020;
const KDF_HKDF_SHA256: u16 = 0x0001;
const AEAD_CHACHA20_POLY1305: u16 = 0x0003;
const REQUEST_LABEL: &[u8] = b"message/bhttp request";
const RESPONSE_LABEL: &[u8] = b"message/bhttp response";
/// `max(Nn, Nk)` for ChaCha20-Poly1305.
const RESPONSE_NONCE_LEN: usize = 32;
const TAG_LEN: usize = 16;

/// One gateway key configuration (RFC 9458 section 3) that this client can use.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyConfig {
    key_id: u8,
    public_key: [u8; 32],
    encoded: Vec<u8>,
}

impl core::fmt::Debug for KeyConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "KeyConfig(id {})", self.key_id)
    }
}

impl KeyConfig {
    /// Decode one key configuration (without the list length prefix). Fails when it is
    /// malformed or does not offer X25519 / HKDF-SHA256 / ChaCha20-Poly1305.
    pub fn decode(config: &[u8]) -> Result<Self> {
        Self::decode_any(config)?.ok_or(Error::Malformed("ohttp key config: unsupported suite"))
    }

    /// `Ok(None)` for a well-formed configuration with a suite this client lacks.
    fn decode_any(config: &[u8]) -> Result<Option<Self>> {
        let bad = Error::Malformed("ohttp key config");
        let mut r = Reader::new(config);
        let key_id = r.u8()?;
        if r.u16()? != KEM_X25519_SHA256 {
            return Ok(None); // unknown KEM: public key length unknown, skip the entry
        }
        let public_key: [u8; 32] = r.take(32)?.try_into().map_err(|_| bad.clone())?;
        let suites_len = usize::from(r.u16()?);
        let suites = r.take(suites_len)?;
        if suites.is_empty() || suites.len() % 4 != 0 || !r.is_empty() {
            return Err(bad);
        }
        let supported = suites
            .chunks_exact(4)
            .any(|s| s == [0, KDF_HKDF_SHA256 as u8, 0, AEAD_CHACHA20_POLY1305 as u8]);
        Ok(supported.then(|| KeyConfig {
            key_id,
            public_key,
            encoded: config.to_vec(),
        }))
    }

    /// The configuration as published (used as the stored pin).
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// Key identifier.
    pub fn key_id(&self) -> u8 {
        self.key_id
    }

    fn same_key(&self, other: &KeyConfig) -> bool {
        self.key_id == other.key_id && self.public_key == other.public_key
    }
}

/// Parse an `application/ohttp-keys` list and return the usable configurations in list
/// order (the relay lists the newest first). Malformed lists, and lists without any
/// usable configuration, are errors.
pub fn parse_key_configs(list: &[u8]) -> Result<Vec<KeyConfig>> {
    let mut r = Reader::new(list);
    let mut out = Vec::new();
    while !r.is_empty() {
        let len = usize::from(r.u16()?);
        if let Some(c) = KeyConfig::decode_any(r.take(len)?)? {
            out.push(c);
        }
    }
    if out.is_empty() {
        return Err(Error::Malformed(
            "ohttp key config: no usable configuration",
        ));
    }
    Ok(out)
}

/// The configuration to pin from a list obtained out of band (newest usable entry).
pub fn select(list: &[u8]) -> Result<KeyConfig> {
    parse_key_configs(list)?
        .into_iter()
        .next()
        .ok_or(Error::Malformed(
            "ohttp key config: no usable configuration",
        ))
}

/// Check a list against the pinned configuration and return the new pin: the newest
/// usable configuration, provided the list still contains the pinned key. Only called
/// on lists authenticated by the pinned key (see
/// [`ResponseContext::decapsulate_key_rotation`]).
fn rotate(pinned: &KeyConfig, fetched_list: &[u8]) -> Result<KeyConfig> {
    let configs = parse_key_configs(fetched_list)?;
    if !configs.iter().any(|c| c.same_key(pinned)) {
        return Err(Error::OhttpKeyMismatch);
    }
    configs.into_iter().next().ok_or(Error::OhttpKeyMismatch)
}

/// An inner HTTP request.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// Method, e.g. `GET`.
    pub method: &'a str,
    /// Scheme of the target, normally `https`.
    pub scheme: &'a str,
    /// Authority (host and optional port) of the target.
    pub authority: &'a str,
    /// Path and query, starting with `/`.
    pub path: &'a str,
    /// Header fields (names are sent in lowercase).
    pub headers: &'a [(String, String)],
    /// Content (empty for none).
    pub body: &'a [u8],
}

/// An inner HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// Final status code.
    pub status: u16,
    /// Header fields in order (lowercase names).
    pub headers: Vec<(String, String)>,
    /// Content.
    pub body: Vec<u8>,
}

impl Response {
    /// First value of a header field (case-insensitive name).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Encapsulates requests to one pinned gateway key configuration.
#[derive(Debug, Clone)]
pub struct Client {
    config: KeyConfig,
}

/// Single-use state for decapsulating the response to one request.
pub struct ResponseContext {
    /// Configuration the request was encapsulated to.
    config: KeyConfig,
    enc: [u8; 32],
    secret: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for ResponseContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ResponseContext")
    }
}

impl Client {
    /// Client for a pinned configuration.
    pub fn new(config: KeyConfig) -> Self {
        Client { config }
    }

    /// The pinned configuration.
    pub fn config(&self) -> &KeyConfig {
        &self.config
    }

    /// Encode `req` as binary HTTP and encapsulate it (RFC 9458 section 4.3). Returns the
    /// `message/ohttp-req` body and the context for the response.
    pub fn encapsulate(
        &self,
        rng: &mut dyn Entropy,
        req: &Request<'_>,
    ) -> Result<(Vec<u8>, ResponseContext)> {
        let plain = encode_request(req)?;
        let hdr = [
            self.config.key_id,
            0,
            KEM_X25519_SHA256 as u8,
            0,
            KDF_HKDF_SHA256 as u8,
            0,
            AEAD_CHACHA20_POLY1305 as u8,
        ];
        let mut info = Vec::with_capacity(REQUEST_LABEL.len() + 1 + hdr.len());
        info.extend_from_slice(REQUEST_LABEL);
        info.push(0);
        info.extend_from_slice(&hdr);
        let (enc, mut ctx) = HpkeSender::setup(rng, &self.config.public_key, &info, None)?;
        let ct = ctx.seal(&[], &plain)?;
        let secret = Zeroizing::new(ctx.export(RESPONSE_LABEL)?);
        let mut out = Vec::with_capacity(hdr.len() + enc.len() + ct.len());
        out.extend_from_slice(&hdr);
        out.extend_from_slice(&enc);
        out.extend_from_slice(&ct);
        Ok((
            out,
            ResponseContext {
                config: self.config.clone(),
                enc,
                secret,
            },
        ))
    }
}

impl ResponseContext {
    /// Decrypt a `message/ohttp-res` body (RFC 9458 section 4.4) and decode the binary
    /// HTTP response. A tampered or foreign response gives [`Error::Decrypt`].
    pub fn decapsulate(self, enc_response: &[u8]) -> Result<Response> {
        if enc_response.len() < RESPONSE_NONCE_LEN + TAG_LEN {
            return Err(Error::Malformed("ohttp response: truncated"));
        }
        let (response_nonce, ct) = enc_response.split_at(RESPONSE_NONCE_LEN);
        let mut salt = [0u8; 32 + RESPONSE_NONCE_LEN];
        salt[..32].copy_from_slice(&self.enc);
        salt[32..].copy_from_slice(response_nonce);
        let prk = Zeroizing::new(hkdf_extract(&salt, self.secret.as_slice()));
        let key = Zeroizing::new(hkdf_expand::<32>(&prk, b"key")?);
        let nonce = hkdf_expand::<12>(&prk, b"nonce")?;
        let plain = ChaCha20Poly1305::new(&(*key).into())
            .decrypt(&Nonce::from(nonce), Payload { msg: ct, aad: &[] })
            .map_err(|_| Error::Decrypt)?;
        decode_response(&plain)
    }

    /// Decapsulate the answer to an encapsulated `GET /.well-known/ohttp-keys` and return
    /// the new pin. The response decrypting proves it came from the holder of the pinned
    /// key; the list must still contain that key ([`Error::OhttpKeyMismatch`] otherwise)
    /// and the status must be 200.
    pub fn decapsulate_key_rotation(self, enc_response: &[u8]) -> Result<KeyConfig> {
        let pinned = self.config.clone();
        let res = self.decapsulate(enc_response)?;
        if res.status != 200 {
            return Err(Error::OhttpKeyMismatch);
        }
        rotate(&pinned, &res.body)
    }
}

// ---------------------------------------------------------------------------
// Binary HTTP (RFC 9292)
// ---------------------------------------------------------------------------

fn put_varint(out: &mut Vec<u8>, v: usize) -> Result<()> {
    let v = u64::try_from(v).map_err(|_| Error::TooLarge)?;
    match v {
        0..=0x3f => out.push(v as u8),
        0x40..=0x3fff => out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes()),
        0x4000..=0x3fff_ffff => out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes()),
        0x4000_0000..=0x3fff_ffff_ffff_ffff => {
            out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes());
        }
        _ => return Err(Error::TooLarge),
    }
    Ok(())
}

fn put_vec(out: &mut Vec<u8>, b: &[u8]) -> Result<()> {
    put_varint(out, b.len())?;
    out.extend_from_slice(b);
    Ok(())
}

/// Known-length request (framing indicator 0).
fn encode_request(req: &Request<'_>) -> Result<Vec<u8>> {
    if !req.path.starts_with('/') {
        return Err(Error::Malformed("ohttp request: path must start with /"));
    }
    let mut fields = Vec::new();
    for (name, value) in req.headers {
        let lower = name.to_ascii_lowercase();
        if lower.is_empty() || value.contains(['\r', '\n', '\0']) {
            return Err(Error::Malformed("ohttp request: header field"));
        }
        put_vec(&mut fields, lower.as_bytes())?;
        put_vec(&mut fields, value.as_bytes())?;
    }
    let mut out = Vec::with_capacity(req.body.len() + fields.len() + 64);
    out.push(0);
    for part in [req.method, req.scheme, req.authority, req.path] {
        put_vec(&mut out, part.as_bytes())?;
    }
    put_vec(&mut out, &fields)?;
    put_vec(&mut out, req.body)?;
    out.push(0); // empty trailer section
    Ok(out)
}

fn decode_response(b: &[u8]) -> Result<Response> {
    let bad = Error::Malformed("ohttp response: binary HTTP");
    let mut r = Reader::new(b);
    let known = match r.varint()? {
        1 => true,
        3 => false,
        _ => return Err(bad),
    };
    loop {
        let status = u16::try_from(r.varint()?).map_err(|_| bad.clone())?;
        if !(100..=599).contains(&status) {
            return Err(bad);
        }
        let headers = if known && r.is_empty() {
            Vec::new() // truncated empty sections (RFC 9292 section 3.8)
        } else if known {
            let section = r.vec()?;
            parse_fields(&mut Reader::new(section), true)?
        } else {
            parse_fields(&mut r, false)?
        };
        if status < 200 {
            continue; // informational response
        }
        let mut body = Vec::new();
        if known {
            if !r.is_empty() {
                body = r.vec()?.to_vec();
            }
        } else {
            while !r.is_empty() {
                let chunk = r.vec()?;
                if chunk.is_empty() {
                    break;
                }
                body.extend_from_slice(chunk);
            }
        }
        // Trailers and padding are ignored.
        return Ok(Response {
            status,
            headers,
            body,
        });
    }
}

/// Field lines: until the end of `r` (known length) or a zero-length name.
fn parse_fields(r: &mut Reader<'_>, known: bool) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    loop {
        if known && r.is_empty() {
            return Ok(out);
        }
        let name = r.vec()?;
        if name.is_empty() {
            if known {
                return Err(Error::Malformed("ohttp response: empty field name"));
            }
            return Ok(out);
        }
        let value = r.vec()?;
        let text = |v: &[u8]| {
            String::from_utf8(v.to_vec()).map_err(|_| Error::Malformed("ohttp response: field"))
        };
        out.push((text(name)?.to_ascii_lowercase(), text(value)?));
    }
}

struct Reader<'a> {
    b: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b }
    }
    fn is_empty(&self) -> bool {
        self.b.is_empty()
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.b.len() {
            return Err(Error::Malformed("ohttp: truncated"));
        }
        let (h, t) = self.b.split_at(n);
        self.b = t;
        Ok(h)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?.first().copied().unwrap_or(0))
    }
    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([
            b.first().copied().unwrap_or(0),
            b.get(1).copied().unwrap_or(0),
        ]))
    }
    fn varint(&mut self) -> Result<usize> {
        let first = self.u8()?;
        let len = 1usize << (first >> 6);
        let mut v = u64::from(first & 0x3f);
        for b in self.take(len - 1)? {
            v = (v << 8) | u64::from(*b);
        }
        usize::try_from(v).map_err(|_| Error::Malformed("ohttp: length"))
    }
    fn vec(&mut self) -> Result<&'a [u8]> {
        let n = self.varint()?;
        self.take(n)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cloned_ref_to_slice_refs,
    reason = "tests"
)]
mod tests {
    use super::*;
    use crate::crypto::{HpkeReceiver, OsEntropy, X25519Secret};

    fn config_bytes(key_id: u8, pk: &[u8; 32], suites: &[(u16, u16)]) -> Vec<u8> {
        let mut c = vec![key_id, 0, 0x20];
        c.extend_from_slice(pk);
        c.extend_from_slice(&((suites.len() * 4) as u16).to_be_bytes());
        for (k, a) in suites {
            c.extend_from_slice(&k.to_be_bytes());
            c.extend_from_slice(&a.to_be_bytes());
        }
        c
    }

    fn list(configs: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for c in configs {
            out.extend_from_slice(&(c.len() as u16).to_be_bytes());
            out.extend_from_slice(c);
        }
        out
    }

    /// Minimal gateway side written against RFC 9458 with the core HPKE receiver, so the
    /// round trip also runs on wasm32. (Native tests also check against Mozilla `ohttp`.)
    fn serve(sk: &X25519Secret, enc_request: &[u8], response: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let (hdr, rest) = enc_request.split_at(7);
        let (enc, ct) = rest.split_at(32);
        let mut info = REQUEST_LABEL.to_vec();
        info.push(0);
        info.extend_from_slice(hdr);
        let mut rx = HpkeReceiver::setup(sk, enc.try_into().unwrap(), &info, None).unwrap();
        let plain = rx.open(&[], ct).unwrap();
        let secret = rx.export(RESPONSE_LABEL).unwrap();
        let nonce_r = [9u8; 32];
        let mut salt = enc.to_vec();
        salt.extend_from_slice(&nonce_r);
        let prk = hkdf_extract(&salt, &secret);
        let key: [u8; 32] = hkdf_expand(&prk, b"key").unwrap();
        let nonce: [u8; 12] = hkdf_expand(&prk, b"nonce").unwrap();
        let ct = ChaCha20Poly1305::new(&key.into())
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: response,
                    aad: &[],
                },
            )
            .unwrap();
        ([nonce_r.to_vec(), ct].concat(), plain)
    }

    fn keypair() -> (X25519Secret, [u8; 32]) {
        let sk = X25519Secret::random(&mut OsEntropy);
        let pk = sk.public_key();
        (sk, pk)
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn round_trip_and_binary_http() {
        let (sk, pk) = keypair();
        let cfg = select(&list(&[config_bytes(4, &pk, &[(1, 1), (1, 3)])])).unwrap();
        assert_eq!(cfg.key_id(), 4);
        let client = Client::new(cfg);
        let headers = vec![("Authorization".to_owned(), "Bearer abc".to_owned())];
        let req = Request {
            method: "POST",
            scheme: "https",
            authority: "relay.example",
            path: "/v1/mailboxes/x/messages",
            headers: &headers,
            body: b"{\"env\":\"AA\"}",
        };
        let (enc_req, ctx) = client.encapsulate(&mut OsEntropy, &req).unwrap();
        assert_eq!(&enc_req[..7], &[4, 0, 0x20, 0, 1, 0, 3]);
        // Known-length response with an informational 103, two fields and content.
        let mut resp = vec![1, 0x40, 103, 0];
        resp.extend_from_slice(&[0x40, 202]);
        let mut fields = Vec::new();
        put_vec(&mut fields, b"content-type").unwrap();
        put_vec(&mut fields, b"application/json").unwrap();
        put_vec(&mut fields, b"retry-after").unwrap();
        put_vec(&mut fields, b"3").unwrap();
        put_vec(&mut resp, &fields).unwrap();
        put_vec(&mut resp, b"{}").unwrap();
        let (enc_resp, inner) = serve(&sk, &enc_req, &resp);
        // The inner request is RFC 9292 known-length.
        let mut expect = vec![0];
        for p in ["POST", "https", "relay.example", "/v1/mailboxes/x/messages"] {
            put_vec(&mut expect, p.as_bytes()).unwrap();
        }
        let mut f = Vec::new();
        put_vec(&mut f, b"authorization").unwrap();
        put_vec(&mut f, b"Bearer abc").unwrap();
        put_vec(&mut expect, &f).unwrap();
        put_vec(&mut expect, b"{\"env\":\"AA\"}").unwrap();
        expect.push(0);
        assert_eq!(inner, expect);
        let r = ctx.decapsulate(&enc_resp).unwrap();
        assert_eq!(r.status, 202);
        assert_eq!(r.header("Content-Type"), Some("application/json"));
        assert_eq!(r.header("retry-after"), Some("3"));
        assert_eq!(r.body, b"{}");
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn tampered_or_foreign_responses_fail() {
        let (sk, pk) = keypair();
        let client = Client::new(KeyConfig::decode(&config_bytes(1, &pk, &[(1, 3)])).unwrap());
        let req = Request {
            method: "GET",
            scheme: "https",
            authority: "r",
            path: "/v1/info",
            headers: &[],
            body: &[],
        };
        let (enc_req, ctx) = client.encapsulate(&mut OsEntropy, &req).unwrap();
        let (mut enc_resp, _) = serve(&sk, &enc_req, &[1, 0x40, 200, 0, 0]);
        let last = enc_resp.len() - 1;
        enc_resp[last] ^= 1;
        assert_eq!(ctx.decapsulate(&enc_resp).unwrap_err(), Error::Decrypt);
        // A response to another request does not open under this context.
        let (enc_a, _ctx_a) = client.encapsulate(&mut OsEntropy, &req).unwrap();
        let (_, ctx_b) = client.encapsulate(&mut OsEntropy, &req).unwrap();
        let (resp_a, _) = serve(&sk, &enc_a, &[1, 0x40, 200, 0, 0]);
        assert_eq!(ctx_b.decapsulate(&resp_a).unwrap_err(), Error::Decrypt);
        let (_, ctx) = client.encapsulate(&mut OsEntropy, &req).unwrap();
        assert!(ctx.decapsulate(&[0; 40]).is_err());
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn key_configuration_parsing_pinning_and_rotation() {
        let (_, pk1) = keypair();
        let (_, pk2) = keypair();
        let old = config_bytes(1, &pk1, &[(1, 1), (1, 3)]);
        let new = config_bytes(2, &pk2, &[(1, 1), (1, 3)]);
        let aes_only = config_bytes(3, &pk2, &[(1, 1)]);
        let mut p256 = vec![5, 0, 0x10];
        p256.extend_from_slice(&[4; 65]);
        p256.extend_from_slice(&[0, 4, 0, 1, 0, 1]);

        // Unsupported entries are skipped, order is kept.
        let parsed = parse_key_configs(&list(&[
            p256.clone(),
            aes_only.clone(),
            new.clone(),
            old.clone(),
        ]))
        .unwrap();
        assert_eq!(
            parsed.iter().map(KeyConfig::key_id).collect::<Vec<_>>(),
            vec![2, 1]
        );
        assert!(parse_key_configs(&list(&[aes_only.clone()])).is_err());
        assert!(KeyConfig::decode(&aes_only).is_err());
        for bad in [
            vec![0u8],                                // truncated length
            list(&[old[..30].to_vec()]),              // truncated config
            list(&[[old.clone(), vec![0]].concat()]), // trailing byte in an entry
            list(&[config_bytes(1, &pk1, &[])]),      // no suites
            vec![],                                   // empty list
        ] {
            assert!(parse_key_configs(&bad).is_err());
        }

        let pinned = select(&list(&[old.clone()])).unwrap();
        assert_eq!(pinned.encoded(), old.as_slice());
        // Same list: pin unchanged.
        assert_eq!(rotate(&pinned, &list(&[old.clone()])).unwrap(), pinned);
        // Rotation with overlap: move to the newest.
        let next = rotate(&pinned, &list(&[new.clone(), old.clone()])).unwrap();
        assert_eq!(next.key_id(), 2);
        // Old key gone, or a different key under the same id: hard error.
        assert_eq!(
            rotate(&pinned, &list(&[new.clone()])).unwrap_err(),
            Error::OhttpKeyMismatch
        );
        let impostor = config_bytes(1, &pk2, &[(1, 3)]);
        assert_eq!(
            rotate(&pinned, &list(&[impostor])).unwrap_err(),
            Error::OhttpKeyMismatch
        );
        // Suites may change without a key change.
        assert!(rotate(&pinned, &list(&[config_bytes(1, &pk1, &[(1, 3)])])).is_ok());
    }

    /// Known-length binary HTTP response with no fields.
    fn bhttp_response(status: u16, body: &[u8]) -> Vec<u8> {
        let mut r = vec![1];
        put_varint(&mut r, usize::from(status)).unwrap();
        put_vec(&mut r, &[]).unwrap();
        put_vec(&mut r, body).unwrap();
        r
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn rotation_only_from_responses_authenticated_by_the_pin() {
        let (sk1, pk1) = keypair();
        let (sk2, pk2) = keypair();
        let old = config_bytes(1, &pk1, &[(1, 3)]);
        let new = config_bytes(2, &pk2, &[(1, 3)]);
        let client = Client::new(select(&list(&[old.clone()])).unwrap());
        let req = Request {
            method: "GET",
            scheme: "https",
            authority: "relay.example",
            path: "/.well-known/ohttp-keys",
            headers: &[],
            body: &[],
        };
        let rotated = list(&[new.clone(), old.clone()]);

        // Answered by the pinned key's holder: rotate to the newest entry.
        let (enc_req, ctx) = client.encapsulate(&mut OsEntropy, &req).unwrap();
        let (resp, _) = serve(&sk1, &enc_req, &bhttp_response(200, &rotated));
        assert_eq!(ctx.decapsulate_key_rotation(&resp).unwrap().key_id(), 2);

        // An edge that puts its own key first cannot answer under the pinned key: the
        // HPKE open fails for it, and a response sealed with any other secret does not
        // decrypt.
        let (enc_req, _) = client.encapsulate(&mut OsEntropy, &req).unwrap();
        let mut info = REQUEST_LABEL.to_vec();
        info.push(0);
        info.extend_from_slice(&enc_req[..7]);
        assert!(
            HpkeReceiver::setup(&sk2, enc_req[7..39].try_into().unwrap(), &info, None)
                .and_then(|mut rx| rx.open(&[], &enc_req[39..]))
                .is_err()
        );
        let (enc_a, ctx_a) = client.encapsulate(&mut OsEntropy, &req).unwrap();
        let (_, ctx_b) = client.encapsulate(&mut OsEntropy, &req).unwrap();
        let (resp_a, _) = serve(&sk1, &enc_a, &bhttp_response(200, &rotated));
        assert_eq!(
            ctx_b.decapsulate_key_rotation(&resp_a).unwrap_err(),
            Error::Decrypt
        );
        drop(ctx_a);

        // Non-200 answers and lists without the pinned key are hard errors.
        let (enc_req, ctx) = client.encapsulate(&mut OsEntropy, &req).unwrap();
        let (resp, _) = serve(&sk1, &enc_req, &bhttp_response(404, &rotated));
        assert_eq!(
            ctx.decapsulate_key_rotation(&resp).unwrap_err(),
            Error::OhttpKeyMismatch
        );
        let (enc_req, ctx) = client.encapsulate(&mut OsEntropy, &req).unwrap();
        let (resp, _) = serve(&sk1, &enc_req, &bhttp_response(200, &list(&[new])));
        assert_eq!(
            ctx.decapsulate_key_rotation(&resp).unwrap_err(),
            Error::OhttpKeyMismatch
        );
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn binary_http_decoding_edge_cases() {
        // Indeterminate-length response: fields, two content chunks, padding.
        let mut b = vec![3, 0x40, 200];
        put_vec(&mut b, b"content-type").unwrap();
        put_vec(&mut b, b"text/plain").unwrap();
        b.push(0);
        put_vec(&mut b, b"ab").unwrap();
        put_vec(&mut b, b"c").unwrap();
        b.extend_from_slice(&[0, 0, 0, 0]);
        let r = decode_response(&b).unwrap();
        assert_eq!((r.status, r.body.as_slice()), (200, b"abc".as_slice()));
        assert_eq!(r.header("content-type"), Some("text/plain"));
        // Truncated trailing sections are allowed (RFC 9292 section 3.8).
        assert_eq!(decode_response(&[1, 0x40, 204]).unwrap().status, 204);
        assert_eq!(decode_response(&[1, 0x40, 204, 0]).unwrap().body, b"");
        assert!(
            decode_response(&[1, 0x40, 204, 5, 1]).is_err(),
            "section beyond input"
        );
        // Requests are not responses; bad status; lengths beyond the input.
        for bad in [
            vec![0u8, 0],
            vec![1, 0x40, 99, 0],
            vec![1, 0x42, 0x58, 0], // 600
            vec![1, 0x40, 200, 0x7f, 0xff],
        ] {
            assert!(decode_response(&bad).is_err());
        }
        let mut v = Vec::new();
        for n in [0usize, 63, 64, 16383, 16384, 1 << 30] {
            v.clear();
            put_varint(&mut v, n).unwrap();
            assert_eq!(Reader::new(&v).varint().unwrap(), n);
        }
        let bad_header = [("x".to_owned(), "a\r\nb".to_owned())];
        let req = Request {
            method: "GET",
            scheme: "https",
            authority: "r",
            path: "/",
            headers: &bad_header,
            body: &[],
        };
        assert!(encode_request(&req).is_err());
        assert!(
            encode_request(&Request {
                path: "v1",
                headers: &[],
                ..req
            })
            .is_err()
        );
    }

    /// Interop with Mozilla's `ohttp`/`bhttp` gateway side (the relay's implementation).
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn mozilla_gateway_interop() {
        use ohttp::hpke::{Aead as A, Kdf as K, Kem as M};
        let config = ohttp::KeyConfig::new(
            7,
            M::X25519Sha256,
            vec![
                ohttp::SymmetricSuite::new(K::HkdfSha256, A::Aes128Gcm),
                ohttp::SymmetricSuite::new(K::HkdfSha256, A::ChaCha20Poly1305),
            ],
        )
        .unwrap();
        let server = ohttp::Server::new(config).unwrap();
        let published = ohttp::KeyConfig::encode_list(&[server.config()]).unwrap();
        let client = Client::new(select(&published).unwrap());
        let headers = vec![("authorization".to_owned(), "Bearer t".to_owned())];
        let req = Request {
            method: "PUT",
            scheme: "https",
            authority: "relay.example",
            path: "/v1/mailboxes/m/push?x=1",
            headers: &headers,
            body: br#"{"push_reg":null}"#,
        };
        let (enc_req, ctx) = client.encapsulate(&mut OsEntropy, &req).unwrap();
        let (plain, sctx) = server.decapsulate(&enc_req).unwrap();
        let msg = bhttp::Message::read_bhttp(&mut std::io::Cursor::new(&plain[..])).unwrap();
        let c = msg.control();
        assert_eq!(c.method(), Some(&b"PUT"[..]));
        assert_eq!(c.authority(), Some(&b"relay.example"[..]));
        assert_eq!(c.path(), Some(&b"/v1/mailboxes/m/push?x=1"[..]));
        assert_eq!(msg.header().get(b"authorization"), Some(&b"Bearer t"[..]));
        assert_eq!(msg.content(), br#"{"push_reg":null}"#);

        for mode in [bhttp::Mode::KnownLength, bhttp::Mode::IndeterminateLength] {
            let (enc_req, ctx) = client.encapsulate(&mut OsEntropy, &req).unwrap();
            let (_, sctx) = server.decapsulate(&enc_req).unwrap();
            let mut resp = bhttp::Message::response(bhttp::StatusCode::try_from(429u16).unwrap());
            resp.put_header("retry-after", "7");
            resp.write_content(b"{\"error\":\"rate_limited\"}");
            let mut out = Vec::new();
            resp.write_bhttp(mode, &mut out).unwrap();
            let r = ctx.decapsulate(&sctx.encapsulate(&out).unwrap()).unwrap();
            assert_eq!(r.status, 429);
            assert_eq!(r.header("retry-after"), Some("7"));
            assert_eq!(r.body, b"{\"error\":\"rate_limited\"}");
        }
        let mut resp = bhttp::Message::response(bhttp::StatusCode::try_from(204u16).unwrap());
        resp.put_header("content-type", "application/json");
        let mut out = Vec::new();
        resp.write_bhttp(bhttp::Mode::KnownLength, &mut out)
            .unwrap();
        let r = ctx.decapsulate(&sctx.encapsulate(&out).unwrap()).unwrap();
        assert_eq!((r.status, r.body.len()), (204, 0));
    }
}
