//! Oblivious HTTP gateway (spec 10, RFC 9458 with RFC 9292 binary HTTP).
//!
//! - `GET /.well-known/ohttp-keys` serves the key configurations (`application/ohttp-keys`,
//!   newest first). `GET /.well-known/ohttp-gateway` serves the same list (RFC 9540).
//! - `POST /.well-known/ohttp-gateway` accepts `message/ohttp-req`, decapsulates the
//!   binary HTTP request, dispatches it in-process to the same router as direct requests
//!   (same body limit, authentication and rate limits) and returns the encapsulated
//!   response as `message/ohttp-res`.
//!
//! Inner requests reach only the protocol routes (`/v1/*`, health, key configuration);
//! `/metrics` and the gateway itself are not reachable through the gateway. Only the
//! `authorization`, `content-type` and `xchonnect-api-key` inner header fields are passed
//! on; everything else in the inner request is dropped. Long-polls through the gateway
//! are capped at `max_wait_ohttp_s` (spec 10.1).
//!
//! Replay (spec 10.4, RFC 9458 section 6.5): every node remembers the HPKE `enc` of the
//! encapsulated requests it accepted, in memory only, for [`REPLAY_WINDOW_S`] and at most
//! [`REPLAY_CAPACITY`] entries, and refuses repeats with the same `400 bad_request` as a
//! malformed encapsulation, without reaching the inner endpoint. An `enc` is remembered
//! only after the encapsulation decrypted, so a forgery that copies an observed `enc`
//! cannot keep the genuine request out. Replays after the window or to another node are
//! executed like any repeated direct request; the API tolerates that (envelopes carry
//! `seq`/`id` replay protection end to end, proofs and tickets are single-use, ack and
//! delete are idempotent). See `docs/operating.md`.
//!
//! Padding (spec 10.5): encapsulated responses are padded to size buckets, so their
//! length does not tell the OHTTP relay which endpoint was called or how many envelopes a
//! fetch returned (T9, T10). Inner requests are padded by the client; unpadded ones are
//! accepted.

use crate::error::ApiError;
use crate::{AppState, lock};
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::rejection::BytesRejection;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use std::collections::{HashSet, VecDeque};
use std::sync::Mutex;
use tower::ServiceExt;
use xchonnect_core::ohttp as core_ohttp;
use zeroize::Zeroizing;

/// Key configuration path (spec 10).
pub const KEYS_PATH: &str = "/.well-known/ohttp-keys";
/// Gateway resource (RFC 9540 well-known name).
pub const GATEWAY_PATH: &str = "/.well-known/ohttp-gateway";
/// Media types (RFC 9458 section 9).
pub const KEYS_MEDIA_TYPE: &str = "application/ohttp-keys";
/// Encapsulated request media type.
pub const REQUEST_MEDIA_TYPE: &str = "message/ohttp-req";
/// Encapsulated response media type.
pub const RESPONSE_MEDIA_TYPE: &str = "message/ohttp-res";
/// RFC 9458 section 5.3 problem type for key configuration errors.
pub const KEY_PROBLEM_TYPE: &str = "https://iana.org/assignments/http-problem-types#ohttp-key";

/// Largest encapsulated request: the largest padded inner request (spec 10.5, 512 KiB for
/// the 400 KiB direct body limit plus binary HTTP framing and inner header fields) plus
/// the HPKE header, `enc` and tag. The inner body limit stays [`MAX_BODY_BYTES`].
pub const MAX_ENCAPSULATED_BYTES: usize = 512 * 1024 + 1024;
/// Largest inner response that is encapsulated (32 messages of the largest envelope is
/// about 10.7 MiB). Bounded so that padding the binary HTTP response to a bucket always
/// fits [`xchonnect_core::ohttp::MAX_PADDED_BYTES`].
const MAX_INNER_RESPONSE_BYTES: usize = core_ohttp::MAX_PADDED_BYTES - 1024;
/// How long a node remembers accepted requests for replay detection.
pub const REPLAY_WINDOW_S: u64 = 600;
/// Upper bound on remembered requests per node (oldest are forgotten first).
const REPLAY_CAPACITY: usize = 200_000;
/// Most key configurations served at once (current plus rotation overlap).
pub const MAX_KEYS: usize = 8;
/// Inner header fields passed to the router; all others are dropped.
const INNER_HEADERS: [&str; 3] = ["authorization", "content-type", "xchonnect-api-key"];
/// Request header length: key id, KEM, KDF and AEAD identifiers (RFC 9458 section 4.3).
const REQUEST_HEADER_LEN: usize = 7;
/// `enc` length for DHKEM(X25519, HKDF-SHA256).
const ENC_LEN: usize = 32;

/// Marker extension on requests that arrived through the gateway.
#[derive(Debug, Clone, Copy)]
pub struct ViaOhttp;

/// One gateway key: identifier and 32 bytes of secret input keying material from which
/// the X25519 key pair is derived (RFC 9180 `DeriveKeyPair`).
#[derive(Clone)]
pub struct OhttpKey {
    /// Key identifier announced in the key configuration.
    pub id: u8,
    ikm: Zeroizing<[u8; 32]>,
}

impl OhttpKey {
    /// Key from an identifier and secret seed.
    pub fn new(id: u8, ikm: [u8; 32]) -> Self {
        OhttpKey {
            id,
            ikm: Zeroizing::new(ikm),
        }
    }
}

impl std::fmt::Debug for OhttpKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OhttpKey({}, [redacted])", self.id)
    }
}

/// Parse `id:base64url(32 bytes)` entries separated by commas or whitespace, newest first.
pub fn parse_keys(text: &str) -> Result<Vec<OhttpKey>, String> {
    let mut keys: Vec<OhttpKey> = Vec::new();
    for entry in text
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
    {
        let (id, seed) = entry
            .split_once(':')
            .ok_or("OHTTP keys: expected id:base64url-seed")?;
        let id: u8 = id
            .parse()
            .map_err(|_| "OHTTP keys: key id must be 0..=255")?;
        let ikm = xchonnect_core::b64::decode_array::<32>(seed)
            .map_err(|_| "OHTTP keys: seed must be base64url of 32 bytes")?;
        if keys.iter().any(|k| k.id == id) {
            return Err("OHTTP keys: duplicate key id".into());
        }
        keys.push(OhttpKey::new(id, ikm));
    }
    if keys.is_empty() {
        return Err("OHTTP keys: no keys given".into());
    }
    if keys.len() > MAX_KEYS {
        return Err(format!("OHTTP keys: at most {MAX_KEYS} keys"));
    }
    Ok(keys)
}

/// How the gateway obtains its keys.
#[derive(Debug, Clone, Default)]
pub enum OhttpMode {
    /// No gateway; `/v1/info` reports `"ohttp": false` and the gateway paths give 404.
    Disabled,
    /// A key generated at startup. Development only: it changes on every restart and
    /// differs between nodes, so clients that pinned it fail.
    #[default]
    Ephemeral,
    /// Configured keys, newest first; all are accepted, the first is preferred.
    Keys(Vec<OhttpKey>),
}

/// Gateway state: the key servers and the encoded key configuration list.
pub struct Gateway {
    servers: Vec<(u8, ohttp::Server)>,
    encoded: Vec<u8>,
    replay: Mutex<ReplayCache>,
}

impl std::fmt::Debug for Gateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ids: Vec<u8> = self.servers.iter().map(|(id, _)| *id).collect();
        write!(f, "Gateway(keys {ids:?})")
    }
}

fn suites() -> Vec<ohttp::SymmetricSuite> {
    use ohttp::hpke::{Aead, Kdf};
    // AES-128-GCM first: the suite every OHTTP implementation supports. Xchonnect
    // clients use ChaCha20-Poly1305 (the protocol's AEAD; smaller WASM).
    vec![
        ohttp::SymmetricSuite::new(Kdf::HkdfSha256, Aead::Aes128Gcm),
        ohttp::SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305),
    ]
}

/// Why an encapsulated request was refused before dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayError {
    /// Unknown key id or the request does not decrypt under it (RFC 9458 section 5.3).
    Key,
    /// Truncated or otherwise malformed encapsulation.
    Malformed,
    /// The same encapsulated request was already accepted (replay).
    Replay,
}

impl Gateway {
    /// Build the gateway for a mode; `Ok(None)` when disabled.
    pub fn new(mode: &OhttpMode) -> Result<Option<Self>, String> {
        let keys = match mode {
            OhttpMode::Disabled => return Ok(None),
            OhttpMode::Ephemeral => vec![OhttpKey::new(
                0,
                xchonnect_core::crypto::random_array(&mut xchonnect_core::crypto::OsEntropy),
            )],
            OhttpMode::Keys(k) => k.clone(),
        };
        let servers = keys
            .iter()
            .map(|k| {
                let kem = ohttp::hpke::Kem::X25519Sha256;
                let config = ohttp::KeyConfig::derive(k.id, kem, suites(), k.ikm.as_slice())
                    .map_err(|_| "OHTTP keys: key derivation failed")?;
                let server = ohttp::Server::new(config).map_err(|_| "OHTTP keys: invalid key")?;
                Ok((k.id, server))
            })
            .collect::<Result<Vec<_>, &str>>()?;
        let configs: Vec<&ohttp::KeyConfig> = servers.iter().map(|(_, s)| s.config()).collect();
        let encoded = ohttp::KeyConfig::encode_list(&configs)
            .map_err(|_| "OHTTP keys: cannot encode key configuration")?;
        Ok(Some(Gateway {
            servers,
            encoded,
            replay: Mutex::default(),
        }))
    }

    /// The `application/ohttp-keys` body (newest key first).
    pub fn key_configs(&self) -> &[u8] {
        &self.encoded
    }

    /// Decapsulate a request at time `now`; returns the binary HTTP request and the
    /// context for encapsulating the response.
    pub fn decapsulate(
        &self,
        enc_request: &[u8],
        now: u64,
    ) -> Result<(Vec<u8>, ohttp::ServerResponse), GatewayError> {
        let key_id = *enc_request.first().ok_or(GatewayError::Malformed)?;
        let enc: [u8; ENC_LEN] = enc_request
            .get(REQUEST_HEADER_LEN..REQUEST_HEADER_LEN + ENC_LEN)
            .and_then(|s| s.try_into().ok())
            .ok_or(GatewayError::Malformed)?;
        let (_, server) = self
            .servers
            .iter()
            .find(|(id, _)| *id == key_id)
            .ok_or(GatewayError::Key)?;
        if lock(&self.replay).seen(&enc, now) {
            return Err(GatewayError::Replay);
        }
        let out = server.decapsulate(enc_request).map_err(|e| match e {
            ohttp::Error::Truncated | ohttp::Error::Format | ohttp::Error::Io(_) => {
                GatewayError::Malformed
            }
            _ => GatewayError::Key,
        })?;
        // Remember only requests that decrypted; a concurrent duplicate loses here.
        if !lock(&self.replay).insert(enc, now) {
            return Err(GatewayError::Replay);
        }
        Ok(out)
    }
}

/// Recently accepted `enc` values with their expiry, oldest first.
#[derive(Default)]
struct ReplayCache {
    seen: HashSet<[u8; ENC_LEN]>,
    order: VecDeque<([u8; ENC_LEN], u64)>,
}

impl ReplayCache {
    fn expire(&mut self, now: u64) {
        while let Some((k, exp)) = self.order.front() {
            if *exp > now && self.order.len() < REPLAY_CAPACITY {
                break;
            }
            self.seen.remove(k);
            self.order.pop_front();
        }
    }

    fn seen(&mut self, enc: &[u8; ENC_LEN], now: u64) -> bool {
        self.expire(now);
        self.seen.contains(enc)
    }

    fn insert(&mut self, enc: [u8; ENC_LEN], now: u64) -> bool {
        self.expire(now);
        if !self.seen.insert(enc) {
            return false;
        }
        self.order.push_back((enc, now + REPLAY_WINDOW_S));
        true
    }
}

/// Gateway and key configuration routes. `inner` is the router that decapsulated
/// requests are dispatched to.
pub fn routes(inner: Router) -> Router<AppState> {
    Router::new()
        .route(KEYS_PATH, axum::routing::get(keys))
        .route(GATEWAY_PATH, axum::routing::get(keys).post(gateway))
        .layer(Extension(inner))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_ENCAPSULATED_BYTES))
}

/// Key configuration list (also reachable through the gateway, so that clients can
/// learn rotated keys without revealing their address).
pub async fn keys(State(s): State<AppState>) -> Response {
    match s.ohttp() {
        None => ApiError::NotFound.into_response(),
        Some(g) => (
            [(header::CONTENT_TYPE, KEYS_MEDIA_TYPE)],
            g.key_configs().to_vec(),
        )
            .into_response(),
    }
}

fn key_problem() -> Response {
    (
        StatusCode::BAD_REQUEST,
        [(header::CONTENT_TYPE, "application/problem+json")],
        format!(r#"{{"type":"{KEY_PROBLEM_TYPE}","title":"key configuration mismatch"}}"#),
    )
        .into_response()
}

async fn gateway(
    State(s): State<AppState>,
    Extension(inner): Extension<Router>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let Some(gw) = s.ohttp() else {
        return ApiError::NotFound.into_response();
    };
    let body = match body {
        Ok(b) => b,
        Err(e) => return ApiError::from(e).into_response(),
    };
    let media_ok = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case(REQUEST_MEDIA_TYPE));
    if !media_ok {
        return ApiError::BadRequest.into_response();
    }
    let (plain, response_ctx) = match gw.decapsulate(&body, s.now()) {
        Ok(v) => v,
        Err(GatewayError::Key) => return key_problem(),
        Err(GatewayError::Malformed | GatewayError::Replay) => {
            return ApiError::BadRequest.into_response();
        }
    };
    // From here on every answer, including errors, is encapsulated.
    let inner_res = match inner_request(&plain) {
        Some(req) => inner
            .oneshot(req)
            .await
            .unwrap_or_else(|never| match never {}),
        None => ApiError::BadRequest.into_response(),
    };
    let Some(encoded) = encode_response(inner_res).await else {
        return ApiError::Unavailable.into_response();
    };
    match response_ctx.encapsulate(&encoded) {
        Ok(enc) => ([(header::CONTENT_TYPE, RESPONSE_MEDIA_TYPE)], enc).into_response(),
        Err(_) => ApiError::Unavailable.into_response(),
    }
}

/// Binary HTTP request to an axum request (path and allowed header fields only).
fn inner_request(plain: &[u8]) -> Option<Request<Body>> {
    let msg = bhttp::Message::read_bhttp(&mut std::io::Cursor::new(plain)).ok()?;
    let control = msg.control();
    let method = Method::from_bytes(control.method()?).ok()?;
    let path = std::str::from_utf8(control.path()?).ok()?;
    if !path.starts_with('/') {
        return None;
    }
    let uri: Uri = path.parse().ok()?;
    if uri.scheme().is_some() || uri.authority().is_some() {
        return None;
    }
    let mut req = Request::builder().method(method).uri(uri);
    for field in msg.header().iter() {
        let name = field.name();
        if let Some(allowed) = INNER_HEADERS
            .iter()
            .find(|h| h.as_bytes().eq_ignore_ascii_case(name))
        {
            req = req.header(*allowed, HeaderValue::from_bytes(field.value()).ok()?);
        }
    }
    let mut req = req.body(Body::from(msg.content().to_vec())).ok()?;
    req.extensions_mut().insert(ViaOhttp);
    Some(req)
}

/// Axum response to a known-length binary HTTP response, padded to a size bucket
/// (spec 10.5) so that the encapsulated length does not reveal the endpoint or how many
/// envelopes a fetch returned.
async fn encode_response(res: Response) -> Option<Vec<u8>> {
    let status = bhttp::StatusCode::try_from(res.status().as_u16()).ok()?;
    let mut msg = bhttp::Message::response(status);
    for name in [header::CONTENT_TYPE, header::RETRY_AFTER] {
        if let Some(v) = res.headers().get(&name) {
            msg.put_header(name.as_str(), v.as_bytes());
        }
    }
    let body = axum::body::to_bytes(res.into_body(), MAX_INNER_RESPONSE_BYTES)
        .await
        .ok()?;
    msg.write_content(&body);
    let mut out = Vec::with_capacity(body.len() + 64);
    msg.write_bhttp(bhttp::Mode::KnownLength, &mut out).ok()?;
    core_ohttp::pad_inner(&mut out).ok()?;
    Some(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
pub(crate) mod tests {
    use super::*;
    use crate::api::tests::{
        call, create, envelope, err, get, hashes, json_of, open_config, test_state,
    };
    use crate::{Config, MAX_BODY_BYTES};
    use serde_json::{Value, json};
    use std::sync::atomic::{AtomicU64, Ordering};
    use xchonnect_core::b64;
    use xchonnect_core::crypto::{OsEntropy, Token};
    use xchonnect_core::ohttp as core_ohttp;

    /// Encapsulation overhead of a request and of a response for the suite the core client
    /// uses (RFC 9458 section 4.3/4.4 with ChaCha20-Poly1305).
    const REQUEST_OVERHEAD: usize = REQUEST_HEADER_LEN + ENC_LEN + 16;
    const RESPONSE_OVERHEAD: usize = 32 + 16;

    pub(crate) fn keyed_config(keys: &[(u8, u8)]) -> Config {
        let keys = keys
            .iter()
            .map(|(id, seed)| OhttpKey::new(*id, [*seed; 32]));
        Config {
            ohttp: OhttpMode::Keys(keys.collect()),
            ..open_config()
        }
    }

    /// An inner request in binary HTTP.
    pub(crate) struct Inner<'a> {
        method: &'a str,
        path: &'a str,
        headers: Vec<(&'a str, String)>,
        body: Vec<u8>,
    }

    impl<'a> Inner<'a> {
        pub(crate) fn new(method: &'a str, path: &'a str) -> Self {
            Inner {
                method,
                path,
                headers: Vec::new(),
                body: Vec::new(),
            }
        }
        pub(crate) fn token(mut self, t: &Token) -> Self {
            let bearer = format!("Bearer {}", b64::encode(t.expose()));
            self.headers.push(("authorization", bearer));
            self
        }
        pub(crate) fn json(mut self, v: &Value) -> Self {
            self.headers
                .push(("content-type", "application/json".to_owned()));
            self.body = v.to_string().into_bytes();
            self
        }
        fn encode(&self) -> Vec<u8> {
            let (m, p) = (self.method.as_bytes(), self.path.as_bytes());
            let mut msg = bhttp::Message::request(
                m.to_vec(),
                b"https".to_vec(),
                b"relay.example".to_vec(),
                p.to_vec(),
            );
            for (k, v) in &self.headers {
                msg.put_header(*k, v.as_bytes());
            }
            msg.write_content(&self.body);
            let mut out = Vec::new();
            msg.write_bhttp(bhttp::Mode::KnownLength, &mut out).unwrap();
            out
        }
    }

    /// Fetch the key configurations from the relay (direct).
    pub(crate) async fn key_configs(s: &AppState) -> Vec<ohttp::KeyConfig> {
        let (st, h, body) = call(s, get(KEYS_PATH)).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(h["content-type"], KEYS_MEDIA_TYPE);
        ohttp::KeyConfig::decode_list(&body).unwrap()
    }

    /// Newest key configuration of a relay with `keys`.
    fn key_of(keys: &[(u8, u8)]) -> ohttp::KeyConfig {
        let s = test_state(keyed_config(keys));
        let list = ohttp::KeyConfig::decode_list(s.ohttp().unwrap().key_configs());
        list.unwrap().remove(0)
    }

    fn outer(enc: Vec<u8>) -> Request<Body> {
        Request::post(GATEWAY_PATH)
            .header("content-type", REQUEST_MEDIA_TYPE)
            .body(Body::from(enc))
            .unwrap()
    }

    /// Encapsulated request with key configuration `key` (Mozilla `ohttp` client).
    fn encapsulate(key: &mut ohttp::KeyConfig, plain: &[u8]) -> (Vec<u8>, ohttp::ClientResponse) {
        let client = ohttp::ClientRequest::from_config(key).unwrap();
        client.encapsulate(plain).unwrap()
    }

    /// Send binary HTTP `plain` through the gateway; returns the inner response.
    async fn via_gateway_raw(
        s: &AppState,
        key: &mut ohttp::KeyConfig,
        plain: &[u8],
    ) -> bhttp::Message {
        let (enc, pending) = encapsulate(key, plain);
        let (st, h, body) = call(s, outer(enc)).await;
        assert_eq!(st, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        assert_eq!(h["content-type"], RESPONSE_MEDIA_TYPE);
        assert_eq!(h["cache-control"], "no-store");
        let plain = pending.decapsulate(&body).unwrap();
        bhttp::Message::read_bhttp(&mut std::io::Cursor::new(&plain[..])).unwrap()
    }

    /// Send `inner` through the gateway with the Mozilla `ohttp` client using key
    /// configuration `key`. Returns the inner status, content type and body.
    pub(crate) async fn via_gateway(
        s: &AppState,
        key: &mut ohttp::KeyConfig,
        inner: &Inner<'_>,
    ) -> (u16, Option<String>, Vec<u8>) {
        let msg = via_gateway_raw(s, key, &inner.encode()).await;
        let ct = msg.header().get(b"content-type");
        let ct = ct.map(|v| String::from_utf8(v.to_vec()).unwrap());
        let status = msg.control().status().unwrap().code();
        (status, ct, msg.content().to_vec())
    }

    #[tokio::test]
    async fn key_configuration_and_info() {
        let s = test_state(keyed_config(&[(2, 0xb2), (1, 0xb1)]));
        let configs = key_configs(&s).await;
        assert_eq!(configs.len(), 2, "current and previous key during rotation");
        let list = s.ohttp().unwrap().key_configs();
        let discovered = call(&s, get(GATEWAY_PATH)).await.2;
        assert_eq!(discovered, list, "RFC 9540 discovery");
        // Encoding: [len(2)][key_id=2][kem 0x0020][pk 32][suites len 8][AES-128-GCM][ChaCha].
        assert_eq!(&list[..5], &[0, 45, 2, 0, 0x20]);
        assert_eq!(&list[37..47], &[0, 8, 0, 1, 0, 1, 0, 1, 0, 3]);
        let info = |s: AppState| async move {
            json_of(&call(&s, get("/v1/info")).await.2)["ohttp"].clone()
        };
        assert_eq!(info(s.clone()).await, true);

        // Keys are derived deterministically: every node with the same secret serves the
        // same configuration.
        let again = test_state(keyed_config(&[(2, 0xb2), (1, 0xb1)]));
        assert_eq!(again.ohttp().unwrap().key_configs(), list);

        let off = test_state(Config {
            ohttp: OhttpMode::Disabled,
            ..open_config()
        });
        assert_eq!(info(off.clone()).await, false);
        for req in [get(KEYS_PATH), outer(vec![1; 100])] {
            let (st, _, body) = call(&off, req).await;
            assert_eq!((st, body), (StatusCode::NOT_FOUND, err("not_found")));
        }
    }

    #[tokio::test]
    async fn every_endpoint_works_through_the_gateway_with_both_keys() {
        let s = test_state(keyed_config(&[(2, 0xb2), (1, 0xb1)]));
        let mut configs = key_configs(&s).await;
        for key in &mut configs {
            let (st, _, body) = via_gateway(&s, key, &Inner::new("GET", "/v1/info")).await;
            let info = json_of(&body);
            assert_eq!(
                (st, &info["ohttp"], &info["max_wait_ohttp_s"]),
                (200, &json!(true), &json!(0))
            );
        }
        let key = &mut configs[0];
        let (r, w) = (Token::from_bytes([7; 32]), Token::from_bytes([8; 32]));
        let create = Inner::new("POST", "/v1/mailboxes").json(&hashes(7, 8));
        let (st, _, body) = via_gateway(&s, key, &create).await;
        assert_eq!(st, 201);
        let id = json_of(&body)["mailbox_id"].as_str().unwrap().to_owned();
        let base = format!("/v1/mailboxes/{id}");
        let msgs = format!("{base}/messages");
        let post = Inner::new("POST", &msgs)
            .token(&w)
            .json(&json!({ "env": envelope() }));
        assert_eq!(via_gateway(&s, key, &post).await.0, 202);
        let (st, ct, body) = via_gateway(&s, key, &Inner::new("GET", &msgs).token(&r)).await;
        assert_eq!((st, ct.as_deref()), (200, Some("application/json")));
        let v = json_of(&body);
        assert_eq!(v["messages"][0]["env"], envelope().as_str());
        // Key configuration is reachable through the gateway (rotation without exposing
        // the client address).
        let (st, ct, body) = via_gateway(&s, key, &Inner::new("GET", KEYS_PATH)).await;
        assert_eq!((st, ct.as_deref()), (200, Some(KEYS_MEDIA_TYPE)));
        assert_eq!(body, s.ohttp().unwrap().key_configs());
        let ack = json!({ "msg_ids": [v["messages"][0]["msg_id"]] });
        let no_push = json!({ "push_reg": null });
        let (ack_path, push_path) = (format!("{base}/ack"), format!("{base}/push"));
        for (inner, status) in [
            (Inner::new("POST", &ack_path).token(&r).json(&ack), 204),
            (Inner::new("PUT", &push_path).token(&r).json(&no_push), 204),
            (Inner::new("POST", "/v1/challenge"), 200),
            (Inner::new("DELETE", &base).token(&r), 204),
            (Inner::new("GET", &msgs).token(&r), 404),
        ] {
            let st = via_gateway(&s, key, &inner).await.0;
            assert_eq!(st, status, "{} {}", inner.method, inner.path);
        }
    }

    #[tokio::test]
    async fn same_auth_size_and_rate_rules_as_direct_requests() {
        let s = test_state(Config {
            write_rate: 60,
            ..keyed_config(&[(1, 0xb1)])
        });
        let key = &mut key_configs(&s).await.remove(0);
        let (id, _, w) = create(&s).await;
        let msgs = format!("/v1/mailboxes/{id}/messages");

        // Wrong token: byte-identical not_found inside the encapsulation.
        let (st, ct, body) = via_gateway(&s, key, &Inner::new("GET", &msgs).token(&w)).await;
        assert_eq!(ct.as_deref(), Some("application/json"));
        assert_eq!((st, body), (404, err("not_found")));
        let st = via_gateway(&s, key, &Inner::new("GET", &msgs)).await.0;
        assert_eq!(st, 404, "no token");

        // Same 400 KiB body limit.
        let huge = json!({ "env": "A".repeat(crate::MAX_BODY_BYTES) });
        let post = Inner::new("POST", &msgs).token(&w).json(&huge);
        let (st, _, body) = via_gateway(&s, key, &post).await;
        assert_eq!((st, body), (413, err("too_large")));

        // Same rate limits, shared with direct requests on the same token.
        let mut limited = None;
        let post = Inner::new("POST", &msgs)
            .token(&w)
            .json(&json!({ "env": envelope() }));
        for _ in 0..30 {
            let msg = via_gateway_raw(&s, key, &post.encode()).await;
            if msg.control().status().unwrap().code() == 429 {
                limited = Some(msg.header().get(b"retry-after").map(<[u8]>::to_vec));
                break;
            }
        }
        let retry_after = limited.expect("rate limited through OHTTP");
        assert!(retry_after.is_some(), "Retry-After kept");

        // Operator and gateway routes are not reachable from inside.
        for path in ["/metrics", GATEWAY_PATH] {
            let st = via_gateway(&s, key, &Inner::new("GET", path)).await.0;
            assert_eq!(st, 404, "{path}");
        }
        // Absolute-form targets are refused.
        let absolute = Inner::new("GET", "https://elsewhere.example/v1/info");
        let (st, _, body) = via_gateway(&s, key, &absolute).await;
        assert_eq!((st, body), (400, err("bad_request")));
    }

    #[tokio::test]
    async fn long_polls_through_ohttp_use_max_wait_ohttp_s() {
        let s = test_state(Config {
            max_wait_s: 25,
            max_wait_ohttp_s: 0,
            ..keyed_config(&[(1, 0xb1)])
        });
        let mut key = key_configs(&s).await.remove(0);
        let (id, r, _) = create(&s).await;
        let start = std::time::Instant::now();
        let path = format!("/v1/mailboxes/{id}/messages?wait=20");
        let poll = Inner::new("GET", &path).token(&r);
        let (st, _, body) = via_gateway(&s, &mut key, &poll).await;
        assert_eq!((st, body), (200, br#"{"messages":[]}"#.to_vec()));
        let held = start.elapsed();
        assert!(held < std::time::Duration::from_secs(2), "not held open");
        assert_eq!((s.max_wait(false), s.max_wait(true)), (25, 0));
    }

    #[tokio::test]
    async fn key_errors_replays_and_malformed_requests() {
        let s = test_state(keyed_config(&[(1, 0xb1)]));
        let mut key = key_configs(&s).await.remove(0);
        let info = Inner::new("GET", "/v1/info").encode();

        // A configuration the gateway does not have (rotated away): RFC 9458 problem.
        let (stale, _) = encapsulate(&mut key_of(&[(9, 0xc9)]), &info);
        let (st, h, body) = call(&s, outer(stale)).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        assert_eq!(h["content-type"], "application/problem+json");
        assert_eq!(json_of(&body)["type"], KEY_PROBLEM_TYPE);
        // Same key id, different key: also a key problem.
        let (wrong, _) = encapsulate(&mut key_of(&[(1, 0xee)]), b"x");
        let (_, h, _) = call(&s, outer(wrong)).await;
        assert_eq!(h["content-type"], "application/problem+json");

        // Replay of an accepted encapsulated request is refused.
        let (enc, _) = encapsulate(&mut key, &info);
        assert_eq!(call(&s, outer(enc.clone())).await.0, StatusCode::OK);
        let (st, _, body) = call(&s, outer(enc.clone())).await;
        assert_eq!((st, body), (StatusCode::BAD_REQUEST, err("bad_request")));

        // Wrong media type, truncated body, oversized body.
        let mut wrong_type = outer(enc);
        let json = "application/json".parse().unwrap();
        wrong_type.headers_mut().insert("content-type", json);
        let truncated = outer(vec![1, 0, 0x20]);
        for req in [wrong_type, truncated] {
            assert_eq!(call(&s, req).await.0, StatusCode::BAD_REQUEST);
        }
        let (st, _, body) = call(&s, outer(vec![1; MAX_ENCAPSULATED_BYTES + 1])).await;
        assert_eq!(
            (st, body),
            (StatusCode::PAYLOAD_TOO_LARGE, err("too_large"))
        );

        // Garbage binary HTTP inside a valid encapsulation gets an encapsulated 400.
        let msg = via_gateway_raw(&s, &mut key, &[0xff, 0xff]).await;
        assert_eq!(msg.control().status().unwrap().code(), 400);
    }

    /// A state whose clock can be moved forward (replay window tests).
    fn state_with_clock(config: Config) -> (AppState, std::sync::Arc<AtomicU64>) {
        let now = std::sync::Arc::new(AtomicU64::new(1_790_000_000));
        let read = std::sync::Arc::clone(&now);
        let clock = std::sync::Arc::new(move || read.load(Ordering::Relaxed));
        (AppState::in_memory(config, clock), now)
    }

    /// Messages waiting in a mailbox, fetched through the gateway.
    async fn message_count(s: &AppState, path: &str, token: &Token) -> usize {
        let mut key = key_configs(s).await.remove(0);
        let fetch = Inner::new("GET", path).token(token);
        let (st, _, body) = via_gateway(s, &mut key, &fetch).await;
        assert_eq!(st, 200);
        json_of(&body)["messages"].as_array().map_or(0, Vec::len)
    }

    /// Spec 10.4: a replay is refused like a malformed encapsulation, does not reach the
    /// inner endpoint, and is accepted again only once the window has passed.
    #[tokio::test]
    async fn replays_are_refused_without_reaching_the_endpoint() {
        let (s, now) = state_with_clock(keyed_config(&[(1, 0xb1)]));
        let mut key = key_configs(&s).await.remove(0);
        let (id, r, w) = create(&s).await;
        let msgs = format!("/v1/mailboxes/{id}/messages");
        let post = Inner::new("POST", &msgs)
            .token(&w)
            .json(&json!({ "env": envelope() }));

        // The first copy is accepted and stores one message.
        let (enc, _) = encapsulate(&mut key, &post.encode());
        assert_eq!(call(&s, outer(enc.clone())).await.0, StatusCode::OK);
        assert_eq!(message_count(&s, &msgs, &r).await, 1);

        // Every further copy is refused byte-identically to a malformed encapsulation,
        // and no second message is stored.
        let malformed = call(&s, outer(vec![1, 0, 0x20])).await;
        for _ in 0..3 {
            let replay = call(&s, outer(enc.clone())).await;
            assert_eq!(replay.0, StatusCode::BAD_REQUEST);
            assert_eq!(replay.2, err("bad_request"));
            assert_eq!((replay.0, &replay.2), (malformed.0, &malformed.2));
            assert_eq!(
                replay.1.get("content-type"),
                malformed.1.get("content-type"),
                "a replay is not distinguishable from a malformed request"
            );
        }
        assert_eq!(message_count(&s, &msgs, &r).await, 1, "no second message");

        // Just inside the window: still refused. After it: executed again (spec 10.4.5).
        now.fetch_add(REPLAY_WINDOW_S - 1, Ordering::Relaxed);
        assert_eq!(
            call(&s, outer(enc.clone())).await.0,
            StatusCode::BAD_REQUEST
        );
        now.fetch_add(1, Ordering::Relaxed);
        assert_eq!(call(&s, outer(enc)).await.0, StatusCode::OK);
        assert_eq!(
            message_count(&s, &msgs, &r).await,
            2,
            "an undetected replay is just a repeated request"
        );
    }

    /// Spec 10.4.2: the `enc` is remembered only after the encapsulation decrypted, so a
    /// forgery that copies an observed `enc` cannot keep the genuine request out.
    #[tokio::test]
    async fn an_enc_reusing_forgery_does_not_block_the_genuine_request() {
        let s = test_state(keyed_config(&[(1, 0xb1)]));
        let mut key = key_configs(&s).await.remove(0);
        let (enc, pending) = encapsulate(&mut key, &Inner::new("GET", "/v1/info").encode());

        // The OHTTP relay sees the encapsulation and sends a tampered copy first.
        let mut forged = enc.clone();
        let last = forged.len() - 1;
        forged[last] ^= 0xff;
        let (st, h, _) = call(&s, outer(forged)).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        assert_eq!(h["content-type"], "application/problem+json");

        // The genuine request still works; only then is its `enc` spent.
        let (st, _, body) = call(&s, outer(enc.clone())).await;
        assert_eq!(st, StatusCode::OK);
        let plain = pending.decapsulate(&body).unwrap();
        let msg = bhttp::Message::read_bhttp(&mut std::io::Cursor::new(&plain[..])).unwrap();
        assert_eq!(msg.control().status().unwrap().code(), 200);
        assert_eq!(call(&s, outer(enc)).await.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn replay_cache_expires_and_is_bounded() {
        let mut c = ReplayCache::default();
        assert!(c.insert([1; 32], 100));
        assert!(c.seen(&[1; 32], 100 + REPLAY_WINDOW_S - 1));
        assert!(!c.insert([1; 32], 101));
        assert!(!c.seen(&[1; 32], 100 + REPLAY_WINDOW_S));
        assert!(c.insert([1; 32], 100 + REPLAY_WINDOW_S));
        assert!(c.order.len() == 1 && c.seen.len() == 1);
    }

    #[test]
    fn key_parsing() {
        let seed = b64::encode(&[3; 32]);
        let keys = parse_keys(&format!("2:{seed}, 1:{seed}\n")).unwrap();
        assert_eq!(keys.iter().map(|k| k.id).collect::<Vec<_>>(), vec![2, 1]);
        assert!(!format!("{keys:?}").contains(&seed), "seeds never print");
        let dup = format!("1:{seed},1:{seed}");
        for bad in ["", "x", "1:AAAA", &dup, &format!("256:{seed}")] {
            assert!(parse_keys(bad).is_err(), "{bad}");
        }
        let many: Vec<String> = (0..=MAX_KEYS).map(|i| format!("{i}:{seed}")).collect();
        assert!(parse_keys(&many.join(",")).is_err());
    }

    #[test]
    fn configuration_from_environment() {
        let seed = b64::encode(&[4; 32]);
        let get = |vars: &[(&str, &str)]| {
            Config::from_lookup(|k| {
                vars.iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| (*v).to_owned())
            })
        };
        let mode = |vars: &[(&str, &str)]| get(vars).unwrap().ohttp;
        // No keys: a startup error, never a silent per-process key.
        let err = get(&[]).unwrap_err();
        assert!(err.contains("XCHONNECT_OHTTP_KEYS is required"), "{err}");
        assert!(get(&[("XCHONNECT_OHTTP_KEYS", "")]).is_err());
        let ephemeral = mode(&[("XCHONNECT_OHTTP", "ephemeral")]);
        assert!(matches!(ephemeral, OhttpMode::Ephemeral));
        assert!(get(&[("XCHONNECT_OHTTP", "maybe")]).is_err());
        let disabled = mode(&[("XCHONNECT_OHTTP", "false")]);
        assert!(matches!(disabled, OhttpMode::Disabled));
        let five = format!("5:{seed}");
        let m = mode(&[("XCHONNECT_OHTTP_KEYS", &five)]);
        assert!(matches!(&m, OhttpMode::Keys(k) if k.len() == 1 && k[0].id == 5));
        assert!(get(&[("XCHONNECT_OHTTP_KEYS", "5:short")]).is_err());

        let file = std::env::temp_dir().join(format!("xchonnect-ohttp-{}", std::process::id()));
        std::fs::write(&file, format!("7:{seed}\n6:{seed}\n")).unwrap();
        let path = file.display().to_string();
        let m = mode(&[
            ("XCHONNECT_OHTTP_KEYS_FILE", &path),
            ("XCHONNECT_OHTTP_KEYS", &five),
        ]);
        std::fs::remove_file(&file).unwrap();
        assert!(matches!(&m, OhttpMode::Keys(k) if k.len() == 2 && k[0].id == 7));
        assert!(get(&[("XCHONNECT_OHTTP_KEYS_FILE", "/nonexistent/x")]).is_err());
    }

    /// Encapsulate a request with the core OHTTP client (TASK-52) and send it.
    async fn core_send(
        s: &AppState,
        client: &core_ohttp::Client,
        (method, path): (&str, &str),
        headers: &[(String, String)],
        body: &[u8],
    ) -> (StatusCode, HeaderMap, Vec<u8>, core_ohttp::ResponseContext) {
        let req = core_ohttp::Request {
            method,
            scheme: "https",
            authority: "relay.example",
            path,
            headers,
            body,
        };
        let (enc, ctx) = client.encapsulate(&mut OsEntropy, &req).unwrap();
        let (st, h, out) = call(s, outer(enc)).await;
        (st, h, out, ctx)
    }

    /// Send a request with the core OHTTP client. `Err` carries the outer status and
    /// content type when the gateway refused the encapsulation.
    async fn core_call(
        s: &AppState,
        client: &core_ohttp::Client,
        target: (&str, &str),
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<core_ohttp::Response, (StatusCode, String)> {
        let (st, h, out, ctx) = core_send(s, client, target, headers, body).await;
        if st != StatusCode::OK {
            let ct = h.get("content-type").map(|v| v.to_str().unwrap());
            return Err((st, ct.unwrap_or_default().to_owned()));
        }
        Ok(ctx.decapsulate(&out).unwrap())
    }

    /// Rotation through the gateway with the core client's authenticated path.
    async fn rotate_via(s: &AppState, client: &core_ohttp::Client) -> core_ohttp::KeyConfig {
        let (st, _, out, ctx) = core_send(s, client, ("GET", KEYS_PATH), &[], &[]).await;
        assert_eq!(st, StatusCode::OK);
        ctx.decapsulate_key_rotation(&out).unwrap()
    }

    /// Inner request and inner response length of one operation, with the core client.
    /// Panics unless both are exactly a size bucket (spec 10.5).
    async fn bucketed(
        s: &AppState,
        client: &core_ohttp::Client,
        target: (&str, &str),
        headers: &[(String, String)],
        body: &[u8],
    ) -> (usize, usize, core_ohttp::Response) {
        let (method, path) = target;
        let req = core_ohttp::Request {
            method,
            scheme: "https",
            authority: "relay.example",
            path,
            headers,
            body,
        };
        let (enc, ctx) = client.encapsulate(&mut OsEntropy, &req).unwrap();
        let (st, h, out) = call(s, outer(enc.clone())).await;
        assert_eq!(st, StatusCode::OK, "{}", String::from_utf8_lossy(&out));
        assert_eq!(h["content-type"], RESPONSE_MEDIA_TYPE);
        let (sent, got) = (enc.len() - REQUEST_OVERHEAD, out.len() - RESPONSE_OVERHEAD);
        for len in [sent, got] {
            assert_eq!(
                core_ohttp::padded_len(len),
                Ok(len),
                "{method} {path}: {len} is not a size bucket"
            );
        }
        (sent, got, ctx.decapsulate(&out).unwrap())
    }

    /// Spec 10.5 / TASK-69 AC #2: every operation's inner request and response lands on a
    /// bucket boundary, and the common ones all land on the 2 KiB floor.
    #[tokio::test]
    async fn every_operation_is_padded_to_a_size_bucket() {
        use core_ohttp::MIN_PADDED_BYTES;
        let s = test_state(keyed_config(&[(1, 0xb1)]));
        let pinned = core_ohttp::select(s.ohttp().unwrap().key_configs()).unwrap();
        let client = core_ohttp::Client::new(pinned);
        let ct = ("content-type".to_owned(), "application/json".to_owned());
        let jh = [ct.clone()];
        let auth = |t: &Token| {
            let bearer = format!("Bearer {}", b64::encode(t.expose()));
            [("authorization".to_owned(), bearer), ct.clone()]
        };
        let (r, w) = (Token::from_bytes([5; 32]), Token::from_bytes([6; 32]));
        let create = hashes(5, 6).to_string();
        let target = ("POST", "/v1/mailboxes");
        let (sent, got, res) = bucketed(&s, &client, target, &jh, create.as_bytes()).await;
        assert_eq!(
            (sent, got, res.status),
            (MIN_PADDED_BYTES, MIN_PADDED_BYTES, 201)
        );
        let id = json_of(&res.body)["mailbox_id"].clone();
        let id = id.as_str().unwrap();
        let base = format!("/v1/mailboxes/{id}");
        let msgs = format!("{base}/messages");
        let post = json!({ "env": envelope() }).to_string();
        let ack = json!({ "msg_ids": [] }).to_string();
        let push = json!({ "push_reg": null }).to_string();

        // One 1 KiB-bucket envelope posted, an empty fetch, a fetch with that envelope and
        // every control request are all 2 KiB in both directions: the length does not say
        // which operation it is, nor whether a message was waiting.
        for (target, headers, body) in [
            (("GET", "/v1/info"), &[][..], &[][..]),
            (("POST", "/v1/challenge"), &[], &[]),
            (("GET", KEYS_PATH), &[], &[]),
            (("GET", msgs.as_str()), &auth(&r)[..], &[]),
            (("POST", msgs.as_str()), &auth(&w), post.as_bytes()),
            (("GET", msgs.as_str()), &auth(&r), &[]),
            (("POST", &format!("{base}/ack")), &auth(&r), ack.as_bytes()),
            (("PUT", &format!("{base}/push")), &auth(&r), push.as_bytes()),
            (("DELETE", base.as_str()), &auth(&r)[..1], &[]),
        ] {
            let (sent, got, _) = bucketed(&s, &client, target, headers, body).await;
            let what = format!("{} {}", target.0, target.1);
            assert_eq!((sent, got), (MIN_PADDED_BYTES, MIN_PADDED_BYTES), "{what}");
        }
    }

    /// Spec 10.5 / TASK-69 AC #2: the length of a fetch response does not reveal how many
    /// envelopes it carries — several counts share one bucket, 0 and 1 included.
    #[tokio::test]
    async fn fetch_response_length_hides_the_envelope_count() {
        let s = test_state(keyed_config(&[(1, 0xb1)]));
        let pinned = core_ohttp::select(s.ohttp().unwrap().key_configs()).unwrap();
        let client = core_ohttp::Client::new(pinned);
        let (id, r, w) = create(&s).await;
        let msgs = format!("/v1/mailboxes/{id}/messages");
        let ct = ("content-type".to_owned(), "application/json".to_owned());
        let auth = |t: &Token| {
            let bearer = format!("Bearer {}", b64::encode(t.expose()));
            [("authorization".to_owned(), bearer), ct.clone()]
        };
        let post = json!({ "env": envelope() }).to_string();
        let mut lengths = Vec::new();
        for n in 0..8usize {
            let (_, got, res) = bucketed(&s, &client, ("GET", &msgs), &auth(&r), &[]).await;
            assert_eq!(res.status, 200);
            let count = json_of(&res.body)["messages"]
                .as_array()
                .map_or(0, Vec::len);
            assert_eq!(count, n, "mailbox holds {n} envelopes");
            lengths.push(got);
            let target = ("POST", msgs.as_str());
            bucketed(&s, &client, target, &auth(&w), post.as_bytes()).await;
        }
        // 0 and 1 envelope are indistinguishable (the 2 KiB floor), and so are 3, 4 and 5.
        assert_eq!(lengths[0], lengths[1], "a waiting message is not visible");
        assert_eq!(lengths[3], lengths[4], "3 and 4 envelopes look the same");
        assert_eq!(lengths[4], lengths[5], "4 and 5 envelopes look the same");
        assert!(lengths.windows(2).all(|p| p[0] <= p[1]), "{lengths:?}");
        assert!(lengths.last() > lengths.first(), "buckets do grow");
    }

    /// Spec 10.5: the gateway accepts an unpadded inner request (generic OHTTP clients do
    /// not pad) and still pads its response.
    #[tokio::test]
    async fn unpadded_requests_are_accepted_and_answers_are_padded() {
        let s = test_state(keyed_config(&[(1, 0xb1)]));
        let mut key = key_configs(&s).await.remove(0);
        let (enc, pending) = encapsulate(&mut key, &Inner::new("GET", "/v1/info").encode());
        assert!(
            enc.len() < core_ohttp::MIN_PADDED_BYTES,
            "Mozilla client does not pad"
        );
        let (st, _, body) = call(&s, outer(enc)).await;
        assert_eq!(st, StatusCode::OK);
        let plain = pending.decapsulate(&body).unwrap();
        assert_eq!(core_ohttp::padded_len(plain.len()), Ok(plain.len()));
        assert_eq!(plain.len(), core_ohttp::MIN_PADDED_BYTES);
        let msg = bhttp::Message::read_bhttp(&mut std::io::Cursor::new(&plain[..])).unwrap();
        assert_eq!(msg.control().status().unwrap().code(), 200);
        assert_eq!(json_of(msg.content())["ohttp"], true);
    }

    /// The gateway's outer body limit admits the largest padded request that still carries
    /// a body within the direct limit, and nothing more.
    #[test]
    fn encapsulated_size_limit_matches_the_padded_maximum() {
        let inner = MAX_BODY_BYTES + 1024; // body plus binary HTTP framing and headers
        let padded = core_ohttp::padded_len(inner).unwrap();
        assert_eq!(padded, 512 * 1024);
        assert!(padded + REQUEST_OVERHEAD <= MAX_ENCAPSULATED_BYTES);
        // A response that was read within the limit always fits the largest bucket.
        let largest = core_ohttp::padded_len(MAX_INNER_RESPONSE_BYTES + 512).unwrap();
        assert_eq!(largest, core_ohttp::MAX_PADDED_BYTES);
    }

    #[tokio::test]
    async fn core_client_round_trip_and_rotation() {
        use core_ohttp::Client;
        // Before rotation the relay has key 1; the app ships that configuration pinned.
        let before = test_state(keyed_config(&[(1, 0xb1)]));
        let pinned = core_ohttp::select(before.ohttp().unwrap().key_configs()).unwrap();

        // The operator rotates: key 2 is new, key 1 stays during the overlap.
        let s = test_state(keyed_config(&[(2, 0xb2), (1, 0xb1)]));
        let client = Client::new(pinned.clone());
        let (r, w) = (Token::from_bytes([3; 32]), Token::from_bytes([4; 32]));
        let create = hashes(3, 4).to_string();
        let ct = ("content-type".to_owned(), "application/json".to_owned());
        let jh = [ct.clone()];
        let target = ("POST", "/v1/mailboxes");
        let res = core_call(&s, &client, target, &jh, create.as_bytes()).await;
        let res = res.unwrap();
        assert_eq!(res.status, 201);
        let id = json_of(&res.body)["mailbox_id"].clone();
        let id = id.as_str().unwrap();
        let auth = |t: &Token| {
            let bearer = format!("Bearer {}", b64::encode(t.expose()));
            [("authorization".to_owned(), bearer), ct.clone()]
        };
        let msgs = format!("/v1/mailboxes/{id}/messages");
        let post = json!({ "env": envelope() }).to_string();
        let res = core_call(&s, &client, ("POST", &msgs), &auth(&w), post.as_bytes()).await;
        assert_eq!(res.unwrap().status, 202);

        // Learn the rotation through the gateway, authenticated by the pinned key.
        let res = core_call(&s, &client, ("GET", KEYS_PATH), &[], &[]).await;
        assert_eq!(res.unwrap().header("content-type"), Some(KEYS_MEDIA_TYPE));
        let next = rotate_via(&s, &client).await;
        assert_eq!(next.key_id(), 2);
        let client = Client::new(next);
        let poll = format!("{msgs}?wait=30");
        let res = core_call(&s, &client, ("GET", &poll), &auth(&r), &[]).await;
        let res = res.unwrap();
        assert_eq!(res.status, 200);
        let v = json_of(&res.body);
        assert_eq!(v["messages"][0]["env"], envelope().as_str());

        // Overlap over: key 1 removed. The new pin keeps working; the old pin gets the
        // RFC 9458 key problem, and its rotation check is a hard error.
        let after = test_state(keyed_config(&[(3, 0xb3), (2, 0xb2)]));
        let res = core_call(&after, &client, ("GET", "/v1/info"), &[], &[]).await;
        assert_eq!(res.unwrap().status, 200);
        let stale = Client::new(pinned);
        let res = core_call(&after, &stale, ("GET", "/v1/info"), &[], &[]).await;
        let problem = "application/problem+json".to_owned();
        assert_eq!(res.unwrap_err(), (StatusCode::BAD_REQUEST, problem));
        assert_eq!(rotate_via(&after, &client).await.key_id(), 3);
    }
}
