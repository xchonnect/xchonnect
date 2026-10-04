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
//! Replay (RFC 9458 section 6.5; the Xchonnect spec does not define gateway replay
//! handling): every node remembers the HPKE `enc` of the encapsulated requests it accepted
//! for [`REPLAY_WINDOW_S`] and rejects repeats. Replays after the window or to another
//! node are executed like any repeated direct request; the API tolerates that (envelopes
//! carry `seq`/`id` replay protection end to end, proofs and tickets are single-use, ack
//! and delete are idempotent). See `docs/operating.md`.

use crate::error::ApiError;
use crate::{AppState, MAX_BODY_BYTES};
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::rejection::BytesRejection;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use std::collections::{HashSet, VecDeque};
use std::sync::Mutex;
use tower::ServiceExt;
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

/// Largest encapsulated request: the direct body limit plus binary HTTP framing, inner
/// header fields and the HPKE header, `enc` and tag.
pub const MAX_ENCAPSULATED_BYTES: usize = MAX_BODY_BYTES + 16 * 1024;
/// Largest inner response that is encapsulated (32 messages of the largest envelope).
const MAX_INNER_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
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
        let mut servers = Vec::with_capacity(keys.len());
        for k in &keys {
            let config = ohttp::KeyConfig::derive(
                k.id,
                ohttp::hpke::Kem::X25519Sha256,
                suites(),
                k.ikm.as_slice(),
            )
            .map_err(|_| "OHTTP keys: key derivation failed")?;
            let server = ohttp::Server::new(config).map_err(|_| "OHTTP keys: invalid key")?;
            servers.push((k.id, server));
        }
        let configs: Vec<&ohttp::KeyConfig> = servers.iter().map(|(_, s)| s.config()).collect();
        let encoded = ohttp::KeyConfig::encode_list(&configs)
            .map_err(|_| "OHTTP keys: cannot encode key configuration")?;
        Ok(Some(Gateway {
            servers,
            encoded,
            replay: Mutex::new(ReplayCache::default()),
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
        if self.replay_lock().seen(&enc, now) {
            return Err(GatewayError::Replay);
        }
        let out = server.decapsulate(enc_request).map_err(|e| match e {
            ohttp::Error::Truncated | ohttp::Error::Format | ohttp::Error::Io(_) => {
                GatewayError::Malformed
            }
            _ => GatewayError::Key,
        })?;
        // Remember only requests that decrypted; a concurrent duplicate loses here.
        if !self.replay_lock().insert(enc, now) {
            return Err(GatewayError::Replay);
        }
        Ok(out)
    }

    fn replay_lock(&self) -> std::sync::MutexGuard<'_, ReplayCache> {
        self.replay
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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
        Err(e) if e.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            return ApiError::TooLarge.into_response();
        }
        Err(_) => return ApiError::BadRequest.into_response(),
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
        Some(req) => match inner.oneshot(req).await {
            Ok(res) => res,
            Err(never) => match never {},
        },
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

/// Axum response to a known-length binary HTTP response.
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
    Some(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
pub(crate) mod tests {
    use super::*;
    use crate::Config;
    use crate::api::tests::{call, create, envelope, open_config, test_state};
    use serde_json::{Value, json};
    use xchonnect_core::b64;
    use xchonnect_core::crypto::Token;

    pub(crate) fn keyed_config(keys: &[(u8, u8)]) -> Config {
        Config {
            ohttp: OhttpMode::Keys(
                keys.iter()
                    .map(|(id, seed)| OhttpKey::new(*id, [*seed; 32]))
                    .collect(),
            ),
            ..open_config()
        }
    }

    /// An inner request in binary HTTP.
    pub(crate) struct Inner<'a> {
        pub method: &'a str,
        pub path: &'a str,
        pub headers: Vec<(&'a str, String)>,
        pub body: Vec<u8>,
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
            self.headers.push((
                "authorization",
                format!("Bearer {}", b64::encode(t.expose())),
            ));
            self
        }
        pub(crate) fn json(mut self, v: &Value) -> Self {
            self.headers
                .push(("content-type", "application/json".to_owned()));
            self.body = v.to_string().into_bytes();
            self
        }
        fn encode(&self) -> Vec<u8> {
            let mut m = bhttp::Message::request(
                self.method.as_bytes().to_vec(),
                b"https".to_vec(),
                b"relay.example".to_vec(),
                self.path.as_bytes().to_vec(),
            );
            for (k, v) in &self.headers {
                m.put_header(*k, v.as_bytes());
            }
            m.write_content(&self.body);
            let mut out = Vec::new();
            m.write_bhttp(bhttp::Mode::KnownLength, &mut out).unwrap();
            out
        }
    }

    /// Fetch the key configurations from the relay (direct).
    pub(crate) async fn key_configs(s: &AppState) -> Vec<ohttp::KeyConfig> {
        let (st, h, body) = call(s, Request::get(KEYS_PATH).body(Body::empty()).unwrap()).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(h["content-type"], KEYS_MEDIA_TYPE);
        ohttp::KeyConfig::decode_list(&body).unwrap()
    }

    pub(crate) fn outer(enc: Vec<u8>) -> Request<Body> {
        Request::post(GATEWAY_PATH)
            .header("content-type", REQUEST_MEDIA_TYPE)
            .body(Body::from(enc))
            .unwrap()
    }

    /// Send `inner` through the gateway with the Mozilla `ohttp` client using key
    /// configuration `key`. Returns the inner status, content type and body.
    pub(crate) async fn via_gateway(
        s: &AppState,
        key: &mut ohttp::KeyConfig,
        inner: &Inner<'_>,
    ) -> (u16, Option<String>, Vec<u8>) {
        let client = ohttp::ClientRequest::from_config(key).unwrap();
        let (enc, pending) = client.encapsulate(&inner.encode()).unwrap();
        let (st, h, body) = call(s, outer(enc)).await;
        assert_eq!(st, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        assert_eq!(h["content-type"], RESPONSE_MEDIA_TYPE);
        assert_eq!(h["cache-control"], "no-store");
        let plain = pending.decapsulate(&body).unwrap();
        let msg = bhttp::Message::read_bhttp(&mut std::io::Cursor::new(&plain[..])).unwrap();
        let status = msg.control().status().unwrap().code();
        let ct = msg
            .header()
            .get(b"content-type")
            .map(|v| String::from_utf8(v.to_vec()).unwrap());
        (status, ct, msg.content().to_vec())
    }

    #[tokio::test]
    async fn key_configuration_and_info() {
        let s = test_state(keyed_config(&[(2, 0xb2), (1, 0xb1)]));
        let configs = key_configs(&s).await;
        assert_eq!(configs.len(), 2, "current and previous key during rotation");
        let (_, _, body) = call(&s, Request::get(GATEWAY_PATH).body(Body::empty()).unwrap()).await;
        assert_eq!(body, s.ohttp().unwrap().key_configs(), "RFC 9540 discovery");
        // Encoding: [len(2)][key_id=2][kem 0x0020][pk 32][suites len 8][AES-128-GCM][ChaCha].
        let list = s.ohttp().unwrap().key_configs();
        assert_eq!(&list[..5], &[0, 45, 2, 0, 0x20]);
        assert_eq!(&list[37..47], &[0, 8, 0, 1, 0, 1, 0, 1, 0, 3]);
        let (_, _, info) = call(&s, Request::get("/v1/info").body(Body::empty()).unwrap()).await;
        assert_eq!(
            serde_json::from_slice::<Value>(&info).unwrap()["ohttp"],
            true
        );

        // Keys are derived deterministically: every node with the same secret serves the
        // same configuration.
        let again = test_state(keyed_config(&[(2, 0xb2), (1, 0xb1)]));
        assert_eq!(again.ohttp().unwrap().key_configs(), list);

        let off = test_state(Config {
            ohttp: OhttpMode::Disabled,
            ..open_config()
        });
        let (_, _, info) = call(&off, Request::get("/v1/info").body(Body::empty()).unwrap()).await;
        assert_eq!(
            serde_json::from_slice::<Value>(&info).unwrap()["ohttp"],
            false
        );
        for req in [
            Request::get(KEYS_PATH).body(Body::empty()).unwrap(),
            outer(vec![1; 100]),
        ] {
            let (st, _, body) = call(&off, req).await;
            assert_eq!(
                (st, body.as_slice()),
                (
                    StatusCode::NOT_FOUND,
                    br#"{"error":"not_found"}"#.as_slice()
                )
            );
        }
    }

    #[tokio::test]
    async fn every_endpoint_works_through_the_gateway_with_both_keys() {
        let s = test_state(keyed_config(&[(2, 0xb2), (1, 0xb1)]));
        let mut configs = key_configs(&s).await;
        for key in &mut configs {
            let (st, _, body) = via_gateway(&s, key, &Inner::new("GET", "/v1/info")).await;
            assert_eq!(st, 200);
            let info: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(info["ohttp"], true);
            assert_eq!(info["max_wait_ohttp_s"], 0);
        }
        let key = &mut configs[0];
        let (r, w) = (Token::from_bytes([7; 32]), Token::from_bytes([8; 32]));
        let (st, _, body) = via_gateway(
            &s,
            key,
            &Inner::new("POST", "/v1/mailboxes").json(&json!({
                "read_token_hash": b64::encode(&r.hash()),
                "write_token_hash": b64::encode(&w.hash()),
            })),
        )
        .await;
        assert_eq!(st, 201);
        let id = serde_json::from_slice::<Value>(&body).unwrap()["mailbox_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let base = format!("/v1/mailboxes/{id}");
        let msgs = format!("{base}/messages");
        let (st, _, _) = via_gateway(
            &s,
            key,
            &Inner::new("POST", &msgs)
                .token(&w)
                .json(&json!({ "env": envelope() })),
        )
        .await;
        assert_eq!(st, 202);
        let (st, ct, body) = via_gateway(&s, key, &Inner::new("GET", &msgs).token(&r)).await;
        assert_eq!((st, ct.as_deref()), (200, Some("application/json")));
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["messages"][0]["env"], envelope().as_str());
        let msg_id = v["messages"][0]["msg_id"].clone();
        let (st, _, _) = via_gateway(
            &s,
            key,
            &Inner::new("POST", &format!("{base}/ack"))
                .token(&r)
                .json(&json!({ "msg_ids": [msg_id] })),
        )
        .await;
        assert_eq!(st, 204);
        let (st, _, _) = via_gateway(
            &s,
            key,
            &Inner::new("PUT", &format!("{base}/push"))
                .token(&r)
                .json(&json!({ "push_reg": null })),
        )
        .await;
        assert_eq!(st, 204);
        let (st, _, _) = via_gateway(&s, key, &Inner::new("POST", "/v1/challenge")).await;
        assert_eq!(st, 200);
        // Key configuration is reachable through the gateway (rotation without exposing
        // the client address).
        let (st, ct, body) = via_gateway(&s, key, &Inner::new("GET", KEYS_PATH)).await;
        assert_eq!((st, ct.as_deref()), (200, Some(KEYS_MEDIA_TYPE)));
        assert_eq!(body, s.ohttp().unwrap().key_configs());
        let (st, _, _) = via_gateway(&s, key, &Inner::new("DELETE", &base).token(&r)).await;
        assert_eq!(st, 204);
        let (st, _, _) = via_gateway(&s, key, &Inner::new("GET", &msgs).token(&r)).await;
        assert_eq!(st, 404);
    }

    #[tokio::test]
    async fn same_auth_size_and_rate_rules_as_direct_requests() {
        let s = test_state(Config {
            write_rate: 60,
            ..keyed_config(&[(1, 0xb1)])
        });
        let mut key = key_configs(&s).await.remove(0);
        let (id, r, w) = create(&s).await;
        let msgs = format!("/v1/mailboxes/{id}/messages");

        // Wrong token: byte-identical not_found inside the encapsulation.
        let (st, ct, body) = via_gateway(&s, &mut key, &Inner::new("GET", &msgs).token(&w)).await;
        assert_eq!(
            (st, ct.as_deref(), body.as_slice()),
            (
                404,
                Some("application/json"),
                br#"{"error":"not_found"}"#.as_slice()
            )
        );
        let (st, _, _) = via_gateway(&s, &mut key, &Inner::new("GET", &msgs)).await;
        assert_eq!(st, 404, "no token");

        // Same 400 KiB body limit.
        let huge = json!({ "env": "A".repeat(crate::MAX_BODY_BYTES) });
        let (st, _, body) = via_gateway(
            &s,
            &mut key,
            &Inner::new("POST", &msgs).token(&w).json(&huge),
        )
        .await;
        assert_eq!(
            (st, body.as_slice()),
            (413, br#"{"error":"too_large"}"#.as_slice())
        );

        // Same rate limits, shared with direct requests on the same token.
        let mut limited = None;
        for _ in 0..30 {
            let inner = Inner::new("POST", &msgs)
                .token(&w)
                .json(&json!({ "env": envelope() }));
            let client = ohttp::ClientRequest::from_config(&mut key).unwrap();
            let (enc, pending) = client.encapsulate(&inner.encode()).unwrap();
            let (_, _, body) = call(&s, outer(enc)).await;
            let plain = pending.decapsulate(&body).unwrap();
            let msg = bhttp::Message::read_bhttp(&mut std::io::Cursor::new(&plain[..])).unwrap();
            if msg.control().status().unwrap().code() == 429 {
                limited = Some(msg.header().get(b"retry-after").map(<[u8]>::to_vec));
                break;
            }
        }
        assert!(
            limited.expect("rate limited through OHTTP").is_some(),
            "Retry-After kept"
        );

        // Operator and gateway routes are not reachable from inside.
        for path in ["/metrics", GATEWAY_PATH] {
            let (st, _, _) = via_gateway(&s, &mut key, &Inner::new("GET", path)).await;
            assert_eq!(st, 404, "{path}");
        }
        // Absolute-form targets are refused.
        let (st, _, body) = via_gateway(
            &s,
            &mut key,
            &Inner::new("GET", "https://elsewhere.example/v1/info"),
        )
        .await;
        assert_eq!(
            (st, body.as_slice()),
            (400, br#"{"error":"bad_request"}"#.as_slice())
        );
        let _ = r;
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
        let (st, _, body) = via_gateway(
            &s,
            &mut key,
            &Inner::new("GET", &format!("/v1/mailboxes/{id}/messages?wait=20")).token(&r),
        )
        .await;
        assert_eq!(st, 200);
        assert_eq!(body, br#"{"messages":[]}"#);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "not held open"
        );
        assert_eq!(s.max_wait(false), 25);
        assert_eq!(s.max_wait(true), 0);
    }

    #[tokio::test]
    async fn key_errors_replays_and_malformed_requests() {
        let s = test_state(keyed_config(&[(1, 0xb1)]));
        let mut key = key_configs(&s).await.remove(0);

        // A configuration the gateway does not have (rotated away): RFC 9458 problem.
        let stale = test_state(keyed_config(&[(9, 0xc9)]));
        let mut stale_key = key_configs(&stale).await.remove(0);
        let client = ohttp::ClientRequest::from_config(&mut stale_key).unwrap();
        let (enc, _) = client
            .encapsulate(&Inner::new("GET", "/v1/info").encode())
            .unwrap();
        let (st, h, body) = call(&s, outer(enc)).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        assert_eq!(h["content-type"], "application/problem+json");
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["type"], KEY_PROBLEM_TYPE);
        // Same key id, different key: also a key problem.
        let same_id = test_state(keyed_config(&[(1, 0xee)]));
        let mut wrong = key_configs(&same_id).await.remove(0);
        let (enc, _) = ohttp::ClientRequest::from_config(&mut wrong)
            .unwrap()
            .encapsulate(b"x")
            .unwrap();
        assert_eq!(
            call(&s, outer(enc)).await.1["content-type"],
            "application/problem+json"
        );

        // Replay of an accepted encapsulated request is refused.
        let client = ohttp::ClientRequest::from_config(&mut key).unwrap();
        let (enc, _) = client
            .encapsulate(&Inner::new("GET", "/v1/info").encode())
            .unwrap();
        assert_eq!(call(&s, outer(enc.clone())).await.0, StatusCode::OK);
        let (st, _, body) = call(&s, outer(enc.clone())).await;
        assert_eq!(
            (st, body.as_slice()),
            (
                StatusCode::BAD_REQUEST,
                br#"{"error":"bad_request"}"#.as_slice()
            )
        );

        // Wrong media type, truncated body, oversized body.
        let req = Request::post(GATEWAY_PATH)
            .header("content-type", "application/json")
            .body(Body::from(enc))
            .unwrap();
        assert_eq!(call(&s, req).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(
            call(&s, outer(vec![1, 0, 0x20])).await.0,
            StatusCode::BAD_REQUEST
        );
        let (st, _, body) = call(&s, outer(vec![1; MAX_ENCAPSULATED_BYTES + 1])).await;
        assert_eq!(
            (st, body.as_slice()),
            (
                StatusCode::PAYLOAD_TOO_LARGE,
                br#"{"error":"too_large"}"#.as_slice()
            )
        );

        // Garbage binary HTTP inside a valid encapsulation gets an encapsulated 400.
        let client = ohttp::ClientRequest::from_config(&mut key).unwrap();
        let (enc, pending) = client.encapsulate(&[0xff, 0xff]).unwrap();
        let (st, _, body) = call(&s, outer(enc)).await;
        assert_eq!(st, StatusCode::OK);
        let plain = pending.decapsulate(&body).unwrap();
        let msg = bhttp::Message::read_bhttp(&mut std::io::Cursor::new(&plain[..])).unwrap();
        assert_eq!(msg.control().status().unwrap().code(), 400);
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
        for bad in [
            "",
            "x",
            "1:AAAA",
            &format!("1:{seed},1:{seed}"),
            &format!("256:{seed}"),
        ] {
            assert!(parse_keys(bad).is_err(), "{bad}");
        }
        let many: Vec<String> = (0..=MAX_KEYS).map(|i| format!("{i}:{seed}")).collect();
        assert!(parse_keys(&many.join(",")).is_err());
    }

    #[test]
    fn configuration_from_environment() {
        let seed = b64::encode(&[4; 32]);
        let get = |vars: Vec<(&'static str, String)>| {
            Config::from_lookup(move |k| vars.iter().find(|(n, _)| *n == k).map(|(_, v)| v.clone()))
        };
        // No keys: a startup error, never a silent per-process key.
        let err = get(vec![]).unwrap_err();
        assert!(err.contains("XCHONNECT_OHTTP_KEYS is required"), "{err}");
        assert!(get(vec![("XCHONNECT_OHTTP_KEYS", String::new())]).is_err());
        assert!(matches!(
            get(vec![("XCHONNECT_OHTTP", "ephemeral".into())])
                .unwrap()
                .ohttp,
            OhttpMode::Ephemeral
        ));
        assert!(get(vec![("XCHONNECT_OHTTP", "maybe".into())]).is_err());
        assert!(matches!(
            get(vec![("XCHONNECT_OHTTP", "false".into())])
                .unwrap()
                .ohttp,
            OhttpMode::Disabled
        ));
        let c = get(vec![("XCHONNECT_OHTTP_KEYS", format!("5:{seed}"))]).unwrap();
        assert!(matches!(&c.ohttp, OhttpMode::Keys(k) if k.len() == 1 && k[0].id == 5));
        assert!(get(vec![("XCHONNECT_OHTTP_KEYS", "5:short".into())]).is_err());

        let dir = std::env::temp_dir().join(format!("xchonnect-ohttp-{}", std::process::id()));
        std::fs::write(&dir, format!("7:{seed}\n6:{seed}\n")).unwrap();
        let c = get(vec![
            ("XCHONNECT_OHTTP_KEYS_FILE", dir.display().to_string()),
            ("XCHONNECT_OHTTP_KEYS", format!("5:{seed}")),
        ])
        .unwrap();
        std::fs::remove_file(&dir).unwrap();
        assert!(matches!(&c.ohttp, OhttpMode::Keys(k) if k.len() == 2 && k[0].id == 7));
        assert!(get(vec![("XCHONNECT_OHTTP_KEYS_FILE", "/nonexistent/x".into())]).is_err());
    }

    /// Send a request with the core OHTTP client (TASK-52). `Err` carries the outer
    /// status and content type when the gateway refused the encapsulation.
    async fn core_call(
        s: &AppState,
        client: &xchonnect_core::ohttp::Client,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<xchonnect_core::ohttp::Response, (StatusCode, String)> {
        let req = xchonnect_core::ohttp::Request {
            method,
            scheme: "https",
            authority: "relay.example",
            path,
            headers,
            body,
        };
        let (enc, ctx) = client
            .encapsulate(&mut xchonnect_core::crypto::OsEntropy, &req)
            .unwrap();
        let (st, h, out) = call(s, outer(enc)).await;
        if st != StatusCode::OK {
            let ct = h
                .get("content-type")
                .map(|v| v.to_str().unwrap().to_owned())
                .unwrap_or_default();
            return Err((st, ct));
        }
        Ok(ctx.decapsulate(&out).unwrap())
    }

    #[tokio::test]
    async fn core_client_round_trip_and_rotation() {
        use xchonnect_core::ohttp::{self as core_ohttp, Client};
        // Before rotation the relay has key 1; the app ships that configuration pinned.
        let before = test_state(keyed_config(&[(1, 0xb1)]));
        let shipped = before.ohttp().unwrap().key_configs().to_vec();
        let pinned = core_ohttp::select(&shipped).unwrap();

        // The operator rotates: key 2 is new, key 1 stays during the overlap.
        let s = test_state(keyed_config(&[(2, 0xb2), (1, 0xb1)]));
        let client = Client::new(pinned.clone());
        let (r, w) = (Token::from_bytes([3; 32]), Token::from_bytes([4; 32]));
        let create = json!({ "read_token_hash": b64::encode(&r.hash()), "write_token_hash": b64::encode(&w.hash()) }).to_string();
        let jh = vec![("content-type".to_owned(), "application/json".to_owned())];
        let res = core_call(&s, &client, "POST", "/v1/mailboxes", &jh, create.as_bytes())
            .await
            .unwrap();
        assert_eq!(res.status, 201);
        let id = serde_json::from_slice::<Value>(&res.body).unwrap()["mailbox_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let auth = |t: &Token| {
            vec![
                (
                    "authorization".to_owned(),
                    format!("Bearer {}", b64::encode(t.expose())),
                ),
                ("content-type".to_owned(), "application/json".to_owned()),
            ]
        };
        let msgs = format!("/v1/mailboxes/{id}/messages");
        let post = json!({ "env": envelope() }).to_string();
        let res = core_call(&s, &client, "POST", &msgs, &auth(&w), post.as_bytes())
            .await
            .unwrap();
        assert_eq!(res.status, 202);

        // Learn the rotation through the gateway, authenticated by the pinned key.
        let res = core_call(&s, &client, "GET", KEYS_PATH, &[], &[])
            .await
            .unwrap();
        assert_eq!(res.header("content-type"), Some(KEYS_MEDIA_TYPE));
        let next = rotate_via(&s, &client).await;
        assert_eq!(next.key_id(), 2);
        let client = Client::new(next.clone());
        let res = core_call(
            &s,
            &client,
            "GET",
            &format!("{msgs}?wait=30"),
            &auth(&r),
            &[],
        )
        .await
        .unwrap();
        assert_eq!(res.status, 200);
        let v: Value = serde_json::from_slice(&res.body).unwrap();
        assert_eq!(v["messages"][0]["env"], envelope().as_str());

        // Overlap over: key 1 removed. The new pin keeps working; the old pin gets the
        // RFC 9458 key problem, and its rotation check is a hard error.
        let after = test_state(keyed_config(&[(3, 0xb3), (2, 0xb2)]));
        let res = core_call(&after, &client, "GET", "/v1/info", &[], &[])
            .await
            .unwrap();
        assert_eq!(res.status, 200);
        let stale = Client::new(pinned.clone());
        let err = core_call(&after, &stale, "GET", "/v1/info", &[], &[])
            .await
            .unwrap_err();
        assert_eq!(
            err,
            (
                StatusCode::BAD_REQUEST,
                "application/problem+json".to_owned()
            )
        );
        assert_eq!(rotate_via(&after, &client).await.key_id(), 3);
    }

    /// Rotation through the gateway with the core client's authenticated path.
    async fn rotate_via(
        s: &AppState,
        client: &xchonnect_core::ohttp::Client,
    ) -> xchonnect_core::ohttp::KeyConfig {
        let req = xchonnect_core::ohttp::Request {
            method: "GET",
            scheme: "https",
            authority: "relay.example",
            path: KEYS_PATH,
            headers: &[],
            body: &[],
        };
        let (enc, ctx) = client
            .encapsulate(&mut xchonnect_core::crypto::OsEntropy, &req)
            .unwrap();
        let (st, _, out) = call(s, outer(enc)).await;
        assert_eq!(st, StatusCode::OK);
        ctx.decapsulate_key_rotation(&out).unwrap()
    }
}
