//! The relay's HTTP surface at the request level (spec 7, `docs/spec/wire/relay-api.md`).
//!
//! Drives the real `axum` router returned by `xchonnect_relay::app` with sequences of
//! fuzzer-built requests: routes, methods, path parameters, capability tokens, query
//! strings and bodies are all chosen by the fuzzer. A mailbox is created up front with
//! known tokens, so a request can be aimed at an existing mailbox with the right token,
//! the wrong token, or at a mailbox that does not exist.
//!
//! Invariants beyond "no panic":
//!   * no request produces 500 (an internal error on attacker input is a bug);
//!   * every response carries the privacy headers (`no-store`, `nosniff`, `no-referrer`);
//!   * every error body is exactly `{"error":"<known code>"}`, at the status the spec
//!     pins that code to — the uniform error model, which is also what keeps the relay
//!     from describing mailboxes it knows nothing of. The only exception is the RFC 9458
//!     section 5.3 key-configuration problem document;
//!   * no response body or header echoes a presented capability token (spec 13.5: the
//!     relay keeps hashes, never the tokens).
//!
//! Input: one byte `n` (`n % 6 + 1` requests), then that many frames of
//! `route | method | flags | u16be token len || token | u16be path len || path |
//!  u16be query len || query | u16be body len || body`.
//! `flags` bit 0: use the real mailbox id instead of the frame's path bytes; bit 1: use
//! the real read token; bit 2: use the real write token; bit 3: send the API key header;
//! bit 4: send `content-type: application/json`.
#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::sync::Arc;
use tower::ServiceExt;
use xchonnect_core::{b64, crypto};
use xchonnect_relay::config::{Config, Creation, GatewayPolicy, api_key_hash};
use xchonnect_relay::{AppState, app};

const NOW: u64 = 1_790_000_000;
const READ_TOKEN: [u8; 32] = [0x11; 32];
const WRITE_TOKEN: [u8; 32] = [0x77; 32];
const API_KEY: &str = "fuzz-api-key";

/// Error codes the uniform error model may return, with the status each one is pinned
/// to by the table in `docs/spec/wire/relay-api.md` (`error.rs`).
const ERROR_CODES: &[(&str, u16)] = &[
    ("bad_request", 400),
    ("auth_required", 403),
    ("pow_invalid", 403),
    ("ticket_invalid", 403),
    ("api_key_invalid", 403),
    ("gateway_not_allowed", 403),
    ("not_found", 404),
    ("method_not_allowed", 405),
    ("mailbox_full", 409),
    ("too_large", 413),
    ("rate_limited", 429),
    ("unavailable", 503),
];

const ROUTES: &[&str] = &[
    "/healthz",
    "/readyz",
    "/v1/info",
    "/v1/challenge",
    "/v1/tickets",
    "/v1/mailboxes",
    "/v1/mailboxes/{id}",
    "/v1/mailboxes/{id}/messages",
    "/v1/mailboxes/{id}/ack",
    "/v1/mailboxes/{id}/push",
    "/metrics",
    "/.well-known/ohttp-gateway",
];

const METHODS: &[&str] = &["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"];

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn byte(&mut self) -> Option<u8> {
        let (first, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(*first)
    }

    fn chunk(&mut self) -> Option<&'a [u8]> {
        let hi = self.byte()? as usize;
        let lo = self.byte()? as usize;
        let len = ((hi << 8) | lo).min(self.0.len());
        let (head, rest) = self.0.split_at(len);
        self.0 = rest;
        Some(head)
    }
}

fn config() -> Config {
    Config {
        // Open creation and an API key, so the fuzzer reaches the handlers behind
        // creation without having to solve a proof of work.
        creation: vec![Creation::Open, Creation::ApiKey, Creation::Ticket],
        api_keys: HashMap::from([(api_key_hash(API_KEY), "fuzz".to_string())]),
        // Long polling would stall the fuzzer; 0 makes every fetch return at once.
        max_wait_s: 0,
        max_wait_ohttp_s: 0,
        // Rate limiting is covered by its own unit tests; here it would only mask the
        // handlers behind 429s.
        write_rate: u32::MAX,
        read_rate: u32::MAX,
        customer_rate: u32::MAX,
        create_rate: u32::MAX,
        gateway_policy: GatewayPolicy::Allowlist(Vec::new()),
        metrics: true,
        ..Config::default()
    }
}

fn b64_path_safe(bytes: &[u8]) -> String {
    // A path segment: keep the fuzzer's bytes but make them a legal URI.
    bytes
        .iter()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                char::from(*b).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fuzz_target!(|data: &[u8]| {
    let mut cur = Cursor(data);
    let Some(count) = cur.byte() else { return };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();

    rt.block_on(async {
        let state = AppState::in_memory(config(), Arc::new(|| NOW));
        let router = app(state);
        let mailbox = create_mailbox(&router).await;

        for _ in 0..(count % 6 + 1) {
            let (Some(route), Some(method), Some(flags)) = (cur.byte(), cur.byte(), cur.byte())
            else {
                return;
            };
            let (Some(token), Some(path), Some(query), Some(body)) =
                (cur.chunk(), cur.chunk(), cur.chunk(), cur.chunk())
            else {
                return;
            };

            let template = ROUTES[route as usize % ROUTES.len()];
            let id = if flags & 1 != 0 {
                mailbox.clone()
            } else {
                b64_path_safe(path)
            };
            let mut uri = template.replace("{id}", &id);
            if !query.is_empty() {
                uri.push('?');
                uri.push_str(&b64_path_safe(query));
            }

            let verb = METHODS[method as usize % METHODS.len()];
            let mut req = Request::builder().method(verb).uri(&uri);
            let presented = if flags & 2 != 0 {
                Some(b64::encode(&READ_TOKEN))
            } else if flags & 4 != 0 {
                Some(b64::encode(&WRITE_TOKEN))
            } else if token.is_empty() {
                None
            } else {
                Some(b64::encode(token))
            };
            if let Some(t) = &presented {
                req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
            }
            if flags & 8 != 0 {
                req = req.header("xchonnect-api-key", API_KEY);
            }
            if flags & 16 != 0 {
                req = req.header(header::CONTENT_TYPE, "application/json");
            }
            let Ok(req) = req.body(Body::from(body.to_vec())) else {
                // Only an unbuildable URI lands here; nothing to check.
                continue;
            };

            let res = router.clone().oneshot(req).await.unwrap();
            let status = res.status();
            assert_ne!(
                status,
                StatusCode::INTERNAL_SERVER_ERROR,
                "{uri} produced 500"
            );
            for (name, want) in [
                (header::CACHE_CONTROL, "no-store"),
                (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
                (header::REFERRER_POLICY, "no-referrer"),
            ] {
                assert_eq!(
                    res.headers().get(&name).map(|v| v.as_bytes()),
                    Some(want.as_bytes()),
                    "{uri}: missing {name}"
                );
            }
            let headers = res.headers().clone();
            let bytes = res.into_body().collect().await.unwrap().to_bytes();

            let content_type = headers
                .get(header::CONTENT_TYPE)
                .map(|v| v.as_bytes().to_vec())
                .unwrap_or_default();
            // A HEAD response carries the headers of the GET it mirrors and no body,
            // so there is nothing to check in it.
            // The OHTTP key-configuration mismatch is the one error RFC 9458 section
            // 5.3 fixes as a problem document, so it is outside the uniform model.
            let problem = content_type.starts_with(b"application/problem+json");
            if (status.is_client_error() || status.is_server_error()) && verb != "HEAD" && !problem
            {
                // Every error the relay answers with is the uniform model, the
                // framework's own extractor rejections included (an unmatched path, a
                // method the route does not declare, a path that does not
                // percent-decode to UTF-8) - see F-1 in fuzz/README.md.
                assert!(
                    content_type.starts_with(b"application/json"),
                    "{uri}: error body is {}, not application/json",
                    String::from_utf8_lossy(&content_type)
                );
                let v: serde_json::Value = serde_json::from_slice(&bytes)
                    .unwrap_or_else(|_| panic!("{uri}: JSON error body does not parse"));
                let obj = v.as_object().expect("error body is not an object");
                assert_eq!(obj.len(), 1, "{uri}: error body has extra fields");
                let code = obj["error"].as_str().expect("error code is not a string");
                let want = ERROR_CODES
                    .iter()
                    .find(|(c, _)| *c == code)
                    .unwrap_or_else(|| panic!("{uri}: unknown error code {code}"));
                // Status and code always agree with the spec's table.
                assert_eq!(status.as_u16(), want.1, "{uri}: {status} carries {code}");
            }

            // Spec 13.5: a presented token must not come back, in the body or a header.
            if let Some(t) = presented.filter(|t| t.len() >= 16) {
                assert!(
                    !contains(&bytes, t.as_bytes()),
                    "{uri}: response body echoes the capability token"
                );
                for v in headers.values() {
                    assert!(
                        !contains(v.as_bytes(), t.as_bytes()),
                        "{uri}: response header echoes the capability token"
                    );
                }
            }
        }
    });
});

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Create one mailbox with the known tokens and return its id.
async fn create_mailbox(router: &Router) -> String {
    let body = serde_json::json!({
        "read_token_hash": b64::encode(&crypto::token_hash(&READ_TOKEN)),
        "write_token_hash": b64::encode(&crypto::token_hash(&WRITE_TOKEN)),
    })
    .to_string();
    let req = Request::builder()
        .method("POST")
        .uri("/v1/mailboxes")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["mailbox_id"].as_str().unwrap().to_string()
}
