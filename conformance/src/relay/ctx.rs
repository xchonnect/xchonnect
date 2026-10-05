//! Shared state and helpers for checks: mailbox creation with automatic method
//! discovery, posting with rate-limit pacing, error assertions.

use super::Options;
use super::envelope;
use crate::http::{Client, Req, Resp};
pub(crate) use crate::report::{CheckRes, Fail, ensure, skip};
use serde_json::{Map, Value, json};
use std::time::{Duration, Instant};
use xchonnect_core::b64;
use xchonnect_core::crypto::{self, OsEntropy, Token};

/// Longest `Retry-After` the suite is willing to sleep for when pacing requests.
const MAX_PACING_SLEEP_S: u64 = 15;
/// Total pacing budget per call.
const PACING_BUDGET: Duration = Duration::from_secs(60);

/// A mailbox created for a check.
pub(crate) struct Mailbox {
    pub(crate) id: String,
    pub(crate) read: Token,
    pub(crate) write: Token,
}

impl std::fmt::Debug for Mailbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Mailbox([redacted])")
    }
}

impl Mailbox {
    pub(crate) fn path(&self, suffix: &str) -> String {
        format!("/v1/mailboxes/{}{suffix}", self.id)
    }
}

/// Fresh random read and write tokens.
pub(crate) fn tokens() -> (Token, Token) {
    (Token::random(&mut OsEntropy), Token::random(&mut OsEntropy))
}

/// Random base64url value of `N` bytes.
pub(crate) fn random_b64<const N: usize>() -> String {
    b64::encode(&crypto::random_array::<N>(&mut OsEntropy))
}

/// `POST <path>` with the body `{}`.
pub(crate) fn post_empty(path: &str) -> Req {
    Req::new("POST", path).raw_json(b"{}".to_vec())
}

/// Mailbox creation method used for a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Method {
    Open,
    Pow,
    Ticket,
    ApiKey,
}

/// Suite context.
#[derive(Debug)]
pub(crate) struct Ctx {
    pub(crate) client: Client,
    /// `GET /v1/info` body (`Null` if unusable).
    pub(crate) info: Value,
    pub(crate) api_key: Option<String>,
}

impl Ctx {
    pub(crate) fn new(opts: &Options) -> Self {
        let client = Client::new(&opts.base_url);
        let info = client
            .send(&Req::new("GET", "/v1/info"))
            .ok()
            .filter(|r| r.status == 200)
            .map(|r| r.json())
            .filter(Value::is_object)
            .unwrap_or(Value::Null);
        let api_key = opts.api_key.clone();
        Ctx {
            client,
            info,
            api_key,
        }
    }

    // ---- /v1/info accessors -------------------------------------------------

    pub(crate) fn info_u64(&self, key: &str) -> Option<u64> {
        self.info.get(key).and_then(Value::as_u64)
    }

    pub(crate) fn offers(&self, method: &str) -> bool {
        self.info
            .get("mailbox_creation")
            .and_then(Value::as_array)
            .is_some_and(|a| a.iter().any(|m| m.as_str() == Some(method)))
    }

    pub(crate) fn pow_usable(&self) -> bool {
        let max = u64::from(xchonnect_core::pow::MAX_CLIENT_DIFFICULTY);
        self.offers("pow") && self.info_u64("pow_difficulty").is_some_and(|d| d <= max)
    }

    pub(crate) fn max_wait_s(&self) -> u64 {
        self.info_u64("max_wait_s").unwrap_or(0)
    }

    pub(crate) fn max_envelope_bytes(&self) -> usize {
        self.info_u64("max_envelope_bytes")
            .and_then(|v| usize::try_from(v).ok())
            .unwrap_or(xchonnect_core::envelope::MAX_ENVELOPE_BYTES)
    }

    pub(crate) fn gateway_allowlist(&self) -> Option<Vec<String>> {
        if self.info.get("gateway_policy").and_then(Value::as_str) != Some("allowlist") {
            return None;
        }
        let list = self.info.get("gateway_allowlist").and_then(Value::as_array);
        Some(
            list.into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
        )
    }

    pub(crate) fn api_key(&self) -> Result<&str, Fail> {
        self.api_key
            .as_deref()
            .ok_or_else(|| Fail::Skip("needs --api-key".into()))
    }

    // ---- HTTP ---------------------------------------------------------------

    /// Send once, no pacing.
    pub(crate) fn send(&self, req: &Req) -> Result<Resp, Fail> {
        Ok(self.client.send(req)?)
    }

    /// Run `attempt`, sleeping and retrying on `429` with a short `Retry-After` so that
    /// checks are not confused by the relay's rate limits.
    fn paced(&self, attempt: &dyn Fn() -> Result<Resp, Fail>) -> Result<Resp, Fail> {
        let started = Instant::now();
        loop {
            let r = attempt()?;
            match pacing_delay(&r) {
                Some(d) if started.elapsed() + d < PACING_BUDGET => std::thread::sleep(d),
                _ => return Ok(r),
            }
        }
    }

    /// Send with rate-limit pacing.
    pub(crate) fn call(&self, req: &Req) -> Result<Resp, Fail> {
        self.paced(&|| self.send(req))
    }

    // ---- Mailbox creation ---------------------------------------------------

    /// The method the suite uses by default: open, then pow, then ticket / API key
    /// (when `--api-key` is given).
    pub(crate) fn default_method(&self) -> Result<Method, Fail> {
        let key = self.api_key.is_some();
        if self.offers("open") {
            Ok(Method::Open)
        } else if self.pow_usable() {
            Ok(Method::Pow)
        } else if key && self.offers("ticket") {
            Ok(Method::Ticket)
        } else if key && self.offers("api_key") {
            Ok(Method::ApiKey)
        } else {
            Err(Fail::Skip(
                "no usable mailbox creation method (relay offers neither open nor pow with \
                 difficulty <= 26; pass --api-key for api_key/ticket relays)"
                    .to_owned(),
            ))
        }
    }

    /// Fresh proof-of-work solution as a JSON object.
    pub(crate) fn solve_pow(&self) -> Result<Value, Fail> {
        let r = self.call(&post_empty("/v1/challenge"))?;
        expect_status(&r, 200, "POST /v1/challenge")?;
        let c = field(&r.json(), "challenge")
            .as_str()
            .and_then(|c| b64::decode(c).ok())
            .ok_or_else(|| "POST /v1/challenge: no base64url challenge".to_owned())?;
        let nonce =
            xchonnect_core::pow::solve(&c).map_err(|e| format!("cannot solve challenge: {e:?}"))?;
        Ok(json!({ "challenge": b64::encode(&c), "nonce": b64::encode(&nonce) }))
    }

    /// Fresh sponsorship ticket (needs `--api-key`).
    pub(crate) fn ticket(&self) -> Result<String, Fail> {
        let key = self.api_key()?;
        let r = self.call(&post_empty("/v1/tickets").header("xchonnect-api-key", key))?;
        expect_status(&r, 200, "POST /v1/tickets")?;
        let ticket = field(&r.json(), "ticket").as_str().map(str::to_owned);
        ticket.ok_or_else(|| Fail::Fail("POST /v1/tickets: no ticket in response".into()))
    }

    /// Build a creation request from `body` (any JSON object), adding the proof for
    /// `method`.
    pub(crate) fn creation_req(
        &self,
        mut body: Map<String, Value>,
        method: Method,
    ) -> Result<Req, Fail> {
        let mut req = Req::new("POST", "/v1/mailboxes");
        match method {
            Method::Open => {}
            Method::Pow => {
                body.insert("pow".into(), self.solve_pow()?);
            }
            Method::Ticket => {
                body.insert("ticket".into(), self.ticket()?.into());
            }
            Method::ApiKey => req = req.header("xchonnect-api-key", self.api_key()?),
        }
        Ok(req.json(&Value::Object(body)))
    }

    /// Body with token hashes plus `extra` fields.
    pub(crate) fn hashes_body(read: &Token, write: &Token, extra: &Value) -> Map<String, Value> {
        let mut body = Map::new();
        body.insert("read_token_hash".into(), b64::encode(&read.hash()).into());
        body.insert("write_token_hash".into(), b64::encode(&write.hash()).into());
        for (k, v) in extra.as_object().into_iter().flatten() {
            body.insert(k.clone(), v.clone());
        }
        body
    }

    /// Send a creation request built by `build`, rebuilding it (fresh proof) when the
    /// relay asks to retry later.
    pub(crate) fn create_raw_with(
        &self,
        build: &dyn Fn() -> Result<Req, Fail>,
    ) -> Result<Resp, Fail> {
        self.paced(&|| self.send(&build()?))
    }

    /// Create a mailbox with fresh tokens and `extra` body fields via `method`; returns
    /// the raw response and the tokens.
    pub(crate) fn create_raw(
        &self,
        extra: &Value,
        method: Method,
    ) -> Result<(Resp, Token, Token), Fail> {
        let (read, write) = tokens();
        let r = self.create_raw_with(&|| {
            self.creation_req(Self::hashes_body(&read, &write, extra), method)
        })?;
        Ok((r, read, write))
    }

    /// Create a mailbox with the default method; any outcome but `201` fails the check.
    pub(crate) fn mailbox(&self) -> Result<Mailbox, Fail> {
        self.mailbox_with(&Value::Null, self.default_method()?)
    }

    pub(crate) fn mailbox_with(&self, extra: &Value, method: Method) -> Result<Mailbox, Fail> {
        let (r, read, write) = self.create_raw(extra, method)?;
        let id = created_id(&r)?;
        Ok(Mailbox { id, read, write })
    }

    // ---- Messages -----------------------------------------------------------

    pub(crate) fn post_req(mb: &Mailbox, env: &[u8], ttl_s: Option<u64>) -> Req {
        let mut body = json!({ "env": b64::encode(env) });
        if let (Some(t), Some(o)) = (ttl_s, body.as_object_mut()) {
            o.insert("ttl_s".into(), t.into());
        }
        Req::new("POST", mb.path("/messages"))
            .bearer(mb.write.expose())
            .json(&body)
    }

    /// Post an envelope (paced).
    pub(crate) fn post(&self, mb: &Mailbox, env: &[u8], ttl_s: Option<u64>) -> Result<Resp, Fail> {
        self.call(&Self::post_req(mb, env, ttl_s))
    }

    /// Post an envelope; anything but `202` with a 16-byte `msg_id` fails the check.
    pub(crate) fn post_ok(&self, mb: &Mailbox, env: &[u8]) -> Result<String, Fail> {
        accepted_id(&self.post(mb, env, None)?)
    }

    /// Post the `i`-th distinguishable session envelope.
    pub(crate) fn post_nth(&self, mb: &Mailbox, i: usize) -> Result<String, Fail> {
        self.post_ok(mb, &envelope::session_nth(i))
    }

    /// Post the first `n` distinguishable session envelopes; returns their ids.
    pub(crate) fn post_n(&self, mb: &Mailbox, n: usize) -> Result<Vec<String>, Fail> {
        (0..n).map(|i| self.post_nth(mb, i)).collect()
    }

    /// Fetch messages (`query` without leading `?`); returns `(msg_id, env)` pairs.
    pub(crate) fn fetch(&self, mb: &Mailbox, query: &str) -> Result<Vec<(String, String)>, Fail> {
        let r = self.fetch_raw(mb, query)?;
        expect_status(&r, 200, &format!("GET messages?{query}"))?;
        parse_messages(&r)
    }

    pub(crate) fn fetch_raw(&self, mb: &Mailbox, query: &str) -> Result<Resp, Fail> {
        let path = if query.is_empty() {
            mb.path("/messages")
        } else {
            format!("{}?{query}", mb.path("/messages"))
        };
        self.call(&Req::new("GET", path).bearer(mb.read.expose()))
    }

    pub(crate) fn ack(&self, mb: &Mailbox, ids: &[String]) -> Result<Resp, Fail> {
        let req = Req::new("POST", mb.path("/ack")).bearer(mb.read.expose());
        self.call(&req.json(&json!({ "msg_ids": ids })))
    }

    pub(crate) fn ack_ok(&self, mb: &Mailbox, ids: &[String]) -> Result<(), Fail> {
        for chunk in ids.chunks(256) {
            expect_status(&self.ack(mb, chunk)?, 204, "ack")?;
        }
        Ok(())
    }
}

/// Sleep requested by a `429` response, if it is short enough to wait for.
fn pacing_delay(r: &Resp) -> Option<Duration> {
    if r.status != 429 {
        return None;
    }
    let s: u64 = r.header("retry-after")?.trim().parse().ok()?;
    (s <= MAX_PACING_SLEEP_S).then(|| Duration::from_secs(s.max(1)))
}

/// The base64url string `key` of a `status` response, which must decode to 16 bytes.
fn id16(r: &Resp, status: u16, what: &str, key: &str) -> Result<String, Fail> {
    expect_status(r, status, what)?;
    let id = field(&r.json(), key).as_str().map(str::to_owned);
    let id = id.ok_or_else(|| format!("{status} without {key}: {}", r.body_text()))?;
    ensure!(
        b64::decode(&id).is_ok_and(|b| b.len() == 16),
        "{key} {id:?} is not base64url of 16 bytes"
    );
    Ok(id)
}

/// Mailbox id from a `201` creation response.
pub(crate) fn created_id(r: &Resp) -> Result<String, Fail> {
    id16(r, 201, "POST /v1/mailboxes", "mailbox_id")
}

/// Message id from a `202` post response.
pub(crate) fn accepted_id(r: &Resp) -> Result<String, Fail> {
    id16(r, 202, "POST messages", "msg_id")
}

/// `(msg_id, env)` pairs of a fetch response.
pub(crate) fn parse_messages(r: &Resp) -> Result<Vec<(String, String)>, Fail> {
    let v = r.json();
    let arr = field(&v, "messages")
        .as_array()
        .ok_or_else(|| format!("fetch: no messages array: {}", r.body_text()))?;
    arr.iter()
        .map(
            |m| match (field(m, "msg_id").as_str(), field(m, "env").as_str()) {
                (Some(i), Some(e)) => Ok((i.to_owned(), e.to_owned())),
                _ => Err(Fail::Fail(format!("fetch: malformed message entry {m}"))),
            },
        )
        .collect()
}

/// `v[key]`, or `Null` when `v` is not an object or lacks `key`.
pub(crate) fn field<'a>(v: &'a Value, key: &str) -> &'a Value {
    static NULL: Value = Value::Null;
    v.get(key).unwrap_or(&NULL)
}

/// Assert the response status.
pub(crate) fn expect_status(r: &Resp, status: u16, what: &str) -> Result<(), Fail> {
    ensure!(
        r.status == status,
        "{what}: expected {status}, got {}",
        r.describe()
    );
    Ok(())
}

/// An expected error answer: status and `error` code (relay-api.md §Errors).
pub(crate) type Expected = (u16, &'static str);
pub(crate) const BAD_REQUEST: Expected = (400, "bad_request");
pub(crate) const API_KEY_INVALID: Expected = (403, "api_key_invalid");
pub(crate) const AUTH_REQUIRED: Expected = (403, "auth_required");
pub(crate) const GATEWAY_NOT_ALLOWED: Expected = (403, "gateway_not_allowed");
pub(crate) const POW_INVALID: Expected = (403, "pow_invalid");
pub(crate) const TICKET_INVALID: Expected = (403, "ticket_invalid");
pub(crate) const NOT_FOUND: Expected = (404, "not_found");
pub(crate) const METHOD_NOT_ALLOWED: Expected = (405, "method_not_allowed");
pub(crate) const MAILBOX_FULL: Expected = (409, "mailbox_full");
pub(crate) const TOO_LARGE: Expected = (413, "too_large");
pub(crate) const RATE_LIMITED: Expected = (429, "rate_limited");
pub(crate) const UNAVAILABLE: Expected = (503, "unavailable");

/// Every code the uniform error model defines, each pinned to one status
/// (relay-api.md §Errors).
pub(crate) const ERROR_MODEL: &[Expected] = &[
    BAD_REQUEST,
    AUTH_REQUIRED,
    POW_INVALID,
    TICKET_INVALID,
    API_KEY_INVALID,
    GATEWAY_NOT_ALLOWED,
    NOT_FOUND,
    METHOD_NOT_ALLOWED,
    MAILBOX_FULL,
    TOO_LARGE,
    RATE_LIMITED,
    UNAVAILABLE,
];

/// Assert a response is *some* error in the uniform model, without saying which:
/// `application/json`, a body of exactly `{"error": "<code>"}` naming a defined code,
/// and the status that code is pinned to.
pub(crate) fn expect_uniform_error(r: &Resp, what: &str) -> Result<(), Fail> {
    ensure!(
        r.status >= 400,
        "{what}: expected an error, got {}",
        r.describe()
    );
    let ct = r.header("content-type");
    ensure!(
        ct.is_some_and(|c| c.starts_with("application/json")),
        "{what}: content-type {ct:?}, body {}",
        r.body_text()
    );
    let code = error_code(r).ok_or_else(|| {
        Fail::Fail(format!(
            "{what}: body is not exactly {{\"error\": code}}: {}",
            r.body_text()
        ))
    })?;
    let (status, _) = *ERROR_MODEL
        .iter()
        .find(|(_, c)| *c == code)
        .ok_or_else(|| Fail::Fail(format!("{what}: undefined error code {code:?}")))?;
    ensure!(
        r.status == status,
        "{what}: {code} is defined for {status}, got {}",
        r.status
    );
    Ok(())
}

/// Assert an error response: status, `{"error": code}` body with no other fields.
pub(crate) fn expect_error(r: &Resp, (status, code): Expected, what: &str) -> Result<(), Fail> {
    ensure!(
        r.status == status && error_code(r).as_deref() == Some(code),
        "{what}: expected {status} {code}, got {}",
        r.describe()
    );
    Ok(())
}

/// The `error` code if the body is exactly `{"error": "<code>"}`.
pub(crate) fn error_code(r: &Resp) -> Option<String> {
    let v = r.json();
    let o = v.as_object().filter(|o| o.len() == 1)?;
    o.get("error").and_then(Value::as_str).map(str::to_owned)
}
