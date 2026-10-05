//! HTTP routes (`docs/spec/wire/relay-api.md`).

use crate::AppState;
use crate::config::{Creation, GatewayPolicy, api_key_hash};
use crate::creation::{self, MAX_SEALED_TOKEN, TICKET_TTL_S};
use crate::error::ApiError;
use crate::limits;
use crate::store::{self, MailboxRecord, PushReg, QueueLimits, StoredMessage};
use axum::body::Bytes;
use axum::extract::rejection::{BytesRejection, QueryRejection};
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::time::Duration;
use xchonnect_core::b64;
use xchonnect_core::crypto::{self, MailboxId, OsEntropy};
use xchonnect_core::envelope::{Envelope, MAX_ENVELOPE_BYTES};

/// Maximum messages returned per fetch.
pub const MAX_FETCH: usize = 32;
/// Maximum ids per ack.
pub const MAX_ACK: usize = 256;
/// Hash compared against when the mailbox does not exist, so both paths do the same work.
const DUMMY_HASH: [u8; 32] = [0x5a; 32];

type Body = Result<Bytes, BytesRejection>;
type JsonReply = Result<(StatusCode, Json<Value>), ApiError>;

/// All routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(readyz))
        .route("/v1/info", get(info))
        .route("/v1/challenge", post(challenge))
        .route("/v1/tickets", post(ticket))
        .route("/v1/mailboxes", post(create_mailbox))
        .route("/v1/mailboxes/{id}", delete(delete_mailbox))
        .route(
            "/v1/mailboxes/{id}/messages",
            post(post_message).get(get_messages),
        )
        .route("/v1/mailboxes/{id}/ack", post(ack))
        .route("/v1/mailboxes/{id}/push", put(set_push))
}

fn parse_json<T: DeserializeOwned>(body: Body) -> Result<T, ApiError> {
    serde_json::from_slice(&body?).map_err(|_| ApiError::BadRequest)
}

fn ok(status: StatusCode, v: Value) -> JsonReply {
    Ok((status, Json(v)))
}

#[derive(Clone, Copy)]
enum Access {
    Read,
    Write,
}

fn bearer(headers: &HeaderMap) -> Option<[u8; 32]> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    b64::decode_array::<32>(v.strip_prefix("Bearer ")?).ok()
}

/// Authenticate a capability token. Unknown mailbox, malformed id, missing or wrong
/// token all produce the same `NotFound` after the same hashing and comparison work.
async fn authorize(
    s: &AppState,
    id: &str,
    headers: &HeaderMap,
    access: Access,
) -> Result<(MailboxId, MailboxRecord), ApiError> {
    let token = bearer(headers);
    let presented = crypto::token_hash(&token.unwrap_or([0; 32]));
    let mailbox = MailboxId::from_b64(id).ok();
    let rec = match mailbox {
        Some(m) => s.store().get(&m).await?,
        None => None,
    };
    let expected = match (&rec, access) {
        (Some(r), Access::Read) => r.read_hash,
        (Some(r), Access::Write) => r.write_hash,
        (None, _) => DUMMY_HASH,
    };
    let ok = crypto::ct_eq(&presented, &expected) && token.is_some();
    let (true, Some(m), Some(r)) = (ok, mailbox, rec) else {
        return Err(ApiError::NotFound);
    };
    if matches!(access, Access::Read) {
        s.limits().read.check(&r.read_hash, s.now())?;
    }
    let today = store::day(s.now());
    if r.last_used_day < today {
        s.store().touch(&m, today).await?;
    }
    Ok((m, r))
}

fn push_reg_from(s: &AppState, v: Option<&PushRegBody>) -> Result<Option<PushReg>, ApiError> {
    let Some(v) = v else { return Ok(None) };
    creation::check_gateway_url(s.config(), &v.gateway_url)?;
    let sealed = b64::decode(&v.sealed_token).map_err(|_| ApiError::BadRequest)?;
    if sealed.is_empty() || sealed.len() > MAX_SEALED_TOKEN {
        return Err(ApiError::BadRequest);
    }
    Ok(Some(PushReg {
        gateway_url: v.gateway_url.clone(),
        sealed_token: sealed,
    }))
}

/// Customer of the presented API key; a missing or unknown key is `ApiKeyInvalid`.
fn customer_for_key(s: &AppState, headers: &HeaderMap) -> Result<String, ApiError> {
    let key = headers
        .get("xchonnect-api-key")
        .and_then(|v| v.to_str().ok());
    key.and_then(|k| s.config().api_keys.get(&api_key_hash(k)).cloned())
        .ok_or(ApiError::ApiKeyInvalid)
}

async fn readyz(State(s): State<AppState>) -> Result<&'static str, ApiError> {
    s.store().ping().await?;
    Ok("ok")
}

async fn info(State(s): State<AppState>) -> Json<Value> {
    let c = s.config();
    let mut v = json!({
        "protocol": 1,
        "max_wait_s": c.max_wait_s,
        "max_wait_ohttp_s": c.max_wait_ohttp_s,
        "default_ttl_s": c.default_ttl_s,
        "max_ttl_s": c.max_ttl_s,
        "max_envelope_bytes": MAX_ENVELOPE_BYTES,
        "max_messages_per_mailbox": c.max_messages,
        "mailbox_creation": c.creation.iter().map(|m| m.as_str()).collect::<Vec<_>>(),
        "gateway_policy": match c.gateway_policy { GatewayPolicy::Allowlist(_) => "allowlist", GatewayPolicy::Open => "open" },
        "ohttp": s.ohttp().is_some(),
    });
    if let Some(o) = v.as_object_mut() {
        if c.creation.contains(&Creation::Pow) {
            o.insert("pow_difficulty".into(), json!(c.pow_difficulty));
        }
        if let GatewayPolicy::Allowlist(list) = &c.gateway_policy {
            o.insert("gateway_allowlist".into(), json!(list));
        }
    }
    Json(v)
}

async fn challenge(State(s): State<AppState>) -> JsonReply {
    if !s.config().creation.contains(&Creation::Pow) {
        return Err(ApiError::NotFound);
    }
    let c = s.pow().issue(s.now(), s.config().pow_difficulty)?;
    let info = xchonnect_core::pow::parse(&c).map_err(|_| ApiError::Unavailable)?;
    ok(
        StatusCode::OK,
        json!({ "challenge": b64::encode(&c), "difficulty": info.difficulty, "expires_at": info.expires_at }),
    )
}

async fn ticket(State(s): State<AppState>, headers: HeaderMap) -> JsonReply {
    if !s.config().creation.contains(&Creation::Ticket) {
        return Err(ApiError::NotFound);
    }
    let customer = customer_for_key(&s, &headers)?;
    let t: [u8; 32] = crypto::random_array(&mut OsEntropy);
    let expires_at = s.now() + TICKET_TTL_S;
    s.store()
        .put_ticket(creation::ticket_hash(&t), &customer, expires_at)
        .await?;
    ok(
        StatusCode::OK,
        json!({ "ticket": b64::encode(&t), "expires_at": expires_at }),
    )
}

#[derive(Deserialize)]
struct PushRegBody {
    gateway_url: String,
    sealed_token: String,
}

#[derive(Deserialize)]
struct PowBody {
    challenge: String,
    nonce: String,
}

#[derive(Deserialize)]
struct CreateBody {
    read_token_hash: String,
    write_token_hash: String,
    push_reg: Option<PushRegBody>,
    pow: Option<PowBody>,
    ticket: Option<String>,
}

async fn create_mailbox(State(s): State<AppState>, headers: HeaderMap, body: Body) -> JsonReply {
    let b: CreateBody = parse_json(body)?;
    let hash = |h: &str| b64::decode_array::<32>(h).map_err(|_| ApiError::BadRequest);
    let (read_hash, write_hash) = (hash(&b.read_token_hash)?, hash(&b.write_token_hash)?);
    if read_hash == write_hash {
        return Err(ApiError::BadRequest);
    }
    let push = push_reg_from(&s, b.push_reg.as_ref())?;
    let c = s.config();
    let now = s.now();
    // Anonymous creation (proof-of-work or open) shares one global bucket. It is charged
    // only after a proof has been verified and before it is spent, so invalid requests do
    // not drain the bucket and a 429 does not burn a valid proof.
    let charge_global = || s.limits().create.check(&limits::GLOBAL_KEY, now);
    // Precedence: API key, ticket, pow, open (relay-api.md).
    let customer =
        if c.creation.contains(&Creation::ApiKey) && headers.contains_key("xchonnect-api-key") {
            Some(customer_for_key(&s, &headers)?)
        } else if let (true, Some(t)) = (c.creation.contains(&Creation::Ticket), &b.ticket) {
            // Tickets are sponsored by a customer and single-use; not part of the anonymous budget.
            let t = b64::decode_array::<32>(t).map_err(|_| ApiError::TicketInvalid)?;
            let taken = s
                .store()
                .take_ticket(&creation::ticket_hash(&t), now)
                .await?;
            Some(taken.ok_or(ApiError::TicketInvalid)?)
        } else if let (true, Some(p)) = (c.creation.contains(&Creation::Pow), &b.pow) {
            let ch = b64::decode(&p.challenge).map_err(|_| ApiError::PowInvalid)?;
            let nonce = b64::decode(&p.nonce).map_err(|_| ApiError::PowInvalid)?;
            let (spent_key, expires_at) = s.pow().verify(&ch, &nonce, now, c.pow_difficulty)?;
            charge_global()?;
            if !s.store().spend_pow(spent_key, expires_at).await? {
                return Err(ApiError::PowInvalid);
            }
            None
        } else if c.creation.contains(&Creation::Open) {
            charge_global()?;
            None
        } else {
            return Err(ApiError::AuthRequired);
        };
    if let Some(c) = &customer {
        s.limits().usage.mailbox_created(c);
    }
    let today = store::day(now);
    let rec = MailboxRecord {
        read_hash,
        write_hash,
        push,
        customer,
        created_day: today,
        last_used_day: today,
    };
    let id = MailboxId(crypto::random_array(&mut OsEntropy));
    s.store().create(id, rec).await?;
    ok(StatusCode::CREATED, json!({ "mailbox_id": id.to_b64() }))
}

#[derive(Deserialize)]
struct PostBody {
    env: String,
    ttl_s: Option<u64>,
}

async fn post_message(
    State(s): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> JsonReply {
    let (mailbox, rec) = authorize(&s, &id, &headers, Access::Write).await?;
    let now = s.now();
    s.limits().write.check(&rec.write_hash, now)?;
    if let Some(c) = &rec.customer {
        s.limits().customer.check(&limits::customer_key(c), now)?;
    }
    let b: PostBody = parse_json(body)?;
    let env = b64::decode(&b.env).map_err(|_| ApiError::BadRequest)?;
    if env.len() > MAX_ENVELOPE_BYTES {
        return Err(ApiError::TooLarge);
    }
    Envelope::decode(&env).map_err(|_| ApiError::BadRequest)?;
    let c = s.config();
    let ttl = b.ttl_s.unwrap_or(c.default_ttl_s).clamp(60, c.max_ttl_s);
    let msg_id: [u8; 16] = crypto::random_array(&mut OsEntropy);
    let limits = QueueLimits {
        max_messages: c.max_messages,
        max_bytes: c.max_bytes,
    };
    let msg = StoredMessage {
        msg_id,
        envelope: env,
    };
    let now = s.now();
    s.store()
        .enqueue(&mailbox, msg, now, now + ttl, limits)
        .await?;
    if let Some(c) = &rec.customer {
        s.limits().usage.message(c);
    }
    s.on_message_accepted(&mailbox, &rec);
    ok(
        StatusCode::ACCEPTED,
        json!({ "msg_id": b64::encode(&msg_id) }),
    )
}

#[derive(Deserialize)]
struct FetchQuery {
    wait: Option<u64>,
    limit: Option<usize>,
}

async fn get_messages(
    State(s): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    via_ohttp: Option<Extension<crate::ohttp::ViaOhttp>>,
    q: Result<Query<FetchQuery>, QueryRejection>,
) -> JsonReply {
    let (mailbox, _) = authorize(&s, &id, &headers, Access::Read).await?;
    let Query(q) = q.map_err(|_| ApiError::BadRequest)?;
    let wait = q.wait.unwrap_or(0).min(s.max_wait(via_ohttp.is_some()));
    let limit = q.limit.unwrap_or(MAX_FETCH).clamp(1, MAX_FETCH);
    let rx = s.notifier().subscribe(&mailbox);
    let mut msgs = s.store().fetch(&mailbox, limit, s.now()).await?;
    if msgs.is_empty() && wait > 0 {
        store::wait(rx, Duration::from_secs(wait)).await;
        msgs = s.store().fetch(&mailbox, limit, s.now()).await?;
    }
    let out: Vec<Value> = msgs
        .iter()
        .map(|m| json!({ "msg_id": b64::encode(&m.msg_id), "env": b64::encode(&m.envelope) }))
        .collect();
    ok(StatusCode::OK, json!({ "messages": out }))
}

#[derive(Deserialize)]
struct AckBody {
    msg_ids: Vec<String>,
}

async fn ack(
    State(s): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<StatusCode, ApiError> {
    let (mailbox, _) = authorize(&s, &id, &headers, Access::Read).await?;
    let b: AckBody = parse_json(body)?;
    if b.msg_ids.len() > MAX_ACK {
        return Err(ApiError::BadRequest);
    }
    let ids: Vec<[u8; 16]> = b
        .msg_ids
        .iter()
        .filter_map(|m| b64::decode_array::<16>(m).ok())
        .collect();
    s.store().ack(&mailbox, &ids).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct PushBody {
    push_reg: Option<PushRegBody>,
}

async fn set_push(
    State(s): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<StatusCode, ApiError> {
    let (mailbox, _) = authorize(&s, &id, &headers, Access::Read).await?;
    let b: PushBody = parse_json(body)?;
    let push = push_reg_from(&s, b.push_reg.as_ref())?;
    s.store().set_push(&mailbox, push).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_mailbox(
    State(s): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let (mailbox, _) = authorize(&s, &id, &headers, Access::Read).await?;
    s.store().delete(&mailbox).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
pub(crate) mod tests {
    use crate::config::{Creation, GatewayPolicy, api_key_hash};
    use crate::{AppState, Config, app};
    use axum::body::Body;
    use axum::http::{HeaderMap, Request, StatusCode};
    use http_body_util::BodyExt;
    use serde_json::{Value, json};
    use std::sync::Arc;
    use tower::ServiceExt;
    use xchonnect_core::b64;
    use xchonnect_core::crypto::{Token, token_hash};
    use xchonnect_core::envelope::{Envelope, Kind};

    const API_KEY: &str = "pengui-key-0123456789";

    pub(crate) fn open_config() -> Config {
        use Creation::{ApiKey, Open, Pow, Ticket};
        Config {
            creation: vec![Open, Pow, Ticket, ApiKey],
            ..Config::default()
        }
    }

    /// `c` with [`API_KEY`] registered for customer `pengui`.
    fn keyed(mut c: Config) -> Config {
        c.api_keys.insert(api_key_hash(API_KEY), "pengui".into());
        c
    }

    pub(crate) fn test_state(config: Config) -> AppState {
        AppState::in_memory(config, Arc::new(|| 1_790_000_000))
    }

    pub(crate) async fn call(s: &AppState, req: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
        let res = app(s.clone()).oneshot(req).await.unwrap();
        let (status, headers) = (res.status(), res.headers().clone());
        let body = res.into_body().collect().await.unwrap().to_bytes().to_vec();
        (status, headers, body)
    }

    /// Status and body only.
    pub(crate) async fn send(s: &AppState, req: Request<Body>) -> (StatusCode, Vec<u8>) {
        let (st, _, body) = call(s, req).await;
        (st, body)
    }

    pub(crate) fn json_of(body: &[u8]) -> Value {
        serde_json::from_slice(body).unwrap()
    }

    /// A request with optional bearer token and JSON body.
    pub(crate) fn req(
        m: &str,
        uri: &str,
        token: Option<&Token>,
        body: Option<Value>,
    ) -> Request<Body> {
        let mut b = Request::builder().method(m).uri(uri);
        if let Some(t) = token {
            let bearer = format!("Bearer {}", b64::encode(t.expose()));
            b = b.header("authorization", bearer);
        }
        if body.is_some() {
            b = b.header("content-type", "application/json");
        }
        b.body(body.map_or_else(Body::empty, |v| Body::from(v.to_string())))
            .unwrap()
    }

    pub(crate) fn get(uri: &str) -> Request<Body> {
        req("GET", uri, None, None)
    }

    fn with_api_key(mut r: Request<Body>, key: &str) -> Request<Body> {
        r.headers_mut()
            .insert("xchonnect-api-key", key.parse().unwrap());
        r
    }

    /// Creation body for the tokens `[r; 32]` and `[w; 32]`.
    pub(crate) fn hashes(r: u8, w: u8) -> Value {
        let h = |b: u8| b64::encode(&token_hash(&[b; 32]));
        json!({ "read_token_hash": h(r), "write_token_hash": h(w) })
    }

    /// The exact wire body of an error.
    pub(crate) fn err(code: &str) -> Vec<u8> {
        format!(r#"{{"error":"{code}"}}"#).into_bytes()
    }

    pub(crate) fn envelope() -> String {
        let env = Envelope {
            kind: Kind::Session,
            n: vec![1; 24],
            ct: vec![2; 1024],
        };
        b64::encode(&env.encode().unwrap())
    }

    pub(crate) async fn create(s: &AppState) -> (String, Token, Token) {
        let (r, w) = (Token::from_bytes([1; 32]), Token::from_bytes([2; 32]));
        let (st, body) = send(s, req("POST", "/v1/mailboxes", None, Some(hashes(1, 2)))).await;
        let text = String::from_utf8_lossy(&body);
        assert_eq!(st, StatusCode::CREATED, "{text}");
        let id = json_of(&body)["mailbox_id"].as_str().unwrap().to_owned();
        (id, r, w)
    }

    async fn solved_challenge(s: &AppState) -> Value {
        let (_, body) = send(s, req("POST", "/v1/challenge", None, None)).await;
        let ch = json_of(&body)["challenge"].as_str().unwrap().to_owned();
        let nonce = xchonnect_core::pow::solve(&b64::decode(&ch).unwrap()).unwrap();
        json!({ "challenge": ch, "nonce": b64::encode(&nonce) })
    }

    #[tokio::test]
    async fn info_and_health() {
        let s = test_state(Config::default());
        let (st, h, body) = call(&s, get("/v1/info")).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(h["cache-control"], "no-store");
        let v = json_of(&body);
        assert_eq!(v["protocol"], 1);
        assert_eq!(v["gateway_policy"], "allowlist");
        assert_eq!(send(&s, get("/readyz")).await.0, StatusCode::OK);
    }

    /// `relay-api.md` §Errors: *every* error body is `{"error":"<code>"}`, including the
    /// ones axum raises before a handler runs. Those used to answer in plain text.
    #[tokio::test]
    async fn framework_rejections_use_the_uniform_error_model() {
        let s = test_state(open_config());
        let (id, r, _) = create(&s).await;
        // (request, status, code)
        let cases: Vec<(Request<Body>, StatusCode, &str)> = vec![
            // An unmatched path.
            (get("/nope"), StatusCode::NOT_FOUND, "not_found"),
            (get("/v1"), StatusCode::NOT_FOUND, "not_found"),
            (
                get("/v1/mailboxes/x/y/z"),
                StatusCode::NOT_FOUND,
                "not_found",
            ),
            // A method the route does not declare.
            (
                req("PATCH", "/v1/info", None, None),
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
            ),
            (
                req(
                    "PUT",
                    &format!("/v1/mailboxes/{id}/messages"),
                    Some(&r),
                    None,
                ),
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
            ),
            (
                req("DELETE", "/v1/mailboxes", None, None),
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
            ),
            // A path that does not percent-decode to UTF-8: the `Path` extractor
            // rejects it before `authorize` ever sees an id.
            (
                get("/v1/mailboxes/not-%7F%FF-a-mailbox/messages"),
                StatusCode::BAD_REQUEST,
                "bad_request",
            ),
            (
                req("POST", "/v1/mailboxes/%FF/ack", None, None),
                StatusCode::BAD_REQUEST,
                "bad_request",
            ),
        ];
        for (request, status, code) in cases {
            let uri = request.uri().to_string();
            let method = request.method().clone();
            let (st, h, body) = call(&s, request).await;
            assert_eq!(st, status, "{method} {uri}");
            assert_eq!(h["content-type"], "application/json", "{method} {uri}");
            assert_eq!(body, err(code), "{method} {uri}");
            // The privacy headers still apply to a rewritten response.
            assert_eq!(h["cache-control"], "no-store", "{method} {uri}");
            assert_eq!(h["x-content-type-options"], "nosniff", "{method} {uri}");
            assert_eq!(h["referrer-policy"], "no-referrer", "{method} {uri}");
        }
        // 405 keeps the `Allow` header RFC 9110 requires, and a HEAD of a route that
        // has no GET keeps its empty body.
        let (st, h, _) = call(&s, req("PATCH", "/v1/info", None, None)).await;
        assert_eq!(st, StatusCode::METHOD_NOT_ALLOWED);
        let allow = h["allow"].to_str().unwrap();
        assert!(allow.contains("GET"), "Allow was {allow:?}");
        let (st, _, body) = call(&s, req("HEAD", "/v1/challenge", None, None)).await;
        assert_eq!((st, body.len()), (StatusCode::METHOD_NOT_ALLOWED, 0));
    }

    #[tokio::test]
    async fn cors_preflight() {
        let s = test_state(Config::default());
        let req = Request::options("/v1/mailboxes")
            .header("origin", "https://dapp.example")
            .header("access-control-request-method", "POST")
            .header(
                "access-control-request-headers",
                "authorization,content-type",
            )
            .body(Body::empty())
            .unwrap();
        let (st, h, _) = call(&s, req).await;
        assert!(st.is_success());
        assert_eq!(h["access-control-allow-origin"], "*");
        assert!(h.get("access-control-allow-credentials").is_none());
    }

    #[tokio::test]
    async fn full_message_flow() {
        let s = test_state(open_config());
        let (id, r, w) = create(&s).await;
        let base = format!("/v1/mailboxes/{id}");
        let msgs = format!("{base}/messages");
        let post = json!({ "env": envelope(), "ttl_s": 3600 });
        let (st, body) = send(&s, req("POST", &msgs, Some(&w), Some(post))).await;
        assert_eq!(st, StatusCode::ACCEPTED);
        let msg_id = json_of(&body)["msg_id"].clone();
        let (st, body) = send(&s, req("GET", &msgs, Some(&r), None)).await;
        assert_eq!(st, StatusCode::OK);
        let v = json_of(&body);
        assert_eq!(v["messages"][0]["msg_id"], msg_id);
        assert_eq!(v["messages"][0]["env"], envelope().as_str());
        let ack = Some(json!({ "msg_ids": [msg_id] }));
        let ack = send(&s, req("POST", &format!("{base}/ack"), Some(&r), ack)).await;
        assert_eq!(ack.0, StatusCode::NO_CONTENT);
        let (_, body) = send(&s, req("GET", &msgs, Some(&r), None)).await;
        assert_eq!(json_of(&body)["messages"], json!([]));
        let del = send(&s, req("DELETE", &base, Some(&r), None)).await;
        assert_eq!(del.0, StatusCode::NO_CONTENT);
        let gone = send(&s, req("GET", &msgs, Some(&r), None)).await;
        assert_eq!(gone.0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn tokens_are_not_interchangeable_and_not_found_is_identical() {
        let s = test_state(open_config());
        let (id, r, w) = create(&s).await;
        let msgs = format!("/v1/mailboxes/{id}/messages");
        // Read token cannot write, write token cannot read.
        let post = Some(json!({ "env": envelope() }));
        let reference = call(&s, req("POST", &msgs, Some(&r), post)).await;
        let unknown = format!("/v1/mailboxes/{}/messages", "A".repeat(22));
        let others = [
            req("GET", &msgs, Some(&w), None),
            req("GET", &unknown, Some(&r), None),
            req("GET", "/v1/mailboxes/not-an-id/messages", Some(&r), None),
            get(&msgs),
        ];
        let names = |h: &HeaderMap| {
            let mut v: Vec<_> = h
                .iter()
                .map(|(k, v)| format!("{k}={}", v.to_str().unwrap_or("")))
                .collect();
            v.sort();
            v
        };
        for other in others {
            let other = call(&s, other).await;
            assert_eq!(other.0, StatusCode::NOT_FOUND);
            assert_eq!((other.0, &other.2), (reference.0, &reference.2));
            assert_eq!(names(&other.1), names(&reference.1));
        }
        assert_eq!(reference.2, err("not_found"));
    }

    #[tokio::test]
    async fn malformed_and_oversized_envelopes_rejected() {
        let s = test_state(open_config());
        let (id, _, w) = create(&s).await;
        let uri = format!("/v1/mailboxes/{id}/messages");
        let truncated = b64::encode(&b64::decode(&envelope()).unwrap()[..20]);
        for env in [truncated.as_str(), "!!"] {
            let post = Some(json!({ "env": env }));
            let st = send(&s, req("POST", &uri, Some(&w), post)).await.0;
            assert_eq!(st, StatusCode::BAD_REQUEST);
        }
        let huge = Some(json!({ "env": "A".repeat(crate::MAX_BODY_BYTES + 10) }));
        let res = send(&s, req("POST", &uri, Some(&w), huge)).await;
        assert_eq!(res, (StatusCode::PAYLOAD_TOO_LARGE, err("too_large")));
        let mut bad = req("POST", &uri, Some(&w), None);
        *bad.body_mut() = Body::from("{not json");
        assert_eq!(send(&s, bad).await.1, err("bad_request"));
    }

    #[tokio::test]
    async fn quota_and_ttl() {
        let s = test_state(Config {
            max_messages: 2,
            ..open_config()
        });
        let (id, _, w) = create(&s).await;
        let uri = format!("/v1/mailboxes/{id}/messages");
        for _ in 0..2 {
            let post = Some(json!({ "env": envelope(), "ttl_s": 1 }));
            let st = send(&s, req("POST", &uri, Some(&w), post)).await.0;
            assert_eq!(st, StatusCode::ACCEPTED);
        }
        let post = Some(json!({ "env": envelope() }));
        let res = send(&s, req("POST", &uri, Some(&w), post)).await;
        assert_eq!(res, (StatusCode::CONFLICT, err("mailbox_full")));
    }

    #[tokio::test]
    async fn long_poll_returns_when_message_arrives() {
        let s = test_state(open_config());
        let (id, r, w) = create(&s).await;
        let uri = format!("/v1/mailboxes/{id}/messages");
        let (s2, uri2) = (s.clone(), uri.clone());
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            let post = Some(json!({ "env": envelope() }));
            call(&s2, req("POST", &uri2, Some(&w), post)).await;
        });
        let t = std::time::Instant::now();
        let (st, body) = send(&s, req("GET", &format!("{uri}?wait=10"), Some(&r), None)).await;
        assert_eq!(st, StatusCode::OK);
        assert!(t.elapsed() < std::time::Duration::from_secs(5));
        assert_eq!(json_of(&body)["messages"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn creation_requires_proof_unless_open() {
        let s = test_state(Config::default());
        let res = send(&s, req("POST", "/v1/mailboxes", None, Some(hashes(1, 2)))).await;
        assert_eq!(res, (StatusCode::FORBIDDEN, err("auth_required")));
        // Equal hashes rejected.
        let same = req("POST", "/v1/mailboxes", None, Some(hashes(1, 1)));
        assert_eq!(
            send(&test_state(open_config()), same).await.0,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn pow_creation() {
        let s = test_state(Config {
            pow_difficulty: 8,
            ..Config::default()
        });
        let mut body = hashes(1, 2);
        body["pow"] = solved_challenge(&s).await;
        let create = || req("POST", "/v1/mailboxes", None, Some(body.clone()));
        assert_eq!(send(&s, create()).await.0, StatusCode::CREATED);
        assert_eq!(
            send(&s, create()).await,
            (StatusCode::FORBIDDEN, err("pow_invalid"))
        );
    }

    #[tokio::test]
    async fn api_keys_and_tickets() {
        let s = test_state(keyed(Config::default()));
        let create = |body: Value| req("POST", "/v1/mailboxes", None, Some(body));
        // API key creation.
        let res = send(&s, with_api_key(create(hashes(1, 2)), API_KEY)).await;
        assert_eq!(res.0, StatusCode::CREATED);
        let wrong = with_api_key(create(hashes(1, 2)), "wrong-key-0123456789");
        assert_eq!(send(&s, wrong).await.1, err("api_key_invalid"));
        // Ticket issued with the key, used once by a wallet without a key.
        let issue = with_api_key(req("POST", "/v1/tickets", None, None), API_KEY);
        let (st, ticket) = send(&s, issue).await;
        assert_eq!(st, StatusCode::OK);
        let mut body = hashes(5, 6);
        body["ticket"] = json_of(&ticket)["ticket"].clone();
        assert_eq!(send(&s, create(body.clone())).await.0, StatusCode::CREATED);
        assert_eq!(send(&s, create(body)).await.1, err("ticket_invalid"));
        let no_key = send(&s, req("POST", "/v1/tickets", None, None)).await;
        assert_eq!(no_key.0, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn write_rate_limit_and_usage() {
        let s = test_state(keyed(Config {
            write_rate: 60,
            ..open_config()
        }));
        let w = Token::from_bytes([2; 32]);
        let create = req("POST", "/v1/mailboxes", None, Some(hashes(1, 2)));
        let (_, body) = send(&s, with_api_key(create, API_KEY)).await;
        let id = json_of(&body)["mailbox_id"].as_str().unwrap().to_owned();
        let uri = format!("/v1/mailboxes/{id}/messages");
        let mut limited = None;
        for _ in 0..20 {
            let post = Some(json!({ "env": envelope() }));
            let (st, h, _) = call(&s, req("POST", &uri, Some(&w), post)).await;
            if st == StatusCode::TOO_MANY_REQUESTS {
                limited = Some(h);
                break;
            }
        }
        let h = limited.expect("rate limit reached within burst");
        assert!(h.get("retry-after").is_some());
        let usage = s.usage();
        assert_eq!(
            (usage[0].0.as_str(), usage[0].1.mailboxes_created),
            ("pengui", 1)
        );
        assert!(usage[0].1.messages >= 10);
    }

    #[tokio::test]
    async fn invalid_proofs_do_not_drain_the_anonymous_budget() {
        // Review finding: the global bucket must only be charged for verified proofs.
        let s = test_state(Config {
            pow_difficulty: 4,
            create_rate: 4,
            ..Config::default()
        });
        let create = |pow: Value| {
            let mut body = hashes(1, 2);
            body["pow"] = pow;
            req("POST", "/v1/mailboxes", None, Some(body))
        };
        for _ in 0..100 {
            let res = send(&s, create(json!({ "challenge": "AA", "nonce": "AA" }))).await;
            assert_eq!(res, (StatusCode::FORBIDDEN, err("pow_invalid")));
        }
        let valid = create(solved_challenge(&s).await);
        assert_eq!(send(&s, valid).await.0, StatusCode::CREATED);
    }

    #[tokio::test]
    async fn api_key_header_does_not_bypass_the_limit_when_keys_are_disabled() {
        // Review finding: an ignored API key header must not skip the anonymous limit.
        let s = test_state(Config {
            creation: vec![Creation::Open],
            create_rate: 4,
            ..Config::default()
        });
        let mut limited = false;
        for i in 0..40u8 {
            let body = Some(hashes(i, i.wrapping_add(100)));
            let r = with_api_key(req("POST", "/v1/mailboxes", None, body), "not-a-key");
            if send(&s, r).await.0 == StatusCode::TOO_MANY_REQUESTS {
                limited = true;
                break;
            }
        }
        assert!(limited);
    }

    #[tokio::test]
    async fn push_registration_policy() {
        let allow = GatewayPolicy::Allowlist(vec!["https://push.example/".into()]);
        let s = test_state(Config {
            gateway_policy: allow,
            ..open_config()
        });
        let (id, r, _) = create(&s).await;
        let uri = format!("/v1/mailboxes/{id}/push");
        let sealed = b64::encode(&[1; 64]);
        let put = |url: Option<&str>| {
            let reg = url.map(|u| json!({ "gateway_url": u, "sealed_token": sealed }));
            req("PUT", &uri, Some(&r), Some(json!({ "push_reg": reg })))
        };
        let ok = send(&s, put(Some("https://push.example/v1/wake"))).await;
        assert_eq!(ok.0, StatusCode::NO_CONTENT);
        let bad = send(&s, put(Some("https://169.254.169.254/latest"))).await;
        assert_eq!(bad.1, err("gateway_not_allowed"));
        assert_eq!(send(&s, put(None)).await.0, StatusCode::NO_CONTENT);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod privacy_tests {
    use super::tests::{call, create, envelope, get, json_of, open_config, req, test_state};
    use serde_json::json;
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use xchonnect_core::b64;

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl Write for Capture {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Spec 13.5: run every endpoint, including error paths, at TRACE level and check that
    /// no identifier, token or ciphertext reaches the logs or the metrics.
    #[tokio::test]
    async fn logs_and_metrics_contain_no_identifiers() {
        let cap = Capture::default();
        let writer = cap.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let s = test_state(open_config());
        let (id, r, w) = create(&s).await;
        let base = format!("/v1/mailboxes/{id}");
        let msgs = format!("{base}/messages");
        let env = envelope();
        call(
            &s,
            req("POST", &msgs, Some(&w), Some(json!({ "env": env }))),
        )
        .await;
        let (_, _, body) = call(&s, req("GET", &msgs, Some(&r), None)).await;
        let msg_id = json_of(&body)["messages"][0]["msg_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let ack = Some(json!({ "msg_ids": [msg_id] }));
        call(&s, req("POST", &format!("{base}/ack"), Some(&r), ack)).await;
        let push = Some(
            json!({ "push_reg": { "gateway_url": "https://x.example/w", "sealed_token": "AAAA" } }),
        );
        call(&s, req("PUT", &format!("{base}/push"), Some(&r), push)).await;
        call(&s, req("GET", &msgs, Some(&w), None)).await; // wrong token
        call(
            &s,
            req("POST", &msgs, Some(&w), Some(json!({ "env": "!!" }))),
        )
        .await; // bad body
        // The same requests through the OHTTP gateway, including an error path.
        {
            use crate::ohttp::tests::{Inner, key_configs, via_gateway};
            let mut key = key_configs(&s).await.remove(0);
            let post = Inner::new("POST", &msgs)
                .token(&w)
                .json(&json!({ "env": env }));
            via_gateway(&s, &mut key, &post).await;
            via_gateway(&s, &mut key, &Inner::new("GET", &msgs).token(&r)).await;
            via_gateway(&s, &mut key, &Inner::new("GET", &msgs).token(&w)).await;
        }
        call(&s, req("DELETE", &base, Some(&r), None)).await;
        let (_, _, metrics) = call(&s, get("/metrics")).await;
        let metrics = String::from_utf8(metrics).unwrap();
        let logs = String::from_utf8(cap.0.lock().unwrap().clone()).unwrap();

        let secrets = [
            id.clone(),
            b64::encode(r.expose()),
            b64::encode(w.expose()),
            b64::encode(&r.hash()),
            b64::encode(&w.hash()),
            env.clone(),
            msg_id.clone(),
        ];
        for (name, text) in [("logs", &logs), ("metrics", &metrics)] {
            for sec in &secrets {
                assert!(
                    !text.contains(sec.as_str()),
                    "{name} contain an identifier or token"
                );
            }
        }
        assert!(
            metrics.contains(r#"route="/v1/mailboxes/{id}/messages",class="2xx""#),
            "{metrics}"
        );
        assert!(metrics.contains(r#"route="/v1/mailboxes/{id}/messages",class="4xx""#));
        assert!(metrics.contains("xchonnect_mailboxes 0"));
    }

    #[test]
    fn identifier_types_do_not_print() {
        let id = xchonnect_core::crypto::MailboxId([7; 16]);
        let t = xchonnect_core::crypto::Token::from_bytes([7; 32]);
        assert!(!format!("{id:?} {t:?}").contains(&b64::encode(&[7; 16])));
    }
}
