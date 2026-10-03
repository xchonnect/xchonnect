//! HTTP routes (`docs/spec/wire/relay-api.md`).

use crate::AppState;
use crate::config::{Creation, GatewayPolicy, api_key_hash};
use crate::creation::{self, MAX_SEALED_TOKEN, TICKET_TTL_S};
use crate::error::ApiError;
use crate::store::{self, MailboxRecord, PushReg, QueueLimits, StoredMessage};
use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
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

/// All routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(readyz))
        .route("/v1/info", get(info))
        .route("/v1/challenge", post(challenge))
        .route("/v1/tickets", post(ticket))
        .route("/v1/mailboxes", post(create_mailbox))
        .route("/v1/mailboxes/{id}", axum::routing::delete(delete_mailbox))
        .route(
            "/v1/mailboxes/{id}/messages",
            post(post_message).get(get_messages),
        )
        .route("/v1/mailboxes/{id}/ack", post(ack))
        .route("/v1/mailboxes/{id}/push", put(set_push))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_json<T: DeserializeOwned>(body: Result<Bytes, BytesRejection>) -> Result<T, ApiError> {
    let bytes = body.map_err(|e| {
        if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::TooLarge
        } else {
            ApiError::BadRequest
        }
    })?;
    serde_json::from_slice(&bytes).map_err(|_| ApiError::BadRequest)
}

fn json_response(status: StatusCode, v: Value) -> Response {
    (status, Json(v)).into_response()
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
    let presented = crypto::token_hash(&bearer(headers).unwrap_or([0; 32]));
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
    let ok = crypto::ct_eq(&presented, &expected) && bearer(headers).is_some();
    match (ok, mailbox, rec) {
        (true, Some(m), Some(r)) => {
            let today = store::day(s.now());
            if r.last_used_day < today {
                s.store().touch(&m, today).await?;
            }
            Ok((m, r))
        }
        _ => Err(ApiError::NotFound),
    }
}

fn push_reg_from(s: &AppState, v: &PushRegBody) -> Result<PushReg, ApiError> {
    creation::check_gateway_url(s.config(), &v.gateway_url)?;
    let sealed = b64::decode(&v.sealed_token).map_err(|_| ApiError::BadRequest)?;
    if sealed.is_empty() || sealed.len() > MAX_SEALED_TOKEN {
        return Err(ApiError::BadRequest);
    }
    Ok(PushReg {
        gateway_url: v.gateway_url.clone(),
        sealed_token: sealed,
    })
}

fn customer_for_key(s: &AppState, headers: &HeaderMap) -> Result<Option<String>, ApiError> {
    match headers.get("xchonnect-api-key") {
        None => Ok(None),
        Some(v) => {
            let key = v.to_str().map_err(|_| ApiError::ApiKeyInvalid)?;
            s.config()
                .api_keys
                .get(&api_key_hash(key))
                .cloned()
                .map(Some)
                .ok_or(ApiError::ApiKeyInvalid)
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn readyz(State(s): State<AppState>) -> Result<&'static str, ApiError> {
    s.store().mailbox_count().await?;
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
        "pow_difficulty": c.pow_difficulty,
        "gateway_policy": match c.gateway_policy { GatewayPolicy::Allowlist(_) => "allowlist", GatewayPolicy::Open => "open" },
        "ohttp": false,
    });
    if let Some(o) = v.as_object_mut() {
        if let GatewayPolicy::Allowlist(list) = &c.gateway_policy {
            o.insert("gateway_allowlist".into(), json!(list));
        }
        if !c.creation.contains(&Creation::Pow) {
            o.remove("pow_difficulty");
        }
    }
    Json(v)
}

async fn challenge(State(s): State<AppState>) -> Result<Response, ApiError> {
    if !s.config().creation.contains(&Creation::Pow) {
        return Err(ApiError::NotFound);
    }
    let now = s.now();
    let c = s.pow().issue(now, s.config().pow_difficulty)?;
    let info = xchonnect_core::pow::parse(&c).map_err(|_| ApiError::Unavailable)?;
    Ok(json_response(
        StatusCode::OK,
        json!({ "challenge": b64::encode(&c), "difficulty": info.difficulty, "expires_at": info.expires_at }),
    ))
}

async fn ticket(State(s): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
    if !s.config().creation.contains(&Creation::Ticket) {
        return Err(ApiError::NotFound);
    }
    let customer = customer_for_key(&s, &headers)?.ok_or(ApiError::ApiKeyInvalid)?;
    let t: [u8; 32] = crypto::random_array(&mut OsEntropy);
    let expires_at = s.now() + TICKET_TTL_S;
    s.store()
        .put_ticket(creation::ticket_hash(&t), &customer, expires_at)
        .await?;
    Ok(json_response(
        StatusCode::OK,
        json!({ "ticket": b64::encode(&t), "expires_at": expires_at }),
    ))
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

async fn create_mailbox(
    State(s): State<AppState>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Response, ApiError> {
    let b: CreateBody = parse_json(body)?;
    let read_hash =
        b64::decode_array::<32>(&b.read_token_hash).map_err(|_| ApiError::BadRequest)?;
    let write_hash =
        b64::decode_array::<32>(&b.write_token_hash).map_err(|_| ApiError::BadRequest)?;
    if read_hash == write_hash {
        return Err(ApiError::BadRequest);
    }
    let push = b
        .push_reg
        .as_ref()
        .map(|p| push_reg_from(&s, p))
        .transpose()?;
    let c = s.config();
    let now = s.now();
    // Precedence: API key, ticket, pow (relay-api.md).
    let customer =
        if c.creation.contains(&Creation::ApiKey) && headers.contains_key("xchonnect-api-key") {
            customer_for_key(&s, &headers)?
        } else if let (true, Some(t)) = (c.creation.contains(&Creation::Ticket), &b.ticket) {
            let t = b64::decode_array::<32>(t).map_err(|_| ApiError::TicketInvalid)?;
            Some(
                s.store()
                    .take_ticket(&creation::ticket_hash(&t), now)
                    .await?
                    .ok_or(ApiError::TicketInvalid)?,
            )
        } else if let (true, Some(p)) = (c.creation.contains(&Creation::Pow), &b.pow) {
            let ch = b64::decode(&p.challenge).map_err(|_| ApiError::PowInvalid)?;
            let nonce = b64::decode(&p.nonce).map_err(|_| ApiError::PowInvalid)?;
            s.pow().redeem(&ch, &nonce, now, c.pow_difficulty)?;
            None
        } else if c.creation.contains(&Creation::Open) {
            None
        } else {
            return Err(ApiError::AuthRequired);
        };
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
    Ok(json_response(
        StatusCode::CREATED,
        json!({ "mailbox_id": id.to_b64() }),
    ))
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
    body: Result<Bytes, BytesRejection>,
) -> Result<Response, ApiError> {
    let (mailbox, rec) = authorize(&s, &id, &headers, Access::Write).await?;
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
    s.store()
        .enqueue(
            &mailbox,
            StoredMessage {
                msg_id,
                envelope: env,
            },
            s.now() + ttl,
            limits,
        )
        .await?;
    s.on_message_accepted(&mailbox, &rec);
    Ok(json_response(
        StatusCode::ACCEPTED,
        json!({ "msg_id": b64::encode(&msg_id) }),
    ))
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
    q: Result<Query<FetchQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Response, ApiError> {
    let (mailbox, _) = authorize(&s, &id, &headers, Access::Read).await?;
    let Query(q) = q.map_err(|_| ApiError::BadRequest)?;
    let wait = q.wait.unwrap_or(0).min(s.max_wait(&headers));
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
    Ok(json_response(StatusCode::OK, json!({ "messages": out })))
}

#[derive(Deserialize)]
struct AckBody {
    msg_ids: Vec<String>,
}

async fn ack(
    State(s): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
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
    body: Result<Bytes, BytesRejection>,
) -> Result<StatusCode, ApiError> {
    let (mailbox, _) = authorize(&s, &id, &headers, Access::Read).await?;
    let b: PushBody = parse_json(body)?;
    let push = b
        .push_reg
        .as_ref()
        .map(|p| push_reg_from(&s, p))
        .transpose()?;
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
    use crate::config::Creation;
    use crate::{AppState, Config, app};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use serde_json::{Value, json};
    use std::sync::Arc;
    use tower::ServiceExt;
    use xchonnect_core::b64;
    use xchonnect_core::crypto::{Token, token_hash};
    use xchonnect_core::envelope::{Envelope, Kind};

    pub(crate) fn open_config() -> Config {
        Config {
            creation: vec![
                Creation::Open,
                Creation::Pow,
                Creation::Ticket,
                Creation::ApiKey,
            ],
            ..Config::default()
        }
    }

    pub(crate) fn test_state(config: Config) -> AppState {
        AppState::in_memory(config, Arc::new(|| 1_790_000_000))
    }

    pub(crate) async fn call(
        state: &AppState,
        req: Request<Body>,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let res = app(state.clone()).oneshot(req).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let body = res.into_body().collect().await.unwrap().to_bytes().to_vec();
        (status, headers, body)
    }

    fn post_json(uri: &str, v: Value) -> Request<Body> {
        Request::post(uri)
            .header("content-type", "application/json")
            .body(Body::from(v.to_string()))
            .unwrap()
    }

    fn authed(method: &str, uri: &str, token: &Token, body: Option<Value>) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(
                "authorization",
                format!("Bearer {}", b64::encode(token.expose())),
            )
            .header("content-type", "application/json")
            .body(body.map_or_else(Body::empty, |v| Body::from(v.to_string())))
            .unwrap()
    }

    pub(crate) fn envelope() -> String {
        b64::encode(
            &Envelope {
                kind: Kind::Session,
                n: vec![1; 24],
                ct: vec![2; 1024],
            }
            .encode()
            .unwrap(),
        )
    }

    pub(crate) async fn create(s: &AppState) -> (String, Token, Token) {
        let (r, w) = (Token::from_bytes([1; 32]), Token::from_bytes([2; 32]));
        let (st, _, body) = call(
            s,
            post_json("/v1/mailboxes", json!({ "read_token_hash": b64::encode(&r.hash()), "write_token_hash": b64::encode(&w.hash()) })),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::CREATED,
            "{}",
            String::from_utf8_lossy(&body)
        );
        let v: Value = serde_json::from_slice(&body).unwrap();
        (v["mailbox_id"].as_str().unwrap().to_owned(), r, w)
    }

    #[tokio::test]
    async fn info_and_health() {
        let s = test_state(Config::default());
        let (st, h, body) = call(&s, Request::get("/v1/info").body(Body::empty()).unwrap()).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(h["cache-control"], "no-store");
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["protocol"], 1);
        assert_eq!(v["gateway_policy"], "allowlist");
        assert_eq!(
            call(&s, Request::get("/readyz").body(Body::empty()).unwrap())
                .await
                .0,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn cors_preflight() {
        let s = test_state(Config::default());
        let req = Request::options("/v1/mailboxes")
            .header("origin", "https://pengui.xyz")
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
        let (st, _, body) = call(
            &s,
            authed(
                "POST",
                &format!("{base}/messages"),
                &w,
                Some(json!({ "env": envelope(), "ttl_s": 3600 })),
            ),
        )
        .await;
        assert_eq!(st, StatusCode::ACCEPTED);
        let msg_id = serde_json::from_slice::<Value>(&body).unwrap()["msg_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let (st, _, body) = call(&s, authed("GET", &format!("{base}/messages"), &r, None)).await;
        assert_eq!(st, StatusCode::OK);
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["messages"][0]["msg_id"], msg_id.as_str());
        assert_eq!(v["messages"][0]["env"], envelope().as_str());
        assert_eq!(
            call(
                &s,
                authed(
                    "POST",
                    &format!("{base}/ack"),
                    &r,
                    Some(json!({ "msg_ids": [msg_id] }))
                )
            )
            .await
            .0,
            StatusCode::NO_CONTENT
        );
        let (_, _, body) = call(&s, authed("GET", &format!("{base}/messages"), &r, None)).await;
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["messages"],
            json!([])
        );
        assert_eq!(
            call(&s, authed("DELETE", &base, &r, None)).await.0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            call(&s, authed("GET", &format!("{base}/messages"), &r, None))
                .await
                .0,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn tokens_are_not_interchangeable_and_not_found_is_identical() {
        let s = test_state(open_config());
        let (id, r, w) = create(&s).await;
        let base = format!("/v1/mailboxes/{id}");
        // Read token cannot write, write token cannot read.
        let wrong_tok = call(
            &s,
            authed(
                "POST",
                &format!("{base}/messages"),
                &r,
                Some(json!({ "env": envelope() })),
            ),
        )
        .await;
        let wrong_read = call(&s, authed("GET", &format!("{base}/messages"), &w, None)).await;
        let unknown = call(
            &s,
            authed(
                "GET",
                "/v1/mailboxes/AAAAAAAAAAAAAAAAAAAAAA/messages",
                &r,
                None,
            ),
        )
        .await;
        let malformed = call(
            &s,
            authed("GET", "/v1/mailboxes/not-an-id/messages", &r, None),
        )
        .await;
        let no_auth = call(
            &s,
            Request::get(format!("{base}/messages"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        let reference = &wrong_tok;
        for other in [&wrong_read, &unknown, &malformed, &no_auth] {
            assert_eq!(other.0, StatusCode::NOT_FOUND);
            assert_eq!(other.0, reference.0);
            assert_eq!(other.2, reference.2);
            let names = |h: &axum::http::HeaderMap| {
                let mut v: Vec<_> = h
                    .iter()
                    .map(|(k, v)| format!("{k}={}", v.to_str().unwrap_or("")))
                    .collect();
                v.sort();
                v
            };
            assert_eq!(names(&other.1), names(&reference.1));
        }
        assert_eq!(reference.2, br#"{"error":"not_found"}"#);
    }

    #[tokio::test]
    async fn malformed_and_oversized_envelopes_rejected() {
        let s = test_state(open_config());
        let (id, _, w) = create(&s).await;
        let uri = format!("/v1/mailboxes/{id}/messages");
        let bad_ct = b64::encode(
            &Envelope {
                kind: Kind::Session,
                n: vec![1; 24],
                ct: vec![2; 1024],
            }
            .encode()
            .unwrap()[..20],
        );
        assert_eq!(
            call(&s, authed("POST", &uri, &w, Some(json!({ "env": bad_ct }))))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            call(&s, authed("POST", &uri, &w, Some(json!({ "env": "!!" }))))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        let huge = "A".repeat(crate::MAX_BODY_BYTES + 10);
        let (st, _, body) = call(&s, authed("POST", &uri, &w, Some(json!({ "env": huge })))).await;
        assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(body, br#"{"error":"too_large"}"#);
        let req = Request::post(&uri)
            .header(
                "authorization",
                format!("Bearer {}", b64::encode(w.expose())),
            )
            .body(Body::from("{not json"))
            .unwrap();
        assert_eq!(call(&s, req).await.2, br#"{"error":"bad_request"}"#);
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
            assert_eq!(
                call(
                    &s,
                    authed(
                        "POST",
                        &uri,
                        &w,
                        Some(json!({ "env": envelope(), "ttl_s": 1 }))
                    )
                )
                .await
                .0,
                StatusCode::ACCEPTED
            );
        }
        let (st, _, body) = call(
            &s,
            authed("POST", &uri, &w, Some(json!({ "env": envelope() }))),
        )
        .await;
        assert_eq!(
            (st, body.as_slice()),
            (
                StatusCode::CONFLICT,
                br#"{"error":"mailbox_full"}"#.as_slice()
            )
        );
    }

    #[tokio::test]
    async fn long_poll_returns_when_message_arrives() {
        let s = test_state(open_config());
        let (id, r, w) = create(&s).await;
        let s2 = s.clone();
        let uri = format!("/v1/mailboxes/{id}/messages");
        let w2 = w.clone();
        let uri2 = uri.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            call(
                &s2,
                authed("POST", &uri2, &w2, Some(json!({ "env": envelope() }))),
            )
            .await;
        });
        let t = std::time::Instant::now();
        let (st, _, body) = call(&s, authed("GET", &format!("{uri}?wait=10"), &r, None)).await;
        assert_eq!(st, StatusCode::OK);
        assert!(t.elapsed() < std::time::Duration::from_secs(5));
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["messages"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn creation_requires_proof_unless_open() {
        let s = test_state(Config::default());
        let hashes = json!({ "read_token_hash": b64::encode(&token_hash(&[1; 32])), "write_token_hash": b64::encode(&token_hash(&[2; 32])) });
        let (st, _, body) = call(&s, post_json("/v1/mailboxes", hashes.clone())).await;
        assert_eq!(
            (st, body.as_slice()),
            (
                StatusCode::FORBIDDEN,
                br#"{"error":"auth_required"}"#.as_slice()
            )
        );
        // Equal hashes rejected.
        let same = json!({ "read_token_hash": b64::encode(&token_hash(&[1; 32])), "write_token_hash": b64::encode(&token_hash(&[1; 32])) });
        assert_eq!(
            call(&test_state(open_config()), post_json("/v1/mailboxes", same))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn pow_creation() {
        let s = test_state(Config {
            pow_difficulty: 8,
            ..Config::default()
        });
        let (_, _, body) = call(
            &s,
            Request::post("/v1/challenge").body(Body::empty()).unwrap(),
        )
        .await;
        let v: Value = serde_json::from_slice(&body).unwrap();
        let ch = b64::decode(v["challenge"].as_str().unwrap()).unwrap();
        let nonce = xchonnect_core::pow::solve(&ch).unwrap();
        let req = json!({
            "read_token_hash": b64::encode(&token_hash(&[1; 32])),
            "write_token_hash": b64::encode(&token_hash(&[2; 32])),
            "pow": { "challenge": v["challenge"], "nonce": b64::encode(&nonce) },
        });
        assert_eq!(
            call(&s, post_json("/v1/mailboxes", req.clone())).await.0,
            StatusCode::CREATED
        );
        let (st, _, body) = call(&s, post_json("/v1/mailboxes", req)).await;
        assert_eq!(
            (st, body.as_slice()),
            (
                StatusCode::FORBIDDEN,
                br#"{"error":"pow_invalid"}"#.as_slice()
            )
        );
    }

    #[tokio::test]
    async fn api_keys_and_tickets() {
        let mut c = Config::default();
        c.api_keys.insert(
            crate::config::api_key_hash("pengui-key-0123456789"),
            "pengui".into(),
        );
        let s = test_state(c);
        let hashes = |a: u8| json!({ "read_token_hash": b64::encode(&token_hash(&[a; 32])), "write_token_hash": b64::encode(&token_hash(&[a + 1; 32])) });
        // API key creation.
        let req = Request::post("/v1/mailboxes")
            .header("xchonnect-api-key", "pengui-key-0123456789")
            .body(Body::from(hashes(1).to_string()))
            .unwrap();
        assert_eq!(call(&s, req).await.0, StatusCode::CREATED);
        let req = Request::post("/v1/mailboxes")
            .header("xchonnect-api-key", "wrong-key-0123456789")
            .body(Body::from(hashes(1).to_string()))
            .unwrap();
        assert_eq!(call(&s, req).await.2, br#"{"error":"api_key_invalid"}"#);
        // Ticket issued with the key, used once by a wallet without a key.
        let req = Request::post("/v1/tickets")
            .header("xchonnect-api-key", "pengui-key-0123456789")
            .body(Body::empty())
            .unwrap();
        let (st, _, body) = call(&s, req).await;
        assert_eq!(st, StatusCode::OK);
        let ticket = serde_json::from_slice::<Value>(&body).unwrap()["ticket"]
            .as_str()
            .unwrap()
            .to_owned();
        let mut body = hashes(5);
        body["ticket"] = json!(ticket);
        assert_eq!(
            call(&s, post_json("/v1/mailboxes", body.clone())).await.0,
            StatusCode::CREATED
        );
        assert_eq!(
            call(&s, post_json("/v1/mailboxes", body)).await.2,
            br#"{"error":"ticket_invalid"}"#
        );
        assert_eq!(
            call(
                &s,
                Request::post("/v1/tickets").body(Body::empty()).unwrap()
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn push_registration_policy() {
        let s = test_state(Config {
            gateway_policy: crate::config::GatewayPolicy::Allowlist(vec![
                "https://push.klimper.app/".into(),
            ]),
            ..open_config()
        });
        let (id, r, _) = create(&s).await;
        let uri = format!("/v1/mailboxes/{id}/push");
        let ok = json!({ "push_reg": { "gateway_url": "https://push.klimper.app/v1/wake", "sealed_token": b64::encode(&[1; 64]) } });
        assert_eq!(
            call(&s, authed("PUT", &uri, &r, Some(ok))).await.0,
            StatusCode::NO_CONTENT
        );
        let bad = json!({ "push_reg": { "gateway_url": "https://169.254.169.254/latest", "sealed_token": b64::encode(&[1; 64]) } });
        assert_eq!(
            call(&s, authed("PUT", &uri, &r, Some(bad))).await.2,
            br#"{"error":"gateway_not_allowed"}"#
        );
        assert_eq!(
            call(
                &s,
                authed("PUT", &uri, &r, Some(json!({ "push_reg": null })))
            )
            .await
            .0,
            StatusCode::NO_CONTENT
        );
    }
}
