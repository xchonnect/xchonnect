//! Uniform error model (`docs/spec/wire/relay-api.md`).

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// Every error the API can return. Bodies are `{"error":"<code>"}` and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiError {
    /// 400 malformed request.
    BadRequest,
    /// 403 creation needs proof.
    AuthRequired,
    /// 403 proof-of-work invalid.
    PowInvalid,
    /// 403 ticket invalid.
    TicketInvalid,
    /// 403 API key invalid.
    ApiKeyInvalid,
    /// 403 gateway rejected.
    GatewayNotAllowed,
    /// 404 unknown mailbox, wrong token or deleted mailbox — always byte-identical.
    NotFound,
    /// 405 the path exists but not for this method.
    MethodNotAllowed,
    /// 409 mailbox quota reached.
    MailboxFull,
    /// 413 body too large.
    TooLarge,
    /// 429 rate limited.
    RateLimited {
        /// Seconds until retry.
        retry_after: u64,
    },
    /// 503 temporary failure.
    Unavailable,
}

impl ApiError {
    /// HTTP status and wire code.
    pub fn parts(self) -> (StatusCode, &'static str) {
        match self {
            ApiError::BadRequest => (StatusCode::BAD_REQUEST, "bad_request"),
            ApiError::AuthRequired => (StatusCode::FORBIDDEN, "auth_required"),
            ApiError::PowInvalid => (StatusCode::FORBIDDEN, "pow_invalid"),
            ApiError::TicketInvalid => (StatusCode::FORBIDDEN, "ticket_invalid"),
            ApiError::ApiKeyInvalid => (StatusCode::FORBIDDEN, "api_key_invalid"),
            ApiError::GatewayNotAllowed => (StatusCode::FORBIDDEN, "gateway_not_allowed"),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            ApiError::MethodNotAllowed => (StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed"),
            ApiError::MailboxFull => (StatusCode::CONFLICT, "mailbox_full"),
            ApiError::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "too_large"),
            ApiError::RateLimited { .. } => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            ApiError::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        }
    }

    /// The uniform error an HTTP status stands for, used to rewrite a rejection the
    /// framework produced before any handler ran.
    fn for_status(status: StatusCode) -> Self {
        match status {
            StatusCode::NOT_FOUND => ApiError::NotFound,
            StatusCode::METHOD_NOT_ALLOWED => ApiError::MethodNotAllowed,
            StatusCode::CONFLICT => ApiError::MailboxFull,
            StatusCode::PAYLOAD_TOO_LARGE => ApiError::TooLarge,
            StatusCode::TOO_MANY_REQUESTS => ApiError::RateLimited { retry_after: 1 },
            s if s.is_server_error() => ApiError::Unavailable,
            // Everything else the framework can reject with is a client mistake in the
            // request itself: a path that does not percent-decode, an unparsable query
            // string, an unsupported media type.
            _ => ApiError::BadRequest,
        }
    }
}

/// Content types that are an error body in their own right and are left alone: the
/// relay's own uniform model, and the RFC 9458 section 5.3 key-configuration problem
/// document the OHTTP gateway must return verbatim.
const PASS_THROUGH: [&str; 2] = ["application/json", "application/problem+json"];

/// Answer every error in the uniform model, including the ones the framework raises
/// before a handler runs (`docs/spec/wire/relay-api.md` makes `{"error":"<code>"}`
/// normative for *every* error).
///
/// axum rejects some requests itself — a path that does not percent-decode to UTF-8, a
/// method the route does not declare, an unmatched path — with a plain-text body. This
/// layer replaces such a body with the uniform one for the status, keeping the status
/// and any `Allow` header. Responses the relay built itself are already one of
/// `PASS_THROUGH` and are returned untouched.
pub async fn uniform_errors(req: Request, next: Next) -> Response {
    // A `HEAD` response carries the headers of the `GET` it mirrors and no body, so
    // there is no body to rewrite.
    let head = req.method() == Method::HEAD;
    let res = next.run(req).await;
    let status = res.status();
    if !(status.is_client_error() || status.is_server_error()) {
        return res;
    }
    let typed = res
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            PASS_THROUGH
                .iter()
                .any(|t| v.split(';').next().is_some_and(|m| m.trim() == *t))
        });
    if typed {
        return res;
    }
    let allow = res.headers().get(header::ALLOW).cloned();
    let mut out = ApiError::for_status(status).into_response();
    if let Some(allow) = allow {
        out.headers_mut().insert(header::ALLOW, allow);
    }
    if head {
        let (mut parts, body) = out.into_parts();
        drop(body);
        parts.headers.remove(header::CONTENT_LENGTH);
        return Response::from_parts(parts, Body::empty());
    }
    out
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = self.parts();
        let mut res = (
            status,
            [(header::CONTENT_TYPE, "application/json")],
            format!("{{\"error\":\"{code}\"}}"),
        )
            .into_response();
        if let ApiError::RateLimited { retry_after } = self {
            res.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(retry_after));
        }
        res
    }
}

impl From<axum::extract::rejection::BytesRejection> for ApiError {
    fn from(e: axum::extract::rejection::BytesRejection) -> Self {
        if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::TooLarge
        } else {
            ApiError::BadRequest
        }
    }
}

impl From<crate::store::StoreError> for ApiError {
    fn from(e: crate::store::StoreError) -> Self {
        match e {
            crate::store::StoreError::NotFound => ApiError::NotFound,
            crate::store::StoreError::MailboxFull => ApiError::MailboxFull,
            crate::store::StoreError::Backend(msg) => {
                tracing::error!(error = msg, "storage backend error");
                ApiError::Unavailable
            }
        }
    }
}
