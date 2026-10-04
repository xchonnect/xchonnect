//! Uniform error model (`docs/spec/wire/relay-api.md`).

use axum::http::{HeaderValue, StatusCode, header};
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
            ApiError::MailboxFull => (StatusCode::CONFLICT, "mailbox_full"),
            ApiError::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "too_large"),
            ApiError::RateLimited { .. } => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            ApiError::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        }
    }
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
