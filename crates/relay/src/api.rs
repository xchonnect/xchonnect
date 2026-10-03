//! HTTP routes (`docs/spec/wire/relay-api.md`).

use crate::AppState;
use crate::config::{Creation, GatewayPolicy};
use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::routing::get;
use serde_json::{Value, json};
use xchonnect_core::envelope::MAX_ENVELOPE_BYTES;

/// All routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(|| async { "ok" }))
        .route("/v1/info", get(info))
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
pub(crate) mod tests {
    use crate::{AppState, Config, app};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    pub(crate) fn test_state(config: Config) -> AppState {
        AppState::new(config, Arc::new(|| 1_790_000_000))
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

    #[tokio::test]
    async fn info_and_health() {
        let s = test_state(Config::default());
        let (st, h, body) = call(&s, Request::get("/v1/info").body(Body::empty()).unwrap()).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(h["cache-control"], "no-store");
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["protocol"], 1);
        assert_eq!(v["gateway_policy"], "allowlist");
        let (st, _, _) = call(&s, Request::get("/healthz").body(Body::empty()).unwrap()).await;
        assert_eq!(st, StatusCode::OK);
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
}
