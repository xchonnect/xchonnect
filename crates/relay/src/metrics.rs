//! Aggregate metrics in Prometheus text format (spec 13.5).
//!
//! Labels are limited to the route *template* (e.g. `/v1/mailboxes/{id}/messages`) and
//! the status class. No mailbox ids, tokens, IPs or per-customer labels are recorded.

use axum::extract::{MatchedPath, Request, State};
use axum::middleware::Next;
use axum::response::Response;
use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::Mutex;
use std::time::Instant;

/// Latency histogram bucket upper bounds in seconds.
const BUCKETS: [f64; 10] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0, 30.0];

#[derive(Debug, Default, Clone)]
struct RouteStats {
    by_class: BTreeMap<&'static str, u64>,
    buckets: [u64; BUCKETS.len()],
    count: u64,
    sum: f64,
}

/// Process-wide metrics.
#[derive(Debug, Default)]
pub struct Metrics {
    routes: Mutex<BTreeMap<String, RouteStats>>,
}

fn class(status: u16) -> &'static str {
    match status {
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        _ => "5xx",
    }
}

impl Metrics {
    fn record(&self, route: &str, status: u16, secs: f64) {
        let mut m = self
            .routes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let r = m.entry(route.to_owned()).or_default();
        *r.by_class.entry(class(status)).or_default() += 1;
        r.count += 1;
        r.sum += secs;
        for (i, b) in BUCKETS.iter().enumerate() {
            if secs <= *b {
                if let Some(slot) = r.buckets.get_mut(i) {
                    *slot += 1;
                }
            }
        }
    }

    /// Render Prometheus text exposition.
    pub fn render(&self, mailboxes: Option<u64>) -> String {
        let m = self
            .routes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut out = String::new();
        let _ = writeln!(
            out,
            "# HELP xchonnect_http_requests_total HTTP requests by route template and status class."
        );
        let _ = writeln!(out, "# TYPE xchonnect_http_requests_total counter");
        for (route, r) in m.iter() {
            for (c, n) in &r.by_class {
                let _ = writeln!(
                    out,
                    "xchonnect_http_requests_total{{route=\"{route}\",class=\"{c}\"}} {n}"
                );
            }
        }
        let _ = writeln!(
            out,
            "# HELP xchonnect_http_request_duration_seconds Request latency by route template."
        );
        let _ = writeln!(
            out,
            "# TYPE xchonnect_http_request_duration_seconds histogram"
        );
        for (route, r) in m.iter() {
            for (b, n) in BUCKETS.iter().zip(r.buckets.iter()) {
                let _ = writeln!(
                    out,
                    "xchonnect_http_request_duration_seconds_bucket{{route=\"{route}\",le=\"{b}\"}} {n}"
                );
            }
            let _ = writeln!(
                out,
                "xchonnect_http_request_duration_seconds_bucket{{route=\"{route}\",le=\"+Inf\"}} {}",
                r.count
            );
            let _ = writeln!(
                out,
                "xchonnect_http_request_duration_seconds_sum{{route=\"{route}\"}} {}",
                r.sum
            );
            let _ = writeln!(
                out,
                "xchonnect_http_request_duration_seconds_count{{route=\"{route}\"}} {}",
                r.count
            );
        }
        if let Some(n) = mailboxes {
            let _ = writeln!(
                out,
                "# HELP xchonnect_mailboxes Current number of mailboxes."
            );
            let _ = writeln!(out, "# TYPE xchonnect_mailboxes gauge");
            let _ = writeln!(out, "xchonnect_mailboxes {n}");
        }
        out
    }
}

/// Middleware recording request metrics by route template.
pub async fn track(State(s): State<crate::AppState>, req: Request, next: Next) -> Response {
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "unmatched".to_owned(), |p| p.as_str().to_owned());
    let start = Instant::now();
    let res = next.run(req).await;
    s.metrics()
        .record(&route, res.status().as_u16(), start.elapsed().as_secs_f64());
    res
}

/// `GET /metrics`.
pub async fn endpoint(
    State(s): State<crate::AppState>,
) -> Result<Response, crate::error::ApiError> {
    if !s.config().metrics {
        return Err(crate::error::ApiError::NotFound);
    }
    let count = s.store().mailbox_count().await.ok();
    let body = s.metrics().render(count);
    Response::builder()
        .header("content-type", "text/plain; version=0.0.4")
        .body(axum::body::Body::from(body))
        .map_err(|_| crate::error::ApiError::Unavailable)
}
