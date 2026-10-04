//! Aggregate metrics in Prometheus text format (spec 13.5).
//!
//! Labels are limited to the route *template* (e.g. `/v1/mailboxes/{id}/messages`) and
//! the status class. No mailbox ids, tokens, IPs or per-customer labels are recorded.

use crate::error::ApiError;
use crate::lock;
use axum::extract::{MatchedPath, Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::Mutex;
use std::time::Instant;

/// Latency histogram bucket upper bounds in seconds.
const BUCKETS: [f64; 10] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0, 30.0];
const DURATION: &str = "xchonnect_http_request_duration_seconds";

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
        let mut m = lock(&self.routes);
        let r = m.entry(route.to_owned()).or_default();
        *r.by_class.entry(class(status)).or_default() += 1;
        r.count += 1;
        r.sum += secs;
        for (b, slot) in BUCKETS.iter().zip(r.buckets.iter_mut()) {
            if secs <= *b {
                *slot += 1;
            }
        }
    }

    /// Render Prometheus text exposition.
    pub fn render(&self, mailboxes: Option<u64>) -> String {
        let m = lock(&self.routes);
        let mut out = String::from(
            "# HELP xchonnect_http_requests_total HTTP requests by route template and status class.\n\
             # TYPE xchonnect_http_requests_total counter\n",
        );
        // `write!` to a `String` cannot fail.
        for (route, r) in m.iter() {
            for (c, n) in &r.by_class {
                let labels = format!("route=\"{route}\",class=\"{c}\"");
                let _ = writeln!(out, "xchonnect_http_requests_total{{{labels}}} {n}");
            }
        }
        let _ = writeln!(out, "# HELP {DURATION} Request latency by route template.");
        let _ = writeln!(out, "# TYPE {DURATION} histogram");
        for (route, r) in m.iter() {
            let le = BUCKETS.iter().map(ToString::to_string);
            let counts = r.buckets.iter().copied();
            for (b, n) in le.zip(counts).chain([("+Inf".to_owned(), r.count)]) {
                let _ = writeln!(out, "{DURATION}_bucket{{route=\"{route}\",le=\"{b}\"}} {n}");
            }
            let _ = writeln!(out, "{DURATION}_sum{{route=\"{route}\"}} {}", r.sum);
            let _ = writeln!(out, "{DURATION}_count{{route=\"{route}\"}} {}", r.count);
        }
        if let Some(n) = mailboxes {
            let _ = writeln!(
                out,
                "# HELP xchonnect_mailboxes Current number of mailboxes.\n\
                 # TYPE xchonnect_mailboxes gauge\nxchonnect_mailboxes {n}"
            );
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
pub async fn endpoint(State(s): State<crate::AppState>) -> Result<Response, ApiError> {
    if !s.config().metrics {
        return Err(ApiError::NotFound);
    }
    let count = s.store().mailbox_count().await.ok();
    let body = s.metrics().render(count);
    let content_type = [("content-type", "text/plain; version=0.0.4")];
    Ok((content_type, body).into_response())
}
