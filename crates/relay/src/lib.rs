//! Xchonnect reference relay (spec Section 7, `docs/spec/wire/relay-api.md`).
//!
//! Privacy rules enforced structurally:
//! - handlers never read client IP addresses, `User-Agent` or forwarding headers
//!   (checked by `tests::handlers_do_not_read_client_identity`);
//! - no request logging: URLs contain mailbox ids, which must not reach logs (spec 13.5);
//! - the store keeps only token hashes, day-granular timestamps and ciphertext.

pub mod api;
pub mod config;
pub mod creation;
pub mod error;
pub mod limits;
pub mod store;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderValue, Method, header};
use axum::response::Response;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tower_http::cors::{Any, CorsLayer};

pub use config::Config;

/// Maximum request body (spec: 400 KiB).
pub const MAX_BODY_BYTES: usize = 400 * 1024;

/// Source of the current time (injectable for tests).
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// System clock in unix seconds.
pub fn system_clock() -> Clock {
    Arc::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    })
}

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    inner: Arc<StateInner>,
}

struct StateInner {
    config: Config,
    store: Arc<dyn store::MailboxStore>,
    notifier: store::Notifier,
    clock: Clock,
    pow: creation::PowState,
    limits: limits::Limits,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AppState")
    }
}

impl AppState {
    /// Create state from parts.
    pub fn new(
        config: Config,
        store: Arc<dyn store::MailboxStore>,
        notifier: store::Notifier,
        clock: Clock,
    ) -> Self {
        AppState {
            inner: Arc::new(StateInner {
                pow: creation::PowState::new(config.pow_key),
                limits: limits::Limits::new(&config),
                config,
                store,
                notifier,
                clock,
            }),
        }
    }

    /// State with the in-memory store.
    pub fn in_memory(config: Config, clock: Clock) -> Self {
        let notifier = store::Notifier::default();
        let backend = Arc::new(store::memory::MemoryStore::new(notifier.clone()));
        AppState::new(config, backend, notifier, clock)
    }

    /// Storage backend.
    pub fn store(&self) -> &dyn store::MailboxStore {
        self.inner.store.as_ref()
    }

    /// Long-poll notifier.
    pub fn notifier(&self) -> &store::Notifier {
        &self.inner.notifier
    }

    /// Configuration.
    pub fn config(&self) -> &Config {
        &self.inner.config
    }

    /// Rate limiters and usage counters.
    pub fn limits(&self) -> &limits::Limits {
        &self.inner.limits
    }

    /// Per-customer usage snapshot for external metering.
    pub fn usage(&self) -> Vec<(String, limits::Usage)> {
        self.inner.limits.usage.snapshot()
    }

    /// Proof-of-work state.
    pub fn pow(&self) -> &creation::PowState {
        &self.inner.pow
    }

    /// Long-poll limit for a request (OHTTP requests get `max_wait_ohttp_s`, M4).
    pub fn max_wait(&self, _headers: &axum::http::HeaderMap) -> u64 {
        self.inner.config.max_wait_s
    }

    /// Called after a message was stored (push wake-ups are dispatched here, TASK-44).
    pub fn on_message_accepted(
        &self,
        _mailbox: &xchonnect_core::crypto::MailboxId,
        _rec: &store::MailboxRecord,
    ) {
    }

    /// Current unix time.
    pub fn now(&self) -> u64 {
        (self.inner.clock)()
    }
}

async fn security_headers(mut res: Response) -> Response {
    let h = res.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    res
}

/// Build the HTTP application.
pub fn app(state: AppState) -> Router {
    // Browsers call the relay cross-origin. No credentials are ever involved.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::HeaderName::from_static("xchonnect-api-key"),
        ])
        .expose_headers([header::RETRY_AFTER])
        .max_age(std::time::Duration::from_secs(3600));
    api::routes()
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(axum::middleware::map_response(security_headers))
        .layer(cors)
        .with_state(state)
}

#[cfg(test)]
mod tests {
    /// Spec 7.1 / 13.5: the relay must not read client identity. Handlers are not
    /// allowed to mention these extractors or headers at all.
    #[test]
    fn handlers_do_not_read_client_identity() {
        let forbidden = [
            "ConnectInfo",
            "user-agent",
            "USER_AGENT",
            "x-forwarded-for",
            "X_FORWARDED_FOR",
            "forwarded",
            "x-real-ip",
            "remote_addr",
            "peer_addr",
        ];
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
        let mut stack = vec![std::path::PathBuf::from(dir)];
        while let Some(p) = stack.pop() {
            for entry in std::fs::read_dir(&p).into_iter().flatten().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") && !path.ends_with("lib.rs") {
                    let text = std::fs::read_to_string(&path).unwrap_or_default();
                    for f in forbidden {
                        assert!(
                            !text.contains(f),
                            "{} mentions forbidden client-identity source `{f}`",
                            path.display()
                        );
                    }
                }
            }
        }
    }
}
