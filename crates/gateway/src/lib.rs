//! Xchonnect reference push gateway (spec 7.3, 7.3.2).
//!
//! Run by each wallet vendor with its own APNs/FCM credentials. For every wake-up it:
//! opens the sealed token with its key, rate-limits per device in memory, hands the
//! token to the platform sender, and forgets it. It never sees mailbox ids or content,
//! never writes device tokens to disk or logs, and answers every request identically so
//! it is not an oracle for token validity.

use async_trait::async_trait;
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use xchonnect_core::b64;
use xchonnect_core::crypto::{self, X25519Secret};
use xchonnect_core::push::{MAX_SEALED, Platform, PushToken};

/// Delivery to a push platform.
#[async_trait]
pub trait PlatformSender: Send + Sync + 'static {
    /// Deliver a content-free wake-up. Implementations must not log the device token.
    async fn send(&self, token: &PushToken) -> Result<(), SendError>;
}

/// Delivery failure (counted, never stored with the token).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    /// The platform reports the device token as invalid or unregistered.
    InvalidToken,
    /// Platform not configured on this gateway.
    Unsupported,
    /// Transient failure.
    Temporary,
}

/// Sender that only counts deliveries (tests and `test` platform tokens).
#[derive(Debug, Default)]
pub struct CountingSender {
    /// Deliveries per platform name.
    pub sent: Mutex<HashMap<&'static str, u64>>,
}

#[async_trait]
impl PlatformSender for CountingSender {
    async fn send(&self, token: &PushToken) -> Result<(), SendError> {
        *self
            .sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(token.platform.as_str())
            .or_default() += 1;
        Ok(())
    }
}

/// Routes tokens to per-platform senders.
#[derive(Default)]
pub struct Senders {
    /// APNs (production and sandbox share a sender that selects the endpoint).
    pub apns: Option<Arc<dyn PlatformSender>>,
    /// FCM.
    pub fcm: Option<Arc<dyn PlatformSender>>,
    /// `test` platform.
    pub test: Option<Arc<dyn PlatformSender>>,
}

impl std::fmt::Debug for Senders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Senders")
            .field("apns", &self.apns.is_some())
            .field("fcm", &self.fcm.is_some())
            .field("test", &self.test.is_some())
            .finish()
    }
}

impl Senders {
    fn for_platform(&self, p: Platform) -> Option<&Arc<dyn PlatformSender>> {
        match p {
            Platform::Apns | Platform::ApnsSandbox => self.apns.as_ref(),
            Platform::Fcm => self.fcm.as_ref(),
            Platform::Test => self.test.as_ref(),
        }
    }
}

/// Per-device limits (spec 7.3.2: at most 1 wake per 10 s and 60 per hour).
#[derive(Debug, Clone, Copy)]
pub struct DeviceLimits {
    /// Minimum seconds between wakes.
    pub min_interval_s: u64,
    /// Maximum wakes per hour.
    pub per_hour: u32,
}

impl Default for DeviceLimits {
    fn default() -> Self {
        DeviceLimits {
            min_interval_s: 10,
            per_hour: 60,
        }
    }
}

/// Aggregate counters.
#[derive(Debug, Default)]
pub struct Stats {
    /// Requests received.
    pub requests: AtomicU64,
    /// Tokens that failed to open or validate.
    pub invalid: AtomicU64,
    /// Dropped by per-device limits.
    pub limited: AtomicU64,
    /// Delivered.
    pub delivered: AtomicU64,
    /// Delivery failures.
    pub failed: AtomicU64,
    /// Platform reported invalid device tokens.
    pub invalid_device: AtomicU64,
}

struct Inner {
    /// Newest first; older keys stay valid during rotation.
    keys: Vec<X25519Secret>,
    senders: Senders,
    limits: DeviceLimits,
    /// SHA-256 of device token → (last wake, window start, count in window). Memory only.
    devices: Mutex<HashMap<[u8; 32], (u64, u64, u32)>>,
    stats: Stats,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
}

/// Gateway state.
#[derive(Clone)]
pub struct Gateway {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Gateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Gateway")
    }
}

impl Gateway {
    /// Create a gateway. `keys` newest first (at least one).
    pub fn new(
        keys: Vec<X25519Secret>,
        senders: Senders,
        limits: DeviceLimits,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        Gateway {
            inner: Arc::new(Inner {
                keys,
                senders,
                limits,
                devices: Mutex::new(HashMap::new()),
                stats: Stats::default(),
                clock,
            }),
        }
    }

    /// Public keys to embed in wallet apps (base64url), newest first.
    pub fn public_keys(&self) -> Vec<String> {
        self.inner
            .keys
            .iter()
            .map(|k| b64::encode(&k.public_key()))
            .collect()
    }

    /// Counters.
    pub fn stats(&self) -> &Stats {
        &self.inner.stats
    }

    fn open(&self, sealed: &[u8], now: u64) -> Option<PushToken> {
        self.inner
            .keys
            .iter()
            .find_map(|k| PushToken::open(k, sealed, now).ok())
    }

    fn allow(&self, token: &PushToken, now: u64) -> bool {
        let key =
            crypto::sha256_parts(&[b"xchonnect gateway device", token.device_token.as_bytes()]);
        let l = self.inner.limits;
        let mut m = self
            .inner
            .devices
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if m.len() > 200_000 {
            m.retain(|_, (_, start, _)| now.saturating_sub(*start) < 3600);
        }
        let e = m.entry(key).or_insert((0, now, 0));
        if now.saturating_sub(e.1) >= 3600 {
            *e = (e.0, now, 0);
        }
        if (e.2 > 0 && now.saturating_sub(e.0) < l.min_interval_s) || e.2 >= l.per_hour {
            return false;
        }
        e.0 = now;
        e.2 += 1;
        true
    }

    /// Process one wake-up. Always succeeds from the caller's point of view.
    pub async fn wake(&self, sealed: &[u8]) {
        let s = &self.inner.stats;
        s.requests.fetch_add(1, Ordering::Relaxed);
        let now = (self.inner.clock)();
        let Some(token) = self.open(sealed, now) else {
            s.invalid.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if !self.allow(&token, now) {
            s.limited.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let Some(sender) = self.inner.senders.for_platform(token.platform) else {
            s.failed.fetch_add(1, Ordering::Relaxed);
            return;
        };
        match sender.send(&token).await {
            Ok(()) => s.delivered.fetch_add(1, Ordering::Relaxed),
            Err(SendError::InvalidToken) => s.invalid_device.fetch_add(1, Ordering::Relaxed),
            Err(_) => s.failed.fetch_add(1, Ordering::Relaxed),
        };
    }
}

#[derive(Deserialize)]
struct WakeBody {
    sealed_token: String,
}

/// Uniform response for every wake request (not an oracle).
fn accepted() -> Response {
    (
        StatusCode::ACCEPTED,
        [
            ("content-type", "application/json"),
            ("cache-control", "no-store"),
        ],
        "{}",
    )
        .into_response()
}

async fn wake(State(g): State<Gateway>, body: Bytes) -> Response {
    if body.len() <= MAX_SEALED * 2 {
        if let Ok(b) = serde_json::from_slice::<WakeBody>(&body) {
            if let Ok(sealed) = b64::decode(&b.sealed_token) {
                // Deliver in the background so timing does not reveal validity.
                let g2 = g.clone();
                tokio::spawn(async move { g2.wake(&sealed).await });
                return accepted();
            }
        }
    }
    g.inner.stats.requests.fetch_add(1, Ordering::Relaxed);
    g.inner.stats.invalid.fetch_add(1, Ordering::Relaxed);
    accepted()
}

async fn keys(State(g): State<Gateway>) -> Response {
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        serde_json::json!({ "keys": g.public_keys() }).to_string(),
    )
        .into_response()
}

async fn metrics(State(g): State<Gateway>) -> Response {
    let s = g.stats();
    let body = format!(
        "xchonnect_gateway_requests_total {}\nxchonnect_gateway_invalid_total {}\nxchonnect_gateway_limited_total {}\nxchonnect_gateway_delivered_total {}\nxchonnect_gateway_failed_total {}\nxchonnect_gateway_invalid_device_total {}\n",
        s.requests.load(Ordering::Relaxed),
        s.invalid.load(Ordering::Relaxed),
        s.limited.load(Ordering::Relaxed),
        s.delivered.load(Ordering::Relaxed),
        s.failed.load(Ordering::Relaxed),
        s.invalid_device.load(Ordering::Relaxed),
    );
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        body,
    )
        .into_response()
}

/// HTTP application.
pub fn app(g: Gateway) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/wake", post(wake))
        .route("/v1/keys", get(keys))
        .route("/metrics", get(metrics))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_SEALED * 2))
        .with_state(g)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use std::io::Write;
    use tower::ServiceExt;
    use xchonnect_core::crypto::OsEntropy;

    const NOW: u64 = 1_790_000_000;

    fn setup(now: Arc<AtomicU64>) -> (Gateway, Arc<CountingSender>, X25519Secret, X25519Secret) {
        let new_key = X25519Secret::from_bytes([1; 32]);
        let old_key = X25519Secret::from_bytes([2; 32]);
        let counter = Arc::new(CountingSender::default());
        let senders = Senders {
            apns: Some(counter.clone()),
            fcm: Some(counter.clone()),
            test: Some(counter.clone()),
        };
        let g = Gateway::new(
            vec![new_key.clone(), old_key.clone()],
            senders,
            DeviceLimits::default(),
            Arc::new(move || now.load(Ordering::Relaxed)),
        );
        (g, counter, new_key, old_key)
    }

    fn sealed(key: &X25519Secret, device: &str, exp: u64) -> Vec<u8> {
        PushToken {
            platform: Platform::Apns,
            device_token: device.into(),
            hint_key: [0; 32],
            exp,
        }
        .seal(&mut OsEntropy, &key.public_key(), NOW)
        .unwrap()
    }

    async fn post(g: &Gateway, body: String) -> (StatusCode, Vec<u8>) {
        let res = app(g.clone())
            .oneshot(
                Request::post("/v1/wake")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let st = res.status();
        (
            st,
            http_body_util::BodyExt::collect(res.into_body())
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
    }

    async fn settle() {
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    }

    #[tokio::test]
    async fn delivers_with_current_and_previous_key_and_limits_per_device() {
        let clock = Arc::new(AtomicU64::new(NOW));
        let (g, counter, new_key, old_key) = setup(clock.clone());
        g.wake(&sealed(&new_key, "dev-a", NOW + 3600)).await;
        g.wake(&sealed(&old_key, "dev-b", NOW + 3600)).await;
        assert_eq!(g.stats().delivered.load(Ordering::Relaxed), 2);
        // Replay of a sealed token within 10 s is dropped (spec 7.3.2).
        let s = sealed(&new_key, "dev-a", NOW + 3600);
        g.wake(&s).await;
        assert_eq!(g.stats().limited.load(Ordering::Relaxed), 1);
        clock.store(NOW + 11, Ordering::Relaxed);
        g.wake(&s).await;
        assert_eq!(g.stats().delivered.load(Ordering::Relaxed), 3);
        // Hourly cap.
        for i in 0..100 {
            clock.store(NOW + 22 + i * 11, Ordering::Relaxed);
            g.wake(&s).await;
        }
        assert!(g.stats().limited.load(Ordering::Relaxed) > 1);
        assert_eq!(
            counter.sent.lock().unwrap()["apns"],
            g.stats().delivered.load(Ordering::Relaxed)
        );
    }

    #[tokio::test]
    async fn invalid_tokens_get_the_same_response() {
        let clock = Arc::new(AtomicU64::new(NOW));
        let (g, _, new_key, _) = setup(clock);
        let good =
            serde_json::json!({ "sealed_token": b64::encode(&sealed(&new_key, "dev", NOW + 60)) })
                .to_string();
        let wrong_key = serde_json::json!({ "sealed_token": b64::encode(&sealed(&X25519Secret::from_bytes([3; 32]), "dev", NOW + 60)) }).to_string();
        let responses = [
            post(&g, good).await,
            post(&g, wrong_key).await,
            post(&g, "{bad".into()).await,
            post(&g, "{\"sealed_token\":\"!!\"}".into()).await,
        ];
        for r in &responses {
            assert_eq!(r, &responses[0]);
        }
        settle().await;
        assert_eq!(g.stats().delivered.load(Ordering::Relaxed), 1);
        assert_eq!(g.stats().invalid.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn device_tokens_never_reach_logs_or_metrics() {
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
        let cap = Capture::default();
        let w = cap.clone();
        let _guard = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::TRACE)
                .with_writer(move || w.clone())
                .finish(),
        );
        let clock = Arc::new(AtomicU64::new(NOW));
        let (g, _, new_key, _) = setup(clock);
        let device = "very-secret-device-token-0123456789";
        post(
            &g,
            serde_json::json!({ "sealed_token": b64::encode(&sealed(&new_key, device, NOW + 60)) })
                .to_string(),
        )
        .await;
        settle().await;
        let res = app(g.clone())
            .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let metrics = String::from_utf8(
            http_body_util::BodyExt::collect(res.into_body())
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        let logs = String::from_utf8(cap.0.lock().unwrap().clone()).unwrap();
        assert!(!logs.contains(device) && !metrics.contains(device));
        assert!(metrics.contains("xchonnect_gateway_delivered_total 1"));
    }

    #[tokio::test]
    async fn publishes_public_keys() {
        let (g, _, new_key, old_key) = setup(Arc::new(AtomicU64::new(NOW)));
        assert_eq!(
            g.public_keys(),
            vec![
                b64::encode(&new_key.public_key()),
                b64::encode(&old_key.public_key())
            ]
        );
    }
}
