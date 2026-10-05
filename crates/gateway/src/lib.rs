//! Xchonnect reference push gateway (spec 7.3, 7.3.2).
//!
//! Run by each wallet vendor with its own APNs/FCM credentials. For every wake-up it:
//! opens the sealed token with its key, rate-limits per device in memory, hands the
//! token to the platform sender, and forgets it. It never sees mailbox ids or content,
//! never writes device tokens to disk or logs, and answers every request identically so
//! it is not an oracle for token validity.
//!
//! Delivery lives in [`apns`] and [`fcm`], both written against the [`http::HttpTransport`]
//! abstraction so request shape, auth tokens, retry, backoff and error classification are
//! covered by tests without vendor credentials or a network.

pub mod apns;
pub mod creds;
pub mod fcm;
pub mod http;

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
use tokio::sync::Semaphore;
use xchonnect_core::b64;
use xchonnect_core::crypto::{self, X25519Secret};
use xchonnect_core::preview;
use xchonnect_core::push::{MAX_SEALED, Platform, PushToken};

pub(crate) fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Delivery to a push platform.
#[async_trait]
pub trait PlatformSender: Send + Sync + 'static {
    /// Deliver a wake-up.
    ///
    /// `preview` is an opaque, already-encrypted notification preview (spec 7.3.3) that
    /// only the device can read; the gateway passes it through without interpreting it.
    /// Implementations must not log the device token.
    async fn send(&self, token: &PushToken, preview: Option<&[u8]>) -> Result<(), SendError>;
}

/// Delivery failure (counted, never stored with the token).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    /// The platform reports the device token as invalid or unregistered, or it could
    /// never be valid. Triggers the forget path: all state for it is dropped.
    InvalidToken,
    /// Platform not configured on this gateway.
    Unsupported,
    /// Transient failure.
    Temporary,
    /// Our configuration or payload is wrong; retrying cannot help.
    Permanent,
}

/// Sender that only counts deliveries (tests and `test` platform tokens).
#[derive(Debug, Default)]
pub struct CountingSender {
    /// Deliveries per platform name.
    pub sent: Mutex<HashMap<&'static str, u64>>,
    /// Previews seen, in order (always opaque to the gateway).
    pub previews: Mutex<Vec<Option<Vec<u8>>>>,
}

#[async_trait]
impl PlatformSender for CountingSender {
    async fn send(&self, token: &PushToken, preview: Option<&[u8]>) -> Result<(), SendError> {
        *lock(&self.sent).entry(token.platform.as_str()).or_default() += 1;
        lock(&self.previews).push(preview.map(<[u8]>::to_vec));
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
    /// Devices whose in-memory state was dropped by the forget path.
    pub forgotten: AtomicU64,
    /// Wake-ups that carried a preview the gateway passed through.
    pub previews: AtomicU64,
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
    /// Bounds background deliveries; requests beyond it are dropped (still 202).
    inflight: Arc<Semaphore>,
}

/// Concurrent background wake deliveries (like the relay's push dispatcher bound).
const MAX_INFLIGHT: usize = 256;

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
                devices: Mutex::default(),
                stats: Stats::default(),
                clock,
                inflight: Arc::new(Semaphore::new(MAX_INFLIGHT)),
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

    /// In-memory rate-limit key for a device. The device token itself is never stored.
    fn device_key(token: &PushToken) -> [u8; 32] {
        crypto::sha256_parts(&[b"xchonnect gateway device", token.device_token.as_bytes()])
    }

    /// The forget path (spec 7.3): once a platform says a device token is gone, every
    /// trace of it leaves the gateway. Nothing is written anywhere, so forgetting is
    /// dropping the one piece of in-memory state the token had: its rate-limit entry.
    fn forget(&self, token: &PushToken) {
        if lock(&self.inner.devices)
            .remove(&Self::device_key(token))
            .is_some()
        {
            self.inner.stats.forgotten.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn allow(&self, token: &PushToken, now: u64) -> bool {
        let key = Self::device_key(token);
        let l = self.inner.limits;
        let mut m = lock(&self.inner.devices);
        if m.len() > 200_000 {
            m.retain(|_, (_, start, _)| now.saturating_sub(*start) < 3600);
        }
        let fresh = !m.contains_key(&key);
        let e = m.entry(key).or_insert((0, now, 0));
        if now.saturating_sub(e.1) >= 3600 {
            *e = (e.0, now, 0);
        }
        // The minimum interval applies across hourly window resets (spec 7.3.2).
        if (!fresh && now.saturating_sub(e.0) < l.min_interval_s) || e.2 >= l.per_hour {
            return false;
        }
        e.0 = now;
        e.2 += 1;
        true
    }

    /// Process one wake-up. Always succeeds from the caller's point of view.
    ///
    /// `preview` is an optional encrypted notification preview (spec 7.3.3), opaque to
    /// the gateway and bounded to exactly [`preview::SEALED_LEN`] bytes by the caller.
    pub async fn wake(&self, sealed: &[u8], preview: Option<&[u8]>) {
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
        if preview.is_some() {
            s.previews.fetch_add(1, Ordering::Relaxed);
        }
        match sender.send(&token, preview).await {
            Ok(()) => s.delivered.fetch_add(1, Ordering::Relaxed),
            Err(SendError::InvalidToken) => {
                // The platform says this device is gone: forget it (spec 7.3). The
                // result is never reported in the response, which stays uniform so the
                // gateway is not an oracle for token validity (spec 7.3.2).
                self.forget(&token);
                s.invalid_device.fetch_add(1, Ordering::Relaxed)
            }
            Err(_) => s.failed.fetch_add(1, Ordering::Relaxed),
        };
    }
}

#[derive(Deserialize)]
struct WakeBody {
    sealed_token: String,
    /// Optional encrypted preview (spec 7.3.3), base64url. Absent from relay wake-ups
    /// today; accepted so a relay that forwards one needs no gateway change.
    #[serde(default)]
    preview: Option<String>,
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
    let parsed = (body.len() <= MAX_SEALED * 2)
        .then(|| serde_json::from_slice::<WakeBody>(&body).ok())
        .flatten();
    let sealed = parsed.as_ref().and_then(|b| {
        let sealed = b64::decode(&b.sealed_token).ok()?;
        // An encrypted preview is exactly one size (spec 7.3.3); anything else is
        // dropped rather than forwarded, and a bad preview never costs the wake-up.
        let preview = b
            .preview
            .as_deref()
            .and_then(|p| b64::decode(p).ok())
            .filter(|p| p.len() == preview::SEALED_LEN);
        Some((sealed, preview))
    });
    if let Some((sealed, preview)) = sealed {
        // Deliver in the background so timing does not reveal validity; bounded so a
        // flood of junk tokens cannot spawn unlimited tasks.
        match g.inner.inflight.clone().try_acquire_owned() {
            Ok(permit) => {
                tokio::spawn(async move {
                    g.wake(&sealed, preview.as_deref()).await;
                    drop(permit);
                });
            }
            Err(_) => {
                g.inner.stats.requests.fetch_add(1, Ordering::Relaxed);
                g.inner.stats.limited.fetch_add(1, Ordering::Relaxed);
            }
        }
    } else {
        g.inner.stats.requests.fetch_add(1, Ordering::Relaxed);
        g.inner.stats.invalid.fetch_add(1, Ordering::Relaxed);
    }
    accepted()
}

async fn keys(State(g): State<Gateway>) -> Response {
    let body = serde_json::json!({ "keys": g.public_keys() }).to_string();
    ([("content-type", "application/json")], body).into_response()
}

async fn metrics(State(g): State<Gateway>) -> Response {
    let s = g.stats();
    let mut body = String::new();
    for (name, n) in [
        ("requests", &s.requests),
        ("invalid", &s.invalid),
        ("limited", &s.limited),
        ("delivered", &s.delivered),
        ("failed", &s.failed),
        ("invalid_device", &s.invalid_device),
        ("forgotten", &s.forgotten),
        ("previews", &s.previews),
    ] {
        let n = n.load(Ordering::Relaxed);
        body.push_str(&format!("xchonnect_gateway_{name}_total {n}\n"));
    }
    ([("content-type", "text/plain; version=0.0.4")], body).into_response()
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

    type Setup = (
        Gateway,
        Arc<CountingSender>,
        X25519Secret,
        X25519Secret,
        Arc<AtomicU64>,
    );

    /// Gateway with a current and a previous key, a counting sender and a settable clock.
    fn setup() -> Setup {
        let new_key = X25519Secret::from_bytes([1; 32]);
        let old_key = X25519Secret::from_bytes([2; 32]);
        let counter = Arc::new(CountingSender::default());
        let senders = Senders {
            apns: Some(counter.clone()),
            fcm: Some(counter.clone()),
            test: Some(counter.clone()),
        };
        let clock = Arc::new(AtomicU64::new(NOW));
        let c = clock.clone();
        let now = Arc::new(move || c.load(Ordering::Relaxed));
        let keys = vec![new_key.clone(), old_key.clone()];
        let g = Gateway::new(keys, senders, DeviceLimits::default(), now);
        (g, counter, new_key, old_key, clock)
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

    fn wake_body(sealed: &[u8]) -> String {
        serde_json::json!({ "sealed_token": b64::encode(sealed) }).to_string()
    }

    async fn call(g: &Gateway, req: Request<Body>) -> (StatusCode, Vec<u8>) {
        let res = app(g.clone()).oneshot(req).await.unwrap();
        let st = res.status();
        let body = http_body_util::BodyExt::collect(res.into_body())
            .await
            .unwrap();
        (st, body.to_bytes().to_vec())
    }

    async fn post(g: &Gateway, body: String) -> (StatusCode, Vec<u8>) {
        let req = Request::post("/v1/wake").header("content-type", "application/json");
        call(g, req.body(Body::from(body)).unwrap()).await
    }

    async fn settle() {
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    }

    #[tokio::test]
    async fn delivers_with_current_and_previous_key_and_limits_per_device() {
        let (g, counter, new_key, old_key, clock) = setup();
        let stat = |s: &AtomicU64| s.load(Ordering::Relaxed);
        g.wake(&sealed(&new_key, "dev-a", NOW + 3600), None).await;
        g.wake(&sealed(&old_key, "dev-b", NOW + 3600), None).await;
        assert_eq!(stat(&g.stats().delivered), 2);
        // Replay of a sealed token within 10 s is dropped (spec 7.3.2).
        let s = sealed(&new_key, "dev-a", NOW + 3600);
        g.wake(&s, None).await;
        assert_eq!(stat(&g.stats().limited), 1);
        clock.store(NOW + 11, Ordering::Relaxed);
        g.wake(&s, None).await;
        assert_eq!(stat(&g.stats().delivered), 3);
        // Hourly cap.
        for i in 0..100 {
            clock.store(NOW + 22 + i * 11, Ordering::Relaxed);
            g.wake(&s, None).await;
        }
        assert!(stat(&g.stats().limited) > 1);
        let apns = counter.sent.lock().unwrap()["apns"];
        assert_eq!(apns, stat(&g.stats().delivered));
    }

    #[tokio::test]
    async fn minimum_interval_holds_across_the_hourly_window_reset() {
        let (g, _, key, _, clock) = setup();
        let s = sealed(&key, "dev-a", NOW + 7200);
        g.wake(&s, None).await;
        clock.store(NOW + 3599, Ordering::Relaxed);
        g.wake(&s, None).await;
        // One second later the hourly window resets, but 10 s have not passed.
        clock.store(NOW + 3600, Ordering::Relaxed);
        g.wake(&s, None).await;
        let st = g.stats();
        assert_eq!(st.delivered.load(Ordering::Relaxed), 2);
        assert_eq!(st.limited.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn background_deliveries_are_bounded() {
        let (g, counter, key, _, _) = setup();
        let held = g
            .inner
            .inflight
            .clone()
            .acquire_many_owned(MAX_INFLIGHT as u32)
            .await;
        let (st, body) = post(&g, wake_body(&sealed(&key, "dev-a", NOW + 3600))).await;
        assert_eq!(
            (st, body.as_slice()),
            (StatusCode::ACCEPTED, b"{}".as_slice())
        );
        settle().await;
        assert_eq!(g.stats().limited.load(Ordering::Relaxed), 1);
        assert!(counter.sent.lock().unwrap().is_empty());
        drop(held);
        post(&g, wake_body(&sealed(&key, "dev-a", NOW + 3600))).await;
        settle().await;
        assert_eq!(g.stats().delivered.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn invalid_tokens_get_the_same_response() {
        let (g, _, new_key, _, _) = setup();
        let wrong_key = X25519Secret::from_bytes([3; 32]);
        let responses = [
            post(&g, wake_body(&sealed(&new_key, "dev", NOW + 60))).await,
            post(&g, wake_body(&sealed(&wrong_key, "dev", NOW + 60))).await,
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
        let (g, _, new_key, _, _) = setup();
        let device = "very-secret-device-token-0123456789";
        post(&g, wake_body(&sealed(&new_key, device, NOW + 60))).await;
        settle().await;
        let (_, metrics) = call(&g, Request::get("/metrics").body(Body::empty()).unwrap()).await;
        let metrics = String::from_utf8(metrics).unwrap();
        let logs = String::from_utf8(cap.0.lock().unwrap().clone()).unwrap();
        assert!(!logs.contains(device) && !metrics.contains(device));
        assert!(metrics.contains("xchonnect_gateway_delivered_total 1"));
    }

    #[tokio::test]
    async fn publishes_public_keys() {
        let (g, _, new_key, old_key, _) = setup();
        let expected = [new_key, old_key].map(|k| b64::encode(&k.public_key()));
        assert_eq!(g.public_keys(), expected);
    }

    /// Sender that always reports the device token as gone.
    #[derive(Debug, Default)]
    struct DeadDevice(AtomicU64);

    #[async_trait]
    impl PlatformSender for DeadDevice {
        async fn send(&self, _t: &PushToken, _p: Option<&[u8]>) -> Result<(), SendError> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Err(SendError::InvalidToken)
        }
    }

    #[tokio::test]
    async fn an_invalidated_token_is_forgotten_and_never_reported_in_the_response() {
        let key = X25519Secret::from_bytes([1; 32]);
        let dead = Arc::new(DeadDevice::default());
        let senders = Senders {
            apns: Some(dead.clone()),
            ..Senders::default()
        };
        let clock = Arc::new(AtomicU64::new(NOW));
        let c = clock.clone();
        let g = Gateway::new(
            vec![key.clone()],
            senders,
            DeviceLimits::default(),
            Arc::new(move || c.load(Ordering::Relaxed)),
        );
        let s = sealed(&key, "dev-gone", NOW + 3600);
        let dead_response = post(&g, wake_body(&s)).await;
        settle().await;
        let st = g.stats();
        assert_eq!(st.invalid_device.load(Ordering::Relaxed), 1);
        assert_eq!(st.forgotten.load(Ordering::Relaxed), 1, "state dropped");
        assert_eq!(st.delivered.load(Ordering::Relaxed), 0);
        // Nothing about the device is left behind: no rate-limit entry, no token.
        assert!(lock(&g.inner.devices).is_empty());
        // The response is the same as for a healthy device, so it is not an oracle.
        let (g2, _, k2, _, _) = setup();
        let live_response = post(&g2, wake_body(&sealed(&k2, "dev-live", NOW + 3600))).await;
        settle().await;
        assert_eq!(dead_response, live_response);
        // Because the entry is gone, the next wake is not rate-limited away: the device
        // gets one more chance after re-registration rather than being silently muted.
        post(&g, wake_body(&s)).await;
        settle().await;
        assert_eq!(dead.0.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn previews_are_passed_through_opaquely_and_strictly_bounded() {
        let (g, counter, key, _, _) = setup();
        let hint = [4u8; 32];
        let good = xchonnect_core::preview::seal(
            &mut OsEntropy,
            &hint,
            &xchonnect_core::preview::Preview::default(),
            NOW,
            60,
        )
        .unwrap();
        let body = |sealed: &[u8], p: &[u8]| {
            serde_json::json!({
                "sealed_token": b64::encode(sealed),
                "preview": b64::encode(p),
            })
            .to_string()
        };
        let s = sealed(&key, "dev-a", NOW + 3600);
        let with_preview = post(&g, body(&s, &good)).await;
        settle().await;
        assert_eq!(lock(&counter.previews).as_slice(), [Some(good.clone())]);
        assert_eq!(g.stats().previews.load(Ordering::Relaxed), 1);
        // The response does not change, with or without a preview.
        assert_eq!(with_preview, post(&g, wake_body(&s)).await);
        // Wrong-size or unparseable previews are dropped; the wake-up still happens.
        for (i, bad) in [vec![0u8; 1], vec![0u8; 169], Vec::new()]
            .into_iter()
            .enumerate()
        {
            let clock_free = sealed(&key, &format!("dev-{i}"), NOW + 3600);
            post(&g, body(&clock_free, &bad)).await;
            settle().await;
        }
        let seen = lock(&counter.previews).clone();
        assert_eq!(
            seen.iter().filter(|p| p.is_some()).count(),
            1,
            "only the correctly sized preview was forwarded"
        );
        assert_eq!(g.stats().previews.load(Ordering::Relaxed), 1);
        assert!(g.stats().delivered.load(Ordering::Relaxed) >= 4);
        // A preview field that is not base64url does not cost the wake-up either.
        let before = g.stats().delivered.load(Ordering::Relaxed);
        let raw = format!(
            "{{\"sealed_token\":\"{}\",\"preview\":\"!!!\"}}",
            b64::encode(&sealed(&key, "dev-raw", NOW + 3600))
        );
        post(&g, raw).await;
        settle().await;
        assert_eq!(g.stats().delivered.load(Ordering::Relaxed), before + 1);
    }
}
