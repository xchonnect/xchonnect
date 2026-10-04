//! Provider transport abstraction (spec 7.3, 7.3.2).
//!
//! Every outbound request to APNs, FCM and Google's token endpoint goes through
//! [`HttpTransport`], so the whole delivery path — request shape, auth tokens, retry,
//! backoff and error classification — is exercised in tests with no vendor credentials
//! and no network. [`Recorder`] is that test double; [`Https`] is the real client.
//!
//! The provider hosts are compile-time constants, never configuration: a wake request is
//! attacker-chosen input and the gateway must not be usable as a request forwarder
//! (spec 7.3.2 "MUST NOT follow URLs or fetch any resource on behalf of a wake request",
//! T21).

use async_trait::async_trait;
use std::sync::Mutex;
use std::time::Duration;

/// One outbound request. `url` is always built from a constant host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Absolute URL.
    pub url: String,
    /// Header names, lowercase, in the order the sender set them.
    pub headers: Vec<(String, String)>,
    /// Request body.
    pub body: Vec<u8>,
}

impl Request {
    /// The value of `name`, if set.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// The body as UTF-8, or `""` if it is not UTF-8.
    pub fn body_str(&self) -> &str {
        std::str::from_utf8(&self.body).unwrap_or_default()
    }
}

/// One response. Bodies are read bounded and only used for error classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// HTTP status.
    pub status: u16,
    /// `retry-after` in seconds, if the provider sent one.
    pub retry_after_s: Option<u64>,
    /// Response body, truncated to [`MAX_REPLY_BODY`].
    pub body: Vec<u8>,
}

impl Reply {
    /// A reply with just a status.
    pub fn status(status: u16) -> Self {
        Reply {
            status,
            retry_after_s: None,
            body: Vec::new(),
        }
    }

    /// A reply with a status and a JSON body.
    pub fn json(status: u16, body: &str) -> Self {
        Reply {
            status,
            retry_after_s: None,
            body: body.as_bytes().to_vec(),
        }
    }

    /// The body as UTF-8, or `""`.
    pub fn body_str(&self) -> &str {
        std::str::from_utf8(&self.body).unwrap_or_default()
    }
}

/// Transport failure. Carries no detail: provider error strings can echo request data,
/// and nothing here may reach a log (spec 13.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportError;

/// Largest response body the gateway reads from a provider.
pub const MAX_REPLY_BODY: usize = 4096;
/// Connect timeout for provider requests.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Total timeout for provider requests.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// An HTTPS POST transport.
#[async_trait]
pub trait HttpTransport: Send + Sync + 'static {
    /// POST `req` and return the reply.
    async fn post(&self, req: Request) -> Result<Reply, TransportError>;
}

/// How a provider reply is acted on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Accepted by the provider.
    Delivered,
    /// The provider says this device token is gone. Triggers the forget path.
    Invalid,
    /// Our auth token is stale: mint a new one and try once more.
    Reauth,
    /// Transient; retry after the given number of seconds, if the provider said.
    Retry(Option<u64>),
    /// Our configuration or payload is wrong. Retrying cannot help.
    Permanent,
}

/// Bounded retry with exponential backoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Total attempts, including the first.
    pub max_attempts: u32,
    /// Delay before the second attempt.
    pub base_delay: Duration,
    /// Cap for any single delay, including a provider `retry-after`.
    pub max_delay: Duration,
    /// Random spread added to each delay, in milliseconds. Zero makes it deterministic.
    pub jitter_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        RetryPolicy {
            max_attempts: 3,
            base_delay: Duration::from_millis(200),
            max_delay: Duration::from_secs(2),
            jitter_ms: 100,
        }
    }
}

impl RetryPolicy {
    /// Deterministic policy for tests.
    pub fn no_jitter() -> Self {
        RetryPolicy {
            jitter_ms: 0,
            ..RetryPolicy::default()
        }
    }

    /// Delay before attempt `attempt` (1-based: `attempt == 2` is the first retry).
    ///
    /// A provider `retry-after` wins but is still capped by `max_delay`, so a wake-up
    /// can never be held open longer than the gateway's own bound.
    pub fn delay(&self, attempt: u32, retry_after_s: Option<u64>) -> Duration {
        let base = match retry_after_s {
            Some(s) => Duration::from_secs(s),
            None => self
                .base_delay
                .saturating_mul(1u32 << attempt.saturating_sub(2).min(16)),
        };
        let jitter = if self.jitter_ms == 0 {
            0
        } else {
            let r: [u8; 8] =
                xchonnect_core::crypto::random_array(&mut xchonnect_core::crypto::OsEntropy);
            u64::from_be_bytes(r) % self.jitter_ms
        };
        base.min(self.max_delay)
            .saturating_add(Duration::from_millis(jitter))
    }
}

/// Suspends a task. Injected so retry backoff is instant and observable under test.
#[async_trait]
pub trait Sleeper: Send + Sync + 'static {
    /// Wait for `d`.
    async fn sleep(&self, d: Duration);
}

/// Real sleeping.
#[derive(Debug, Default, Clone, Copy)]
pub struct TokioSleeper;

#[async_trait]
impl Sleeper for TokioSleeper {
    async fn sleep(&self, d: Duration) {
        tokio::time::sleep(d).await;
    }
}

/// Records the backoff schedule instead of waiting.
#[derive(Debug, Default)]
pub struct RecordedSleeps {
    /// Every requested delay, in order.
    pub delays: Mutex<Vec<Duration>>,
}

#[async_trait]
impl Sleeper for RecordedSleeps {
    async fn sleep(&self, d: Duration) {
        crate::lock(&self.delays).push(d);
    }
}

/// Test double: records requests and replies from a queued script.
///
/// The queue is consumed front to back; once empty, [`Recorder::fallback`] is returned.
#[derive(Debug)]
pub struct Recorder {
    /// Requests seen, in order.
    pub requests: Mutex<Vec<Request>>,
    /// Replies still to be handed out.
    pub replies: Mutex<std::collections::VecDeque<Result<Reply, TransportError>>>,
    /// Reply used once `replies` is empty.
    pub fallback: Result<Reply, TransportError>,
}

impl Default for Recorder {
    fn default() -> Self {
        Recorder {
            requests: Mutex::default(),
            replies: Mutex::default(),
            fallback: Ok(Reply::status(200)),
        }
    }
}

impl Recorder {
    /// Recorder that always answers `reply`.
    pub fn always(reply: Reply) -> Self {
        Recorder {
            fallback: Ok(reply),
            ..Recorder::default()
        }
    }

    /// Recorder that answers `replies` in order, then 200.
    pub fn script(replies: Vec<Result<Reply, TransportError>>) -> Self {
        Recorder {
            replies: Mutex::new(replies.into()),
            ..Recorder::default()
        }
    }

    /// Queue another reply at the back.
    pub fn push(&self, reply: Result<Reply, TransportError>) {
        crate::lock(&self.replies).push_back(reply);
    }

    /// Requests seen so far.
    pub fn seen(&self) -> Vec<Request> {
        crate::lock(&self.requests).clone()
    }

    /// Number of requests seen.
    pub fn count(&self) -> usize {
        crate::lock(&self.requests).len()
    }

    /// The `n`th request, if any.
    pub fn nth(&self, n: usize) -> Option<Request> {
        crate::lock(&self.requests).get(n).cloned()
    }
}

#[async_trait]
impl HttpTransport for Recorder {
    async fn post(&self, req: Request) -> Result<Reply, TransportError> {
        crate::lock(&self.requests).push(req);
        crate::lock(&self.replies)
            .pop_front()
            .unwrap_or_else(|| self.fallback.clone())
    }
}

fn ensure_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // Ignore the error if the embedding application installed a provider already.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Real HTTPS transport: HTTP/2 over rustls, no redirects, no proxy, bounded timeouts
/// and a bounded response body.
pub struct Https {
    client: reqwest::Client,
}

impl std::fmt::Debug for Https {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Https")
    }
}

impl Https {
    /// Build the client. Fails only if the TLS stack cannot be initialised.
    pub fn new() -> Result<Self, TransportError> {
        ensure_crypto_provider();
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .no_proxy()
            .user_agent("xchonnect-gateway")
            .build()
            .map_err(|_| TransportError)?;
        Ok(Https { client })
    }
}

#[async_trait]
impl HttpTransport for Https {
    async fn post(&self, req: Request) -> Result<Reply, TransportError> {
        let mut r = self.client.post(&req.url);
        for (k, v) in &req.headers {
            r = r.header(k, v);
        }
        let res = r.body(req.body).send().await.map_err(|_| TransportError)?;
        let status = res.status().as_u16();
        let retry_after_s = res
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok());
        let mut body = res.bytes().await.map_err(|_| TransportError)?.to_vec();
        body.truncate(MAX_REPLY_BODY);
        Ok(Reply {
            status,
            retry_after_s,
            body,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn recorder_follows_its_script_then_falls_back() {
        let r = Recorder::script(vec![Ok(Reply::status(429)), Err(TransportError)]);
        let req = Request {
            url: "https://example.invalid/x".into(),
            headers: vec![("authorization".into(), "bearer t".into())],
            body: b"{}".to_vec(),
        };
        assert_eq!(r.post(req.clone()).await, Ok(Reply::status(429)));
        assert_eq!(r.post(req.clone()).await, Err(TransportError));
        assert_eq!(r.post(req.clone()).await, Ok(Reply::status(200)));
        assert_eq!(r.count(), 3);
        assert_eq!(r.nth(0).unwrap().header("authorization"), Some("bearer t"));
        assert_eq!(r.nth(0).unwrap().body_str(), "{}");
        assert_eq!(r.nth(9), None);
    }

    #[tokio::test]
    async fn recorded_sleeps_do_not_wait() {
        let s = RecordedSleeps::default();
        s.sleep(Duration::from_secs(3600)).await;
        assert_eq!(*crate::lock(&s.delays), vec![Duration::from_secs(3600)]);
    }

    #[test]
    fn the_real_client_builds() {
        assert!(Https::new().is_ok());
    }

    #[test]
    fn backoff_grows_is_capped_and_honours_retry_after() {
        let p = RetryPolicy::no_jitter();
        assert_eq!(p.delay(2, None), Duration::from_millis(200));
        assert_eq!(p.delay(3, None), Duration::from_millis(400));
        assert_eq!(p.delay(4, None), Duration::from_millis(800));
        assert_eq!(p.delay(9, None), p.max_delay, "capped");
        assert_eq!(p.delay(2, Some(1)), Duration::from_secs(1));
        assert_eq!(p.delay(2, Some(3600)), p.max_delay, "retry-after is capped");
        // Jitter stays inside the configured spread.
        let j = RetryPolicy::default();
        for _ in 0..50 {
            let d = j.delay(2, None);
            assert!(d >= Duration::from_millis(200) && d < Duration::from_millis(300));
        }
    }

    #[test]
    fn non_utf8_bodies_do_not_panic() {
        let req = Request {
            url: String::new(),
            headers: Vec::new(),
            body: vec![0xff, 0xfe],
        };
        assert_eq!(req.body_str(), "");
        assert_eq!(
            Reply {
                status: 1,
                retry_after_s: None,
                body: vec![0xff]
            }
            .body_str(),
            ""
        );
    }
}
