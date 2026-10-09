//! FCM delivery (spec 7.3; stack doc 2.4).
//!
//! FCM HTTP v1 high-priority **data** messages: there is no `notification` block, so the
//! app's own data handler decides what to show and can decrypt an encrypted preview
//! (spec 7.3.3). The data is content-free — a constant marker plus, optionally, the
//! opaque preview — so Google learns only that a push happened (T11) and the payload can
//! never drive a signing decision (T12).
//!
//! Authentication is an OAuth 2.0 access token obtained with a service-account JWT
//! assertion and cached until shortly before it expires. The send host and the token
//! endpoint are constants, so nothing in a wake request can redirect either (spec 7.3.2,
//! T21).

use crate::creds::{GOOGLE_TOKEN_URI, ServiceAccount, Signer, jwt};
use crate::http::{Class, HttpTransport, Reply, Request, RetryPolicy, Sleeper};
use crate::{PlatformSender, SendError};
use async_trait::async_trait;
use std::sync::Arc;
use xchonnect_core::b64;
use xchonnect_core::push::{Platform, PushToken};

/// FCM HTTP v1 host.
pub const SEND_HOST: &str = "fcm.googleapis.com";
/// OAuth scope needed to send messages.
pub const SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
/// Largest FCM message body.
pub const MAX_PAYLOAD: usize = 4096;
/// Data key carrying the encrypted preview (spec 7.3.3).
pub const PREVIEW_KEY: &str = "xcp";
/// Data key marking a wake-up.
pub const MARKER_KEY: &str = "xck";
/// Value of [`MARKER_KEY`].
pub const MARKER: &str = "wake";
/// Refresh an access token this long before it expires.
pub const REFRESH_MARGIN_S: u64 = 300;
/// Lifetime requested for the assertion.
pub const ASSERTION_LIFETIME_S: u64 = 3600;

/// Supplies OAuth 2.0 access tokens for FCM.
#[async_trait]
pub trait AccessTokens: Send + Sync + 'static {
    /// A usable access token at `now`. `force` discards any cached one (after a 401).
    async fn token(&self, now: u64, force: bool) -> Result<Arc<str>, SendError>;
}

/// A token minted elsewhere (a sidecar, or `gcloud` in development). Never refreshed.
pub struct StaticToken(Arc<str>);

impl std::fmt::Debug for StaticToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StaticToken([redacted])")
    }
}

impl StaticToken {
    /// Wrap a token.
    pub fn new(token: &str) -> Self {
        StaticToken(token.into())
    }
}

#[async_trait]
impl AccessTokens for StaticToken {
    async fn token(&self, _now: u64, _force: bool) -> Result<Arc<str>, SendError> {
        Ok(self.0.clone())
    }
}

/// Whether an access token is safe to put in an `authorization` header.
fn access_token_is_valid(t: &str) -> bool {
    (16..=4096).contains(&t.len()) && t.chars().all(|c| c.is_ascii_graphic())
}

/// Access tokens from a service account, cached and refreshed before expiry.
pub struct ServiceAccountTokens {
    account: ServiceAccount,
    signer: Arc<dyn Signer>,
    http: Arc<dyn HttpTransport>,
    /// Token and its expiry. An async mutex makes the refresh single-flight: concurrent
    /// wake-ups mint one assertion, not one each.
    cached: tokio::sync::Mutex<Option<(Arc<str>, u64)>>,
    /// Assertions minted (observability; never includes the token itself).
    pub minted: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for ServiceAccountTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceAccountTokens")
            .field("client_email", &self.account.client_email)
            .finish_non_exhaustive()
    }
}

impl ServiceAccountTokens {
    /// Build a token source for `account`, signing assertions with `signer`.
    pub fn new(
        account: ServiceAccount,
        signer: Arc<dyn Signer>,
        http: Arc<dyn HttpTransport>,
    ) -> Self {
        ServiceAccountTokens {
            account,
            signer,
            http,
            cached: tokio::sync::Mutex::new(None),
            minted: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// The project the account belongs to.
    pub fn project_id(&self) -> &str {
        &self.account.project_id
    }

    /// The assertion sent to Google's token endpoint.
    pub fn assertion(&self, now: u64) -> Result<String, SendError> {
        let claims = serde_json::json!({
            "iss": self.account.client_email,
            "scope": SCOPE,
            "aud": GOOGLE_TOKEN_URI,
            "iat": now,
            "exp": now.saturating_add(ASSERTION_LIFETIME_S),
        });
        // A signing failure is a configuration problem; the error is a fixed label so no
        // key material can reach a log.
        jwt(self.signer.as_ref(), &claims).map_err(|_| SendError::Permanent)
    }
}

#[async_trait]
impl AccessTokens for ServiceAccountTokens {
    async fn token(&self, now: u64, force: bool) -> Result<Arc<str>, SendError> {
        let mut cached = self.cached.lock().await;
        if !force {
            if let Some((t, exp)) = cached.as_ref() {
                if now.saturating_add(REFRESH_MARGIN_S) < *exp {
                    return Ok(t.clone());
                }
            }
        }
        let body = format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={}",
            self.assertion(now)?
        );
        let reply = self
            .http
            .post(Request {
                url: GOOGLE_TOKEN_URI.to_owned(),
                headers: vec![(
                    "content-type".into(),
                    "application/x-www-form-urlencoded".into(),
                )],
                body: body.into_bytes(),
            })
            .await
            .map_err(|_| SendError::Temporary)?;
        self.minted
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if !(200..=299).contains(&reply.status) {
            // A rejected assertion is a configuration problem; everything else is an
            // outage at Google.
            return Err(match reply.status {
                400 | 401 | 403 => SendError::Permanent,
                _ => SendError::Temporary,
            });
        }
        let parsed: serde_json::Value =
            serde_json::from_slice(&reply.body).map_err(|_| SendError::Temporary)?;
        let token = parsed
            .get("access_token")
            .and_then(|v| v.as_str())
            .filter(|t| access_token_is_valid(t))
            .ok_or(SendError::Temporary)?;
        let ttl = parsed
            .get("expires_in")
            .and_then(serde_json::Value::as_u64)
            .filter(|s| (60..=86_400).contains(s))
            .ok_or(SendError::Temporary)?;
        let token: Arc<str> = token.into();
        *cached = Some((token.clone(), now.saturating_add(ttl)));
        Ok(token)
    }
}

/// FCM sender configuration. No endpoint URL: see [`SEND_HOST`].
#[derive(Debug, Clone)]
pub struct Config {
    /// Firebase project id, from the service account.
    pub project_id: String,
    /// `android.ttl` (default 600 s, as long as messages live on the relay). A wake-up
    /// that cannot be delivered in this window is dropped.
    pub ttl_s: u64,
    /// Retry and backoff bounds.
    pub retry: RetryPolicy,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            project_id: String::new(),
            ttl_s: 600,
            retry: RetryPolicy::default(),
        }
    }
}

impl Config {
    /// Reject configuration that could not produce a valid request.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !crate::creds::project_id_is_valid(&self.project_id) {
            return Err("FCM project_id must be a Google project id");
        }
        if !(1..=86_400).contains(&self.ttl_s) {
            return Err("FCM ttl_s must be between 1 s and 24 h");
        }
        Ok(())
    }
}

/// Whether a registration token is safe to send.
pub fn device_token_is_valid(t: &str) -> bool {
    (32..=1024).contains(&t.len()) && t.chars().all(|c| c.is_ascii_graphic())
}

/// Classify an FCM reply from its status, `error.details[].errorCode` and
/// `error.message`.
pub fn classify(status: u16, error_code: &str, message: &str) -> Class {
    let about_the_token = message.to_ascii_lowercase().contains("registration token");
    match (status, error_code) {
        (200..=299, _) => Class::Delivered,
        (_, "UNREGISTERED" | "SENDER_ID_MISMATCH") => Class::Invalid,
        (404, _) => Class::Invalid,
        (400, _) if about_the_token => Class::Invalid,
        (_, "UNAVAILABLE" | "INTERNAL" | "QUOTA_EXCEEDED") => Class::Retry(None),
        (401, _) => Class::Reauth,
        (429 | 500 | 502 | 503 | 504, _) => Class::Retry(None),
        _ => Class::Permanent,
    }
}

/// `(errorCode, message)` from an FCM error body. Total: anything unexpected yields
/// empty strings.
fn error_of(reply: &Reply) -> (String, String) {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&reply.body) else {
        return (String::new(), String::new());
    };
    let error = v.get("error");
    let message = error
        .and_then(|e| e.get("message"))
        .and_then(|m| m.as_str())
        .unwrap_or_default();
    let code = error
        .and_then(|e| e.get("details"))
        .and_then(|d| d.as_array())
        .into_iter()
        .flatten()
        .find_map(|d| d.get("errorCode").and_then(|c| c.as_str()))
        .unwrap_or_default();
    (code.to_owned(), message.to_owned())
}

/// Delivers wake-ups to FCM.
pub struct Sender {
    config: Config,
    tokens: Arc<dyn AccessTokens>,
    http: Arc<dyn HttpTransport>,
    sleeper: Arc<dyn Sleeper>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl std::fmt::Debug for Sender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FcmSender")
            .field("project_id", &self.config.project_id)
            .finish_non_exhaustive()
    }
}

impl Sender {
    /// Build a sender. Returns the configuration problem if there is one.
    pub fn new(
        config: Config,
        tokens: Arc<dyn AccessTokens>,
        http: Arc<dyn HttpTransport>,
        sleeper: Arc<dyn Sleeper>,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Result<Self, &'static str> {
        config.validate()?;
        Ok(Sender {
            config,
            tokens,
            http,
            sleeper,
            clock,
        })
    }

    /// The message body. Everything except the registration token and the optional
    /// preview is constant.
    pub fn body(&self, device_token: &str, preview: Option<&[u8]>) -> Vec<u8> {
        let build = |preview: Option<&[u8]>| {
            let mut data = serde_json::Map::new();
            data.insert(MARKER_KEY.into(), serde_json::json!(MARKER));
            if let Some(p) = preview {
                data.insert(PREVIEW_KEY.into(), serde_json::json!(b64::encode(p)));
            }
            serde_json::to_vec(&serde_json::json!({ "message": {
                "token": device_token,
                "android": { "priority": "HIGH", "ttl": format!("{}s", self.config.ttl_s) },
                "data": data,
            }}))
            .unwrap_or_default()
        };
        let out = build(preview);
        if out.len() <= MAX_PAYLOAD {
            return out;
        }
        // Too large with the preview: send the wake-up anyway; the app shows the generic
        // alert (spec 7.3.3).
        build(None)
    }

    fn request(&self, device_token: &str, access: &str, preview: Option<&[u8]>) -> Request {
        Request {
            url: format!(
                "https://{SEND_HOST}/v1/projects/{}/messages:send",
                self.config.project_id
            ),
            headers: vec![
                ("authorization".into(), format!("Bearer {access}")),
                ("content-type".into(), "application/json".into()),
            ],
            body: self.body(device_token, preview),
        }
    }
}

#[async_trait]
impl PlatformSender for Sender {
    async fn send(&self, token: &PushToken, preview: Option<&[u8]>) -> Result<(), SendError> {
        if token.platform != Platform::Fcm {
            return Err(SendError::Unsupported);
        }
        if !device_token_is_valid(&token.device_token) {
            // Not a token FCM could ever accept: forget it like an unregistered one.
            return Err(SendError::InvalidToken);
        }
        let mut force = false;
        let mut reauths = 0u32;
        for attempt in 1..=self.config.retry.max_attempts {
            let now = (self.clock)();
            let access = self.tokens.token(now, force).await?;
            force = false;
            let req = self.request(&token.device_token, &access, preview);
            let class = match self.http.post(req).await {
                Ok(reply) => {
                    let (code, message) = error_of(&reply);
                    match classify(reply.status, &code, &message) {
                        Class::Retry(None) => Class::Retry(reply.retry_after_s),
                        other => other,
                    }
                }
                // A network failure says nothing about the registration token.
                Err(_) => Class::Retry(None),
            };
            match class {
                Class::Delivered => return Ok(()),
                Class::Invalid => return Err(SendError::InvalidToken),
                Class::Permanent => return Err(SendError::Permanent),
                Class::Reauth if reauths == 0 => {
                    reauths += 1;
                    force = true;
                }
                Class::Reauth => return Err(SendError::Temporary),
                Class::Retry(after) => {
                    if attempt == self.config.retry.max_attempts {
                        break;
                    }
                    self.sleeper
                        .sleep(self.config.retry.delay(attempt + 1, after))
                        .await;
                }
            }
        }
        Err(SendError::Temporary)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::creds::TestSigner;
    use crate::creds::tests::segment;
    use crate::http::{RecordedSleeps, Recorder, TransportError};
    use crate::lock;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    const NOW: u64 = 1_790_000_000;
    const DEVICE: &str =
        "fMEP0vJqSBC1a2b3c4d5e6:APA91bHZq0w9e8r7t6y5u4i3o2p1aSdFgHjKlZxCvBnM0987654321";

    fn config() -> Config {
        Config {
            project_id: "klimper-wallet".into(),
            retry: RetryPolicy::no_jitter(),
            ..Config::default()
        }
    }

    struct Rig {
        sender: Sender,
        http: Arc<Recorder>,
        sleeps: Arc<RecordedSleeps>,
    }

    fn rig_with(config: Config, http: Recorder, tokens: Arc<dyn AccessTokens>) -> Rig {
        let http = Arc::new(http);
        let sleeps = Arc::new(RecordedSleeps::default());
        let sender = Sender::new(
            config,
            tokens,
            http.clone(),
            sleeps.clone(),
            Arc::new(|| NOW),
        )
        .unwrap();
        Rig {
            sender,
            http,
            sleeps,
        }
    }

    fn rig(http: Recorder) -> Rig {
        rig_with(
            config(),
            http,
            Arc::new(StaticToken::new("ya29.test-access-token")),
        )
    }

    fn token(platform: Platform, device: &str) -> PushToken {
        PushToken {
            platform,
            device_token: device.into(),
            hint_key: [3; 32],
            exp: NOW + 3600,
        }
    }

    fn fcm_error(status: u16, code: &str, message: &str) -> Reply {
        Reply::json(
            status,
            &serde_json::json!({ "error": {
                "code": status, "message": message, "status": "ERROR",
                "details": [{
                    "@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError",
                    "errorCode": code,
                }],
            }})
            .to_string(),
        )
    }

    fn account() -> ServiceAccount {
        ServiceAccount {
            client_email: "push@klimper-wallet.iam.gserviceaccount.com".into(),
            project_id: "klimper-wallet".into(),
        }
    }

    fn token_reply(token: &str, expires_in: u64) -> Reply {
        Reply::json(
            200,
            &serde_json::json!({
                "access_token": token, "expires_in": expires_in, "token_type": "Bearer",
            })
            .to_string(),
        )
    }

    #[tokio::test]
    async fn request_shape_matches_the_fcm_http_v1_api() {
        let r = rig(Recorder::always(Reply::json(
            200,
            "{\"name\":\"projects/x/messages/1\"}",
        )));
        assert_eq!(
            r.sender.send(&token(Platform::Fcm, DEVICE), None).await,
            Ok(())
        );
        let req = r.http.nth(0).unwrap();
        assert_eq!(
            req.url,
            "https://fcm.googleapis.com/v1/projects/klimper-wallet/messages:send"
        );
        assert_eq!(
            req.header("authorization"),
            Some("Bearer ya29.test-access-token")
        );
        assert_eq!(req.header("content-type"), Some("application/json"));
        let v: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
        assert_eq!(
            v,
            serde_json::json!({ "message": {
                "token": DEVICE,
                "android": { "priority": "HIGH", "ttl": "600s" },
                "data": { "xck": "wake" },
            }})
        );
        assert_eq!(v["message"].get("notification"), None, "data-only message");
    }

    #[tokio::test]
    async fn the_data_payload_carries_nothing_but_the_marker_and_an_opaque_preview() {
        let r = rig(Recorder::always(Reply::status(200)));
        let preview = [9u8; xchonnect_core::preview::SEALED_LEN];
        r.sender
            .send(&token(Platform::Fcm, DEVICE), Some(&preview))
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&r.http.nth(0).unwrap().body).unwrap();
        assert_eq!(
            v["message"]["data"][PREVIEW_KEY],
            serde_json::json!(b64::encode(&preview))
        );
        let text = String::from_utf8(r.http.nth(0).unwrap().body).unwrap();
        for leak in ["xch1", "XCH", "mailbox"] {
            assert!(!text.contains(leak), "{leak} must not be in the payload");
        }
        // An oversize preview is dropped instead of failing the wake-up.
        let body = r.sender.body(DEVICE, Some(&vec![0u8; MAX_PAYLOAD]));
        assert!(body.len() <= MAX_PAYLOAD);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["message"]["data"].get(PREVIEW_KEY), None);
    }

    #[tokio::test]
    async fn only_fcm_tokens_and_only_sane_ones_are_sent() {
        let r = rig(Recorder::always(Reply::status(200)));
        for p in [Platform::Apns, Platform::ApnsSandbox, Platform::Test] {
            assert_eq!(
                r.sender.send(&token(p, DEVICE), None).await,
                Err(SendError::Unsupported)
            );
        }
        for bad in [
            "",
            "short",
            &"a".repeat(1025),
            &format!("{DEVICE} x"),
            "a\nb",
        ] {
            assert_eq!(
                r.sender.send(&token(Platform::Fcm, bad), None).await,
                Err(SendError::InvalidToken),
                "{bad:?}"
            );
        }
        assert_eq!(r.http.count(), 0);
        assert!(device_token_is_valid(DEVICE));
    }

    #[tokio::test]
    async fn google_error_responses_are_classified() {
        for (status, code, message, want) in [
            (200, "", "", Class::Delivered),
            (
                404,
                "UNREGISTERED",
                "Requested entity was not found.",
                Class::Invalid,
            ),
            (404, "", "", Class::Invalid),
            (403, "SENDER_ID_MISMATCH", "", Class::Invalid),
            (
                400,
                "INVALID_ARGUMENT",
                "The registration token is not a valid FCM registration token",
                Class::Invalid,
            ),
            (
                400,
                "INVALID_ARGUMENT",
                "Invalid JSON payload",
                Class::Permanent,
            ),
            (
                401,
                "",
                "Request had invalid authentication credentials.",
                Class::Reauth,
            ),
            (403, "", "Permission denied", Class::Permanent),
            (429, "QUOTA_EXCEEDED", "", Class::Retry(None)),
            (429, "", "", Class::Retry(None)),
            (500, "INTERNAL", "", Class::Retry(None)),
            (503, "UNAVAILABLE", "", Class::Retry(None)),
            (400, "THIRD_PARTY_AUTH_ERROR", "", Class::Permanent),
        ] {
            assert_eq!(classify(status, code, message), want, "{status} {code}");
        }
        // The error parser is total.
        for body in [
            "",
            "{",
            "null",
            "[]",
            "{\"error\":5}",
            "{\"error\":{\"details\":{}}}",
        ] {
            assert_eq!(
                error_of(&Reply::json(400, body)),
                (String::new(), String::new())
            );
        }
    }

    #[tokio::test]
    async fn unregistered_tokens_stop_immediately() {
        let r = rig(Recorder::always(fcm_error(
            404,
            "UNREGISTERED",
            "Requested entity was not found.",
        )));
        assert_eq!(
            r.sender.send(&token(Platform::Fcm, DEVICE), None).await,
            Err(SendError::InvalidToken)
        );
        assert_eq!(r.http.count(), 1, "no retry for a dead token");
        assert!(lock(&r.sleeps.delays).is_empty());
    }

    #[tokio::test]
    async fn transient_failures_retry_with_bounded_backoff() {
        let r = rig(Recorder::always(fcm_error(503, "UNAVAILABLE", "")));
        assert_eq!(
            r.sender.send(&token(Platform::Fcm, DEVICE), None).await,
            Err(SendError::Temporary)
        );
        assert_eq!(r.http.count(), 3);
        assert_eq!(
            *lock(&r.sleeps.delays),
            vec![Duration::from_millis(200), Duration::from_millis(400)]
        );
        let r = rig(Recorder::script(vec![
            Err(TransportError),
            Ok(Reply::status(200)),
        ]));
        assert_eq!(
            r.sender.send(&token(Platform::Fcm, DEVICE), None).await,
            Ok(())
        );
        assert_eq!(r.http.count(), 2);
    }

    #[tokio::test]
    async fn access_tokens_are_cached_refreshed_and_never_logged() {
        let http = Arc::new(Recorder::script(vec![
            Ok(token_reply("ya29.first-access-token", 3600)),
            Ok(token_reply("ya29.second-access-token", 3600)),
        ]));
        let tokens =
            ServiceAccountTokens::new(account(), Arc::new(TestSigner::new("RS256")), http.clone());
        assert_eq!(
            &*tokens.token(NOW, false).await.unwrap(),
            "ya29.first-access-token"
        );
        // Cached: no second round trip.
        assert_eq!(
            &*tokens.token(NOW + 100, false).await.unwrap(),
            "ya29.first-access-token"
        );
        assert_eq!(http.count(), 1);
        // Inside the refresh margin: a new token is fetched.
        let near = NOW + 3600 - REFRESH_MARGIN_S;
        assert_eq!(
            &*tokens.token(near, false).await.unwrap(),
            "ya29.second-access-token"
        );
        assert_eq!(http.count(), 2);
        assert_eq!(tokens.minted.load(Ordering::Relaxed), 2);
        // Nothing secret in Debug.
        let d = format!("{tokens:?}");
        assert!(d.contains("push@klimper-wallet") && !d.contains("ya29"));
        assert!(!format!("{:?}", StaticToken::new("ya29.x")).contains("ya29"));
    }

    #[tokio::test]
    async fn the_assertion_is_a_jwt_bearer_grant_for_the_messaging_scope() {
        let http = Arc::new(Recorder::always(token_reply("ya29.t-access-token", 3600)));
        let tokens =
            ServiceAccountTokens::new(account(), Arc::new(TestSigner::new("RS256")), http.clone());
        tokens.token(NOW, false).await.unwrap();
        let req = http.nth(0).unwrap();
        assert_eq!(req.url, GOOGLE_TOKEN_URI);
        assert_eq!(
            req.header("content-type"),
            Some("application/x-www-form-urlencoded")
        );
        let body = req.body_str();
        let assertion = body
            .split('&')
            .find_map(|p| p.strip_prefix("assertion="))
            .unwrap();
        assert!(
            body.starts_with("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&")
        );
        assert_eq!(
            segment(assertion, 0),
            serde_json::json!({ "alg": "RS256", "typ": "JWT" })
        );
        assert_eq!(
            segment(assertion, 1),
            serde_json::json!({
                "iss": "push@klimper-wallet.iam.gserviceaccount.com",
                "scope": SCOPE,
                "aud": GOOGLE_TOKEN_URI,
                "iat": NOW,
                "exp": NOW + ASSERTION_LIFETIME_S,
            })
        );
        assert_eq!(tokens.project_id(), "klimper-wallet");
    }

    /// A sender with one recorder for sends and a service-account token source with its
    /// own recorder, so the two request streams can be asserted separately.
    fn sender_with(
        send_http: Arc<Recorder>,
        token_http: Arc<Recorder>,
    ) -> (Sender, Arc<ServiceAccountTokens>) {
        let tokens = Arc::new(ServiceAccountTokens::new(
            account(),
            Arc::new(TestSigner::new("RS256")),
            token_http,
        ));
        let sender = Sender::new(
            config(),
            tokens.clone(),
            send_http,
            Arc::new(RecordedSleeps::default()),
            Arc::new(|| NOW),
        )
        .unwrap();
        (sender, tokens)
    }

    #[tokio::test]
    async fn a_401_refreshes_the_access_token_once_and_then_gives_up() {
        let send_http = Arc::new(Recorder::script(vec![
            Ok(fcm_error(
                401,
                "",
                "Request had invalid authentication credentials.",
            )),
            Ok(Reply::status(200)),
        ]));
        let token_http = Arc::new(Recorder::script(vec![
            Ok(token_reply("ya29.stale-access-token", 3600)),
            Ok(token_reply("ya29.fresh-access-token", 3600)),
        ]));
        let (sender, tokens) = sender_with(send_http.clone(), token_http.clone());
        assert_eq!(
            sender.send(&token(Platform::Fcm, DEVICE), None).await,
            Ok(())
        );
        let auth = |n: usize| {
            send_http
                .nth(n)
                .unwrap()
                .header("authorization")
                .unwrap()
                .to_owned()
        };
        assert_eq!(auth(0), "Bearer ya29.stale-access-token");
        assert_eq!(
            auth(1),
            "Bearer ya29.fresh-access-token",
            "forced refresh after a 401"
        );
        assert_eq!(tokens.minted.load(Ordering::Relaxed), 2);
        // Repeated 401s stop rather than loop.
        let send_http = Arc::new(Recorder::always(fcm_error(401, "", "")));
        let (sender, _) = sender_with(
            send_http.clone(),
            Arc::new(Recorder::always(token_reply(
                "ya29.whatever-access-token",
                3600,
            ))),
        );
        assert_eq!(
            sender.send(&token(Platform::Fcm, DEVICE), None).await,
            Err(SendError::Temporary)
        );
        assert_eq!(send_http.count(), 2);
    }

    #[tokio::test]
    async fn concurrent_wake_ups_mint_one_assertion() {
        let token_http = Arc::new(Recorder::always(token_reply(
            "ya29.shared-access-token",
            3600,
        )));
        let (sender, tokens) = sender_with(
            Arc::new(Recorder::always(Reply::status(200))),
            token_http.clone(),
        );
        let sender = Arc::new(sender);
        let mut set = Vec::new();
        for _ in 0..8 {
            let s = sender.clone();
            set.push(tokio::spawn(async move {
                s.send(&token(Platform::Fcm, DEVICE), None).await
            }));
        }
        for j in set {
            assert_eq!(j.await.unwrap(), Ok(()));
        }
        assert_eq!(tokens.minted.load(Ordering::Relaxed), 1, "single flight");
    }

    #[tokio::test]
    async fn bad_token_endpoint_replies_are_classified_and_never_cached() {
        let cases = [
            (Ok(Reply::status(400)), SendError::Permanent),
            (Ok(Reply::status(500)), SendError::Temporary),
            (Err(TransportError), SendError::Temporary),
            (Ok(Reply::json(200, "not json")), SendError::Temporary),
            (Ok(Reply::json(200, "{}")), SendError::Temporary),
            (Ok(token_reply("short", 3600)), SendError::Temporary),
            (Ok(token_reply("ya29.ok-token", 5)), SendError::Temporary),
            (
                Ok(token_reply("ya29.ok-token", 999_999)),
                SendError::Temporary,
            ),
        ];
        for (reply, want) in cases {
            let http = Arc::new(Recorder::script(vec![reply.clone()]));
            let tokens = ServiceAccountTokens::new(
                account(),
                Arc::new(TestSigner::new("RS256")),
                http.clone(),
            );
            assert_eq!(
                tokens.token(NOW, false).await.map(|_| ()),
                Err(want),
                "{reply:?}"
            );
        }
        // A broken signer never reaches the network.
        let http = Arc::new(Recorder::default());
        let tokens = ServiceAccountTokens::new(
            account(),
            Arc::new(TestSigner::broken("RS256")),
            http.clone(),
        );
        assert_eq!(
            tokens.token(NOW, false).await.map(|_| ()),
            Err(SendError::Permanent)
        );
        assert_eq!(http.count(), 0);
    }

    #[test]
    fn configuration_is_validated() {
        assert!(config().validate().is_ok());
        for (c, msg) in [
            (
                Config {
                    project_id: "BAD".into(),
                    ..config()
                },
                "FCM project_id must be a Google project id",
            ),
            (
                Config {
                    project_id: "../x".into(),
                    ..config()
                },
                "FCM project_id must be a Google project id",
            ),
            (
                Config {
                    ttl_s: 0,
                    ..config()
                },
                "FCM ttl_s must be between 1 s and 24 h",
            ),
        ] {
            assert_eq!(c.validate(), Err(msg));
        }
        assert!(!access_token_is_valid("short"));
        assert!(!access_token_is_valid("has space in it and is long enough"));
        assert!(access_token_is_valid("ya29.a0AfH6SMB-long-enough-token"));
    }
}
