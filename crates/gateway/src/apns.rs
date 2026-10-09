//! APNs delivery (spec 7.3; stack doc 2.4).
//!
//! Token-based (`.p8`) provider authentication over HTTP/2. The notification is
//! content-free: a static generic alert configured by the operator, `time-sensitive`
//! interruption level, `mutable-content` so the wallet's Notification Service
//! Extension can replace it with an encrypted preview it decrypts itself (spec 7.3.3),
//! and `content-available` so iOS also wakes the wallet app in the background, with the
//! phone locked, to fetch the request before the user opens it (spec 7.3).
//!
//! The payload is a pure function of the gateway's configuration and the presence of a
//! preview — never of the device token, the mailbox or the request — so Apple learns only
//! that a push happened (T11), and the text can never drive a signing decision (T12).
//!
//! The two endpoint hosts are constants. Nothing in a wake request can point this sender
//! anywhere else (spec 7.3.2, T21).

use crate::creds::{Signer, jwt};
use crate::http::{Class, HttpTransport, Reply, Request, RetryPolicy, Sleeper};
use crate::{PlatformSender, SendError, lock};
use async_trait::async_trait;
use std::sync::{Arc, Mutex};
use xchonnect_core::b64;
use xchonnect_core::push::{Platform, PushToken};

/// Production endpoint host.
pub const PRODUCTION_HOST: &str = "api.push.apple.com";
/// Development endpoint host.
pub const SANDBOX_HOST: &str = "api.sandbox.push.apple.com";
/// Largest APNs payload Apple accepts for an alert notification.
pub const MAX_PAYLOAD: usize = 4096;
/// Custom payload key carrying the encrypted preview (spec 7.3.3).
pub const PREVIEW_KEY: &str = "xcp";
/// Re-mint the provider token after this long. Apple rejects tokens older than one hour.
pub const TOKEN_MAX_AGE_S: u64 = 2700;

/// Which APNs environments this gateway delivers to (`apns` and `apns-sandbox` tokens).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Environments {
    /// Production only. The default for a shipped gateway.
    #[default]
    Production,
    /// Development builds only.
    Sandbox,
    /// Both, chosen per sealed token.
    Both,
}

impl Environments {
    fn host(self, platform: Platform) -> Option<&'static str> {
        match (self, platform) {
            (Environments::Production | Environments::Both, Platform::Apns) => {
                Some(PRODUCTION_HOST)
            }
            (Environments::Sandbox | Environments::Both, Platform::ApnsSandbox) => {
                Some(SANDBOX_HOST)
            }
            _ => None,
        }
    }
}

/// The generic lock-screen alert. Static configuration, identical for every device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Alert {
    /// Literal text. Must stay generic: no amounts, addresses or dApp names (spec 7.3).
    Text {
        /// Title line.
        title: String,
        /// Body line.
        body: String,
    },
    /// Localisation keys the wallet app resolves on-device, so no user-visible text
    /// leaves the gateway at all. Preferred.
    Localised {
        /// `title-loc-key`.
        title_loc_key: String,
        /// `loc-key`.
        loc_key: String,
    },
}

impl Default for Alert {
    fn default() -> Self {
        Alert::Text {
            title: "Signing request".into(),
            body: "Open your wallet to review it.".into(),
        }
    }
}

impl Alert {
    fn json(&self) -> serde_json::Value {
        match self {
            Alert::Text { title, body } => serde_json::json!({ "title": title, "body": body }),
            Alert::Localised {
                title_loc_key,
                loc_key,
            } => serde_json::json!({ "title-loc-key": title_loc_key, "loc-key": loc_key }),
        }
    }
}

/// APNs sender configuration. No endpoint URL: see [`Environments`].
#[derive(Debug, Clone)]
pub struct Config {
    /// Apple Developer Team ID (the provider token `iss`).
    pub team_id: String,
    /// App bundle id (`apns-topic`).
    pub topic: String,
    /// Environments this gateway serves.
    pub environments: Environments,
    /// `apns-expiration` offset in seconds (default 600). A wake-up that cannot be
    /// delivered within this window is dropped rather than shown late. Messages live on
    /// the relay for at least as long, so a phone that comes back online within it still
    /// learns that one is waiting.
    pub expiration_s: u64,
    /// The generic alert.
    pub alert: Alert,
    /// Retry and backoff bounds.
    pub retry: RetryPolicy,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            team_id: String::new(),
            topic: String::new(),
            environments: Environments::default(),
            expiration_s: 600,
            alert: Alert::default(),
            retry: RetryPolicy::default(),
        }
    }
}

fn ident_is_valid(s: &str, max: usize, extra: &[char]) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || extra.contains(&c))
}

impl Config {
    /// Reject configuration that could not produce a valid request.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !ident_is_valid(&self.team_id, 32, &[]) {
            return Err("APNs team_id must be short and alphanumeric");
        }
        if !ident_is_valid(&self.topic, 155, &['.', '-']) {
            return Err("APNs topic must be a bundle identifier");
        }
        if !(1..=86_400).contains(&self.expiration_s) {
            return Err("APNs expiration_s must be between 1 s and 24 h");
        }
        Ok(())
    }
}

/// Whether a device token can be placed in the APNs request path.
///
/// APNs device tokens are hex. Anything else is refused before it reaches a URL, so a
/// sealed token cannot steer the request to another path on Apple's host (T21).
pub fn device_token_is_valid(t: &str) -> bool {
    (64..=200).contains(&t.len()) && t.chars().all(|c| c.is_ascii_hexdigit())
}

/// Classify an APNs reply. `reason` is the `reason` member of Apple's JSON error body.
pub fn classify(status: u16, reason: &str) -> Class {
    match (status, reason) {
        (200..=299, _) => Class::Delivered,
        (_, "BadDeviceToken" | "DeviceTokenNotForTopic" | "Unregistered") => Class::Invalid,
        (410, _) => Class::Invalid,
        (403, "ExpiredProviderToken" | "InvalidProviderToken" | "MissingProviderToken") => {
            Class::Reauth
        }
        (429, "TooManyProviderTokenUpdates") => Class::Reauth,
        (429 | 500 | 502 | 503 | 504, _) => Class::Retry(None),
        _ => Class::Permanent,
    }
}

fn reason_of(reply: &Reply) -> String {
    serde_json::from_slice::<serde_json::Value>(&reply.body)
        .ok()
        .as_ref()
        .and_then(|v| v.get("reason"))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned()
}

/// Delivers wake-ups to APNs.
pub struct Sender {
    config: Config,
    signer: Arc<dyn Signer>,
    http: Arc<dyn HttpTransport>,
    sleeper: Arc<dyn Sleeper>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    /// Provider token and the time it was minted. Memory only.
    token: Mutex<Option<(Arc<str>, u64)>>,
}

impl std::fmt::Debug for Sender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApnsSender")
            .field("topic", &self.config.topic)
            .field("environments", &self.config.environments)
            .finish_non_exhaustive()
    }
}

impl Sender {
    /// Build a sender. Returns the configuration problem if there is one.
    pub fn new(
        config: Config,
        signer: Arc<dyn Signer>,
        http: Arc<dyn HttpTransport>,
        sleeper: Arc<dyn Sleeper>,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Result<Self, &'static str> {
        config.validate()?;
        Ok(Sender {
            config,
            signer,
            http,
            sleeper,
            clock,
            token: Mutex::default(),
        })
    }

    /// The cached provider token, minting a new one if it is missing, too old, or
    /// `force` is set (after a 403 from Apple).
    fn provider_token(&self, now: u64, force: bool) -> Result<Arc<str>, SendError> {
        {
            let cached = lock(&self.token);
            if let Some((t, issued)) = cached.as_ref() {
                if !force && now.saturating_sub(*issued) < TOKEN_MAX_AGE_S {
                    return Ok(t.clone());
                }
            }
        }
        let claims = serde_json::json!({ "iss": self.config.team_id, "iat": now });
        // A signing failure is a configuration problem, not a device problem; the error
        // string is a fixed label, so no key material can reach a log.
        let t: Arc<str> = jwt(self.signer.as_ref(), &claims)
            .map_err(|_| SendError::Permanent)?
            .into();
        *lock(&self.token) = Some((t.clone(), now));
        Ok(t)
    }

    /// The notification payload. Identical for every device; the only variable is
    /// whether a preview is attached.
    pub fn payload(&self, preview: Option<&[u8]>) -> Vec<u8> {
        let aps = serde_json::json!({
            "alert": self.config.alert.json(),
            "content-available": 1,
            "interruption-level": "time-sensitive",
            "mutable-content": 1,
            "sound": "default",
        });
        let mut body = serde_json::json!({ "aps": aps });
        if let (Some(p), Some(map)) = (preview, body.as_object_mut()) {
            map.insert(PREVIEW_KEY.into(), serde_json::json!(b64::encode(p)));
        }
        let out = serde_json::to_vec(&body).unwrap_or_default();
        if out.len() <= MAX_PAYLOAD {
            return out;
        }
        // Too large with the preview: fall back to the generic alert rather than let
        // Apple reject the wake-up (the device then shows the generic text).
        serde_json::to_vec(&serde_json::json!({ "aps": aps })).unwrap_or_default()
    }

    fn request(
        &self,
        host: &str,
        device_token: &str,
        provider_token: &str,
        now: u64,
        preview: Option<&[u8]>,
    ) -> Request {
        Request {
            url: format!("https://{host}/3/device/{device_token}"),
            headers: vec![
                ("authorization".into(), format!("bearer {provider_token}")),
                ("apns-topic".into(), self.config.topic.clone()),
                ("apns-push-type".into(), "alert".into()),
                ("apns-priority".into(), "10".into()),
                (
                    "apns-expiration".into(),
                    (now.saturating_add(self.config.expiration_s)).to_string(),
                ),
                ("content-type".into(), "application/json".into()),
            ],
            body: self.payload(preview),
        }
    }
}

#[async_trait]
impl PlatformSender for Sender {
    async fn send(&self, token: &PushToken, preview: Option<&[u8]>) -> Result<(), SendError> {
        let Some(host) = self.config.environments.host(token.platform) else {
            return Err(SendError::Unsupported);
        };
        if !device_token_is_valid(&token.device_token) {
            // Not a token APNs could ever accept: forget it like an invalid one.
            return Err(SendError::InvalidToken);
        }
        let mut force = false;
        let mut reauths = 0u32;
        for attempt in 1..=self.config.retry.max_attempts {
            let now = (self.clock)();
            let provider = self.provider_token(now, force)?;
            force = false;
            let req = self.request(host, &token.device_token, &provider, now, preview);
            let class = match self.http.post(req).await {
                Ok(reply) => {
                    classify(reply.status, &reason_of(&reply)).pipe_retry_after(reply.retry_after_s)
                }
                // A network failure says nothing about the device token.
                Err(_) => Class::Retry(None),
            };
            match class {
                Class::Delivered => return Ok(()),
                Class::Invalid => return Err(SendError::InvalidToken),
                Class::Permanent => return Err(SendError::Permanent),
                Class::Reauth if reauths == 0 => {
                    reauths += 1;
                    *lock(&self.token) = None;
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

trait PipeRetryAfter {
    fn pipe_retry_after(self, after: Option<u64>) -> Class;
}

impl PipeRetryAfter for Class {
    /// Attach the provider's `retry-after` to a retryable class.
    fn pipe_retry_after(self, after: Option<u64>) -> Class {
        match self {
            Class::Retry(None) => Class::Retry(after),
            other => other,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::creds::Es256Signer;
    use crate::creds::TestSigner;
    use crate::creds::tests::{segment, test_p8, verify_es256};
    use crate::http::{RecordedSleeps, Recorder, TransportError};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    const NOW: u64 = 1_790_000_000;
    const DEVICE: &str = "aa11bb22cc33dd44ee55ff6600778899aa11bb22cc33dd44ee55ff6600778899";

    fn config() -> Config {
        Config {
            team_id: "TEAM123456".into(),
            topic: "app.klimper.wallet".into(),
            retry: RetryPolicy::no_jitter(),
            ..Config::default()
        }
    }

    struct Rig {
        sender: Sender,
        http: Arc<Recorder>,
        sleeps: Arc<RecordedSleeps>,
        clock: Arc<AtomicU64>,
    }

    fn rig_with(config: Config, http: Recorder, signer: Arc<dyn Signer>) -> Rig {
        let http = Arc::new(http);
        let sleeps = Arc::new(RecordedSleeps::default());
        let clock = Arc::new(AtomicU64::new(NOW));
        let c = clock.clone();
        let sender = Sender::new(
            config,
            signer,
            http.clone(),
            sleeps.clone(),
            Arc::new(move || c.load(Ordering::Relaxed)),
        )
        .unwrap();
        Rig {
            sender,
            http,
            sleeps,
            clock,
        }
    }

    fn rig(http: Recorder) -> Rig {
        rig_with(
            config(),
            http,
            Arc::new(TestSigner::with_key_id("ES256", "KEYID12345")),
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

    fn apns_error(status: u16, reason: &str) -> Reply {
        Reply::json(status, &format!("{{\"reason\":\"{reason}\"}}"))
    }

    #[tokio::test]
    async fn request_shape_matches_the_apns_http2_api() {
        let r = rig(Recorder::always(Reply::status(200)));
        assert_eq!(
            r.sender.send(&token(Platform::Apns, DEVICE), None).await,
            Ok(())
        );
        let req = r.http.nth(0).unwrap();
        assert_eq!(
            req.url,
            format!("https://{PRODUCTION_HOST}/3/device/{DEVICE}")
        );
        assert_eq!(req.header("apns-topic"), Some("app.klimper.wallet"));
        assert_eq!(req.header("apns-push-type"), Some("alert"));
        assert_eq!(req.header("apns-priority"), Some("10"));
        assert_eq!(
            req.header("apns-expiration"),
            Some((NOW + 600).to_string().as_str())
        );
        assert_eq!(req.header("content-type"), Some("application/json"));
        let auth = req.header("authorization").unwrap();
        let provider = auth.strip_prefix("bearer ").unwrap();
        assert_eq!(
            segment(provider, 0),
            serde_json::json!({ "alg": "ES256", "kid": "KEYID12345", "typ": "JWT" })
        );
        assert_eq!(
            segment(provider, 1),
            serde_json::json!({ "iss": "TEAM123456", "iat": NOW })
        );
    }

    #[tokio::test]
    async fn the_provider_token_is_a_real_es256_jwt_over_the_p8_key() {
        let signer = Arc::new(Es256Signer::from_p8("KEYID12345", &test_p8()).unwrap());
        let public = signer.public_key();
        let r = rig_with(config(), Recorder::always(Reply::status(200)), signer);
        r.sender
            .send(&token(Platform::Apns, DEVICE), None)
            .await
            .unwrap();
        let auth = r
            .http
            .nth(0)
            .unwrap()
            .header("authorization")
            .unwrap()
            .to_owned();
        let provider = auth.strip_prefix("bearer ").unwrap();
        assert!(verify_es256(&public, provider), "APNs .p8 token auth");
    }

    #[tokio::test]
    async fn the_payload_is_generic_mutable_and_time_sensitive() {
        let r = rig(Recorder::always(Reply::status(200)));
        let other = "ff00".repeat(16);
        for d in [DEVICE, other.as_str()] {
            r.sender
                .send(&token(Platform::Apns, d), None)
                .await
                .unwrap();
        }
        let bodies: Vec<Vec<u8>> = r.http.seen().into_iter().map(|q| q.body).collect();
        assert_eq!(
            bodies[0], bodies[1],
            "payload does not depend on the device"
        );
        let v: serde_json::Value = serde_json::from_slice(&bodies[0]).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"aps": {
                "alert": { "title": "Signing request", "body": "Open your wallet to review it." },
                "content-available": 1,
                "interruption-level": "time-sensitive",
                "mutable-content": 1,
                "sound": "default",
            }})
        );
        let text = String::from_utf8(bodies[0].clone()).unwrap();
        for leak in [DEVICE, other.as_str(), "xch1", "XCH"] {
            assert!(!text.contains(leak), "{leak} must not be in the payload");
        }
        // Localisation keys keep even the generic text off the wire.
        let mut c = config();
        c.alert = Alert::Localised {
            title_loc_key: "xchonnect.wake.title".into(),
            loc_key: "xchonnect.preview.generic".into(),
        };
        let r = rig_with(
            c,
            Recorder::always(Reply::status(200)),
            Arc::new(TestSigner::new("ES256")),
        );
        r.sender
            .send(&token(Platform::Apns, DEVICE), None)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&r.http.nth(0).unwrap().body).unwrap();
        assert_eq!(
            v["aps"]["alert"],
            serde_json::json!({
                "title-loc-key": "xchonnect.wake.title",
                "loc-key": "xchonnect.preview.generic"
            })
        );
    }

    #[tokio::test]
    async fn an_encrypted_preview_rides_along_and_oversize_ones_are_dropped() {
        let r = rig(Recorder::always(Reply::status(200)));
        let preview = [9u8; xchonnect_core::preview::SEALED_LEN];
        r.sender
            .send(&token(Platform::Apns, DEVICE), Some(&preview))
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&r.http.nth(0).unwrap().body).unwrap();
        assert_eq!(v[PREVIEW_KEY], serde_json::json!(b64::encode(&preview)));
        assert_eq!(v["aps"]["mutable-content"], 1);
        assert_eq!(v["aps"]["content-available"], 1);
        assert!(r.http.nth(0).unwrap().body.len() < MAX_PAYLOAD);
        // Something far too large for APNs never makes the wake-up fail.
        let huge = vec![0u8; MAX_PAYLOAD];
        let body = r.sender.payload(Some(&huge));
        assert!(body.len() <= MAX_PAYLOAD);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v.get(PREVIEW_KEY), None);
    }

    #[tokio::test]
    async fn environments_are_selectable_per_gateway_and_per_token() {
        for (envs, platform, host) in [
            (
                Environments::Production,
                Platform::Apns,
                Some(PRODUCTION_HOST),
            ),
            (Environments::Production, Platform::ApnsSandbox, None),
            (
                Environments::Sandbox,
                Platform::ApnsSandbox,
                Some(SANDBOX_HOST),
            ),
            (Environments::Sandbox, Platform::Apns, None),
            (Environments::Both, Platform::Apns, Some(PRODUCTION_HOST)),
            (
                Environments::Both,
                Platform::ApnsSandbox,
                Some(SANDBOX_HOST),
            ),
        ] {
            let c = Config {
                environments: envs,
                ..config()
            };
            let r = rig_with(
                c,
                Recorder::always(Reply::status(200)),
                Arc::new(TestSigner::new("ES256")),
            );
            let res = r.sender.send(&token(platform, DEVICE), None).await;
            match host {
                Some(h) => {
                    assert_eq!(res, Ok(()), "{envs:?} {platform:?}");
                    assert!(
                        r.http
                            .nth(0)
                            .unwrap()
                            .url
                            .starts_with(&format!("https://{h}/"))
                    );
                }
                None => {
                    assert_eq!(res, Err(SendError::Unsupported), "{envs:?} {platform:?}");
                    assert_eq!(r.http.count(), 0, "nothing is sent");
                }
            }
        }
    }

    #[tokio::test]
    async fn invalid_device_tokens_never_reach_a_url() {
        let r = rig(Recorder::always(Reply::status(200)));
        for bad in [
            "",
            "short",
            "../../../../../../../../../../../../../../../../../../../../../../x",
            &format!("{DEVICE}/../2/other"),
            &format!("{}?x=1", DEVICE),
            &"g".repeat(64),
            &"a".repeat(201),
        ] {
            assert_eq!(
                r.sender.send(&token(Platform::Apns, bad), None).await,
                Err(SendError::InvalidToken),
                "{bad:?}"
            );
        }
        assert_eq!(r.http.count(), 0);
        assert!(device_token_is_valid(DEVICE));
        assert!(device_token_is_valid(&DEVICE.to_uppercase()));
    }

    #[tokio::test]
    async fn apple_error_responses_are_classified() {
        for (status, reason, want) in [
            (200, "", Class::Delivered),
            (400, "BadDeviceToken", Class::Invalid),
            (400, "DeviceTokenNotForTopic", Class::Invalid),
            (410, "Unregistered", Class::Invalid),
            (410, "", Class::Invalid),
            (403, "ExpiredProviderToken", Class::Reauth),
            (403, "InvalidProviderToken", Class::Reauth),
            (403, "MissingProviderToken", Class::Reauth),
            (403, "Forbidden", Class::Permanent),
            (429, "TooManyProviderTokenUpdates", Class::Reauth),
            (429, "TooManyRequests", Class::Retry(None)),
            (500, "InternalServerError", Class::Retry(None)),
            (503, "ServiceUnavailable", Class::Retry(None)),
            (400, "TopicDisallowed", Class::Permanent),
            (413, "PayloadTooLarge", Class::Permanent),
            (404, "BadPath", Class::Permanent),
        ] {
            assert_eq!(classify(status, reason), want, "{status} {reason}");
        }
        // The reason parser is total.
        for body in ["", "{", "null", "{\"reason\":5}", "[]"] {
            assert_eq!(reason_of(&Reply::json(400, body)), "");
        }
    }

    #[tokio::test]
    async fn invalid_tokens_stop_immediately_and_are_reported_as_invalid() {
        let r = rig(Recorder::always(apns_error(410, "Unregistered")));
        assert_eq!(
            r.sender.send(&token(Platform::Apns, DEVICE), None).await,
            Err(SendError::InvalidToken)
        );
        assert_eq!(r.http.count(), 1, "no retry for a dead token");
        assert!(lock(&r.sleeps.delays).is_empty());
    }

    #[tokio::test]
    async fn transient_failures_retry_with_bounded_backoff_then_give_up() {
        let r = rig(Recorder::always(apns_error(503, "ServiceUnavailable")));
        assert_eq!(
            r.sender.send(&token(Platform::Apns, DEVICE), None).await,
            Err(SendError::Temporary)
        );
        assert_eq!(r.http.count(), 3, "max_attempts");
        assert_eq!(
            *lock(&r.sleeps.delays),
            vec![Duration::from_millis(200), Duration::from_millis(400)]
        );
        // A network error is transient too, and a later success ends the loop.
        let r = rig(Recorder::script(vec![
            Err(TransportError),
            Ok(Reply::status(200)),
        ]));
        assert_eq!(
            r.sender.send(&token(Platform::Apns, DEVICE), None).await,
            Ok(())
        );
        assert_eq!(r.http.count(), 2);
    }

    #[tokio::test]
    async fn retry_after_is_honoured_within_the_cap() {
        let mut reply = apns_error(429, "TooManyRequests");
        reply.retry_after_s = Some(1);
        let r = rig(Recorder::script(vec![Ok(reply), Ok(Reply::status(200))]));
        r.sender
            .send(&token(Platform::Apns, DEVICE), None)
            .await
            .unwrap();
        assert_eq!(*lock(&r.sleeps.delays), vec![Duration::from_secs(1)]);
    }

    #[tokio::test]
    async fn the_provider_token_is_reused_renewed_and_reminted_after_a_403() {
        let r = rig(Recorder::always(Reply::status(200)));
        let t = token(Platform::Apns, DEVICE);
        r.sender.send(&t, None).await.unwrap();
        r.sender.send(&t, None).await.unwrap();
        let auth = |n: usize| {
            r.http
                .nth(n)
                .unwrap()
                .header("authorization")
                .unwrap()
                .to_owned()
        };
        assert_eq!(auth(0), auth(1), "token reused within the hour");
        // Past the renewal age a fresh token is minted (new `iat`).
        r.clock.store(NOW + TOKEN_MAX_AGE_S, Ordering::Relaxed);
        r.sender.send(&t, None).await.unwrap();
        assert_ne!(auth(1), auth(2), "renewed");
        // A 403 forces a re-mint and exactly one extra attempt.
        let r = rig(Recorder::script(vec![
            Ok(apns_error(403, "ExpiredProviderToken")),
            Ok(Reply::status(200)),
        ]));
        r.clock.store(NOW, Ordering::Relaxed);
        assert_eq!(r.sender.send(&t, None).await, Ok(()));
        assert_eq!(r.http.count(), 2);
        assert!(
            lock(&r.sleeps.delays).is_empty(),
            "re-auth does not back off"
        );
        // Repeated 403s stop instead of looping.
        let r = rig(Recorder::always(apns_error(403, "ExpiredProviderToken")));
        assert_eq!(r.sender.send(&t, None).await, Err(SendError::Temporary));
        assert_eq!(r.http.count(), 2);
    }

    #[tokio::test]
    async fn a_broken_signer_is_a_configuration_error_not_a_dead_device() {
        let r = rig_with(
            config(),
            Recorder::always(Reply::status(200)),
            Arc::new(TestSigner::broken("ES256")),
        );
        assert_eq!(
            r.sender.send(&token(Platform::Apns, DEVICE), None).await,
            Err(SendError::Permanent)
        );
        assert_eq!(r.http.count(), 0);
    }

    #[test]
    fn configuration_is_validated_and_debug_hides_credentials() {
        assert!(config().validate().is_ok());
        for (c, msg) in [
            (
                Config {
                    team_id: String::new(),
                    ..config()
                },
                "APNs team_id must be short and alphanumeric",
            ),
            (
                Config {
                    team_id: "a b".into(),
                    ..config()
                },
                "APNs team_id must be short and alphanumeric",
            ),
            (
                Config {
                    topic: "bad topic".into(),
                    ..config()
                },
                "APNs topic must be a bundle identifier",
            ),
            (
                Config {
                    expiration_s: 0,
                    ..config()
                },
                "APNs expiration_s must be between 1 s and 24 h",
            ),
            (
                Config {
                    expiration_s: 86_401,
                    ..config()
                },
                "APNs expiration_s must be between 1 s and 24 h",
            ),
        ] {
            assert_eq!(c.validate(), Err(msg));
        }
        let r = rig(Recorder::always(Reply::status(200)));
        let d = format!("{:?}", r.sender);
        assert!(d.contains("app.klimper.wallet") && !d.contains("TEAM123456"));
    }
}
