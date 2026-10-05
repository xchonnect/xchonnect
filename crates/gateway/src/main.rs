//! Xchonnect push gateway binary.
//!
//! | Variable | Meaning |
//! |---|---|
//! | `XCHONNECT_GATEWAY_LISTEN` | listen address (default `127.0.0.1:8788`) |
//! | `XCHONNECT_GATEWAY_KEYS` | comma-separated base64url X25519 secret keys, newest first (required) |
//! | `XCHONNECT_GATEWAY_TEST_PLATFORM` | `true` to accept `test` platform tokens (counts only) |
//! | `XCHONNECT_LOG` | log filter |
//!
//! APNs (all four required together):
//!
//! | Variable | Meaning |
//! |---|---|
//! | `XCHONNECT_GATEWAY_APNS_TEAM_ID` | Apple Developer Team ID |
//! | `XCHONNECT_GATEWAY_APNS_KEY_ID` | Key ID of the `.p8` key |
//! | `XCHONNECT_GATEWAY_APNS_KEY_FILE` | path to the `.p8` file (secret source) |
//! | `XCHONNECT_GATEWAY_APNS_TOPIC` | app bundle id |
//! | `XCHONNECT_GATEWAY_APNS_ENV` | `production` (default), `sandbox` or `both` |
//! | `XCHONNECT_GATEWAY_APNS_ALERT_TITLE` / `_BODY` | generic alert text |
//! | `XCHONNECT_GATEWAY_APNS_ALERT_TITLE_LOC_KEY` / `_LOC_KEY` | localisation keys instead |
//!
//! FCM:
//!
//! | Variable | Meaning |
//! |---|---|
//! | `XCHONNECT_GATEWAY_FCM_SERVICE_ACCOUNT_FILE` | path to the service account JSON (secret source) |
//! | `XCHONNECT_GATEWAY_FCM_ACCESS_TOKEN` | a pre-issued OAuth token instead (development) |
//! | `XCHONNECT_GATEWAY_FCM_PROJECT_ID` | required only with `FCM_ACCESS_TOKEN` |
//!
//! Credentials are read from their secret source once at start-up, held zeroizing and
//! never logged (spec 13.5).

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use xchonnect_core::b64;
use xchonnect_core::crypto::X25519Secret;
use xchonnect_gateway::creds::{Es256Signer, Secret, ServiceAccount};
use xchonnect_gateway::http::{HttpTransport, Https, Sleeper, TokioSleeper};
use xchonnect_gateway::{CountingSender, DeviceLimits, Gateway, Senders, apns, app, fcm};

fn fail(msg: &str) -> ! {
    tracing::error!("{msg}");
    std::process::exit(2);
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Build the APNs sender if it is configured. Any partial configuration is fatal: a
/// gateway that silently drops iOS wake-ups is worse than one that refuses to start.
fn apns_sender(
    http: &Arc<dyn HttpTransport>,
    sleeper: &Arc<dyn Sleeper>,
    clock: &Clock,
) -> Option<Arc<apns::Sender>> {
    let team_id = var("XCHONNECT_GATEWAY_APNS_TEAM_ID")?;
    let key_id = var("XCHONNECT_GATEWAY_APNS_KEY_ID")
        .unwrap_or_else(|| fail("XCHONNECT_GATEWAY_APNS_KEY_ID is required with APNs"));
    let key_file = var("XCHONNECT_GATEWAY_APNS_KEY_FILE")
        .unwrap_or_else(|| fail("XCHONNECT_GATEWAY_APNS_KEY_FILE is required with APNs"));
    let topic = var("XCHONNECT_GATEWAY_APNS_TOPIC")
        .unwrap_or_else(|| fail("XCHONNECT_GATEWAY_APNS_TOPIC is required with APNs"));
    let environments = match var("XCHONNECT_GATEWAY_APNS_ENV").as_deref() {
        None | Some("production") => apns::Environments::Production,
        Some("sandbox") => apns::Environments::Sandbox,
        Some("both") => apns::Environments::Both,
        Some(_) => fail("XCHONNECT_GATEWAY_APNS_ENV: production, sandbox or both"),
    };
    let alert = match (
        var("XCHONNECT_GATEWAY_APNS_ALERT_TITLE_LOC_KEY"),
        var("XCHONNECT_GATEWAY_APNS_ALERT_LOC_KEY"),
    ) {
        (Some(title_loc_key), Some(loc_key)) => apns::Alert::Localised {
            title_loc_key,
            loc_key,
        },
        _ => match apns::Alert::default() {
            apns::Alert::Text { title, body } => apns::Alert::Text {
                title: var("XCHONNECT_GATEWAY_APNS_ALERT_TITLE").unwrap_or(title),
                body: var("XCHONNECT_GATEWAY_APNS_ALERT_BODY").unwrap_or(body),
            },
            localised => localised,
        },
    };
    let p8 = Secret::from_file(&key_file)
        .unwrap_or_else(|e| fail(&format!("XCHONNECT_GATEWAY_APNS_KEY_FILE: {e}")));
    let signer =
        Es256Signer::from_p8(&key_id, &p8).unwrap_or_else(|e| fail(&format!("APNs key: {e}")));
    let config = apns::Config {
        team_id,
        topic,
        environments,
        alert,
        ..apns::Config::default()
    };
    let sender = apns::Sender::new(
        config,
        Arc::new(signer),
        http.clone(),
        sleeper.clone(),
        clock.clone(),
    )
    .unwrap_or_else(|e| fail(&format!("APNs configuration: {e}")));
    Some(Arc::new(sender))
}

/// Build the FCM sender if it is configured.
fn fcm_sender(
    http: &Arc<dyn HttpTransport>,
    sleeper: &Arc<dyn Sleeper>,
    clock: &Clock,
) -> Option<Arc<fcm::Sender>> {
    let (tokens, project_id): (Arc<dyn fcm::AccessTokens>, String) =
        match var("XCHONNECT_GATEWAY_FCM_SERVICE_ACCOUNT_FILE") {
            Some(path) => {
                let json = Secret::from_file(&path).unwrap_or_else(|e| {
                    fail(&format!("XCHONNECT_GATEWAY_FCM_SERVICE_ACCOUNT_FILE: {e}"))
                });
                let (account, signer) = ServiceAccount::parse(&json)
                    .unwrap_or_else(|e| fail(&format!("FCM service account: {e}")));
                let project_id = account.project_id.clone();
                let tokens =
                    fcm::ServiceAccountTokens::new(account, Arc::new(signer), http.clone());
                (Arc::new(tokens), project_id)
            }
            None => {
                let token = var("XCHONNECT_GATEWAY_FCM_ACCESS_TOKEN")?;
                let project_id = var("XCHONNECT_GATEWAY_FCM_PROJECT_ID").unwrap_or_else(|| {
                    fail("XCHONNECT_GATEWAY_FCM_PROJECT_ID is required with FCM_ACCESS_TOKEN")
                });
                tracing::warn!("FCM is using a pre-issued access token; it will not be refreshed");
                (Arc::new(fcm::StaticToken::new(&token)), project_id)
            }
        };
    let config = fcm::Config {
        project_id,
        ..fcm::Config::default()
    };
    let sender = fcm::Sender::new(config, tokens, http.clone(), sleeper.clone(), clock.clone())
        .unwrap_or_else(|e| fail(&format!("FCM configuration: {e}")));
    Some(Arc::new(sender))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("XCHONNECT_LOG")
                .unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .init();
    let keys: Vec<X25519Secret> = std::env::var("XCHONNECT_GATEWAY_KEYS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|k| b64::decode_array::<32>(k).map(X25519Secret::from_bytes))
        .collect::<Result<_, _>>()
        .unwrap_or_else(|_| fail("XCHONNECT_GATEWAY_KEYS: base64url 32-byte keys expected"));
    if keys.is_empty() {
        fail("XCHONNECT_GATEWAY_KEYS is required");
    }
    let clock: Clock = Arc::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    });
    let http: Arc<dyn HttpTransport> = match Https::new() {
        Ok(h) => Arc::new(h),
        Err(_) => fail("cannot initialise the TLS stack"),
    };
    let sleeper: Arc<dyn Sleeper> = Arc::new(TokioSleeper);

    let mut senders = Senders::default();
    if let Some(s) = apns_sender(&http, &sleeper, &clock) {
        tracing::info!("APNs delivery enabled: {s:?}");
        senders.apns = Some(s);
    }
    if let Some(s) = fcm_sender(&http, &sleeper, &clock) {
        tracing::info!("FCM delivery enabled: {s:?}");
        senders.fcm = Some(s);
    }
    if matches!(
        std::env::var("XCHONNECT_GATEWAY_TEST_PLATFORM").as_deref(),
        Ok("1" | "true")
    ) {
        senders.test = Some(Arc::new(CountingSender::default()));
    }
    if senders.apns.is_none() && senders.fcm.is_none() && senders.test.is_none() {
        tracing::warn!("no platform sender configured: every wake-up will be counted as failed");
    }

    let gateway = Gateway::new(keys, senders, DeviceLimits::default(), clock);
    for (i, pk) in gateway.public_keys().iter().enumerate() {
        tracing::info!("gateway public key {i}: {pk}");
    }
    let listen =
        std::env::var("XCHONNECT_GATEWAY_LISTEN").unwrap_or_else(|_| "127.0.0.1:8788".into());
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .unwrap_or_else(|_| fail("cannot listen"));
    tracing::info!("xchonnect push gateway listening on {listen}");
    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    if axum::serve(listener, app(gateway))
        .with_graceful_shutdown(shutdown)
        .await
        .is_err()
    {
        fail("server error");
    }
}
