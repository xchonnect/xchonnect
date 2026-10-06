//! Xchonnect push gateway binary.
//!
//! | Variable | Meaning |
//! |---|---|
//! | `XCHONNECT_GATEWAY_LISTEN` | listen address (default `127.0.0.1:8788`) |
//! | `XCHONNECT_GATEWAY_KEYS` | comma-separated base64url X25519 secret keys, newest first (required) |
//! | `XCHONNECT_GATEWAY_TEST_PLATFORM` | `true` to accept `test` platform tokens (counts only) |
//! | `XCHONNECT_LOG` | log filter |
//!
//! APNs (team id, key id, topic and one of the two key sources are required together):
//!
//! | Variable | Meaning |
//! |---|---|
//! | `XCHONNECT_GATEWAY_APNS_TEAM_ID` | Apple Developer Team ID |
//! | `XCHONNECT_GATEWAY_APNS_KEY_ID` | Key ID of the `.p8` key |
//! | `XCHONNECT_GATEWAY_APNS_KEY_FILE` | path to the `.p8` file (secret source) |
//! | `XCHONNECT_GATEWAY_APNS_KEY` | the `.p8` text itself, instead of the file (ONCE apps; `\n` for line breaks) |
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
//!
//! With settings that are missing or wrong the gateway does not exit: it waits for them
//! (`wait_for_settings`, `docs/operating.md` "Waiting for settings").

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use xchonnect_core::b64;
use xchonnect_core::crypto::X25519Secret;
use xchonnect_gateway::creds::{Es256Signer, Secret, ServiceAccount};
use xchonnect_gateway::http::{HttpTransport, Https, Sleeper, TokioSleeper};
use xchonnect_gateway::{
    CountingSender, DeviceLimits, Gateway, Senders, apns, app, fcm, waiting_app,
};

fn fail(msg: &str) -> ! {
    tracing::error!("{msg}");
    std::process::exit(2);
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Build the APNs sender if it is configured. Any partial configuration is an error: a
/// gateway that silently drops iOS wake-ups is worse than one that does not serve.
fn apns_sender(
    http: &Arc<dyn HttpTransport>,
    sleeper: &Arc<dyn Sleeper>,
    clock: &Clock,
) -> Result<Option<Arc<apns::Sender>>, String> {
    let Some(team_id) = var("XCHONNECT_GATEWAY_APNS_TEAM_ID") else {
        return Ok(None);
    };
    let key_id = var("XCHONNECT_GATEWAY_APNS_KEY_ID")
        .ok_or("XCHONNECT_GATEWAY_APNS_KEY_ID is required with APNs")?;
    let topic = var("XCHONNECT_GATEWAY_APNS_TOPIC")
        .ok_or("XCHONNECT_GATEWAY_APNS_TOPIC is required with APNs")?;
    let environments = match var("XCHONNECT_GATEWAY_APNS_ENV").as_deref() {
        None | Some("production") => apns::Environments::Production,
        Some("sandbox") => apns::Environments::Sandbox,
        Some("both") => apns::Environments::Both,
        Some(_) => return Err("XCHONNECT_GATEWAY_APNS_ENV: production, sandbox or both".into()),
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
    // A file is the better source where files can be mounted; the text itself is for hosts
    // that only pass settings (a ONCE app). Both at once is a mistake worth stopping for.
    let p8 = match (
        var("XCHONNECT_GATEWAY_APNS_KEY_FILE"),
        var("XCHONNECT_GATEWAY_APNS_KEY"),
    ) {
        (Some(_), Some(_)) => {
            return Err(
                "set XCHONNECT_GATEWAY_APNS_KEY_FILE or XCHONNECT_GATEWAY_APNS_KEY, not both"
                    .into(),
            );
        }
        (Some(file), None) => {
            Secret::from_file(&file).map_err(|e| format!("XCHONNECT_GATEWAY_APNS_KEY_FILE: {e}"))?
        }
        (None, Some(_)) => Secret::from_env_pem("XCHONNECT_GATEWAY_APNS_KEY")
            .map_err(|e| format!("XCHONNECT_GATEWAY_APNS_KEY: {e}"))?,
        (None, None) => {
            return Err(
                "XCHONNECT_GATEWAY_APNS_KEY_FILE (or XCHONNECT_GATEWAY_APNS_KEY) is required \
                 with APNs"
                    .into(),
            );
        }
    };
    let signer = Es256Signer::from_p8(&key_id, &p8).map_err(|e| format!("APNs key: {e}"))?;
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
    .map_err(|e| format!("APNs configuration: {e}"))?;
    Ok(Some(Arc::new(sender)))
}

/// Build the FCM sender if it is configured.
fn fcm_sender(
    http: &Arc<dyn HttpTransport>,
    sleeper: &Arc<dyn Sleeper>,
    clock: &Clock,
) -> Result<Option<Arc<fcm::Sender>>, String> {
    let (tokens, project_id): (Arc<dyn fcm::AccessTokens>, String) =
        match var("XCHONNECT_GATEWAY_FCM_SERVICE_ACCOUNT_FILE") {
            Some(path) => {
                let json = Secret::from_file(&path)
                    .map_err(|e| format!("XCHONNECT_GATEWAY_FCM_SERVICE_ACCOUNT_FILE: {e}"))?;
                let (account, signer) = ServiceAccount::parse(&json)
                    .map_err(|e| format!("FCM service account: {e}"))?;
                let project_id = account.project_id.clone();
                let tokens =
                    fcm::ServiceAccountTokens::new(account, Arc::new(signer), http.clone());
                (Arc::new(tokens), project_id)
            }
            None => {
                let Some(token) = var("XCHONNECT_GATEWAY_FCM_ACCESS_TOKEN") else {
                    return Ok(None);
                };
                let project_id = var("XCHONNECT_GATEWAY_FCM_PROJECT_ID")
                    .ok_or("XCHONNECT_GATEWAY_FCM_PROJECT_ID is required with FCM_ACCESS_TOKEN")?;
                tracing::warn!("FCM is using a pre-issued access token; it will not be refreshed");
                (Arc::new(fcm::StaticToken::new(&token)), project_id)
            }
        };
    let config = fcm::Config {
        project_id,
        ..fcm::Config::default()
    };
    let sender = fcm::Sender::new(config, tokens, http.clone(), sleeper.clone(), clock.clone())
        .map_err(|e| format!("FCM configuration: {e}"))?;
    Ok(Some(Arc::new(sender)))
}

/// The gateway the settings describe, or what is wrong with them.
fn configure(
    http: &Arc<dyn HttpTransport>,
    sleeper: &Arc<dyn Sleeper>,
    clock: &Clock,
) -> Result<Gateway, String> {
    let keys: Vec<X25519Secret> = std::env::var("XCHONNECT_GATEWAY_KEYS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|k| b64::decode_array::<32>(k).map(X25519Secret::from_bytes))
        .collect::<Result<_, _>>()
        .map_err(|_| "XCHONNECT_GATEWAY_KEYS: base64url 32-byte keys expected")?;
    if keys.is_empty() {
        return Err("XCHONNECT_GATEWAY_KEYS is required".into());
    }

    let mut senders = Senders::default();
    if let Some(s) = apns_sender(http, sleeper, clock)? {
        tracing::info!("APNs delivery enabled: {s:?}");
        senders.apns = Some(s);
    }
    if let Some(s) = fcm_sender(http, sleeper, clock)? {
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
    Ok(Gateway::new(
        keys,
        senders,
        DeviceLimits::default(),
        clock.clone(),
    ))
}

/// The settings are missing or wrong. Exiting would make a host that starts the
/// container first and takes the settings afterwards (a ONCE app) give the deployment up
/// before anybody could enter them, so the gateway stays up instead and serves nothing:
/// `/up` answers, everything else is `503` (`waiting_app`). The reason goes to the log,
/// again every ten minutes, and never into a response. A restart with working settings
/// ends it.
fn wait_for_settings(error: &str, listen: &str) -> axum::Router {
    let reason = format!(
        "configuration error: {error}. Not serving: waiting for settings on {listen} \
         (only /up answers); set them and restart"
    );
    tracing::error!("{reason}");
    tokio::spawn(async move {
        let mut every = tokio::time::interval(Duration::from_secs(600));
        every.tick().await;
        loop {
            every.tick().await;
            tracing::error!("{reason}");
        }
    });
    waiting_app()
}

/// Ctrl-C, or the `SIGTERM` a container is stopped with.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = term => {},
    }
    tracing::info!("shutting down");
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

    let listen =
        std::env::var("XCHONNECT_GATEWAY_LISTEN").unwrap_or_else(|_| "127.0.0.1:8788".into());
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .unwrap_or_else(|_| fail("cannot listen"));
    let router = match configure(&http, &sleeper, &clock) {
        Ok(gateway) => {
            for (i, pk) in gateway.public_keys().iter().enumerate() {
                tracing::info!("gateway public key {i}: {pk}");
            }
            tracing::info!("xchonnect push gateway listening on {listen}");
            app(gateway)
        }
        Err(e) => wait_for_settings(&e, &listen),
    };
    if axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .is_err()
    {
        fail("server error");
    }
}
