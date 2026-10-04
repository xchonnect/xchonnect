//! Xchonnect push gateway binary.
//!
//! | Variable | Meaning |
//! |---|---|
//! | `XCHONNECT_GATEWAY_LISTEN` | listen address (default `127.0.0.1:8788`) |
//! | `XCHONNECT_GATEWAY_KEYS` | comma-separated base64url X25519 secret keys, newest first (required) |
//! | `XCHONNECT_GATEWAY_TEST_PLATFORM` | `true` to accept `test` platform tokens (counts only) |
//! | `XCHONNECT_LOG` | log filter |
//!
//! APNs and FCM senders are configured in TASK-46/47.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use xchonnect_core::b64;
use xchonnect_core::crypto::X25519Secret;
use xchonnect_gateway::{CountingSender, DeviceLimits, Gateway, Senders, app};

fn fail(msg: &str) -> ! {
    tracing::error!("{msg}");
    std::process::exit(2);
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
    let mut senders = Senders::default();
    if matches!(
        std::env::var("XCHONNECT_GATEWAY_TEST_PLATFORM").as_deref(),
        Ok("1" | "true")
    ) {
        senders.test = Some(Arc::new(CountingSender::default()));
    }
    let clock = Arc::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    });
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
