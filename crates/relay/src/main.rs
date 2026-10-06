//! Xchonnect relay binary. Configuration: see `xchonnect_relay::config`.

use std::net::SocketAddr;
use std::time::Duration;
use xchonnect_relay::{AppState, Config, app, store, system_clock, waiting_app};

fn fail(code: i32, msg: &str) -> ! {
    tracing::error!("{msg}");
    std::process::exit(code);
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

    let config = match Config::from_env() {
        Ok(config) => config,
        Err(e) => wait_for_settings(&e).await,
    };
    let listen = config.listen;
    let state = match &config.database_url {
        None => {
            tracing::warn!("using the in-memory store: data is lost on restart");
            AppState::in_memory(config, system_clock())
        }
        #[cfg(feature = "postgres")]
        Some(url) => {
            let notifier = store::Notifier::default();
            let pg = store::postgres::PostgresStore::connect(url, notifier.clone())
                .await
                .unwrap_or_else(|e| fail(1, &format!("database: {e}")));
            let url_free = Config {
                database_url: None,
                ..config.clone()
            };
            AppState::new(url_free, std::sync::Arc::new(pg), notifier, system_clock())
        }
        #[cfg(not(feature = "postgres"))]
        Some(_) => fail(2, "built without the postgres feature"),
    };
    store::spawn_sweeper(state.clone());
    state.start_workers();

    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .unwrap_or_else(|e| fail(1, &format!("cannot listen on {listen}: {e}")));
    tracing::info!("xchonnect relay listening on {listen}");
    if let Err(e) = axum::serve(listener, app(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        fail(1, &format!("server error: {e}"));
    }
}

/// The settings are missing or wrong. Exiting would make a host that starts the
/// container first and takes the settings afterwards (a ONCE app) give the deployment up
/// before anybody could enter them, so the relay stays up instead and serves nothing:
/// `/up` answers, everything else is `503` (`waiting_app`). The reason goes to the log,
/// again every ten minutes, and never into a response. A restart with working settings
/// ends it.
async fn wait_for_settings(error: &str) -> ! {
    // The address the settings ask for, when that part of them is usable.
    let listen = std::env::var("XCHONNECT_LISTEN")
        .ok()
        .and_then(|v| v.parse::<SocketAddr>().ok())
        .unwrap_or_else(|| Config::default().listen);
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .unwrap_or_else(|e| fail(1, &format!("cannot listen on {listen}: {e}")));
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
    if let Err(e) = axum::serve(listener, waiting_app())
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        fail(1, &format!("server error: {e}"));
    }
    std::process::exit(0);
}

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
