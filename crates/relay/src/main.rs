//! Xchonnect relay binary. Configuration: see `xchonnect_relay::config`.

use std::net::SocketAddr;
use std::time::Duration;
use xchonnect_relay::{AppState, Config, app, store, system_clock, waiting_app};

fn fail(code: i32, msg: &str) -> ! {
    tracing::error!("{msg}");
    std::process::exit(code);
}

/// The relay these settings describe: its store, its workers and its routes.
async fn serving(config: Config) -> axum::Router {
    // `Config` refuses a missing database unless `XCHONNECT_STORE=memory` asked for this.
    let state = match &config.database_url {
        None => {
            tracing::warn!(
                "XCHONNECT_STORE=memory: mailboxes live in memory and are all lost on restart \
                 (development and tests only)"
            );
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
    // Where the mailboxes are, for the operator (not served: /readyz says only "ok").
    tracing::info!("store: {}", state.store().kind());
    store::spawn_sweeper(state.clone());
    state.start_workers();
    app(state)
}

/// Started with no settings at all. Exiting would make a host that starts the container
/// first and takes the settings afterwards (a ONCE app) give the deployment up before
/// anybody could enter them, so the relay stays up and serves nothing: `/up` answers,
/// everything else is `503` (`waiting_app`). What is missing goes to the log, again
/// every ten minutes, and never into a response. A restart with settings ends it; once
/// any setting is given, a missing or wrong one ends the process as it always did.
fn wait_for_settings(missing: &str, listen: SocketAddr) -> axum::Router {
    let reason = format!(
        "no settings yet ({missing}): waiting for them on {listen}, where only /up \
         answers and every other request gets 503. Set them and restart"
    );
    tracing::warn!("{reason}");
    tokio::spawn(async move {
        let mut every = tokio::time::interval(Duration::from_secs(600));
        every.tick().await;
        loop {
            every.tick().await;
            tracing::warn!("{reason}");
        }
    });
    waiting_app()
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

    let listen = Config::listen_from(|k| std::env::var(k).ok())
        .unwrap_or_else(|e| fail(2, &format!("configuration error: {e}")));
    let router = match Config::from_env() {
        Ok(config) => serving(config).await,
        Err(e) if Config::unconfigured(variable_names()) => wait_for_settings(&e, listen),
        Err(e) => fail(2, &format!("configuration error: {e}")),
    };

    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .unwrap_or_else(|e| fail(1, &format!("cannot listen on {listen}: {e}")));
    tracing::info!("xchonnect relay listening on {listen}");
    if let Err(e) = axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        fail(1, &format!("server error: {e}"));
    }
}

/// The names of the environment's variables (the values are not looked at here).
fn variable_names() -> impl Iterator<Item = String> {
    std::env::vars_os().filter_map(|(name, _)| name.into_string().ok())
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
