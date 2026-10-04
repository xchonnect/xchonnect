//! Runs the relay conformance suite over real HTTP against the reference relay
//! (`xchonnect-relay`), served in-process on a free port with the same router the
//! binary uses. The Postgres variant runs only when `XCHONNECT_TEST_DATABASE_URL` is set.
#![allow(clippy::unwrap_used, clippy::panic, reason = "test code")]

use std::collections::HashMap;
use std::sync::{Arc, mpsc};
use xchonnect_conformance::relay::{self, Options};
use xchonnect_relay::{AppState, Config, app, store, system_clock};

const API_KEY: &str = "conformance-test-key-0123";

/// Start a relay configured from `env` (`XCHONNECT_*` names) and return its base URL.
fn start_relay(env: &[(&str, &str)], database_url: Option<String>) -> String {
    // The checks do not cover OHTTP; a throwaway gateway key keeps startup valid.
    let env: HashMap<String, String> = [("XCHONNECT_OHTTP", "ephemeral")]
        .iter()
        .chain(env)
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    let config = Config::from_lookup(|k| env.get(k).cloned()).unwrap();
    let (tx, rx) = mpsc::channel::<Result<String, String>>();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let state = match database_url {
                None => AppState::in_memory(config, system_clock()),
                Some(url) => {
                    let notifier = store::Notifier::default();
                    match store::postgres::PostgresStore::connect(&url, notifier.clone()).await {
                        Ok(pg) => AppState::new(config, Arc::new(pg), notifier, system_clock()),
                        Err(e) => {
                            let _ = tx.send(Err(e));
                            return;
                        }
                    }
                }
            };
            store::spawn_sweeper(state.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let _ = tx.send(Ok(format!("http://{addr}")));
            axum::serve(listener, app(state)).await.unwrap();
        });
    });
    rx.recv().unwrap().unwrap()
}

fn run_suite(base_url: String, api_key: Option<&str>) {
    let report = relay::run(&Options {
        base_url,
        api_key: api_key.map(str::to_owned),
        aggressive: true,
        ..Options::default()
    });
    println!("{}", report.to_text());
    assert!(
        report.is_success(),
        "conformance failures:\n{}",
        report.to_text()
    );
    let skipped: Vec<&str> = report
        .results
        .iter()
        .filter(|r| r.status == relay::Status::Skip)
        .map(|r| r.info.id)
        .collect();
    assert!(
        skipped.iter().all(|id| [
            "R-MSG-06",
            "R-POLL-03",
            "R-CREATE-04",
            "R-POW-01",
            "R-POW-02",
            "R-PUSH-02",
            "R-TICKET-01",
            "R-TICKET-02",
            "R-APIKEY-01",
            "R-QUOTA-01"
        ]
        .contains(id)),
        "unexpected skips: {skipped:?}"
    );
}

/// Hosted-relay profile: pow + tickets + API keys, gateway allowlist, small quota so
/// R-QUOTA-01 and the 32-message fetch cap are exercised.
const HOSTED: &[(&str, &str)] = &[
    ("XCHONNECT_CREATION", "pow,ticket,api_key"),
    ("XCHONNECT_POW_DIFFICULTY", "8"),
    (
        "XCHONNECT_API_KEYS",
        "conformance:conformance-test-key-0123",
    ),
    ("XCHONNECT_GATEWAY_POLICY", "allowlist"),
    (
        "XCHONNECT_GATEWAY_ALLOWLIST",
        "https://push.example-wallet.app/",
    ),
    ("XCHONNECT_MAX_MESSAGES", "40"),
];

/// Self-hosted profile: open creation and open gateway policy, default limits.
const SELF_HOSTED: &[(&str, &str)] = &[
    ("XCHONNECT_CREATION", "open"),
    ("XCHONNECT_GATEWAY_POLICY", "open"),
];

#[test]
fn in_memory_hosted_profile() {
    let url = start_relay(HOSTED, None);
    run_suite(url, Some(API_KEY));
}

#[test]
fn in_memory_self_hosted_profile() {
    let url = start_relay(SELF_HOSTED, None);
    run_suite(url, None);
}

#[test]
fn postgres_hosted_profile() {
    let Some(db) = std::env::var("XCHONNECT_TEST_DATABASE_URL")
        .ok()
        .filter(|s| !s.is_empty())
    else {
        eprintln!("skipped: XCHONNECT_TEST_DATABASE_URL not set");
        return;
    };
    let url = start_relay(HOSTED, Some(db));
    run_suite(url, Some(API_KEY));
}
