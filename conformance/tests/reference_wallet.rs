//! Runs the wallet conformance suite against the example CLI wallet
//! (`examples/wallet-cli`) over real HTTP, with the reference relay served in-process on
//! a free port. This is what makes the suite part of CI (`cargo test --workspace`).
//!
//! The wallet runs with a development key so that it really signs: without one it
//! answers every signing request with the BLS identity element, and the signing checks
//! cannot tell a conforming refusal from a wallet that refuses everything.
#![allow(clippy::unwrap_used, clippy::panic, reason = "test code")]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc;
use xchonnect_conformance::wallet::{self, Options, Status};
use xchonnect_relay::{AppState, Config, app, store, system_clock};

/// Development seed for the wallet under test. Testnet only, and never a real key.
const SEED: &str = "xchonnect wallet conformance development seed";
/// Per-request XCH limit configured in the wallet, in mojos.
const LIMIT: u128 = 1_000_000;

/// Start the reference relay with open mailbox creation (no proof-of-work, so the run
/// stays fast) and return its base URL.
fn start_relay() -> String {
    let env: HashMap<String, String> = [
        ("XCHONNECT_CREATION", "open"),
        ("XCHONNECT_GATEWAY_POLICY", "open"),
        ("XCHONNECT_OHTTP", "ephemeral"),
    ]
    .iter()
    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
    .collect();
    let config = Config::from_lookup(|k| env.get(k).cloned()).unwrap();
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let state = AppState::in_memory(config, system_clock());
            store::spawn_sweeper(state.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let _ = tx.send(format!("http://{addr}"));
            axum::serve(listener, app(state)).await.unwrap();
        });
    });
    rx.recv().unwrap()
}

/// The example wallet's binary, built if it is not there yet (it is when the whole
/// workspace is tested, which is how CI runs this).
fn wallet_binary() -> PathBuf {
    let exe = std::env::current_exe().expect("test executable path");
    let dir = exe
        .parent()
        .and_then(std::path::Path::parent)
        .expect("target/<profile>");
    let bin = dir.join("xchonnect-wallet-cli");
    if bin.exists() {
        return bin;
    }
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let built = std::process::Command::new(cargo)
        .args(["build", "--locked", "-p", "xchonnect-wallet-cli"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(
        built && bin.exists(),
        "cannot find or build {}: the wallet conformance suite needs the example wallet",
        bin.display()
    );
    bin
}

#[test]
fn the_example_cli_wallet_conforms() {
    let bin = wallet_binary();
    // `{uri}` is substituted by the suite and the whole command runs through `sh -c`, so
    // the answer-piping variants need nothing from the wallet but its normal prompts.
    let base = format!(
        "'{}' pair '{{uri}}' --dev --dev-key '{SEED}' --limit-xch-per-request {LIMIT}",
        bin.display()
    );
    let report = wallet::run(&Options {
        relay: start_relay(),
        wallet: format!("{base} --auto-approve"),
        // "pair? yes" then "do the codes match? no".
        wallet_sas_mismatch: Some(format!("printf 'y\\nn\\n' | {base}")),
        // "pair? yes", "codes match? yes", then "approve this request? no".
        wallet_reject: Some(format!("printf 'y\\ny\\nn\\n' | {base}")),
        xch_per_request_limit: Some(LIMIT),
        refusal_timeout_s: 6,
        ..Options::default()
    });
    println!("{}", report.to_text());
    assert!(
        report.is_success(),
        "the example wallet failed its own conformance suite:\n{}",
        report.to_text()
    );
    let skipped = report.ids_with(Status::Skip);
    assert!(
        // W-PAIR-02 waits five minutes for a pairing timeout; it is opt-in (`--slow`).
        skipped.iter().all(|id| *id == "W-PAIR-02"),
        "unexpected skips: {skipped:?}\n{}",
        report.to_text()
    );
}
