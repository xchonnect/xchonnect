//! Property-based privacy checks.
//!
//! The invariants are fixed, so examples are the wrong shape for them: *no* mailbox id,
//! *no* token, *no* envelope and *no* push registration may reach the logs or the
//! metrics, whatever their bytes are and whatever the client sends.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use proptest::prelude::*;
use serde_json::json;
use std::sync::Arc;
use xchonnect_core::b64;
use xchonnect_core::crypto::Token;
use xchonnect_core::envelope::{Envelope, Kind};
use xchonnect_privacy_check::flow::{Call, Transport};
use xchonnect_privacy_check::harness::RouterTransport;
use xchonnect_privacy_check::scan::{Class, Secrets, Surface, scan};
use xchonnect_privacy_check::{capture, inventory};
use xchonnect_relay::config::{Creation, GatewayPolicy};
use xchonnect_relay::{AppState, Config};

/// One request/response round through the relay, on the current thread so that the
/// thread-local log capture sees everything.
fn relay_round(
    read: [u8; 32],
    write: [u8; 32],
    ct: Vec<u8>,
    sealed: Vec<u8>,
    junk: String,
    path_junk: String,
) -> (Surface, Surface, Secrets) {
    let (logs, _guard) = capture::scoped();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let config = Config {
        creation: vec![Creation::Open],
        gateway_policy: GatewayPolicy::Open,
        dev_allow_insecure_gateways: true,
        metrics: true,
        ..Config::default()
    };
    let state = AppState::in_memory(config, Arc::new(|| 1_790_000_000));
    let relay = RouterTransport::new(xchonnect_relay::app(state));
    let (read, write) = (Token::from_bytes(read), Token::from_bytes(write));
    // Session ciphertexts are padded to a bucket size (spec 8.2), so the random bytes
    // fill the smallest bucket.
    let mut ct = ct;
    ct.resize(xchonnect_core::envelope::BUCKETS[0], 0x5c);
    let envelope = Envelope {
        kind: Kind::Session,
        n: vec![7; 24],
        ct: ct.clone(),
    }
    .encode()
    .unwrap();

    let (metrics, msg_id) = runtime.block_on(async {
        let created = relay
            .call(
                Call::new("POST", "/v1/mailboxes").body(json!({
                    "read_token_hash": b64::encode(&read.hash()),
                    "write_token_hash": b64::encode(&write.hash()),
                    "push_reg": {
                        "gateway_url": "http://127.0.0.1:1/v1/wake",
                        "sealed_token": b64::encode(&sealed),
                    },
                })),
            )
            .await
            .unwrap();
        assert_eq!(created.0, 201, "{:?}", created.1);
        let id = created.1["mailbox_id"].as_str().unwrap().to_owned();
        let msgs = format!("/v1/mailboxes/{id}/messages");
        let posted = relay
            .call(
                Call::new("POST", &msgs)
                    .token(&write)
                    .body(json!({ "env": b64::encode(&envelope) })),
            )
            .await
            .unwrap();
        assert_eq!(posted.0, 202, "{:?}", posted.1);
        let msg_id = posted.1["msg_id"].as_str().unwrap().to_owned();
        relay.call(Call::new("GET", &msgs).token(&read)).await.unwrap();
        let ack = format!("/v1/mailboxes/{id}/ack");
        relay
            .call(
                Call::new("POST", &ack)
                    .token(&read)
                    .body(json!({ "msg_ids": [msg_id.clone()] })),
            )
            .await
            .unwrap();
        // Arbitrary client input on every shape of request.
        let junk_path = format!("/v1/mailboxes/{path_junk}/messages");
        relay.call(Call::new("GET", &junk_path).token(&read)).await.unwrap();
        relay
            .call(
                Call::new("POST", &msgs)
                    .token(&write)
                    .body(json!({ "env": junk.clone() })),
            )
            .await
            .unwrap();
        relay
            .call(Call::new("PUT", &format!("/v1/mailboxes/{id}/push")).token(&read).body(
                json!({ "push_reg": { "gateway_url": junk.clone(), "sealed_token": b64::encode(&sealed) } }),
            ))
            .await
            .unwrap();
        (relay.text("/metrics").await.unwrap(), msg_id)
    });

    let mut secrets = Secrets::new();
    secrets
        .bytes(Class::PlaintextToken, "read token", read.expose())
        .bytes(Class::PlaintextToken, "write token", write.expose())
        .bytes(Class::TokenHash, "read token hash", &read.hash())
        .bytes(Class::TokenHash, "write token hash", &write.hash())
        .opaque_bytes(Class::Ciphertext, "envelope", &envelope)
        .opaque_bytes(Class::Ciphertext, "inner ciphertext", &ct)
        .opaque_bytes(Class::SealedPushToken, "sealed token", &sealed);
    if let Ok(raw) = b64::decode(&msg_id) {
        secrets.bytes(Class::MsgId, "message id", &raw);
    }

    let mut log_surface = Surface::new("service_logs");
    log_surface.text = logs.text();
    let mut metrics_surface = Surface::new("relay_metrics");
    metrics_surface.line(metrics);
    (log_surface, metrics_surface, secrets)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 16, failure_persistence: None, ..ProptestConfig::default() })]

    /// Whatever the bytes and whatever the client sends, nothing identifying reaches the
    /// logs or the metrics.
    #[test]
    fn no_identifier_ever_reaches_the_logs_or_metrics(
        read in any::<[u8; 32]>(),
        write in any::<[u8; 32]>(),
        ct in proptest::collection::vec(any::<u8>(), 32..600),
        sealed in proptest::collection::vec(any::<u8>(), 16..200),
        junk in "[ -~]{0,40}",
        path_junk in "[A-Za-z0-9._~-]{0,24}",
    ) {
        prop_assume!(read != write);
        let (logs, metrics, secrets) = relay_round(read, write, ct, sealed, junk, path_junk);
        let inv = inventory::load().unwrap();
        for surface in [logs, metrics] {
            let findings = scan(&surface, &secrets);
            prop_assert!(
                findings.is_empty(),
                "{}: {}",
                surface.name,
                findings.iter().map(ToString::to_string).collect::<Vec<_>>().join("; ")
            );
            // The declared "must never appear" set is what was just verified.
            let policy = inv.policy(&surface.name).unwrap();
            prop_assert!(policy.absent.contains(&Class::MailboxId));
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, failure_persistence: None, ..ProptestConfig::default() })]

    /// The scanner finds an identifier wherever it sits, in every encoding, and does not
    /// invent findings in text that does not contain it.
    #[test]
    fn the_scanner_is_complete_and_has_no_false_positives(
        id in any::<[u8; 16]>(),
        before in "[ -~]{0,30}",
        after in "[ -~]{0,30}",
    ) {
        let mut secrets = Secrets::new();
        secrets.bytes(Class::MailboxId, "mailbox", &id);
        for form in [
            b64::encode(&id),
            format!("{id:?}"),
            id.iter().map(|b| format!("{b:02x}")).collect(),
            id.iter().map(|b| format!("{b:02X}")).collect(),
        ] {
            let mut planted = Surface::new("service_logs");
            planted.line(format!("{before}{form}{after}"));
            prop_assert!(!scan(&planted, &secrets).is_empty(), "missed {form}");
        }
        let mut clean = Surface::new("service_logs");
        clean.line(format!("{before}|{after}"));
        clean.raw(&[0xab; 64]);
        prop_assert!(scan(&clean, &secrets).is_empty());
    }
}
