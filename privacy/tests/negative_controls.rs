//! Negative controls: every privacy check must fail when a leak is planted.
//!
//! A check that cannot fail is not a check. These tests plant the exact mistakes an
//! engineer would plausibly make — a mailbox id in a log line, a session identifier in a
//! metric label, an extra field in the wake-up payload, a client-IP column in the
//! schema, a field added to the sealed push token, tokens stored in the clear — and
//! require the corresponding check to report them.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::collections::BTreeSet;
use xchonnect_core::cbor::{self, Value as Cbor};
use xchonnect_core::crypto::{HpkeSender, MailboxId, OsEntropy, Token, X25519Secret};
use xchonnect_privacy_check::scan::{Class, Secrets, Surface, scan, scan_patterns};
use xchonnect_privacy_check::{capture, flow, inventory, sources};

const MAILBOX: MailboxId = MailboxId([0x4d; 16]);

/// Secrets of a pretend session, covering every class the inventory knows.
fn secrets() -> Secrets {
    let token = Token::from_bytes([0x5e; 32]);
    let mut s = Secrets::new();
    s.text(Class::ClientIp, "client ip", flow::CLIENT_IP)
        .text(Class::UserAgent, "user agent", flow::USER_AGENT)
        .text(Class::DeviceToken, "device token", flow::DEVICE_TOKEN)
        .text(Class::ChiaAddress, "address", flow::CHIA_ADDRESS)
        .text(Class::PublicKey, "public key", flow::BLS_PUBKEY)
        .text(Class::MessagePlaintext, "marker", flow::PLAINTEXT_MARKER)
        .text(Class::MessagePlaintext, "amount", flow::AMOUNT_MOJOS)
        .text(Class::GatewayUrl, "gateway", "https://push.example/v1/wake")
        .text(Class::CustomerId, "customer", flow::CUSTOMER)
        .text(Class::ApiKey, "api key", flow::API_KEY)
        .bytes(Class::MailboxId, "mailbox", &MAILBOX.0)
        .bytes(Class::PlaintextToken, "read token", token.expose())
        .bytes(Class::TokenHash, "read token hash", &token.hash())
        .bytes(Class::MsgId, "message id", &[0x6f; 16])
        .opaque_bytes(Class::Ciphertext, "envelope", &[0x7a; 96])
        .opaque_bytes(Class::SealedPushToken, "sealed token", &[0x8b; 80]);
    assert!(s.missing().is_empty(), "{:?}", s.missing());
    s
}

/// A surface that satisfies every `Must be observed` row of the real inventory, so that
/// a test can add one leak at a time and see only that leak reported.
fn clean_surface(name: &str, inv: &inventory::Inventory) -> Surface {
    let policy = inv.policy(name).expect(name);
    let mut s = Surface::new(name);
    let token = Token::from_bytes([0x5e; 32]);
    s.line("clean baseline");
    for class in &policy.present {
        let line = match class {
            Class::MailboxId => format!("mailbox={}", MAILBOX.to_b64()),
            Class::TokenHash => format!("read_hash={}", xchonnect_core::b64::encode(&token.hash())),
            Class::MsgId => format!("msg_id={}", xchonnect_core::b64::encode(&[0x6f; 16])),
            Class::Ciphertext => format!("env={}", xchonnect_core::b64::encode(&[0x7a; 96])),
            Class::SealedPushToken => {
                format!("sealed={}", xchonnect_core::b64::encode(&[0x8b; 80]))
            }
            Class::GatewayUrl => "url=https://push.example/v1/wake".to_owned(),
            Class::CustomerId => format!("customer={}", flow::CUSTOMER),
            Class::DeviceToken => format!("device_token={}", flow::DEVICE_TOKEN),
            other => panic!("the inventory expects {other} on {name}; teach this fixture about it"),
        };
        s.line(line);
    }
    s
}

fn verify_one(surface: Surface) -> inventory::Report {
    let inv = inventory::load().expect("inventory");
    inventory::verify(&inv, &[surface], &secrets(), true)
}

#[test]
fn the_clean_baseline_passes_so_the_failures_below_mean_something() {
    let inv = inventory::load().expect("inventory");
    for name in inv.names() {
        let report = verify_one(clean_surface(name, &inv));
        assert!(report.ok(), "baseline for {name}: {report}");
    }
}

#[test]
fn a_mailbox_id_in_a_log_line_is_caught_through_the_real_log_capture() {
    let inv = inventory::load().expect("inventory");
    let (logs, _guard) = capture::scoped();
    // Exactly the mistake the policy exists to prevent.
    tracing::info!(mailbox = %MAILBOX.to_b64(), "stored message");
    tracing::warn!("rate limited {}", flow::CLIENT_IP);
    let mut surface = clean_surface("service_logs", &inv);
    surface.text.push_str(&logs.text());

    let report = verify_one(surface.clone());
    assert!(!report.ok(), "a logged mailbox id must fail the check");
    let classes: BTreeSet<Class> = report.leaks.iter().map(|f| f.class).collect();
    assert!(classes.contains(&Class::MailboxId), "{report}");
    assert!(classes.contains(&Class::ClientIp), "{report}");
    // The shape detector catches the IP even without knowing the value.
    let shapes = scan_patterns(&surface, &inv.benign_for("service_logs"));
    assert!(
        shapes.iter().any(|h| h.pattern.id() == "ipv4_literal"),
        "{shapes:?}"
    );
}

#[test]
fn a_truncated_identifier_in_a_log_line_is_still_caught() {
    let inv = inventory::load().expect("inventory");
    let mut surface = clean_surface("service_logs", &inv);
    let prefix: String = MAILBOX.to_b64().chars().take(12).collect();
    surface.line(format!("mailbox {prefix}… fetched"));
    let report = verify_one(surface);
    assert!(
        report.leaks.iter().any(|f| f.class == Class::MailboxId),
        "a 12-character prefix of a mailbox id is still a correlatable identifier: {report}"
    );
}

#[test]
fn a_session_identifier_in_a_metric_label_is_caught() {
    let inv = inventory::load().expect("inventory");
    let mut surface = clean_surface("relay_metrics", &inv);
    surface.line(format!(
        "xchonnect_http_requests_total{{route=\"/v1/mailboxes/{}/messages\",class=\"2xx\"}} 3",
        MAILBOX.to_b64()
    ));
    let report = verify_one(surface);
    assert!(
        report.leaks.iter().any(|f| f.class == Class::MailboxId),
        "a per-mailbox metric label must fail the check: {report}"
    );
}

#[test]
fn plaintext_tokens_or_addresses_in_the_database_are_caught() {
    let inv = inventory::load().expect("inventory");
    let token = Token::from_bytes([0x5e; 32]);
    for (what, line) in [
        (
            Class::PlaintextToken,
            format!(
                "mailbox read_token={}",
                xchonnect_core::b64::encode(token.expose())
            ),
        ),
        (
            Class::ChiaAddress,
            format!("mailbox owner={}", flow::CHIA_ADDRESS),
        ),
        (
            Class::MessagePlaintext,
            format!("message memo={}", flow::PLAINTEXT_MARKER),
        ),
        (
            Class::ClientIp,
            format!("mailbox created_from={}", flow::CLIENT_IP),
        ),
    ] {
        let mut surface = clean_surface("database", &inv);
        surface.line(line);
        let report = verify_one(surface);
        assert!(
            report.leaks.iter().any(|f| f.class == what),
            "{what} stored in the database must fail the check: {report}"
        );
    }
}

#[test]
fn a_raw_binary_dump_is_scanned_too() {
    let inv = inventory::load().expect("inventory");
    let mut surface = clean_surface("database", &inv);
    // A dump that is not valid UTF-8 still has to be searched.
    surface.raw(flow::CHIA_ADDRESS.as_bytes());
    surface.raw(&[0xff, 0xfe, 0x00]);
    let report = verify_one(surface);
    assert!(
        report.leaks.iter().any(|f| f.class == Class::ChiaAddress),
        "{report}"
    );
}

#[test]
fn an_extra_field_in_the_wake_payload_is_caught() {
    let good = r#"{"sealed_token":"AAAA"}"#;
    assert_eq!(flow::wake_body_fields(good).unwrap(), vec!["sealed_token"]);
    let bad = r#"{"sealed_token":"AAAA","mailbox_id":"TU1NTU1NTU1NTU1NTU1NTQ"}"#;
    assert_ne!(
        flow::wake_body_fields(bad).unwrap(),
        vec!["sealed_token"],
        "an extra field in the wake-up body must be visible"
    );
    // And the value itself is found on the wake surface.
    let inv = inventory::load().expect("inventory");
    let mut surface = clean_surface("wake_request", &inv);
    surface.line(format!("body {bad}"));
    let report = verify_one(surface);
    assert!(
        report.leaks.iter().any(|f| f.class == Class::MailboxId),
        "{report}"
    );
    assert!(flow::wake_body_fields("not json").is_err());
}

#[test]
fn a_mailbox_id_or_amount_reaching_the_push_platform_is_caught() {
    let inv = inventory::load().expect("inventory");
    for (what, line) in [
        (
            Class::MailboxId,
            format!("deliver mailbox={}", MAILBOX.to_b64()),
        ),
        (
            Class::MessagePlaintext,
            format!(
                "deliver body=\"You are sending {} mojos\"",
                flow::AMOUNT_MOJOS
            ),
        ),
        (
            Class::ChiaAddress,
            format!("deliver body=\"to {}\"", flow::CHIA_ADDRESS),
        ),
    ] {
        let mut surface = clean_surface("push_delivery", &inv);
        surface.line(line);
        let report = verify_one(surface);
        assert!(
            report.leaks.iter().any(|f| f.class == what),
            "{what} in a push payload must fail the check: {report}"
        );
    }
}

#[test]
fn an_extra_field_in_the_sealed_push_token_is_caught() {
    let gateway = X25519Secret::from_bytes([0x33; 32]);
    let plaintext = cbor::encode(&Cbor::text_map(vec![
        ("p", Cbor::text("test")),
        ("t", Cbor::text(flow::DEVICE_TOKEN)),
        ("h", Cbor::bytes(&[1; 32])),
        ("exp", Cbor::Uint(1_900_000_000)),
        // The mistake: something about the request rides along to the vendor gateway.
        ("mbx", Cbor::bytes(&MAILBOX.0)),
    ]))
    .unwrap();
    let (enc, mut ctx) = HpkeSender::setup(
        &mut OsEntropy,
        &gateway.public_key(),
        xchonnect_core::push::INFO,
        None,
    )
    .unwrap();
    let sealed = [enc.as_slice(), &ctx.seal(b"", &plaintext).unwrap()].concat();
    let fields = flow::sealed_token_fields(&gateway, &sealed).unwrap();
    assert_eq!(fields, vec!["exp", "h", "mbx", "p", "t"]);
    assert_ne!(
        fields,
        vec!["exp", "h", "p", "t"],
        "a new sealed-token field must be visible to the check"
    );
}

#[test]
fn an_identity_column_added_to_the_schema_is_caught() {
    let inv = inventory::load().expect("inventory");
    let real = sources::migration_columns(&inventory::repo_root().join("crates/relay/migrations"))
        .expect("migrations");
    assert!(
        sources::check_schema(&inv.schema, &real).is_empty(),
        "the real schema must match the inventory"
    );
    let mut leaky = real.clone();
    leaky.insert("mailboxes.client_ip".to_owned());
    let problems = sources::check_schema(&inv.schema, &leaky);
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("client_ip"), "{problems:?}");
    // Removing a column is reported too, so the inventory cannot go stale silently.
    let mut shrunk = real.clone();
    shrunk.remove("messages.envelope");
    assert_eq!(sources::check_schema(&inv.schema, &shrunk).len(), 1);
}

#[test]
fn a_missing_planted_value_fails_instead_of_passing_vacuously() {
    let inv = inventory::load().expect("inventory");
    let mut incomplete = Secrets::new();
    incomplete.text(Class::ChiaAddress, "address", flow::CHIA_ADDRESS);
    let report = inventory::verify(
        &inv,
        &[clean_surface("service_logs", &inv)],
        &incomplete,
        true,
    );
    assert_eq!(
        report.violations.len(),
        Class::ALL.len() - 1,
        "a check with nothing to look for must fail: {report}"
    );
    // A surface that was never written to is a failure, not a pass.
    let report = inventory::verify(&inv, &[Surface::new("database")], &secrets(), true);
    assert!(
        report.violations.iter().any(|v| v.contains("empty")),
        "{report}"
    );
}

#[test]
fn a_leaky_log_call_in_a_service_source_is_caught() {
    let bad = "fn store(mailbox: &MailboxId) { tracing::debug!(?mailbox, \"stored\"); }";
    let findings = sources::check_source("crates/relay/src/made_up.rs", bad);
    assert_eq!(findings.len(), 1, "{findings:?}");
    let bad = "async fn h(ConnectInfo(addr): ConnectInfo<SocketAddr>) {}";
    assert!(!sources::check_source("crates/relay/src/made_up.rs", bad).is_empty());
}

#[test]
fn the_scanner_reports_where_without_repeating_the_value() {
    let mut surface = Surface::new("service_logs");
    surface.line(format!("leaked {}", flow::CHIA_ADDRESS));
    let findings = scan(&surface, &secrets());
    assert_eq!(findings.len(), 1);
    let rendered = findings[0].to_string();
    assert!(!rendered.contains(flow::CHIA_ADDRESS), "{rendered}");
    assert!(
        rendered.contains("chia_address") && rendered.contains("leaked"),
        "{rendered}"
    );
}
