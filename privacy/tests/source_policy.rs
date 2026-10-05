//! Static policy on the real repository: what the services may read, what they may log,
//! what the database schema may hold, and that the published inventory matches the spec.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::collections::BTreeSet;
use xchonnect_privacy_check::{inventory, sources};

#[test]
fn no_service_reads_client_identity_or_logs_an_identifier() {
    let root = inventory::repo_root();
    let findings = sources::check_services(&root).expect("service sources");
    assert!(
        findings.is_empty(),
        "{} source policy violation(s):\n{}",
        findings.len(),
        findings
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// The policy above only means something if the extractor really sees the log calls in
/// the production part of the real sources.
#[test]
fn the_log_call_extractor_sees_the_real_log_calls() {
    let root = inventory::repo_root();
    let mut total = 0;
    let mut files = 0;
    for dir in sources::SERVICE_SOURCES {
        for file in sources::rust_files(&root.join(dir)) {
            let text = std::fs::read_to_string(&file).expect("source");
            files += 1;
            total += sources::log_calls(sources::production_part(&text)).len();
        }
    }
    assert!(files >= 20, "only {files} service sources found");
    assert!(
        total >= 5,
        "only {total} log calls found in {files} sources"
    );
    let sweep = root.join("crates/relay/src/store/mod.rs");
    let text = std::fs::read_to_string(sweep).expect("store");
    let calls = sources::log_calls(sources::production_part(&text));
    assert!(
        calls.iter().any(|(_, args)| args.contains("sweep failed")),
        "the sweeper's warning was not extracted: {calls:?}"
    );
}

#[test]
fn the_relay_schema_is_exactly_what_the_inventory_declares() {
    let inv = inventory::load().expect("inventory");
    let columns =
        sources::migration_columns(&inventory::repo_root().join("crates/relay/migrations"))
            .expect("migrations");
    let problems = sources::check_schema(&inv.schema, &columns);
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    // Sanity: the fixture really read a schema.
    assert!(columns.contains("messages.envelope"), "{columns:?}");
}

/// First column of the spec's own data-inventory table (spec 14).
fn spec_data_rows(spec: &str) -> BTreeSet<String> {
    let mut rows = BTreeSet::new();
    let mut inside = false;
    let mut header = false;
    for line in spec.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("## ") {
            inside = trimmed.contains("Privacy considerations");
            header = false;
            continue;
        }
        if !inside || !trimmed.starts_with('|') {
            continue;
        }
        let first = trimmed
            .trim_matches('|')
            .split('|')
            .next()
            .unwrap_or_default()
            .trim()
            .to_owned();
        if first.chars().all(|c| c == '-' || c == ':') {
            continue;
        }
        if !header {
            header = true;
            continue;
        }
        rows.insert(first);
    }
    rows
}

#[test]
fn the_published_inventory_covers_every_row_of_the_spec_table() {
    let root = inventory::repo_root();
    let spec = std::fs::read_to_string(root.join("docs/spec/xchonnect-spec.md")).expect("spec");
    let spec_rows = spec_data_rows(&spec);
    assert!(
        spec_rows.len() >= 5,
        "the spec's data inventory table moved: {spec_rows:?}"
    );
    let inv = inventory::load().expect("inventory");
    let missing: Vec<&String> = spec_rows.difference(&inv.spec_rows).collect();
    assert!(
        missing.is_empty(),
        "docs/privacy/data-inventory.md does not say where these spec 14 rows are verified: {missing:?}"
    );
    let stale: Vec<&String> = inv.spec_rows.difference(&spec_rows).collect();
    assert!(
        stale.is_empty(),
        "docs/privacy/data-inventory.md maps rows the spec no longer has: {stale:?}"
    );
}

#[test]
fn the_logging_policy_is_still_the_one_the_checks_enforce() {
    // If spec 13.5 changes, this test points at the checks that must change with it.
    let spec = std::fs::read_to_string(inventory::repo_root().join("docs/spec/xchonnect-spec.md"))
        .expect("spec");
    let forbidden = spec
        .lines()
        .find(|l| l.trim_start().starts_with("- Forbidden:"))
        .expect("spec 13.5 forbidden list");
    for term in [
        "IPs",
        "User-Agents",
        "mailbox IDs",
        "token values",
        "ciphertext",
    ] {
        assert!(
            forbidden.contains(term),
            "spec 13.5 no longer forbids {term}: {forbidden}"
        );
    }
}
