//! The end-to-end privacy check (spec 13.4 invariants 2 and 5, 13.5, 14; TASK-54).
//!
//! One test, because it installs the process-wide log subscriber: run a complete
//! pairing, signing and push-wake session through the real relay and gateway code, then
//! hold every artefact an operator or an auditor could look at — the data the relay wrote
//! to storage, every log line at `TRACE`, both metrics endpoints, the billing counters,
//! the wake-up request and what the gateway handed the push platform — against the
//! published data inventory.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use xchonnect_privacy_check::scan::Class;
use xchonnect_privacy_check::{capture, flow, harness, inventory};

#[tokio::test(flavor = "multi_thread")]
async fn a_full_session_leaks_nothing_the_inventory_forbids() {
    let logs = capture::global();
    let h = harness::Harness::start().await.expect("harness");
    let outcome = flow::run(&h.relay, &h.params, harness::now())
        .await
        .expect("full pairing, signing and push flow");
    for note in &outcome.notes {
        println!("flow: {note}");
    }

    // The wake-up is dispatched in the background; wait for it, because a run without it
    // would leave `wake_request` and `push_delivery` empty, which `verify` rejects.
    assert!(
        h.wait_for_wake(outcome.expected_wakes).await,
        "the relay never delivered a wake-up to the gateway (delivered {})",
        h.delivered()
    );

    let surfaces = h.surfaces(&logs).await.expect("surfaces");
    let inv = inventory::load().expect("published data inventory");
    assert_eq!(
        surfaces.len(),
        inv.surfaces.len(),
        "this check must observe every surface the inventory declares: observed {:?}, declared {:?}",
        surfaces.iter().map(|s| &s.name).collect::<Vec<_>>(),
        inv.names(),
    );
    for s in &surfaces {
        println!("surface {}: {} bytes", s.name, s.len());
    }

    let report = inventory::verify(&inv, &surfaces, &outcome.secrets, true);
    assert!(report.ok(), "{report}");
    assert!(report.skipped.is_empty(), "{report}");

    // Spot-check the strongest single claim in plain terms: nothing the user typed or
    // owns is anywhere outside the database, and the message plaintext is nowhere at all.
    let anywhere_forbidden = [
        Class::ClientIp,
        Class::UserAgent,
        Class::ChiaAddress,
        Class::PublicKey,
        Class::MessagePlaintext,
        Class::PlaintextToken,
        Class::ApiKey,
    ];
    for surface in &surfaces {
        let found = xchonnect_privacy_check::scan::classes(surface, &outcome.secrets);
        for class in anywhere_forbidden {
            assert!(
                !found.contains(&class),
                "{}: {class} must never appear, found {:?}",
                surface.name,
                found
            );
        }
    }

    // The sealed push token is the only user-specific thing the relay forwards. Pin its
    // shape: a new field would be new data leaving the relay.
    for sealed in &outcome.sealed_tokens {
        let fields = flow::sealed_token_fields(&h.gateway_key, sealed).expect("sealed token opens");
        assert_eq!(
            fields,
            vec!["exp", "h", "p", "t"],
            "the sealed push token carries exactly platform, device token, hint key and expiry"
        );
    }

    // And the wake-up body itself is exactly one field.
    let wake = surfaces
        .iter()
        .find(|s| s.name == "wake_request")
        .expect("wake_request surface");
    let body = wake
        .text
        .lines()
        .find_map(|l| l.strip_prefix("body "))
        .expect("a recorded wake-up body");
    let keys = flow::wake_body_fields(body).expect("wake body is a JSON object");
    assert_eq!(keys, vec!["sealed_token"], "wake-up body: {body}");

    println!("{report}");
}
