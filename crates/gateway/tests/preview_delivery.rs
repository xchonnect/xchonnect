//! End to end for the encrypted notification preview (spec 7.3.3): a dApp seals a
//! preview under the session's mailbox hint key, the gateway opens the sealed push token
//! and hands the still-encrypted preview to APNs and FCM, and the wallet's Notification
//! Service Extension / FCM data handler decrypts it from the delivered payload.
//!
//! The gateway and both providers only ever see a fixed-size opaque blob (T11), and a
//! payload the device cannot authenticate falls back to the generic alert (T12).
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::sync::Arc;
use xchonnect_core::crypto::{OsEntropy, X25519Secret};
use xchonnect_core::preview::{self, Kind, Outcome, Policy, Preview};
use xchonnect_core::push::{Platform, PushToken};
use xchonnect_core::{b64, crypto};
use xchonnect_gateway::creds::TestSigner;
use xchonnect_gateway::http::{Recorder, Reply, TokioSleeper};
use xchonnect_gateway::{DeviceLimits, Gateway, Senders, apns, fcm};

const NOW: u64 = 1_790_000_000;
const DEVICE_APNS: &str = "aa11bb22cc33dd44ee55ff6600778899aa11bb22cc33dd44ee55ff6600778899";
const DEVICE_FCM: &str =
    "fMEP0vJqSBC1a2b3c4d5e6:APA91bHZq0w9e8r7t6y5u4i3o2p1aSdFgHjKlZxCvBnM0987654321";

fn clock() -> Arc<dyn Fn() -> u64 + Send + Sync> {
    Arc::new(|| NOW)
}

fn sealed_token(gw: &X25519Secret, platform: Platform, device: &str, hint: [u8; 32]) -> Vec<u8> {
    PushToken {
        platform,
        device_token: device.into(),
        hint_key: hint,
        exp: NOW + 3600,
    }
    .seal(&mut OsEntropy, &gw.public_key(), NOW)
    .unwrap()
}

/// A gateway with recorded APNs and FCM transports.
fn gateway(gw_key: &X25519Secret) -> (Gateway, Arc<Recorder>, Arc<Recorder>) {
    let apns_http = Arc::new(Recorder::always(Reply::status(200)));
    let fcm_http = Arc::new(Recorder::always(Reply::status(200)));
    let apns_sender = apns::Sender::new(
        apns::Config {
            team_id: "TEAM123456".into(),
            topic: "app.klimper.wallet".into(),
            ..apns::Config::default()
        },
        Arc::new(TestSigner::with_key_id("ES256", "KEYID12345")),
        apns_http.clone(),
        Arc::new(TokioSleeper),
        clock(),
    )
    .unwrap();
    let fcm_sender = fcm::Sender::new(
        fcm::Config {
            project_id: "klimper-wallet".into(),
            ..fcm::Config::default()
        },
        Arc::new(fcm::StaticToken::new("ya29.integration-access-token")),
        fcm_http.clone(),
        Arc::new(TokioSleeper),
        clock(),
    )
    .unwrap();
    let senders = Senders {
        apns: Some(Arc::new(apns_sender)),
        fcm: Some(Arc::new(fcm_sender)),
        test: None,
    };
    let g = Gateway::new(
        vec![gw_key.clone()],
        senders,
        DeviceLimits::default(),
        clock(),
    );
    (g, apns_http, fcm_http)
}

/// What an iOS Notification Service Extension does with the delivered payload.
fn nse_decrypt(payload: &[u8], hint: &[u8; 32], policy: Policy) -> Outcome {
    let v: serde_json::Value = match serde_json::from_slice(payload) {
        Ok(v) => v,
        Err(_) => return Outcome::Generic,
    };
    let Some(blob) = v.get(apns::PREVIEW_KEY).and_then(|p| p.as_str()) else {
        return Outcome::Generic;
    };
    let Ok(sealed) = b64::decode(blob) else {
        return Outcome::Generic;
    };
    preview::open(hint, &sealed, NOW, policy)
}

/// What an Android FCM data handler does with the delivered message.
fn android_decrypt(body: &[u8], hint: &[u8; 32], policy: Policy) -> Outcome {
    let v: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return Outcome::Generic,
    };
    let Some(blob) = v["message"]["data"]
        .get(fcm::PREVIEW_KEY)
        .and_then(|p| p.as_str())
    else {
        return Outcome::Generic;
    };
    let Ok(sealed) = b64::decode(blob) else {
        return Outcome::Generic;
    };
    preview::open(hint, &sealed, NOW, policy)
}

#[tokio::test]
async fn a_preview_survives_the_gateway_and_decrypts_on_both_platforms() {
    let gw_key = X25519Secret::random(&mut OsEntropy);
    let (g, apns_http, fcm_http) = gateway(&gw_key);
    // The hint key the wallet generated at registration and shared with the dApp.
    let hint: [u8; 32] = crypto::random_array(&mut OsEntropy);
    let p = Preview {
        kind: Kind::SigningRequest,
        detail: Some("needs your signature".into()),
    };
    let sealed_preview = preview::seal(&mut OsEntropy, &hint, &p, NOW, preview::TTL_S).unwrap();
    assert_eq!(sealed_preview.len(), preview::SEALED_LEN);

    for (platform, device) in [(Platform::Apns, DEVICE_APNS), (Platform::Fcm, DEVICE_FCM)] {
        let token = sealed_token(&gw_key, platform, device, hint);
        g.wake(&token, Some(&sealed_preview)).await;
    }
    assert_eq!(
        g.stats()
            .delivered
            .load(std::sync::atomic::Ordering::Relaxed),
        2
    );

    // iOS: the NSE recovers exactly what the dApp sealed.
    let ios = apns_http.nth(0).unwrap().body;
    assert_eq!(
        nse_decrypt(&ios, &hint, Policy::with_detail()),
        Outcome::Decrypted(p.clone())
    );
    // Default policy keeps the detail off the lock screen.
    let shown = nse_decrypt(&ios, &hint, Policy::default());
    assert_eq!(shown.preview().unwrap().kind, Kind::SigningRequest);
    assert_eq!(shown.preview().unwrap().detail, None);
    assert_eq!(shown.loc_key(), "xchonnect.preview.signing_request");

    // Android: same.
    let android = fcm_http.nth(0).unwrap().body;
    assert_eq!(
        android_decrypt(&android, &hint, Policy::with_detail()),
        Outcome::Decrypted(p)
    );

    // Neither payload reveals anything to Apple, Google or the gateway.
    for payload in [&ios, &android] {
        let text = String::from_utf8(payload.clone()).unwrap();
        for leak in ["needs your signature", &b64::encode(&hint)] {
            assert!(!text.contains(leak), "{leak} leaked into the payload");
        }
    }
    // And the blob is the same fixed size whatever the preview said.
    let empty = preview::seal(
        &mut OsEntropy,
        &hint,
        &Preview::default(),
        NOW,
        preview::TTL_S,
    )
    .unwrap();
    assert_eq!(empty.len(), sealed_preview.len());
}

#[tokio::test]
async fn a_device_that_cannot_authenticate_the_preview_shows_the_generic_alert() {
    let gw_key = X25519Secret::random(&mut OsEntropy);
    let (g, apns_http, _) = gateway(&gw_key);
    let hint: [u8; 32] = crypto::random_array(&mut OsEntropy);
    let other: [u8; 32] = crypto::random_array(&mut OsEntropy);
    let sealed_preview = preview::seal(
        &mut OsEntropy,
        &hint,
        &Preview {
            kind: Kind::SigningRequest,
            detail: None,
        },
        NOW,
        preview::TTL_S,
    )
    .unwrap();
    let token = sealed_token(&gw_key, Platform::Apns, DEVICE_APNS, hint);

    // A preview forged by someone without the hint key.
    let forged = vec![0xab; preview::SEALED_LEN];
    g.wake(&token, Some(&forged)).await;
    let payload = apns_http.nth(0).unwrap().body;
    assert_eq!(
        nse_decrypt(&payload, &hint, Policy::with_detail()),
        Outcome::Generic
    );
    // The generic alert is still there to fall back to.
    let v: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(v["aps"]["interruption-level"], "time-sensitive");
    assert_eq!(v["aps"]["mutable-content"], 1);
    assert!(v["aps"]["alert"]["title"].is_string());

    // A genuine preview read with the wrong session's hint key.
    assert_eq!(
        preview::open(&other, &sealed_preview, NOW, Policy::with_detail()),
        Outcome::Generic
    );
    // And a wake-up with no preview at all.
    assert_eq!(
        nse_decrypt(
            &serde_json::to_vec(&serde_json::json!({ "aps": {} })).unwrap(),
            &hint,
            Policy::default()
        ),
        Outcome::Generic
    );
}
