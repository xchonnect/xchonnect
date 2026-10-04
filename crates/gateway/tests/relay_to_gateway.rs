//! End to end: wallet registers a sealed token on the relay; a posted message makes the
//! relay wake the gateway, which delivers to the platform sender. Both run in-process on
//! real sockets.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use xchonnect_core::b64;
use xchonnect_core::crypto::{OsEntropy, Token, X25519Secret};
use xchonnect_core::envelope::{Envelope, Kind};
use xchonnect_core::push::{Platform, PushToken};
use xchonnect_gateway::{CountingSender, DeviceLimits, Gateway, Senders};
use xchonnect_relay::config::{Config, Creation, GatewayPolicy};

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn serve(app: axum::Router) -> std::net::SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    a
}

#[tokio::test(flavor = "multi_thread")]
async fn message_on_relay_wakes_device_through_gateway() {
    let gw_key = X25519Secret::random(&mut OsEntropy);
    let sender = Arc::new(CountingSender::default());
    let gateway = Gateway::new(
        vec![gw_key.clone()],
        Senders {
            test: Some(sender.clone()),
            ..Senders::default()
        },
        DeviceLimits::default(),
        Arc::new(now),
    );
    let gw_addr = serve(xchonnect_gateway::app(gateway.clone())).await;

    let gw_url = format!("http://{gw_addr}/v1/wake");
    let config = Config {
        creation: vec![Creation::Open],
        gateway_policy: GatewayPolicy::Allowlist(vec![format!("http://{gw_addr}/")]),
        dev_allow_insecure_gateways: true,
        ..Config::default()
    };
    let state = xchonnect_relay::AppState::in_memory(config, xchonnect_relay::system_clock());
    state.start_workers();
    let relay = format!("http://{}", serve(xchonnect_relay::app(state)).await);

    let sealed = PushToken {
        platform: Platform::Test,
        device_token: "device-123".into(),
        hint_key: [0; 32],
        exp: now() + 3600,
    }
    .seal(&mut OsEntropy, &gw_key.public_key(), now())
    .unwrap();
    let (r, w) = (Token::random(&mut OsEntropy), Token::random(&mut OsEntropy));
    let relay2 = relay.clone();
    let id = tokio::task::spawn_blocking(move || {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .into();
        let body = serde_json::json!({
            "read_token_hash": b64::encode(&r.hash()), "write_token_hash": b64::encode(&w.hash()),
            "push_reg": { "gateway_url": gw_url, "sealed_token": b64::encode(&sealed) },
        });
        let mut res = agent
            .post(format!("{relay2}/v1/mailboxes"))
            .header("content-type", "application/json")
            .send(body.to_string())
            .unwrap();
        assert_eq!(res.status().as_u16(), 201);
        let v: serde_json::Value =
            serde_json::from_str(&res.body_mut().read_to_string().unwrap()).unwrap();
        let id = v["mailbox_id"].as_str().unwrap().to_owned();
        let env = b64::encode(
            &Envelope {
                kind: Kind::Session,
                n: vec![1; 24],
                ct: vec![2; 1024],
            }
            .encode()
            .unwrap(),
        );
        let res = agent
            .post(format!("{relay2}/v1/mailboxes/{id}/messages"))
            .header(
                "authorization",
                format!("Bearer {}", b64::encode(w.expose())),
            )
            .header("content-type", "application/json")
            .send(serde_json::json!({ "env": env }).to_string())
            .unwrap();
        assert_eq!(res.status().as_u16(), 202);
        id
    })
    .await
    .unwrap();
    assert!(!id.is_empty());

    for _ in 0..100 {
        if gateway.stats().delivered.load(Ordering::Relaxed) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert_eq!(gateway.stats().delivered.load(Ordering::Relaxed), 1);
    assert_eq!(sender.sent.lock().unwrap()["test"], 1);
}
