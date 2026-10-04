//! OHTTP through the exported wallet API against the relay's gateway (in process).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use tower::ServiceExt;
use xchonnect_relay::ohttp::{GATEWAY_PATH, KEYS_PATH, OhttpKey, OhttpMode};
use xchonnect_relay::{AppState, Config};
use xchonnect_uniffi::*;

fn relay(keys: &[(u8, u8)]) -> AppState {
    let config = Config {
        creation: vec![xchonnect_relay::config::Creation::Open],
        ohttp: OhttpMode::Keys(
            keys.iter()
                .map(|(i, s)| OhttpKey::new(*i, [*s; 32]))
                .collect(),
        ),
        ..Config::default()
    };
    AppState::in_memory(config, xchonnect_relay::system_clock())
}

async fn post(s: &AppState, path: &str, content_type: &str, body: Vec<u8>) -> (u16, Vec<u8>) {
    let req = Request::post(path)
        .header("content-type", content_type)
        .body(Body::from(body))
        .unwrap();
    let res = xchonnect_relay::app(s.clone()).oneshot(req).await.unwrap();
    let st = res.status().as_u16();
    (
        st,
        res.into_body().collect().await.unwrap().to_bytes().to_vec(),
    )
}

fn request(method: &str, path: &str, headers: Vec<HttpHeader>, body: &[u8]) -> OhttpRequest {
    OhttpRequest {
        method: method.into(),
        scheme: "https".into(),
        authority: "relay.example".into(),
        path: path.into(),
        headers,
        body: body.to_vec(),
    }
}

async fn send(s: &AppState, client: &OhttpClient, req: OhttpRequest) -> OhttpResponse {
    let e = client.encapsulate(req).unwrap();
    let (st, body) = post(s, GATEWAY_PATH, "message/ohttp-req", e.body).await;
    assert_eq!(st, 200);
    e.context.decapsulate(body).unwrap()
}

#[tokio::test]
async fn wallet_round_trip_and_rotation_through_the_gateway() {
    let old = relay(&[(1, 0x11)]);
    let res = xchonnect_relay::app(old.clone())
        .oneshot(Request::get(KEYS_PATH).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let published = res.into_body().collect().await.unwrap().to_bytes().to_vec();
    let pin = ohttp_select_key(published).unwrap();

    let s = relay(&[(2, 0x22), (1, 0x11)]);
    let client = OhttpClient::new(pin.clone()).unwrap();
    assert_eq!(client.key_id(), 1);
    let (read, write) = (generate_token(), generate_token());
    let create = format!(
        r#"{{"read_token_hash":"{}","write_token_hash":"{}"}}"#,
        token_hash(read.clone()).unwrap(),
        token_hash(write).unwrap()
    );
    let json = || HttpHeader {
        name: "content-type".into(),
        value: "application/json".into(),
    };
    let r = send(
        &s,
        &client,
        request("POST", "/v1/mailboxes", vec![json()], create.as_bytes()),
    )
    .await;
    assert_eq!(r.status, 201);
    let body = String::from_utf8(r.body).unwrap();
    let id = body.split('"').nth(3).unwrap().to_owned();
    let auth = HttpHeader {
        name: "authorization".into(),
        value: format!("Bearer {read}"),
    };
    let msgs = format!("/v1/mailboxes/{id}/messages?wait=10");
    let r = send(&s, &client, request("GET", &msgs, vec![auth.clone()], &[])).await;
    assert_eq!(
        (r.status, r.body.as_slice()),
        (200, br#"{"messages":[]}"#.as_slice())
    );
    assert!(r.headers.iter().any(|h| h.name == "content-type"));

    // Rotation learned through the gateway.
    let r = send(&s, &client, request("GET", KEYS_PATH, vec![], &[])).await;
    let next = ohttp_rotate_key(pin.clone(), r.body).unwrap();
    let client = OhttpClient::new(next).unwrap();
    assert_eq!(client.key_id(), 2);
    let r = send(
        &s,
        &client,
        request("DELETE", &format!("/v1/mailboxes/{id}"), vec![auth], &[]),
    )
    .await;
    assert_eq!(r.status, 204);

    // Old key removed: hard error for the old pin.
    let after = relay(&[(3, 0x33), (2, 0x22)]);
    let res = xchonnect_relay::app(after)
        .oneshot(Request::get(KEYS_PATH).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let list = res.into_body().collect().await.unwrap().to_bytes().to_vec();
    assert!(matches!(
        ohttp_rotate_key(pin, list),
        Err(XchonnectError::OhttpKeyMismatch(_))
    ));

    // A context is single use; malformed pins are rejected.
    let e = client
        .encapsulate(request("GET", "/v1/info", vec![], &[]))
        .unwrap();
    let (_, body) = post(&s, GATEWAY_PATH, "message/ohttp-req", e.body).await;
    e.context.decapsulate(body.clone()).unwrap();
    assert!(matches!(
        e.context.decapsulate(body),
        Err(XchonnectError::State(_))
    ));
    assert!(OhttpClient::new(vec![1, 2, 3]).is_err());
}
