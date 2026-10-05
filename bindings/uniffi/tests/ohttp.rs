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

async fn gateway(s: &AppState, body: Vec<u8>) -> (u16, Vec<u8>) {
    post(s, GATEWAY_PATH, "message/ohttp-req", body).await
}

fn keys_request(client: &OhttpClient) -> OhttpEncapsulated {
    client
        .encapsulate(request("GET", KEYS_PATH, vec![], &[]))
        .unwrap()
}

async fn send(s: &AppState, client: &OhttpClient, req: OhttpRequest) -> OhttpResponse {
    let e = client.encapsulate(req).unwrap();
    let (st, body) = gateway(s, e.body).await;
    assert_eq!(st, 200);
    e.context.decapsulate(body).unwrap()
}

async fn rotate_through(s: &AppState, client: &OhttpClient) -> Result<Vec<u8>> {
    let e = keys_request(client);
    let (st, body) = gateway(s, e.body).await;
    assert_eq!(st, 200);
    e.context.decapsulate_key_rotation(body)
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

    // A directly fetched list is never usable for rotation, only an answer under the pin.
    let next = rotate_through(&s, &client).await.unwrap();
    let client = OhttpClient::new(next).unwrap();
    assert_eq!(client.key_id(), 2);
    let r = send(
        &s,
        &client,
        request("DELETE", &format!("/v1/mailboxes/{id}"), vec![auth], &[]),
    )
    .await;
    assert_eq!(r.status, 204);

    // Old key removed: the old pin can no longer reach the gateway (RFC 9458 key
    // problem), the current one rotates on.
    let after = relay(&[(3, 0x33), (2, 0x22)]);
    let e = keys_request(&OhttpClient::new(pin).unwrap());
    let (st, _) = gateway(&after, e.body).await;
    assert_eq!(st, 400);
    let next = rotate_through(&after, &client).await.unwrap();
    assert_eq!(OhttpClient::new(next).unwrap().key_id(), 3);
    // A response to one request cannot rotate another request's context.
    let (a, b) = (keys_request(&client), keys_request(&client));
    let (_, body_a) = gateway(&after, a.body).await;
    assert!(matches!(
        b.context.decapsulate_key_rotation(body_a),
        Err(XchonnectError::Decrypt(_))
    ));

    // A context is single use; malformed pins are rejected.
    let e = client
        .encapsulate(request("GET", "/v1/info", vec![], &[]))
        .unwrap();
    let (_, body) = gateway(&s, e.body).await;
    e.context.decapsulate(body.clone()).unwrap();
    assert!(matches!(
        e.context.decapsulate(body),
        Err(XchonnectError::State(_))
    ));
    assert!(OhttpClient::new(vec![1, 2, 3]).is_err());
}
