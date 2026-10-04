//! In-process test environment: the real relay router, the real gateway application on
//! a loopback socket, a recording store in place of the database and a recording push
//! sender in place of APNs/FCM.

use crate::capture::Capture;
use crate::flow::{self, CLIENT_IP, Call, Params, Transport, USER_AGENT};
use crate::record::{self, RecordingSender, RecordingStore, Shared};
use crate::scan::Surface;
use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::Request;
use serde_json::Value;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tower::ServiceExt;
use xchonnect_core::b64;
use xchonnect_core::crypto::X25519Secret;
use xchonnect_gateway::{DeviceLimits, Gateway, Senders};
use xchonnect_relay::config::{Creation, GatewayPolicy, api_key_hash};
use xchonnect_relay::store::{Notifier, memory::MemoryStore};
use xchonnect_relay::{AppState, Config, system_clock};

type Res<T> = Result<T, String>;

fn err(e: impl std::fmt::Debug) -> String {
    format!("{e:?}")
}

/// Current unix time.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Calls an `axum` router directly, with the client identity headers a browser or a
/// phone would send.
#[derive(Debug, Clone)]
pub struct RouterTransport {
    router: Router,
}

impl RouterTransport {
    /// Wrap a router.
    pub fn new(router: Router) -> Self {
        RouterTransport { router }
    }

    async fn send(&self, req: Request<Body>) -> Res<(u16, Value)> {
        let res = self.router.clone().oneshot(req).await.map_err(err)?;
        let status = res.status().as_u16();
        let body = http_body_util::BodyExt::collect(res.into_body())
            .await
            .map_err(err)?
            .to_bytes();
        Ok((status, serde_json::from_slice(&body).unwrap_or(Value::Null)))
    }

    /// `GET path`, returning the raw body text (for `/metrics`).
    pub async fn text(&self, path: &str) -> Res<String> {
        let req = Request::get(path).body(Body::empty()).map_err(err)?;
        let res = self.router.clone().oneshot(req).await.map_err(err)?;
        let body = http_body_util::BodyExt::collect(res.into_body())
            .await
            .map_err(err)?
            .to_bytes();
        Ok(String::from_utf8_lossy(&body).into_owned())
    }
}

#[async_trait]
impl Transport for RouterTransport {
    async fn call(&self, call: Call<'_>) -> Res<(u16, Value)> {
        let mut b = Request::builder()
            .method(call.method)
            .uri(call.path)
            .header("user-agent", USER_AGENT)
            .header("x-forwarded-for", CLIENT_IP)
            .header("x-real-ip", CLIENT_IP)
            .header("forwarded", format!("for={CLIENT_IP}"));
        if let Some(t) = call.token {
            b = b.header(
                "authorization",
                format!("Bearer {}", b64::encode(t.expose())),
            );
        }
        if let Some(k) = call.api_key {
            b = b.header("xchonnect-api-key", k);
        }
        let body = match &call.body {
            Some(v) => {
                b = b.header("content-type", "application/json");
                Body::from(v.to_string())
            }
            None => Body::empty(),
        };
        self.send(b.body(body).map_err(err)?).await
    }
}

/// Relay plus gateway plus recorders.
#[derive(Debug)]
pub struct Harness {
    /// Relay state (store, metrics, usage counters).
    pub state: AppState,
    /// Relay transport.
    pub relay: RouterTransport,
    /// Gateway transport (for `/metrics`).
    pub gateway: RouterTransport,
    /// Gateway key the device token is sealed to.
    pub gateway_key: X25519Secret,
    /// Gateway URL and relay URL for the pairing URI.
    pub params: Params,
    /// Everything the relay wrote to storage.
    pub database: Shared,
    /// Wake-up requests the gateway received from the relay.
    pub wake: Shared,
    /// What the gateway handed to the push platform.
    pub delivery: Shared,
    sender: Arc<RecordingSender>,
}

fn relay_config(gateway_insecure: bool) -> Config {
    let mut api_keys = std::collections::HashMap::new();
    api_keys.insert(api_key_hash(flow::API_KEY), flow::CUSTOMER.to_owned());
    Config {
        creation: vec![Creation::Open, Creation::ApiKey],
        api_keys,
        gateway_policy: GatewayPolicy::Open,
        dev_allow_insecure_gateways: gateway_insecure,
        metrics: true,
        ..Config::default()
    }
}

impl Harness {
    /// Start the gateway on a loopback socket and build the relay around a recording
    /// store. Needs a Tokio runtime.
    pub async fn start() -> Res<Harness> {
        let database = record::shared("database");
        let wake = record::shared("wake_request");
        let delivery = record::shared("push_delivery");

        let gateway_key = X25519Secret::from_bytes([0x33; 32]);
        let sender = Arc::new(RecordingSender::new(delivery.clone()));
        let senders = Senders {
            apns: Some(sender.clone()),
            fcm: Some(sender.clone()),
            test: Some(sender.clone()),
        };
        let gw = Gateway::new(
            vec![gateway_key.clone()],
            senders,
            DeviceLimits::default(),
            Arc::new(now),
        );
        let gateway_router = record::wake_capturing_app(gw, wake.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(err)?;
        let addr = listener.local_addr().map_err(err)?;
        let serving = gateway_router.clone();
        tokio::spawn(async move {
            let _ = axum::serve(listener, serving).await;
        });

        let notifier = Notifier::default();
        let backend = Arc::new(MemoryStore::new(notifier.clone()));
        let store = Arc::new(RecordingStore::new(backend, database.clone()));
        let state = AppState::new(relay_config(true), store, notifier, system_clock());
        state.start_workers();

        Ok(Harness {
            relay: RouterTransport::new(xchonnect_relay::app(state.clone())),
            gateway: RouterTransport::new(gateway_router),
            params: Params {
                gateway_url: format!("http://{addr}/v1/wake"),
                gateway_pk: gateway_key.public_key(),
                uri_relay: "https://relay.example".to_owned(),
            },
            state,
            gateway_key,
            database,
            wake,
            delivery,
            sender,
        })
    }

    /// Wait until the relay's wake-up reached the push platform, or give up.
    pub async fn wait_for_wake(&self, expected: u64) -> bool {
        for _ in 0..200 {
            if self.sender.count() >= expected {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        false
    }

    /// Wake-ups delivered to the platform.
    pub fn delivered(&self) -> u64 {
        self.sender.count()
    }

    /// Everything an operator or an auditor can look at after the run.
    pub async fn surfaces(&self, logs: &Capture) -> Res<Vec<Surface>> {
        let mut relay_metrics = Surface::new("relay_metrics");
        relay_metrics.line(self.relay.text("/metrics").await?);
        // Wake-up counters are aggregate too, and are read by the same operator.
        relay_metrics.line(format!("push {:?}", self.state.push().stats));

        let mut gateway_metrics = Surface::new("gateway_metrics");
        gateway_metrics.line(self.gateway.text("/metrics").await?);

        let mut billing = Surface::new("relay_billing");
        for (customer, usage) in self.state.usage() {
            billing.line(format!("usage customer={customer} {usage:?}"));
        }

        let mut service_logs = Surface::new("service_logs");
        service_logs.text = logs.text();

        let named = |s: Shared, name: &str| {
            let mut s = record::snapshot(&s);
            s.name = name.to_owned();
            s
        };
        Ok(vec![
            named(self.database.clone(), "database"),
            service_logs,
            relay_metrics,
            gateway_metrics,
            billing,
            named(self.wake.clone(), "wake_request"),
            named(self.delivery.clone(), "push_delivery"),
        ])
    }
}
