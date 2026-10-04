//! Push wake-ups to vendor gateways (spec 7.3, hardened per 7.3.1).
//!
//! `gateway_url` is chosen by anonymous clients, so every wake-up is an outbound request
//! controlled by an untrusted party. Rules enforced here:
//! 1. `https` only, port 443 (allowlisted URLs may use another port);
//! 2. every resolved address must be globally routable; the connection is pinned to the
//!    validated addresses (no second resolution, defeating DNS rebinding) while TLS still
//!    validates the original host name;
//! 3. no redirects;
//! 4. connect timeout 3 s, total 10 s, body = the sealed token only, response discarded;
//! 5. at most one wake-up per mailbox per 10 s; failures never affect message acceptance.
//!
//! `XCHONNECT_DEV_ALLOW_INSECURE_GATEWAYS` relaxes rules 1–2 for local development.

use crate::config::{Config, GatewayPolicy};
use crate::store::PushReg;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::mpsc;
use xchonnect_core::b64;
use xchonnect_core::crypto::MailboxId;

/// Minimum interval between wake-ups for one mailbox.
pub const COALESCE_S: u64 = 10;
const QUEUE: usize = 4096;

/// Whether an IPv4 address is globally routable.
pub fn is_global_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || o[0] == 0
        || (o[0] == 100 && (o[1] & 0xc0) == 64)            // 100.64.0.0/10 CGNAT
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)          // 192.0.0.0/24
        || (o[0] == 198 && (o[1] & 0xfe) == 18)             // 198.18.0.0/15 benchmarking
        || o[0] >= 240) // reserved
}

/// Whether an IPv6 address is globally routable (embedded IPv4 forms are checked too).
pub fn is_global_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_global_v4(v4);
    }
    if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        // 64:ff9b::/96 NAT64
        return is_global_v4(Ipv4Addr::new(
            (s[6] >> 8) as u8,
            s[6] as u8,
            (s[7] >> 8) as u8,
            s[7] as u8,
        ));
    }
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00                       // fc00::/7 unique local
        || (s[0] & 0xffc0) == 0xfe80                       // fe80::/10 link local
        || (s[0] == 0x2001 && s[1] == 0x0db8)              // documentation
        || (s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0)) // ::/96 IPv4-compatible
}

/// Whether an address is globally routable.
pub fn is_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_global_v4(v4),
        IpAddr::V6(v6) => is_global_v6(v6),
    }
}

/// Why a wake-up was not sent (aggregate counters only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeError {
    /// URL fails rules 1/6.
    Url,
    /// A resolved address is not globally routable.
    Destination,
    /// DNS failure.
    Resolve,
    /// Connection, TLS, timeout or non-2xx response (including redirects).
    Delivery,
}

/// Parsed destination.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Target {
    host: String,
    port: u16,
}

fn parse_target(config: &Config, url: &str) -> Result<Target, WakeError> {
    let allowlisted = matches!(&config.gateway_policy, GatewayPolicy::Allowlist(l) if l.iter().any(|p| url.starts_with(p.as_str())));
    let (rest, default_port) = match (url.strip_prefix("https://"), url.strip_prefix("http://")) {
        (Some(r), _) => (r, 443),
        (None, Some(r)) if config.dev_allow_insecure_gateways => (r, 80),
        _ => return Err(WakeError::Url),
    };
    let authority = rest.split('/').next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return Err(WakeError::Url);
    }
    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        let (h, after) = stripped.split_once(']').ok_or(WakeError::Url)?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().map_err(|_| WakeError::Url)?,
            None => default_port,
        };
        (h.to_owned(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_owned(), p.parse().map_err(|_| WakeError::Url)?),
            None => (authority.to_owned(), default_port),
        }
    };
    if port != 443 && !allowlisted && !config.dev_allow_insecure_gateways {
        return Err(WakeError::Url);
    }
    Ok(Target { host, port })
}

/// Resolve and validate destination addresses (rule 2).
async fn resolve(config: &Config, t: &Target) -> Result<Vec<SocketAddr>, WakeError> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((t.host.as_str(), t.port))
        .await
        .map_err(|_| WakeError::Resolve)?
        .collect();
    if addrs.is_empty() {
        return Err(WakeError::Resolve);
    }
    if !config.dev_allow_insecure_gateways && addrs.iter().any(|a| !is_global(a.ip())) {
        return Err(WakeError::Destination);
    }
    Ok(addrs)
}

fn ensure_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // Ignore the error if the embedding application installed a provider already.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Send one wake-up following rules 1–4.
pub async fn send_wake(config: &Config, reg: &PushReg) -> Result<(), WakeError> {
    ensure_crypto_provider();
    let target = parse_target(config, &reg.gateway_url)?;
    let addrs = resolve(config, &target).await?;
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(10))
        .no_proxy()
        .user_agent("xchonnect-relay");
    // Pin the connection to the validated addresses (no second DNS lookup).
    if target.host.parse::<IpAddr>().is_err() {
        builder = builder.resolve_to_addrs(&target.host, &addrs);
    }
    let client = builder.build().map_err(|_| WakeError::Delivery)?;
    let body = format!(
        "{{\"sealed_token\":\"{}\"}}",
        b64::encode(&reg.sealed_token)
    );
    let res = client
        .post(&reg.gateway_url)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|_| WakeError::Delivery)?;
    if res.status().is_success() {
        Ok(())
    } else {
        Err(WakeError::Delivery)
    }
}

/// Aggregate wake-up counters.
#[derive(Debug, Default)]
pub struct WakeStats {
    /// Sent successfully.
    pub sent: AtomicU64,
    /// Skipped by coalescing.
    pub coalesced: AtomicU64,
    /// Dropped because the queue was full.
    pub dropped: AtomicU64,
    /// Failed (any [`WakeError`]).
    pub failed: AtomicU64,
}

/// Queues and coalesces wake-ups; a background worker delivers them.
#[derive(Debug)]
pub struct Dispatcher {
    tx: Mutex<Option<mpsc::Sender<PushReg>>>,
    last: Mutex<HashMap<MailboxId, u64>>,
    /// Counters.
    pub stats: std::sync::Arc<WakeStats>,
}

impl Default for Dispatcher {
    fn default() -> Self {
        Dispatcher {
            tx: Mutex::new(None),
            last: Mutex::new(HashMap::new()),
            stats: std::sync::Arc::new(WakeStats::default()),
        }
    }
}

impl Dispatcher {
    /// Start the delivery worker (needs a Tokio runtime).
    pub fn start(&self, config: Config) {
        let (tx, mut rx) = mpsc::channel::<PushReg>(QUEUE);
        let stats = self.stats.clone();
        tokio::spawn(async move {
            let limit = std::sync::Arc::new(tokio::sync::Semaphore::new(64));
            let config = std::sync::Arc::new(config);
            while let Some(reg) = rx.recv().await {
                let Ok(permit) = limit.clone().acquire_owned().await else {
                    break;
                };
                let (config, stats) = (config.clone(), stats.clone());
                tokio::spawn(async move {
                    match send_wake(&config, &reg).await {
                        Ok(()) => stats.sent.fetch_add(1, Ordering::Relaxed),
                        Err(_) => stats.failed.fetch_add(1, Ordering::Relaxed),
                    };
                    drop(permit);
                });
            }
        });
        *self
            .tx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(tx);
    }

    /// Request a wake-up for `mailbox` (coalesced; never blocks).
    pub fn wake(&self, mailbox: &MailboxId, reg: &PushReg, now: u64) {
        {
            let mut last = self
                .last
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if last.len() > 100_000 {
                last.retain(|_, t| now.saturating_sub(*t) < COALESCE_S);
            }
            if last
                .get(mailbox)
                .is_some_and(|t| now.saturating_sub(*t) < COALESCE_S)
            {
                self.stats.coalesced.fetch_add(1, Ordering::Relaxed);
                return;
            }
            last.insert(*mailbox, now);
        }
        let tx = self
            .tx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        match tx {
            Some(tx) if tx.try_send(reg.clone()).is_ok() => {}
            _ => {
                self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn address_classification() {
        let non_global = [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "198.18.0.1",
            "240.0.0.1",
            "192.0.0.8",
            "::1",
            "::",
            "fc00::1",
            "fd12::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::a9fe:a9fe",
            "::127.0.0.1",
        ];
        for a in non_global {
            assert!(!is_global(a.parse().unwrap()), "{a} must be rejected");
        }
        for a in [
            "1.1.1.1",
            "8.8.8.8",
            "2606:4700::1111",
            "::ffff:1.1.1.1",
            "64:ff9b::101:101",
        ] {
            assert!(is_global(a.parse().unwrap()), "{a} is global");
        }
    }

    #[test]
    fn url_rules() {
        let c = Config::default();
        assert_eq!(
            parse_target(&c, "https://push.example/v1/wake").unwrap(),
            Target {
                host: "push.example".into(),
                port: 443
            }
        );
        assert_eq!(
            parse_target(&c, "http://push.example/v1/wake"),
            Err(WakeError::Url)
        );
        assert_eq!(
            parse_target(&c, "https://push.example:8443/w"),
            Err(WakeError::Url)
        );
        assert_eq!(
            parse_target(&c, "https://u@push.example/w"),
            Err(WakeError::Url)
        );
        assert_eq!(parse_target(&c, "https://[::1]/w").unwrap().host, "::1");
        let allow = Config {
            gateway_policy: GatewayPolicy::Allowlist(vec!["https://push.example:8443/".into()]),
            ..Config::default()
        };
        assert_eq!(
            parse_target(&allow, "https://push.example:8443/w")
                .unwrap()
                .port,
            8443
        );
    }

    #[tokio::test]
    async fn private_destinations_are_never_contacted() {
        let c = Config::default();
        for url in [
            "https://127.0.0.1/w",
            "https://169.254.169.254/latest",
            "https://[::1]/w",
            "https://localhost/w",
            "https://10.0.0.1/w",
        ] {
            let reg = PushReg {
                gateway_url: url.into(),
                sealed_token: vec![1],
            };
            assert_eq!(
                send_wake(&c, &reg).await,
                Err(WakeError::Destination),
                "{url}"
            );
        }
    }

    #[tokio::test]
    async fn local_gateway_receives_only_the_sealed_token_and_wakes_coalesce() {
        use axum::routing::post;
        let received = std::sync::Arc::new(Mutex::new(Vec::<String>::new()));
        let r2 = received.clone();
        let app = axum::Router::new().route(
            "/v1/wake",
            post(move |body: String| {
                let r = r2.clone();
                async move {
                    r.lock().unwrap().push(body);
                    "ok"
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let config = Config {
            dev_allow_insecure_gateways: true,
            ..Config::default()
        };
        let d = Dispatcher::default();
        d.start(config);
        let reg = PushReg {
            gateway_url: format!("http://{addr}/v1/wake"),
            sealed_token: vec![0xab; 40],
        };
        let mbx = MailboxId([5; 16]);
        d.wake(&mbx, &reg, 1000);
        d.wake(&mbx, &reg, 1005); // coalesced
        for _ in 0..100 {
            if d.stats.sent.load(Ordering::Relaxed) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(d.stats.sent.load(Ordering::Relaxed), 1);
        assert_eq!(d.stats.coalesced.load(Ordering::Relaxed), 1);
        let got = received.lock().unwrap().clone();
        assert_eq!(
            got,
            vec![format!(
                "{{\"sealed_token\":\"{}\"}}",
                b64::encode(&[0xab; 40])
            )]
        );
        assert!(
            !got[0].contains(&mbx.to_b64()),
            "no mailbox id in the wake-up"
        );
        d.wake(&mbx, &reg, 1011); // after the coalescing window
        for _ in 0..100 {
            if d.stats.sent.load(Ordering::Relaxed) > 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(d.stats.sent.load(Ordering::Relaxed), 2);
    }

    /// End to end through the API: posting to a mailbox with a push registration wakes the gateway.
    #[tokio::test]
    async fn posting_a_message_triggers_a_wake() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;
        let hits = std::sync::Arc::new(AtomicU64::new(0));
        let h2 = hits.clone();
        let gw = axum::Router::new().route(
            "/wake",
            axum::routing::post(move || {
                let h = h2.clone();
                async move {
                    h.fetch_add(1, Ordering::Relaxed);
                    "ok"
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, gw).await.unwrap() });

        let config = Config {
            dev_allow_insecure_gateways: true,
            gateway_policy: GatewayPolicy::Open,
            creation: vec![crate::config::Creation::Open],
            ..Config::default()
        };
        let state = crate::AppState::in_memory(config, std::sync::Arc::new(|| 1_790_000_000));
        state.start_workers();
        let app = crate::app(state.clone());
        let (r, w) = (
            xchonnect_core::crypto::Token::from_bytes([1; 32]),
            xchonnect_core::crypto::Token::from_bytes([2; 32]),
        );
        let body = serde_json::json!({
            "read_token_hash": b64::encode(&r.hash()),
            "write_token_hash": b64::encode(&w.hash()),
            "push_reg": { "gateway_url": format!("http://{addr}/wake"), "sealed_token": b64::encode(&[9; 48]) },
        });
        let res = app
            .clone()
            .oneshot(
                Request::post("/v1/mailboxes")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = http_body_util::BodyExt::collect(res.into_body())
            .await
            .unwrap()
            .to_bytes();
        let id = serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["mailbox_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let env = b64::encode(
            &xchonnect_core::envelope::Envelope {
                kind: xchonnect_core::envelope::Kind::Session,
                n: vec![1; 24],
                ct: vec![2; 1024],
            }
            .encode()
            .unwrap(),
        );
        let post = Request::post(format!("/v1/mailboxes/{id}/messages"))
            .header(
                "authorization",
                format!("Bearer {}", b64::encode(w.expose())),
            )
            .header("content-type", "application/json")
            .body(Body::from(serde_json::json!({ "env": env }).to_string()))
            .unwrap();
        assert_eq!(
            app.oneshot(post).await.unwrap().status(),
            axum::http::StatusCode::ACCEPTED
        );
        for _ in 0..100 {
            if hits.load(Ordering::Relaxed) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(hits.load(Ordering::Relaxed), 1);
    }
}
