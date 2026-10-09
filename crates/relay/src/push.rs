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
//! 5. at most one wake-up per mailbox per 10 s; a message inside that window gets one
//!    deferred wake-up at its end if the mailbox still holds unacknowledged messages;
//!    failures never affect message acceptance.
//!
//! `XCHONNECT_DEV_ALLOW_INSECURE_GATEWAYS` relaxes rules 1–2 for local development.

use crate::config::{Config, GatewayPolicy};
use crate::lock;
use crate::store::PushReg;
use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
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
        .await;
    match res {
        Ok(r) if r.status().is_success() => Ok(()),
        _ => Err(WakeError::Delivery),
    }
}

/// Aggregate wake-up counters.
#[derive(Debug, Default)]
pub struct WakeStats {
    /// Sent successfully.
    pub sent: AtomicU64,
    /// Skipped by coalescing: a deferred wake-up was already pending, or the mailbox
    /// held nothing any more when it was due.
    pub coalesced: AtomicU64,
    /// Inside the window: deferred to its end.
    pub deferred: AtomicU64,
    /// Dropped because the queue was full.
    pub dropped: AtomicU64,
    /// Failed (any [`WakeError`]).
    pub failed: AtomicU64,
}

/// Asked when a deferred wake-up is due: the push registration to use if the mailbox
/// still holds unacknowledged messages, `None` to skip it.
pub type Recheck =
    Box<dyn FnOnce() -> Pin<Box<dyn Future<Output = Option<PushReg>> + Send>> + Send>;

/// Coalescing state of one mailbox. Memory only, like the mailbox ids it is keyed by.
#[derive(Debug, Clone, Copy)]
struct Slot {
    /// When the last wake-up went out, or the deferred one will.
    last: u64,
    /// A deferred wake-up is scheduled.
    deferred: bool,
}

/// Queues and coalesces wake-ups; a background worker delivers them.
#[derive(Debug)]
pub struct Dispatcher {
    tx: Arc<Mutex<Option<mpsc::Sender<PushReg>>>>,
    slots: Arc<Mutex<HashMap<MailboxId, Slot>>>,
    interval_s: u64,
    /// Counters.
    pub stats: Arc<WakeStats>,
}

impl Default for Dispatcher {
    fn default() -> Self {
        Dispatcher::with_interval(COALESCE_S)
    }
}

impl Dispatcher {
    /// A dispatcher with another coalescing interval than [`COALESCE_S`] (tests).
    pub fn with_interval(interval_s: u64) -> Self {
        Dispatcher {
            tx: Arc::default(),
            slots: Arc::default(),
            interval_s,
            stats: Arc::default(),
        }
    }

    /// Start the delivery worker (needs a Tokio runtime).
    pub fn start(&self, config: Config) {
        let (tx, mut rx) = mpsc::channel::<PushReg>(QUEUE);
        let stats = self.stats.clone();
        tokio::spawn(async move {
            let limit = Arc::new(tokio::sync::Semaphore::new(64));
            let config = Arc::new(config);
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
        *lock(&self.tx) = Some(tx);
    }

    fn enqueue(tx: &Mutex<Option<mpsc::Sender<PushReg>>>, stats: &WakeStats, reg: PushReg) {
        let tx = lock(tx).clone();
        if !tx.is_some_and(|tx| tx.try_send(reg).is_ok()) {
            stats.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Request a wake-up for `mailbox` (coalesced; never blocks).
    ///
    /// Outside the window it is queued at once. Inside it, it is not dropped (the wallet
    /// would miss a request sent a few seconds after the previous one until the next
    /// push): one deferred wake-up goes out at the end of the window, if `recheck` then
    /// says the mailbox still holds unacknowledged messages. At most one is pending per
    /// mailbox; later ones are coalesced into it.
    pub fn wake(&self, mailbox: &MailboxId, reg: &PushReg, now: u64, recheck: Recheck) {
        let delay = {
            let mut slots = lock(&self.slots);
            if slots.len() > 100_000 {
                slots.retain(|_, s| s.deferred || now.saturating_sub(s.last) < self.interval_s);
            }
            match slots.get_mut(mailbox) {
                // `last` may lie in the future: the time of the deferred wake-up.
                Some(s) if s.last > now || now - s.last < self.interval_s => {
                    if s.deferred {
                        self.stats.coalesced.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    let at = s.last.saturating_add(self.interval_s);
                    s.last = at;
                    s.deferred = true;
                    Some(at.saturating_sub(now))
                }
                _ => {
                    slots.insert(
                        *mailbox,
                        Slot {
                            last: now,
                            deferred: false,
                        },
                    );
                    None
                }
            }
        };
        let Some(delay_s) = delay else {
            Self::enqueue(&self.tx, &self.stats, reg.clone());
            return;
        };
        self.stats.deferred.fetch_add(1, Ordering::Relaxed);
        let (tx, slots, stats, id) = (
            self.tx.clone(),
            self.slots.clone(),
            self.stats.clone(),
            *mailbox,
        );
        let clear = move |slots: &Mutex<HashMap<MailboxId, Slot>>| {
            if let Some(s) = lock(slots).get_mut(&id) {
                s.deferred = false;
            }
        };
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            clear(&slots);
            stats.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        rt.spawn(async move {
            tokio::time::sleep(Duration::from_secs(delay_s)).await;
            clear(&slots);
            match recheck().await {
                Some(reg) => Self::enqueue(&tx, &stats, reg),
                None => {
                    stats.coalesced.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn address_classification() {
        let non_global = "127.0.0.1 10.1.2.3 172.16.0.1 192.168.1.1 169.254.169.254 100.64.0.1 \
            0.0.0.0 255.255.255.255 224.0.0.1 192.0.2.1 198.51.100.1 203.0.113.1 198.18.0.1 \
            240.0.0.1 192.0.0.8 ::1 :: fc00::1 fd12::1 fe80::1 ff02::1 2001:db8::1 \
            ::ffff:127.0.0.1 ::ffff:10.0.0.1 64:ff9b::a9fe:a9fe ::127.0.0.1";
        for a in non_global.split_whitespace() {
            assert!(!is_global(a.parse().unwrap()), "{a} must be rejected");
        }
        let global = "1.1.1.1 8.8.8.8 2606:4700::1111 ::ffff:1.1.1.1 64:ff9b::101:101";
        for a in global.split_whitespace() {
            assert!(is_global(a.parse().unwrap()), "{a} is global");
        }
    }

    #[test]
    fn url_rules() {
        let c = Config::default();
        let target = parse_target(&c, "https://push.example/v1/wake").unwrap();
        assert_eq!((target.host.as_str(), target.port), ("push.example", 443));
        let bad = [
            "http://push.example/v1/wake",
            "https://push.example:8443/w",
            "https://u@push.example/w",
        ];
        for url in bad {
            assert_eq!(parse_target(&c, url), Err(WakeError::Url), "{url}");
        }
        assert_eq!(parse_target(&c, "https://[::1]/w").unwrap().host, "::1");
        let allow = Config {
            gateway_policy: GatewayPolicy::Allowlist(vec!["https://push.example:8443/".into()]),
            ..Config::default()
        };
        let target = parse_target(&allow, "https://push.example:8443/w").unwrap();
        assert_eq!(target.port, 8443);
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
            let res = send_wake(&c, &reg).await;
            assert_eq!(res, Err(WakeError::Destination), "{url}");
        }
    }

    /// A gateway on a local socket; returns its wake URL and the bodies it received.
    async fn local_gateway() -> (String, Arc<Mutex<Vec<String>>>) {
        let received = Arc::new(Mutex::new(Vec::new()));
        let r2 = received.clone();
        let wake = move |body: String| async move {
            r2.lock().unwrap().push(body);
            "ok"
        };
        let app = axum::Router::new().route("/v1/wake", axum::routing::post(wake));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}/v1/wake"), received)
    }

    /// Poll `done` for up to two seconds.
    async fn eventually(done: impl Fn() -> bool) {
        for _ in 0..100 {
            if done() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn dev_config() -> Config {
        Config {
            dev_allow_insecure_gateways: true,
            ..Config::default()
        }
    }

    #[tokio::test]
    async fn local_gateway_receives_only_the_sealed_token_and_wakes_coalesce() {
        let (gateway_url, received) = local_gateway().await;
        let d = Dispatcher::default();
        d.start(dev_config());
        let reg = PushReg {
            gateway_url,
            sealed_token: vec![0xab; 40],
        };
        let mbx = MailboxId([5; 16]);
        let sent = || d.stats.sent.load(Ordering::Relaxed);
        d.wake(&mbx, &reg, 1000, pending(None));
        d.wake(&mbx, &reg, 1005, pending(None)); // deferred, then nothing left to wake for
        d.wake(&mbx, &reg, 1006, pending(None)); // coalesced into the deferred one
        eventually(|| sent() > 0).await;
        assert_eq!(sent(), 1);
        assert_eq!(d.stats.deferred.load(Ordering::Relaxed), 1);
        assert_eq!(d.stats.coalesced.load(Ordering::Relaxed), 1);
        let got = received.lock().unwrap().clone();
        let expected = format!("{{\"sealed_token\":\"{}\"}}", b64::encode(&[0xab; 40]));
        assert_eq!(got, vec![expected]);
        assert!(
            !got[0].contains(&mbx.to_b64()),
            "no mailbox id in the wake-up"
        );
        d.wake(&mbx, &reg, 1021, pending(None)); // after the window and the deferred slot
        eventually(|| sent() > 1).await;
        assert_eq!(sent(), 2);
    }

    /// A recheck that answers `reg`: `Some` while messages wait, `None` once acked.
    fn pending(reg: Option<PushReg>) -> Recheck {
        Box::new(move || Box::pin(async move { reg }))
    }

    #[tokio::test]
    async fn a_wake_inside_the_window_goes_out_at_its_end_while_messages_wait() {
        let (gateway_url, received) = local_gateway().await;
        let d = Dispatcher::with_interval(1);
        d.start(dev_config());
        let reg = PushReg {
            gateway_url,
            sealed_token: vec![0xab; 40],
        };
        let mbx = MailboxId([6; 16]);
        let sent = || d.stats.sent.load(Ordering::Relaxed);
        d.wake(&mbx, &reg, 1000, pending(None));
        d.wake(&mbx, &reg, 1000, pending(Some(reg.clone()))); // deferred to 1001
        d.wake(&mbx, &reg, 1000, pending(Some(reg.clone()))); // coalesced
        eventually(|| sent() > 0).await;
        assert_eq!(sent(), 1, "the first goes out at once");
        tokio::time::sleep(Duration::from_millis(1300)).await;
        assert_eq!(sent(), 2, "the deferred one at the end of the window");
        assert_eq!(d.stats.deferred.load(Ordering::Relaxed), 1);
        assert_eq!(d.stats.coalesced.load(Ordering::Relaxed), 1);
        assert_eq!(received.lock().unwrap().len(), 2);
        // A new message after the deferred wake starts a new window.
        d.wake(&mbx, &reg, 1001, pending(Some(reg.clone())));
        assert_eq!(d.stats.deferred.load(Ordering::Relaxed), 2);
    }

    /// End to end through the API: posting to a mailbox with a push registration wakes the gateway.
    #[tokio::test]
    async fn posting_a_message_triggers_a_wake() {
        use crate::api::tests::{envelope, hashes, json_of, req, send};
        use serde_json::json;
        let (gateway_url, received) = local_gateway().await;
        let config = Config {
            gateway_policy: GatewayPolicy::Open,
            creation: vec![crate::config::Creation::Open],
            ..dev_config()
        };
        let state = crate::AppState::in_memory(config, Arc::new(|| 1_790_000_000));
        state.start_workers();
        let mut body = hashes(1, 2);
        let sealed = b64::encode(&[9; 48]);
        body["push_reg"] = json!({ "gateway_url": gateway_url, "sealed_token": sealed });
        let (_, created) = send(&state, req("POST", "/v1/mailboxes", None, Some(body))).await;
        let id = json_of(&created)["mailbox_id"].as_str().unwrap().to_owned();
        let w = xchonnect_core::crypto::Token::from_bytes([2; 32]);
        let post = Some(json!({ "env": envelope() }));
        let uri = format!("/v1/mailboxes/{id}/messages");
        let res = send(&state, req("POST", &uri, Some(&w), post)).await;
        assert_eq!(res.0, axum::http::StatusCode::ACCEPTED);
        let hits = || received.lock().unwrap().len();
        eventually(|| hits() > 0).await;
        assert_eq!(hits(), 1);

        // A deferred wake-up goes out only while a message waits.
        let mbx = MailboxId::from_b64(&id).unwrap();
        assert!(state.recheck(mbx)().await.is_some(), "the message waits");
        let r = xchonnect_core::crypto::Token::from_bytes([1; 32]);
        let (_, fetched) = send(&state, req("GET", &uri, Some(&r), None)).await;
        let msg_id = json_of(&fetched)["messages"][0]["msg_id"].clone();
        let ack = Some(json!({ "msg_ids": [msg_id] }));
        let ack_uri = format!("/v1/mailboxes/{id}/ack");
        send(&state, req("POST", &ack_uri, Some(&r), ack)).await;
        assert!(
            state.recheck(mbx)().await.is_none(),
            "acknowledged: no wake-up"
        );
    }
}
