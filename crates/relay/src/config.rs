//! Relay configuration from environment variables (`XCHONNECT_*`).
//!
//! | Variable | Default | Meaning |
//! |---|---|---|
//! | `XCHONNECT_LISTEN` | `127.0.0.1:8787` | listen address |
//! | `XCHONNECT_DATABASE_URL` | unset → startup error unless `XCHONNECT_STORE=memory` | Postgres URL (`postgres://…`) |
//! | `XCHONNECT_STORE` | `postgres` | `memory` keeps mailboxes in memory: every one is lost on restart (development and tests only) |
//! | `XCHONNECT_MAX_WAIT_S` | `25` | long-poll limit for direct requests |
//! | `XCHONNECT_MAX_WAIT_OHTTP_S` | `0` | long-poll limit through OHTTP; at most the OHTTP relay's request timeout minus 5 s (spec 10.1) |
//! | `XCHONNECT_OHTTP` | `true` | run the OHTTP gateway; requires keys (`false`: no gateway, the relay sees client IPs — say so in your data inventory; `ephemeral`: one key generated per process, development only) |
//! | `XCHONNECT_OHTTP_KEYS` | unset → startup error unless `XCHONNECT_OHTTP` is `false` or `ephemeral` | gateway keys `id:base64url(32-byte seed)`, comma-separated, **newest first**; keep the previous key listed during rotation |
//! | `XCHONNECT_OHTTP_KEYS_FILE` | unset | file with the same content as `XCHONNECT_OHTTP_KEYS` (for secret mounts); takes precedence |
//! | `XCHONNECT_DEFAULT_TTL_S` / `XCHONNECT_MAX_TTL_S` | `86400` / `604800` | message TTL |
//! | `XCHONNECT_MAX_MESSAGES` / `XCHONNECT_MAX_BYTES` | `256` / `4194304` | per-mailbox queue quota |
//! | `XCHONNECT_CREATION` | `pow,ticket,api_key` | accepted mailbox creation methods (`open` = no proof) |
//! | `XCHONNECT_POW_DIFFICULTY` | `18` | proof-of-work difficulty in bits |
//! | `XCHONNECT_POW_KEY` | random per process | base64url 32-byte key shared by all relay nodes |
//! | `XCHONNECT_API_KEYS` | empty | `customer:key,customer:key` (keys are hashed in memory) |
//! | `XCHONNECT_GATEWAY_POLICY` | `allowlist` | `allowlist` or `open` (spec 7.3.1) |
//! | `XCHONNECT_GATEWAY_ALLOWLIST` | empty | comma-separated `https://` URL prefixes |
//! | `XCHONNECT_DEV_ALLOW_INSECURE_GATEWAYS` | `false` | allow `http`/loopback gateways (local development only; refused unless `XCHONNECT_LISTEN` is a loopback address) |
//! | `XCHONNECT_METRICS` | `true` | serve aggregate metrics at `/metrics` (protect it at the proxy) |
//! | `XCHONNECT_WRITE_RATE` | `120` | messages per minute per write token (0 = unlimited) |
//! | `XCHONNECT_READ_RATE` | `600` | requests per minute per read token |
//! | `XCHONNECT_CUSTOMER_RATE` | `60000` | messages per minute per business customer |
//! | `XCHONNECT_CREATE_RATE` | `600` | mailbox creations per minute without API key (all clients) |

use crate::ohttp::OhttpMode;
use std::collections::HashMap;
use std::net::SocketAddr;

/// Mailbox creation methods (spec 7.2, 7.4, 7.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Creation {
    /// Business API key.
    ApiKey,
    /// Sponsorship ticket.
    Ticket,
    /// Proof-of-work.
    Pow,
    /// No proof required.
    Open,
}

impl Creation {
    /// Wire name used in `/v1/info`.
    pub fn as_str(self) -> &'static str {
        match self {
            Creation::ApiKey => "api_key",
            Creation::Ticket => "ticket",
            Creation::Pow => "pow",
            Creation::Open => "open",
        }
    }
}

/// Where the relay keeps mailboxes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreKind {
    /// In memory: lost on every restart. Only on request (`XCHONNECT_STORE=memory`).
    Memory,
    /// Postgres (`XCHONNECT_DATABASE_URL`).
    Postgres,
}

impl StoreKind {
    /// Name used in settings and in `/readyz`.
    pub fn as_str(self) -> &'static str {
        match self {
            StoreKind::Memory => "memory",
            StoreKind::Postgres => "postgres",
        }
    }
}

/// Gateway policy (spec 7.3.1 rule 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayPolicy {
    /// Only listed URL prefixes.
    Allowlist(Vec<String>),
    /// Any URL that passes the egress rules.
    Open,
}

/// Relay configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Listen address.
    pub listen: SocketAddr,
    /// Postgres URL; `None` = in-memory store.
    pub database_url: Option<String>,
    /// The store [`Config::from_lookup`] settled on. A hand-built configuration (tests,
    /// embedding) defaults to `Memory`; the environment never does without being asked.
    pub store: StoreKind,
    /// Long-poll limit (direct).
    pub max_wait_s: u64,
    /// Long-poll limit (OHTTP).
    pub max_wait_ohttp_s: u64,
    /// Default message TTL.
    pub default_ttl_s: u64,
    /// Maximum message TTL.
    pub max_ttl_s: u64,
    /// Per-mailbox message quota.
    pub max_messages: usize,
    /// Per-mailbox byte quota.
    pub max_bytes: usize,
    /// Accepted creation methods.
    pub creation: Vec<Creation>,
    /// PoW difficulty (bits).
    pub pow_difficulty: u8,
    /// Shared PoW base key (multi-node deployments).
    pub pow_key: Option<[u8; 32]>,
    /// SHA-256 of API key → customer id.
    pub api_keys: HashMap<[u8; 32], String>,
    /// Gateway policy.
    pub gateway_policy: GatewayPolicy,
    /// Allow `http` and non-public gateway destinations (local development only).
    pub dev_allow_insecure_gateways: bool,
    /// Serve `/metrics`.
    pub metrics: bool,
    /// Messages per minute per write token.
    pub write_rate: u32,
    /// Requests per minute per read token.
    pub read_rate: u32,
    /// Messages per minute per customer.
    pub customer_rate: u32,
    /// Keyless creations per minute (global).
    pub create_rate: u32,
    /// OHTTP gateway keys (spec 10).
    pub ohttp: crate::ohttp::OhttpMode,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listen: SocketAddr::from(([127, 0, 0, 1], 8787)),
            database_url: None,
            store: StoreKind::Memory,
            max_wait_s: 25,
            max_wait_ohttp_s: 0,
            default_ttl_s: 86_400,
            max_ttl_s: 604_800,
            max_messages: 256,
            max_bytes: 4 * 1024 * 1024,
            creation: vec![Creation::Pow, Creation::Ticket, Creation::ApiKey],
            pow_difficulty: xchonnect_core::pow::DEFAULT_DIFFICULTY,
            pow_key: None,
            api_keys: HashMap::new(),
            gateway_policy: GatewayPolicy::Allowlist(Vec::new()),
            dev_allow_insecure_gateways: false,
            metrics: true,
            write_rate: 120,
            read_rate: 600,
            customer_rate: 60_000,
            create_rate: 600,
            ohttp: crate::ohttp::OhttpMode::default(),
        }
    }
}

/// Hash an API key for lookup (keys are never kept in plaintext).
pub fn api_key_hash(key: &str) -> [u8; 32] {
    xchonnect_core::crypto::sha256_parts(&[b"xchonnect v1 api key", key.as_bytes()])
}

/// Non-empty trimmed entries of a comma-separated list.
fn list(v: &str) -> impl Iterator<Item = &str> {
    v.split(',').map(str::trim).filter(|s| !s.is_empty())
}

impl Config {
    /// Read from the process environment.
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// The listen address alone. `main` needs it before the rest of the settings: a
    /// relay that waits for them (`crate::waiting_app`) still has to listen somewhere.
    pub fn listen_from(get: impl Fn(&str) -> Option<String>) -> Result<SocketAddr, String> {
        get("XCHONNECT_LISTEN").map_or(Ok(Config::default().listen), |v| {
            v.parse()
                .map_err(|_| "XCHONNECT_LISTEN: invalid socket address".to_owned())
        })
    }

    /// Whether none of the relay's settings is present among these variable names. Where
    /// it listens and what it logs do not count: an image or a host sets those for every
    /// deployment alike. A variable that is present but empty does count, so a compose
    /// file that passes every setting through still fails fast on a missing value.
    pub fn unconfigured(names: impl IntoIterator<Item = String>) -> bool {
        !names.into_iter().any(|name| {
            name.starts_with("XCHONNECT_") && name != "XCHONNECT_LISTEN" && name != "XCHONNECT_LOG"
        })
    }

    /// Read using a lookup function (testable).
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let mut c = Config::default();
        let num = |k: &str, d: u64| -> Result<u64, String> {
            get(k).map_or(Ok(d), |v| {
                v.trim().parse().map_err(|_| format!("{k}: not a number"))
            })
        };
        c.listen = Self::listen_from(&get)?;
        c.database_url = get("XCHONNECT_DATABASE_URL").filter(|s| !s.is_empty());
        c.max_wait_s = num("XCHONNECT_MAX_WAIT_S", c.max_wait_s)?.min(60);
        c.max_wait_ohttp_s =
            num("XCHONNECT_MAX_WAIT_OHTTP_S", c.max_wait_ohttp_s)?.min(c.max_wait_s);
        c.default_ttl_s = num("XCHONNECT_DEFAULT_TTL_S", c.default_ttl_s)?;
        c.max_ttl_s = num("XCHONNECT_MAX_TTL_S", c.max_ttl_s)?.min(604_800);
        if c.max_ttl_s < 60 {
            return Err("XCHONNECT_MAX_TTL_S: must be at least 60".into());
        }
        c.default_ttl_s = c.default_ttl_s.clamp(60, c.max_ttl_s);
        c.max_messages = usize::try_from(num("XCHONNECT_MAX_MESSAGES", c.max_messages as u64)?)
            .map_err(|e| e.to_string())?;
        c.max_bytes = usize::try_from(num("XCHONNECT_MAX_BYTES", c.max_bytes as u64)?)
            .map_err(|e| e.to_string())?;
        if let Some(v) = get("XCHONNECT_CREATION") {
            use Creation::{ApiKey, Open, Pow, Ticket};
            c.creation = list(&v)
                .map(|s| {
                    let m = [ApiKey, Ticket, Pow, Open]
                        .into_iter()
                        .find(|m| m.as_str() == s);
                    m.ok_or_else(|| format!("XCHONNECT_CREATION: unknown method {s}"))
                })
                .collect::<Result<_, _>>()?;
        }
        let d = num("XCHONNECT_POW_DIFFICULTY", u64::from(c.pow_difficulty))?;
        c.pow_difficulty = u8::try_from(d)
            .ok()
            .filter(|d| *d <= 32)
            .ok_or("XCHONNECT_POW_DIFFICULTY: 0..=32")?;
        if let Some(v) = get("XCHONNECT_POW_KEY").filter(|v| !v.trim().is_empty()) {
            c.pow_key = Some(
                xchonnect_core::b64::decode_array::<32>(v.trim())
                    .map_err(|_| "XCHONNECT_POW_KEY: base64url 32 bytes")?,
            );
        }
        if let Some(v) = get("XCHONNECT_API_KEYS") {
            for entry in list(&v) {
                let (customer, key) = entry
                    .split_once(':')
                    .ok_or("XCHONNECT_API_KEYS: expected customer:key")?;
                if key.len() < 16 {
                    return Err("XCHONNECT_API_KEYS: keys must have at least 16 characters".into());
                }
                c.api_keys.insert(api_key_hash(key), customer.to_owned());
            }
        }
        let allow = get("XCHONNECT_GATEWAY_ALLOWLIST").unwrap_or_default();
        let allow = list(&allow).map(str::to_owned).collect();
        c.gateway_policy = match get("XCHONNECT_GATEWAY_POLICY")
            .as_deref()
            .unwrap_or("allowlist")
        {
            "allowlist" => GatewayPolicy::Allowlist(allow),
            "open" => GatewayPolicy::Open,
            other => return Err(format!("XCHONNECT_GATEWAY_POLICY: unknown policy {other}")),
        };
        let rate = |k: &str, d: u32| -> Result<u32, String> {
            u32::try_from(num(k, u64::from(d))?).map_err(|_| format!("{k}: too large"))
        };
        c.write_rate = rate("XCHONNECT_WRITE_RATE", c.write_rate)?;
        c.read_rate = rate("XCHONNECT_READ_RATE", c.read_rate)?;
        c.customer_rate = rate("XCHONNECT_CUSTOMER_RATE", c.customer_rate)?;
        c.create_rate = rate("XCHONNECT_CREATE_RATE", c.create_rate)?;
        c.metrics = !matches!(get("XCHONNECT_METRICS").as_deref(), Some("0" | "false"));
        c.dev_allow_insecure_gateways = matches!(
            get("XCHONNECT_DEV_ALLOW_INSECURE_GATEWAYS").as_deref(),
            Some("1" | "true")
        );
        // The flag lets anyone who registers a push gateway make the relay send requests to
        // plain-http and private-network addresses (the host itself, the internal network, a
        // cloud metadata service): server-side request forgery. Only a relay nobody else can
        // reach may run with it, so it is refused on any address but loopback.
        if c.dev_allow_insecure_gateways && !c.listen.ip().is_loopback() {
            return Err(format!(
                "XCHONNECT_DEV_ALLOW_INSECURE_GATEWAYS is for local development only and is refused \
                 while the relay listens on {}; set XCHONNECT_LISTEN to a loopback address \
                 (127.0.0.1 or [::1]) or turn the flag off",
                c.listen
            ));
        }
        c.ohttp = Self::ohttp_mode(&get)?;
        c.store = Self::store_kind(&get, c.database_url.is_some())?;
        Ok(c)
    }

    /// A relay without a database used to fall back to memory without a word, and a
    /// redeploy then dropped every mailbox, so every paired wallet and dApp. Memory is
    /// now chosen explicitly or not at all.
    fn store_kind(
        get: &impl Fn(&str) -> Option<String>,
        has_url: bool,
    ) -> Result<StoreKind, String> {
        match (get("XCHONNECT_STORE").as_deref().map(str::trim), has_url) {
            (Some("memory"), false) => Ok(StoreKind::Memory),
            (Some("memory"), true) => Err(
                "XCHONNECT_STORE=memory and XCHONNECT_DATABASE_URL are both set: choose one".into(),
            ),
            (None | Some("" | "postgres"), true) => Ok(StoreKind::Postgres),
            (None | Some("" | "postgres"), false) => Err(
                "XCHONNECT_DATABASE_URL is not set. A relay keeps its mailboxes in Postgres; \
                 set XCHONNECT_STORE=memory to keep them in memory instead, where every \
                 mailbox is lost on restart (development and tests only)"
                    .into(),
            ),
            (Some(_), _) => Err("XCHONNECT_STORE: expected postgres or memory".into()),
        }
    }

    fn ohttp_mode(get: &impl Fn(&str) -> Option<String>) -> Result<OhttpMode, String> {
        match get("XCHONNECT_OHTTP").as_deref().map(str::trim) {
            Some("0" | "false") => return Ok(OhttpMode::Disabled),
            Some("ephemeral") => return Ok(OhttpMode::Ephemeral),
            None | Some("" | "1" | "true") => {}
            Some(_) => return Err("XCHONNECT_OHTTP: expected true, false or ephemeral".into()),
        }
        let text = match get("XCHONNECT_OHTTP_KEYS_FILE").filter(|p| !p.trim().is_empty()) {
            Some(path) => Some(
                std::fs::read_to_string(path.trim())
                    .map_err(|_| "XCHONNECT_OHTTP_KEYS_FILE: cannot read file")?,
            ),
            None => get("XCHONNECT_OHTTP_KEYS").filter(|v| !v.trim().is_empty()),
        };
        // A per-process key would break every client that pinned it after a restart and
        // differ between nodes, so it is never chosen silently.
        let text = text.ok_or(
            "XCHONNECT_OHTTP_KEYS is required while the OHTTP gateway is enabled \
             (or set XCHONNECT_OHTTP=false, or XCHONNECT_OHTTP=ephemeral for development)",
        )?;
        let mode = OhttpMode::Keys(crate::ohttp::parse_keys(&text)?);
        // Validate now so that a bad key fails startup instead of disabling the gateway.
        crate::ohttp::Gateway::new(&mode)?;
        Ok(mode)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn only_listen_and_log_leave_the_relay_unconfigured() {
        let names = |list: &[&str]| list.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>();
        assert!(Config::unconfigured(names(&[])));
        assert!(Config::unconfigured(names(&[
            "PATH",
            "XCHONNECT_LISTEN",
            "XCHONNECT_LOG",
            "SECRET_KEY_BASE",
        ])));
        // Any setting of the relay's own ends it, a present but empty one included.
        assert!(!Config::unconfigured(names(&["XCHONNECT_OHTTP"])));
        assert!(!Config::unconfigured(names(&[
            "XCHONNECT_LISTEN",
            "XCHONNECT_DATABASE_URL",
        ])));
    }

    #[test]
    fn the_listen_address_is_read_on_its_own() {
        let get = |v: Option<&'static str>| move |_: &str| v.map(str::to_owned);
        assert_eq!(Config::listen_from(get(None)), Ok(Config::default().listen));
        assert_eq!(
            Config::listen_from(get(Some("0.0.0.0:80"))).map(|a| a.port()),
            Ok(80)
        );
        assert!(Config::listen_from(get(Some("localhost:80"))).is_err());
        assert!(Config::listen_from(get(Some(":80"))).is_err());
    }

    #[test]
    fn parses_environment() {
        let env: HashMap<&str, &str> = [
            ("XCHONNECT_LISTEN", "0.0.0.0:9000"),
            ("XCHONNECT_CREATION", "open,pow"),
            ("XCHONNECT_API_KEYS", "pengui:0123456789abcdef0123"),
            ("XCHONNECT_GATEWAY_POLICY", "open"),
            ("XCHONNECT_MAX_WAIT_OHTTP_S", "99"),
            ("XCHONNECT_OHTTP", "ephemeral"),
            ("XCHONNECT_STORE", "memory"),
        ]
        .into_iter()
        .collect();
        let c = Config::from_lookup(|k| env.get(k).map(|v| (*v).to_owned())).unwrap();
        assert_eq!(c.listen.port(), 9000);
        assert_eq!(c.creation, vec![Creation::Open, Creation::Pow]);
        let customer = c.api_keys.get(&api_key_hash("0123456789abcdef0123"));
        assert_eq!(customer.unwrap(), "pengui");
        assert_eq!(c.gateway_policy, GatewayPolicy::Open);
        assert_eq!(c.max_wait_ohttp_s, 25, "clamped to max_wait_s");
        assert!(
            Config::from_lookup(|k| (k == "XCHONNECT_API_KEYS").then(|| "x:short".to_owned()))
                .is_err()
        );
    }

    #[test]
    fn insecure_gateways_are_refused_unless_the_relay_listens_on_loopback() {
        let get = |listen: Option<&'static str>, flag: &'static str| {
            Config::from_lookup(move |k| match k {
                "XCHONNECT_LISTEN" => listen.map(str::to_owned),
                "XCHONNECT_DEV_ALLOW_INSECURE_GATEWAYS" => Some(flag.to_owned()),
                "XCHONNECT_OHTTP" => Some("false".to_owned()),
                "XCHONNECT_STORE" => Some("memory".to_owned()),
                _ => None,
            })
        };
        // The default listen address is loopback, so the plain development command works.
        assert!(get(None, "true").unwrap().dev_allow_insecure_gateways);
        assert!(get(Some("127.0.0.1:8787"), "1").is_ok());
        assert!(get(Some("[::1]:8787"), "true").is_ok());
        let err = get(Some("0.0.0.0:8787"), "true").unwrap_err();
        assert!(
            err.contains("XCHONNECT_DEV_ALLOW_INSECURE_GATEWAYS"),
            "{err}"
        );
        assert!(get(Some("[::]:8787"), "true").is_err());
        assert!(get(Some("192.168.1.10:8787"), "1").is_err());
        // Without the flag any listen address is fine.
        assert!(get(Some("0.0.0.0:8787"), "false").is_ok());
    }

    #[test]
    fn max_ttl_below_the_minimum_is_a_config_error() {
        let get = |v: &'static str| {
            Config::from_lookup(move |k| match k {
                "XCHONNECT_MAX_TTL_S" => Some(v.to_owned()),
                "XCHONNECT_OHTTP" => Some("false".to_owned()),
                "XCHONNECT_STORE" => Some("memory".to_owned()),
                _ => None,
            })
        };
        assert!(get("30").is_err() && get("0").is_err());
        assert_eq!(get("60").unwrap().default_ttl_s, 60);
    }

    #[test]
    fn empty_values_mean_unset() {
        // Compose files and templated env files pass empty strings for unset values.
        let c = Config::from_lookup(|k| {
            matches!(
                k,
                "XCHONNECT_POW_KEY"
                    | "XCHONNECT_API_KEYS"
                    | "XCHONNECT_GATEWAY_ALLOWLIST"
                    | "XCHONNECT_DATABASE_URL"
            )
            .then(String::new)
            .or_else(|| (k == "XCHONNECT_OHTTP").then(|| "false".to_owned()))
            .or_else(|| (k == "XCHONNECT_STORE").then(|| "memory".to_owned()))
        })
        .unwrap();
        assert!(c.pow_key.is_none() && c.api_keys.is_empty() && c.database_url.is_none());
    }

    #[test]
    fn the_in_memory_store_is_only_used_when_asked_for() {
        let with = |pairs: &[(&str, &str)]| {
            Config::from_lookup(|k| {
                (k == "XCHONNECT_OHTTP")
                    .then(|| "false".to_owned())
                    .or_else(|| {
                        pairs
                            .iter()
                            .find(|(n, _)| *n == k)
                            .map(|(_, v)| (*v).to_owned())
                    })
            })
        };
        let url = ("XCHONNECT_DATABASE_URL", "postgres://u@db/x");
        // Nothing said: refuse to start rather than lose every mailbox on the next deploy.
        let err = with(&[]).unwrap_err();
        assert!(err.contains("XCHONNECT_STORE=memory"), "{err}");
        assert!(with(&[("XCHONNECT_STORE", "postgres")]).is_err());
        assert_eq!(
            with(&[("XCHONNECT_STORE", "memory")]).unwrap().store,
            StoreKind::Memory
        );
        assert_eq!(with(&[url]).unwrap().store, StoreKind::Postgres);
        assert_eq!(
            with(&[url, ("XCHONNECT_STORE", "postgres")]).unwrap().store,
            StoreKind::Postgres
        );
        assert!(with(&[url, ("XCHONNECT_STORE", "memory")]).is_err());
        assert!(with(&[("XCHONNECT_STORE", "disk")]).is_err());
    }
}
