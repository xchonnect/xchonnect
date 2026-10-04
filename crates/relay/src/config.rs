//! Relay configuration from environment variables (`XCHONNECT_*`).
//!
//! | Variable | Default | Meaning |
//! |---|---|---|
//! | `XCHONNECT_LISTEN` | `127.0.0.1:8787` | listen address |
//! | `XCHONNECT_DATABASE_URL` | unset → in-memory store | Postgres URL (`postgres://…`) |
//! | `XCHONNECT_MAX_WAIT_S` | `25` | long-poll limit for direct requests |
//! | `XCHONNECT_MAX_WAIT_OHTTP_S` | `0` | long-poll limit through OHTTP; at most the OHTTP relay's request timeout minus 5 s (spec 10.1) |
//! | `XCHONNECT_OHTTP` | `true` | run the OHTTP gateway (`false`: the relay sees client IPs; say so in your data inventory) |
//! | `XCHONNECT_OHTTP_KEYS` | unset → one key generated per process (development only, logged) | gateway keys `id:base64url(32-byte seed)`, comma-separated, **newest first**; keep the previous key listed during rotation |
//! | `XCHONNECT_OHTTP_KEYS_FILE` | unset | file with the same content as `XCHONNECT_OHTTP_KEYS` (for secret mounts); takes precedence |
//! | `XCHONNECT_DEFAULT_TTL_S` / `XCHONNECT_MAX_TTL_S` | `86400` / `604800` | message TTL |
//! | `XCHONNECT_MAX_MESSAGES` / `XCHONNECT_MAX_BYTES` | `256` / `4194304` | per-mailbox queue quota |
//! | `XCHONNECT_CREATION` | `pow,ticket,api_key` | accepted mailbox creation methods (`open` = no proof) |
//! | `XCHONNECT_POW_DIFFICULTY` | `18` | proof-of-work difficulty in bits |
//! | `XCHONNECT_POW_KEY` | random per process | base64url 32-byte key shared by all relay nodes |
//! | `XCHONNECT_API_KEYS` | empty | `customer:key,customer:key` (keys are hashed in memory) |
//! | `XCHONNECT_GATEWAY_POLICY` | `allowlist` | `allowlist` or `open` (spec 7.3.1) |
//! | `XCHONNECT_GATEWAY_ALLOWLIST` | empty | comma-separated `https://` URL prefixes |
//! | `XCHONNECT_DEV_ALLOW_INSECURE_GATEWAYS` | `false` | allow `http`/loopback gateways (local development only) |
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

impl Config {
    /// Read from the process environment.
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Read using a lookup function (testable).
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let mut c = Config::default();
        let num = |k: &str, d: u64| -> Result<u64, String> {
            get(k).map_or(Ok(d), |v| {
                v.trim().parse().map_err(|_| format!("{k}: not a number"))
            })
        };
        if let Some(v) = get("XCHONNECT_LISTEN") {
            c.listen = v
                .parse()
                .map_err(|_| "XCHONNECT_LISTEN: invalid socket address".to_owned())?;
        }
        c.database_url = get("XCHONNECT_DATABASE_URL").filter(|s| !s.is_empty());
        c.max_wait_s = num("XCHONNECT_MAX_WAIT_S", c.max_wait_s)?.min(60);
        c.max_wait_ohttp_s =
            num("XCHONNECT_MAX_WAIT_OHTTP_S", c.max_wait_ohttp_s)?.min(c.max_wait_s);
        c.default_ttl_s = num("XCHONNECT_DEFAULT_TTL_S", c.default_ttl_s)?;
        c.max_ttl_s = num("XCHONNECT_MAX_TTL_S", c.max_ttl_s)?.min(604_800);
        c.default_ttl_s = c.default_ttl_s.clamp(60, c.max_ttl_s);
        c.max_messages = usize::try_from(num("XCHONNECT_MAX_MESSAGES", c.max_messages as u64)?)
            .map_err(|e| e.to_string())?;
        c.max_bytes = usize::try_from(num("XCHONNECT_MAX_BYTES", c.max_bytes as u64)?)
            .map_err(|e| e.to_string())?;
        if let Some(v) = get("XCHONNECT_CREATION") {
            c.creation = v
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| match s {
                    "api_key" => Ok(Creation::ApiKey),
                    "ticket" => Ok(Creation::Ticket),
                    "pow" => Ok(Creation::Pow),
                    "open" => Ok(Creation::Open),
                    other => Err(format!("XCHONNECT_CREATION: unknown method {other}")),
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
            for entry in v.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                let (customer, key) = entry
                    .split_once(':')
                    .ok_or("XCHONNECT_API_KEYS: expected customer:key")?;
                if key.len() < 16 {
                    return Err("XCHONNECT_API_KEYS: keys must have at least 16 characters".into());
                }
                c.api_keys.insert(api_key_hash(key), customer.to_owned());
            }
        }
        let allow: Vec<String> = get("XCHONNECT_GATEWAY_ALLOWLIST")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
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
        c.ohttp = Self::ohttp_mode(&get)?;
        Ok(c)
    }

    fn ohttp_mode(get: &impl Fn(&str) -> Option<String>) -> Result<OhttpMode, String> {
        if matches!(get("XCHONNECT_OHTTP").as_deref(), Some("0" | "false")) {
            return Ok(OhttpMode::Disabled);
        }
        let text = match get("XCHONNECT_OHTTP_KEYS_FILE").filter(|p| !p.trim().is_empty()) {
            Some(path) => Some(
                std::fs::read_to_string(path.trim())
                    .map_err(|_| "XCHONNECT_OHTTP_KEYS_FILE: cannot read file")?,
            ),
            None => get("XCHONNECT_OHTTP_KEYS").filter(|v| !v.trim().is_empty()),
        };
        let mode = match text {
            None => OhttpMode::Ephemeral,
            Some(t) => OhttpMode::Keys(crate::ohttp::parse_keys(&t)?),
        };
        // Validate now so that a bad key fails startup instead of disabling the gateway.
        if let OhttpMode::Keys(_) = &mode {
            crate::ohttp::Gateway::new(&mode)?;
        }
        Ok(mode)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_environment() {
        let env: HashMap<&str, &str> = [
            ("XCHONNECT_LISTEN", "0.0.0.0:9000"),
            ("XCHONNECT_CREATION", "open,pow"),
            ("XCHONNECT_API_KEYS", "pengui:0123456789abcdef0123"),
            ("XCHONNECT_GATEWAY_POLICY", "open"),
            ("XCHONNECT_MAX_WAIT_OHTTP_S", "99"),
        ]
        .into_iter()
        .collect();
        let c = Config::from_lookup(|k| env.get(k).map(|v| (*v).to_owned())).unwrap();
        assert_eq!(c.listen.port(), 9000);
        assert_eq!(c.creation, vec![Creation::Open, Creation::Pow]);
        assert_eq!(
            c.api_keys
                .get(&api_key_hash("0123456789abcdef0123"))
                .unwrap(),
            "pengui"
        );
        assert_eq!(c.gateway_policy, GatewayPolicy::Open);
        assert_eq!(c.max_wait_ohttp_s, 25, "clamped to max_wait_s");
        assert!(
            Config::from_lookup(|k| (k == "XCHONNECT_API_KEYS").then(|| "x:short".to_owned()))
                .is_err()
        );
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
        })
        .unwrap();
        assert!(c.pow_key.is_none() && c.api_keys.is_empty() && c.database_url.is_none());
    }
}
