//! Mailbox creation policy: API keys, sponsorship tickets (spec 7.5) and
//! proof-of-work (spec 7.4), plus push registration checks at registration time
//! (spec 7.3.1 rules 1 and 6).

use crate::config::{Config, GatewayPolicy};
use crate::error::ApiError;
use xchonnect_core::crypto::{self, OsEntropy};
use xchonnect_core::pow;

/// Ticket validity (spec 7.5: at most 10 minutes).
pub const TICKET_TTL_S: u64 = 600;
/// Maximum sealed token size accepted in a push registration.
pub const MAX_SEALED_TOKEN: usize = 8 * 1024;

/// Proof-of-work state: keys derived per day from a base key (shared between relay
/// nodes when `XCHONNECT_POW_KEY` is set). Spent challenges are recorded in the
/// `MailboxStore` so a solution is single-use across nodes and restarts (spec 7.4).
#[derive(Debug)]
pub struct PowState {
    base_key: [u8; 32],
}

impl PowState {
    /// Create from an optional shared base key; random per process otherwise.
    pub fn new(base_key: Option<[u8; 32]>) -> Self {
        PowState {
            base_key: base_key.unwrap_or_else(|| crypto::random_array(&mut OsEntropy)),
        }
    }

    fn key_for_day(&self, day: u64) -> Result<[u8; 32], ApiError> {
        crypto::hmac_sha256(&self.base_key, &[b"xchonnect pow key", &day.to_be_bytes()])
            .map_err(|_| ApiError::Unavailable)
    }

    /// Issue a challenge.
    pub fn issue(&self, now: u64, difficulty: u8) -> Result<[u8; pow::CHALLENGE_LEN], ApiError> {
        let key = self.key_for_day(now / 86_400)?;
        pow::issue(&key, &mut OsEntropy, now, difficulty).map_err(|_| ApiError::Unavailable)
    }

    /// Verify a solution **without** spending it. Returns the store key to spend and the
    /// challenge expiry. Callers rate-limit first and then spend via
    /// `MailboxStore::spend_pow`, so neither invalid requests nor 429s cost anything.
    pub fn verify(
        &self,
        challenge: &[u8],
        nonce: &[u8],
        now: u64,
        min_difficulty: u8,
    ) -> Result<([u8; 32], u64), ApiError> {
        let today = self.key_for_day(now / 86_400)?;
        let yesterday = self.key_for_day((now / 86_400).saturating_sub(1))?;
        let info = pow::verify(&[&today, &yesterday], challenge, nonce, now)
            .map_err(|_| ApiError::PowInvalid)?;
        if info.difficulty < min_difficulty {
            return Err(ApiError::PowInvalid);
        }
        Ok((
            crypto::sha256_parts(&[b"xchonnect v1 pow spent", challenge]),
            info.expires_at,
        ))
    }
}

/// `SHA-256("xchonnect v1 ticket" || ticket)`.
pub fn ticket_hash(ticket: &[u8; 32]) -> [u8; 32] {
    crypto::sha256_parts(&[b"xchonnect v1 ticket", ticket])
}

/// Registration-time checks of a gateway URL (rules 1 and 6). Dispatch-time checks
/// (resolution, private ranges, redirects, timeouts) run when waking (TASK-44).
pub fn check_gateway_url(config: &Config, url: &str) -> Result<(), ApiError> {
    if url.len() > 512 || url.contains(['@', ' ', '#']) {
        return Err(ApiError::GatewayNotAllowed);
    }
    let rest = match (url.strip_prefix("https://"), url.strip_prefix("http://")) {
        (Some(r), _) => r,
        (None, Some(r)) if config.dev_allow_insecure_gateways => r,
        _ => return Err(ApiError::GatewayNotAllowed),
    };
    let host = rest.split('/').next().unwrap_or_default();
    if host.is_empty() {
        return Err(ApiError::GatewayNotAllowed);
    }
    if let Some((_, port)) = host.rsplit_once(':') {
        if port != "443" && !config.dev_allow_insecure_gateways {
            return Err(ApiError::GatewayNotAllowed);
        }
    }
    match &config.gateway_policy {
        GatewayPolicy::Allowlist(list) if !list.iter().any(|p| url.starts_with(p.as_str())) => {
            Err(ApiError::GatewayNotAllowed)
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn pow_verify_difficulty_and_shared_keys() {
        let p = PowState::new(Some([1; 32]));
        let now = 1_790_000_000;
        let c = p.issue(now, 8).unwrap();
        let n = pow::solve(&c).unwrap();
        let (key, exp) = p.verify(&c, &n, now, 8).unwrap();
        let again = p.verify(&c, &n, now, 8).unwrap().0;
        assert_eq!(again, key, "verify does not spend; same store key");
        assert_eq!(exp, now + pow::VALIDITY_S);
        let c2 = p.issue(now, 4).unwrap();
        let n2 = pow::solve(&c2).unwrap();
        let weak = p.verify(&c2, &n2, now, 8);
        assert_eq!(weak, Err(ApiError::PowInvalid), "below required difficulty");
        // Shared base key works across nodes; other keys do not.
        for (base_key, ok) in [([1; 32], true), ([2; 32], false)] {
            let c = p.issue(now, 4).unwrap();
            let res = PowState::new(Some(base_key)).verify(&c, &pow::solve(&c).unwrap(), now, 4);
            assert_eq!(res.is_ok(), ok);
        }
    }

    #[test]
    fn gateway_urls() {
        let mut c = Config {
            gateway_policy: GatewayPolicy::Allowlist(vec!["https://push.klimper.app/".into()]),
            ..Config::default()
        };
        assert!(check_gateway_url(&c, "https://push.klimper.app/v1/wake").is_ok());
        assert!(check_gateway_url(&c, "https://push.klimper.app.evil.com/v1/wake").is_err());
        assert!(check_gateway_url(&c, "http://push.klimper.app/v1/wake").is_err());
        c.gateway_policy = GatewayPolicy::Open;
        assert!(check_gateway_url(&c, "https://anything.example/wake").is_ok());
        assert!(check_gateway_url(&c, "https://user@anything.example/wake").is_err());
        assert!(check_gateway_url(&c, "https://anything.example:8443/wake").is_err());
        c.dev_allow_insecure_gateways = true;
        assert!(check_gateway_url(&c, "http://127.0.0.1:9000/v1/wake").is_ok());
    }
}
