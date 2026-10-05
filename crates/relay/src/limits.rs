//! In-memory rate limiting and usage counters (spec 7.1 rate counters, T8, T16).
//!
//! Buckets are keyed only by token hashes, hashed customer ids or a fixed global key —
//! never by client IPs or other identifiers — and live only in memory.

use crate::error::ApiError;
use crate::lock;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// A token-bucket limiter.
#[derive(Debug)]
pub struct RateLimiter {
    per_minute: f64,
    burst: f64,
    buckets: Mutex<HashMap<[u8; 32], (f64, u64)>>,
    /// Unix second of the last cleanup pass (cleanup is time-gated, not per request).
    last_cleanup: AtomicU64,
}

/// Buckets untouched for this long are dropped (their state would be "full" again or
/// close to it; resetting them is harmless).
const IDLE_S: u64 = 600;
/// Map size above which cleanup runs, at most once per [`CLEANUP_EVERY_S`].
const CLEANUP_ABOVE: usize = 100_000;
const CLEANUP_EVERY_S: u64 = 10;

impl RateLimiter {
    /// `per_minute` sustained rate with a burst of `burst` requests.
    pub fn new(per_minute: u32, burst: u32) -> Self {
        RateLimiter {
            per_minute: f64::from(per_minute),
            burst: f64::from(burst.max(1)),
            buckets: Mutex::new(HashMap::new()),
            last_cleanup: AtomicU64::new(0),
        }
    }

    /// Take one token for `key` at `now` (unix seconds). On refusal returns
    /// [`ApiError::RateLimited`] with the seconds until a token is available.
    pub fn check(&self, key: &[u8; 32], now: u64) -> Result<(), ApiError> {
        if self.per_minute <= 0.0 {
            return Ok(());
        }
        let rate_s = self.per_minute / 60.0;
        let mut map = lock(&self.buckets);
        let last = self.last_cleanup.load(Ordering::Relaxed);
        if map.len() > CLEANUP_ABOVE && now.saturating_sub(last) >= CLEANUP_EVERY_S {
            // Amortised: at most one O(n) pass per CLEANUP_EVERY_S, however many requests.
            self.last_cleanup.store(now, Ordering::Relaxed);
            let burst = self.burst;
            map.retain(|_, (tokens, last)| {
                let idle = now.saturating_sub(*last);
                idle < IDLE_S && *tokens + (idle as f64) * rate_s < burst
            });
        }
        let entry = map.entry(*key).or_insert((self.burst, now));
        let elapsed = now.saturating_sub(entry.1) as f64;
        entry.0 = (entry.0 + elapsed * rate_s).min(self.burst);
        entry.1 = now;
        if entry.0 >= 1.0 {
            entry.0 -= 1.0;
            Ok(())
        } else {
            let retry_after = (((1.0 - entry.0) / rate_s).ceil() as u64).max(1);
            Err(ApiError::RateLimited { retry_after })
        }
    }
}

/// Aggregate usage of one business customer, for external metering.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    /// Mailboxes created or sponsored.
    pub mailboxes_created: u64,
    /// Messages accepted into the customer's mailboxes.
    pub messages: u64,
}

/// Per-customer counters (in memory; exported by the operator's metering job).
#[derive(Debug, Default)]
pub struct UsageCounters {
    map: Mutex<HashMap<String, Usage>>,
}

impl UsageCounters {
    /// Count a created mailbox.
    pub fn mailbox_created(&self, customer: &str) {
        self.with(customer, |u| u.mailboxes_created += 1);
    }

    /// Count an accepted message.
    pub fn message(&self, customer: &str) {
        self.with(customer, |u| u.messages += 1);
    }

    fn with(&self, customer: &str, f: impl FnOnce(&mut Usage)) {
        f(lock(&self.map).entry(customer.to_owned()).or_default());
    }

    /// Snapshot of all counters.
    pub fn snapshot(&self) -> Vec<(String, Usage)> {
        let mut v: Vec<_> = lock(&self.map)
            .iter()
            .map(|(k, u)| (k.clone(), *u))
            .collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }
}

/// All limiters used by the API.
#[derive(Debug)]
pub struct Limits {
    /// Per write token (posting).
    pub write: RateLimiter,
    /// Per read token (fetch, ack, push, delete).
    pub read: RateLimiter,
    /// Per customer (posting into the customer's mailboxes).
    pub customer: RateLimiter,
    /// Global bucket for creation without API key.
    pub create: RateLimiter,
    /// Usage counters.
    pub usage: UsageCounters,
}

impl Limits {
    /// Build from configuration.
    pub fn new(c: &crate::Config) -> Self {
        let token = |rate: u32| RateLimiter::new(rate, rate.div_ceil(4).max(10));
        Limits {
            write: token(c.write_rate),
            read: token(c.read_rate),
            customer: RateLimiter::new(c.customer_rate, c.customer_rate.div_ceil(10).max(100)),
            create: token(c.create_rate),
            usage: UsageCounters::default(),
        }
    }
}

/// Key for a customer bucket.
pub fn customer_key(customer: &str) -> [u8; 32] {
    xchonnect_core::crypto::sha256_parts(&[b"xchonnect customer", customer.as_bytes()])
}

/// Global key for anonymous creation.
pub const GLOBAL_KEY: [u8; 32] = [0; 32];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_refills() {
        let l = RateLimiter::new(60, 3);
        let k = [1; 32];
        for _ in 0..3 {
            assert!(l.check(&k, 100).is_ok());
        }
        assert_eq!(
            l.check(&k, 100),
            Err(ApiError::RateLimited { retry_after: 1 })
        );
        assert!(l.check(&[2; 32], 100).is_ok(), "independent keys");
        assert!(l.check(&k, 101).is_ok(), "one token per second");
        assert!(l.check(&k, 101).is_err());
        assert!(RateLimiter::new(0, 1).check(&k, 0).is_ok(), "0 disables");
    }

    #[test]
    fn usage() {
        let u = UsageCounters::default();
        u.mailbox_created("a");
        u.message("a");
        u.message("a");
        let expected = Usage {
            mailboxes_created: 1,
            messages: 2,
        };
        assert_eq!(u.snapshot(), vec![("a".to_owned(), expected)]);
    }
}
