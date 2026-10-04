//! Mailbox storage (spec 7.1).
//!
//! Every backend stores exactly the fields of the spec's data model: token hashes, an
//! optional sealed push registration, the optional business customer id, day-granular
//! timestamps, and ciphertext envelopes with their expiry. Backends must not log or
//! return identifiers in error messages.

pub mod memory;
#[cfg(feature = "postgres")]
pub mod postgres;

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;
use xchonnect_core::crypto::MailboxId;

/// Seconds per day bucket.
pub const DAY_S: u64 = 86_400;
/// Mailboxes without authenticated use for this many days are deleted.
pub const INACTIVE_DAYS: u32 = 30;

/// Day bucket of a unix time.
pub fn day(now: u64) -> u32 {
    u32::try_from(now / DAY_S).unwrap_or(u32::MAX)
}

/// Sealed push registration (spec 7.3). Opaque to the relay apart from the URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushReg {
    /// Gateway wake URL.
    pub gateway_url: String,
    /// Token sealed to the gateway key.
    pub sealed_token: Vec<u8>,
}

/// A mailbox row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxRecord {
    /// `SHA-256("xchonnect v1 token" || read_token)`.
    pub read_hash: [u8; 32],
    /// `SHA-256("xchonnect v1 token" || write_token)`.
    pub write_hash: [u8; 32],
    /// Optional push registration.
    pub push: Option<PushReg>,
    /// Business customer that created or sponsored it.
    pub customer: Option<String>,
    /// Creation day bucket.
    pub created_day: u32,
    /// Last authenticated use, day bucket.
    pub last_used_day: u32,
}

/// A stored envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMessage {
    /// Relay-chosen id.
    pub msg_id: [u8; 16],
    /// Encoded envelope.
    pub envelope: Vec<u8>,
}

/// Per-mailbox quota.
#[derive(Debug, Clone, Copy)]
pub struct QueueLimits {
    /// Maximum queued messages.
    pub max_messages: usize,
    /// Maximum queued envelope bytes.
    pub max_bytes: usize,
}

/// Result of a sweep.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepStats {
    /// Expired messages removed.
    pub messages: u64,
    /// Inactive mailboxes removed.
    pub mailboxes: u64,
}

/// Storage errors. Never contain identifiers or tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// Mailbox does not exist.
    NotFound,
    /// Quota reached.
    MailboxFull,
    /// Backend failure (static description only).
    Backend(&'static str),
}

/// Storage backend.
#[async_trait]
pub trait MailboxStore: Send + Sync + 'static {
    /// Insert a new mailbox. Fails with `Backend` on id collision.
    async fn create(&self, id: MailboxId, rec: MailboxRecord) -> Result<(), StoreError>;
    /// Fetch a mailbox row.
    async fn get(&self, id: &MailboxId) -> Result<Option<MailboxRecord>, StoreError>;
    /// Record authenticated use on `day`.
    async fn touch(&self, id: &MailboxId, day: u32) -> Result<(), StoreError>;
    /// Delete a mailbox and all its messages.
    async fn delete(&self, id: &MailboxId) -> Result<(), StoreError>;
    /// Replace or remove the push registration.
    async fn set_push(&self, id: &MailboxId, push: Option<PushReg>) -> Result<(), StoreError>;
    /// Append a message, enforcing the quota.
    async fn enqueue(
        &self,
        id: &MailboxId,
        msg: StoredMessage,
        expires_at: u64,
        limits: QueueLimits,
    ) -> Result<(), StoreError>;
    /// Unexpired messages in acceptance order, at most `limit`.
    async fn fetch(
        &self,
        id: &MailboxId,
        limit: usize,
        now: u64,
    ) -> Result<Vec<StoredMessage>, StoreError>;
    /// Delete the given messages.
    async fn ack(&self, id: &MailboxId, msg_ids: &[[u8; 16]]) -> Result<(), StoreError>;
    /// Delete expired messages and mailboxes last used before `inactive_before_day`.
    async fn sweep(&self, now: u64, inactive_before_day: u32) -> Result<SweepStats, StoreError>;
    /// Number of mailboxes (aggregate metric).
    async fn mailbox_count(&self) -> Result<u64, StoreError>;
    /// Store a sponsorship ticket hash (spec 7.5).
    async fn put_ticket(
        &self,
        ticket_hash: [u8; 32],
        customer: &str,
        expires_at: u64,
    ) -> Result<(), StoreError>;
    /// Record a proof-of-work challenge as spent until `expires_at`. Returns `false` if it
    /// was already spent (on any node sharing this store).
    async fn spend_pow(&self, key: [u8; 32], expires_at: u64) -> Result<bool, StoreError>;
    /// Atomically consume a ticket; returns its customer if it existed and was unexpired.
    async fn take_ticket(
        &self,
        ticket_hash: &[u8; 32],
        now: u64,
    ) -> Result<Option<String>, StoreError>;
}

/// Wakes long-polls when a message arrives. One watch channel per mailbox that has
/// waiters; subscribing before checking the store makes waiting race-free.
#[derive(Debug, Clone, Default)]
pub struct Notifier {
    channels: Arc<Mutex<HashMap<MailboxId, watch::Sender<u64>>>>,
}

impl Notifier {
    /// Subscribe to a mailbox. Call before fetching.
    pub fn subscribe(&self, id: &MailboxId) -> watch::Receiver<u64> {
        let mut map = crate::lock(&self.channels);
        map.retain(|_, tx| tx.receiver_count() > 0);
        map.entry(*id)
            .or_insert_with(|| watch::channel(0).0)
            .subscribe()
    }

    /// Signal that `id` has a new message.
    pub fn notify(&self, id: &MailboxId) {
        if let Some(tx) = crate::lock(&self.channels).get(id) {
            tx.send_modify(|n| *n = n.wrapping_add(1));
        }
    }
}

/// Wait until `rx` changes or `timeout` elapses.
pub async fn wait(mut rx: watch::Receiver<u64>, timeout: Duration) {
    let _ = tokio::time::timeout(timeout, rx.changed()).await;
}

/// Periodically delete expired messages and inactive mailboxes.
pub fn spawn_sweeper(state: crate::AppState) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            let now = state.now();
            let cutoff = day(now).saturating_sub(INACTIVE_DAYS);
            if let Err(e) = state.store().sweep(now, cutoff).await {
                tracing::warn!(?e, "sweep failed");
            }
        }
    });
}

/// Backend-agnostic test suite; every `MailboxStore` implementation must pass it.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod suite {
    use super::*;

    pub(crate) fn rec(day: u32) -> MailboxRecord {
        MailboxRecord {
            read_hash: [1; 32],
            write_hash: [2; 32],
            push: None,
            customer: Some("c1".into()),
            created_day: day,
            last_used_day: day,
        }
    }

    pub(crate) fn msg(i: u8, len: usize) -> StoredMessage {
        StoredMessage {
            msg_id: [i; 16],
            envelope: vec![i; len],
        }
    }

    pub(crate) const LIM: QueueLimits = QueueLimits {
        max_messages: 3,
        max_bytes: 1000,
    };

    pub(crate) async fn run(s: &dyn MailboxStore) {
        let now = 1_790_000_000;
        let (a, b) = (MailboxId([0xa1; 16]), MailboxId([0xb2; 16]));
        let (exp, full) = (now + 100, Err(StoreError::MailboxFull));

        // create / get / collision
        s.create(a, rec(day(now))).await.unwrap();
        assert_eq!(s.get(&a).await.unwrap().unwrap(), rec(day(now)));
        assert!(s.create(a, rec(day(now))).await.is_err());
        assert_eq!(s.get(&b).await.unwrap(), None);

        // enqueue order, fetch limit, ack
        for i in 1..=3 {
            s.enqueue(&a, msg(i, 100), exp, LIM).await.unwrap();
        }
        assert_eq!(s.enqueue(&a, msg(4, 100), exp, LIM).await, full);
        let got = s.fetch(&a, 2, now).await.unwrap();
        assert_eq!(got, vec![msg(1, 100), msg(2, 100)]);
        s.ack(&a, &[[1; 16], [9; 16]]).await.unwrap();
        let got = s.fetch(&a, 10, now).await.unwrap();
        assert_eq!(got, vec![msg(2, 100), msg(3, 100)]);
        // byte quota
        s.ack(&a, &[[2; 16], [3; 16]]).await.unwrap();
        s.enqueue(&a, msg(5, 900), exp, LIM).await.unwrap();
        assert_eq!(s.enqueue(&a, msg(6, 200), exp, LIM).await, full);
        s.ack(&a, &[[5; 16]]).await.unwrap();

        // unknown mailbox
        let unknown = s.enqueue(&b, msg(1, 1), now + 1, LIM).await;
        assert_eq!(unknown, Err(StoreError::NotFound));

        // expiry: hidden from fetch, removed by sweep
        s.enqueue(&a, msg(7, 10), now + 5, LIM).await.unwrap();
        s.enqueue(&a, msg(8, 10), now + 500, LIM).await.unwrap();
        assert_eq!(s.fetch(&a, 10, now + 10).await.unwrap(), vec![msg(8, 10)]);
        assert_eq!(s.sweep(now + 10, 0).await.unwrap().messages, 1);

        // push registration
        let p = PushReg {
            gateway_url: "https://push.example/v1/wake".into(),
            sealed_token: vec![1, 2, 3],
        };
        s.set_push(&a, Some(p.clone())).await.unwrap();
        assert_eq!(s.get(&a).await.unwrap().unwrap().push, Some(p));
        s.set_push(&a, None).await.unwrap();
        assert_eq!(s.get(&a).await.unwrap().unwrap().push, None);

        // inactivity: touch keeps a mailbox, sweep removes stale ones
        s.create(b, rec(day(now) - 40)).await.unwrap();
        s.touch(&a, day(now)).await.unwrap();
        assert_eq!(s.sweep(now, day(now) - 30).await.unwrap().mailboxes, 1);
        assert_eq!(s.get(&b).await.unwrap(), None);
        assert!(s.get(&a).await.unwrap().is_some());
        assert_eq!(s.mailbox_count().await.unwrap(), 1);

        // tickets are single-use and expire
        s.put_ticket([5; 32], "c1", now + 600).await.unwrap();
        s.put_ticket([6; 32], "c2", now + 1).await.unwrap();
        assert_eq!(
            s.take_ticket(&[5; 32], now).await.unwrap(),
            Some("c1".into())
        );
        assert_eq!(s.take_ticket(&[5; 32], now).await.unwrap(), None);
        assert_eq!(s.take_ticket(&[6; 32], now + 2).await.unwrap(), None);

        // proof-of-work challenges are single-use
        assert!(s.spend_pow([8; 32], exp).await.unwrap());
        assert!(!s.spend_pow([8; 32], exp).await.unwrap());

        // delete removes messages too
        s.delete(&a).await.unwrap();
        assert_eq!(s.get(&a).await.unwrap(), None);
        assert_eq!(s.fetch(&a, 10, now).await, Err(StoreError::NotFound));
    }

    #[tokio::test]
    async fn notifier_wakes_waiters() {
        let n = Notifier::default();
        let id = MailboxId([1; 16]);
        let rx = n.subscribe(&id);
        let n2 = n.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            n2.notify(&id);
        });
        let t = std::time::Instant::now();
        wait(rx, Duration::from_secs(5)).await;
        assert!(t.elapsed() < Duration::from_secs(2));
    }
}
