//! Recorders that observe what the services actually do with data.
//!
//! * [`RecordingStore`] wraps any [`MailboxStore`] and transcribes every value the relay
//!   ever hands to storage. Scanning that transcript is stronger than dumping a database:
//!   a field that is written but not yet persisted, or persisted in a new column, is in
//!   the transcript the moment the code writes it.
//! * [`RecordingSender`] records what the gateway hands to a push platform.
//! * [`wake_capturing_app`] records the exact relay-to-gateway wake-up requests.

use crate::scan::Surface;
use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use xchonnect_core::b64;
use xchonnect_core::crypto::MailboxId;
use xchonnect_core::push::PushToken;
use xchonnect_gateway::{Gateway, PlatformSender, SendError};
use xchonnect_relay::store::{
    MailboxRecord, MailboxStore, PushReg, QueueLimits, StoreError, StoredMessage, SweepStats,
};

/// A surface shared with the service that writes into it.
pub type Shared = Arc<Mutex<Surface>>;

/// A new shared surface.
pub fn shared(name: &str) -> Shared {
    Arc::new(Mutex::new(Surface::new(name)))
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Snapshot of a shared surface.
pub fn snapshot(s: &Shared) -> Surface {
    lock(s).clone()
}

/// A [`MailboxStore`] that transcribes every write.
pub struct RecordingStore {
    inner: Arc<dyn MailboxStore>,
    transcript: Shared,
}

impl std::fmt::Debug for RecordingStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecordingStore")
    }
}

impl RecordingStore {
    /// Wrap `inner`, writing the transcript into `transcript`.
    pub fn new(inner: Arc<dyn MailboxStore>, transcript: Shared) -> Self {
        RecordingStore { inner, transcript }
    }

    fn record(&self, line: &str, raw: &[&[u8]]) {
        let mut s = lock(&self.transcript);
        s.line(line);
        for bytes in raw {
            s.raw(bytes);
        }
    }

    fn record_record(&self, id: &MailboxId, rec: &MailboxRecord) {
        let push = rec.push.as_ref();
        let sealed = push.map(|p| p.sealed_token.clone()).unwrap_or_default();
        self.record(
            &format!(
                "mailbox id={} read_hash={} write_hash={} push_url={} push_token={} \
                 customer={} created_day={} last_used_day={}",
                id.to_b64(),
                b64::encode(&rec.read_hash),
                b64::encode(&rec.write_hash),
                push.map_or("-", |p| p.gateway_url.as_str()),
                b64::encode(&sealed),
                rec.customer.as_deref().unwrap_or("-"),
                rec.created_day,
                rec.last_used_day,
            ),
            &[&id.0, &rec.read_hash, &rec.write_hash, &sealed],
        );
    }
}

#[async_trait]
impl MailboxStore for RecordingStore {
    async fn create(&self, id: MailboxId, rec: MailboxRecord) -> Result<(), StoreError> {
        self.record_record(&id, &rec);
        self.inner.create(id, rec).await
    }

    async fn get(&self, id: &MailboxId) -> Result<Option<MailboxRecord>, StoreError> {
        self.inner.get(id).await
    }

    async fn touch(&self, id: &MailboxId, day: u32) -> Result<(), StoreError> {
        self.record(&format!("touch id={} day={day}", id.to_b64()), &[&id.0]);
        self.inner.touch(id, day).await
    }

    async fn delete(&self, id: &MailboxId) -> Result<(), StoreError> {
        self.inner.delete(id).await
    }

    async fn set_push(&self, id: &MailboxId, push: Option<PushReg>) -> Result<(), StoreError> {
        let sealed = push
            .as_ref()
            .map(|p| p.sealed_token.clone())
            .unwrap_or_default();
        self.record(
            &format!(
                "push id={} url={} token={}",
                id.to_b64(),
                push.as_ref().map_or("-", |p| p.gateway_url.as_str()),
                b64::encode(&sealed),
            ),
            &[&id.0, &sealed],
        );
        self.inner.set_push(id, push).await
    }

    async fn enqueue(
        &self,
        id: &MailboxId,
        msg: StoredMessage,
        now: u64,
        expires_at: u64,
        limits: QueueLimits,
    ) -> Result<(), StoreError> {
        self.record(
            &format!(
                "message mailbox={} msg_id={} expires_at={expires_at} bytes={} env={}",
                id.to_b64(),
                b64::encode(&msg.msg_id),
                msg.envelope.len(),
                b64::encode(&msg.envelope),
            ),
            &[&id.0, &msg.msg_id, &msg.envelope],
        );
        self.inner.enqueue(id, msg, now, expires_at, limits).await
    }

    async fn fetch(
        &self,
        id: &MailboxId,
        limit: usize,
        now: u64,
    ) -> Result<Vec<StoredMessage>, StoreError> {
        self.inner.fetch(id, limit, now).await
    }

    async fn ack(&self, id: &MailboxId, msg_ids: &[[u8; 16]]) -> Result<(), StoreError> {
        self.inner.ack(id, msg_ids).await
    }

    async fn sweep(&self, now: u64, inactive_before_day: u32) -> Result<SweepStats, StoreError> {
        self.inner.sweep(now, inactive_before_day).await
    }

    async fn mailbox_count(&self) -> Result<u64, StoreError> {
        self.inner.mailbox_count().await
    }

    async fn ping(&self) -> Result<(), StoreError> {
        self.inner.ping().await
    }

    async fn put_ticket(
        &self,
        ticket_hash: [u8; 32],
        customer: &str,
        expires_at: u64,
    ) -> Result<(), StoreError> {
        self.record(
            &format!(
                "ticket hash={} customer={customer} expires_at={expires_at}",
                b64::encode(&ticket_hash)
            ),
            &[&ticket_hash],
        );
        self.inner
            .put_ticket(ticket_hash, customer, expires_at)
            .await
    }

    async fn spend_pow(&self, key: [u8; 32], expires_at: u64) -> Result<bool, StoreError> {
        self.record(
            &format!("pow key={} expires_at={expires_at}", b64::encode(&key)),
            &[&key],
        );
        self.inner.spend_pow(key, expires_at).await
    }

    async fn take_ticket(
        &self,
        ticket_hash: &[u8; 32],
        now: u64,
    ) -> Result<Option<String>, StoreError> {
        self.inner.take_ticket(ticket_hash, now).await
    }
}

/// A push platform sender that records what it was asked to deliver.
#[derive(Debug)]
pub struct RecordingSender {
    delivered: Shared,
    count: AtomicU64,
}

impl RecordingSender {
    /// Record into `delivered`.
    pub fn new(delivered: Shared) -> Self {
        RecordingSender {
            delivered,
            count: AtomicU64::new(0),
        }
    }

    /// Number of deliveries so far.
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl PlatformSender for RecordingSender {
    async fn send(&self, token: &PushToken, preview: Option<&[u8]>) -> Result<(), SendError> {
        {
            let mut s = lock(&self.delivered);
            s.line(format!(
                "deliver platform={} device_token={} hint_key={} exp={} preview_len={} debug={token:?}",
                token.platform.as_str(),
                token.device_token,
                b64::encode(&token.hint_key),
                token.exp,
                preview.map_or(0, <[u8]>::len),
            ));
            s.raw(token.device_token.as_bytes());
            s.raw(&token.hint_key);
            // The sealed notification preview reaches Apple and Google, so it is
            // scanned like every other byte on this surface: it must carry no
            // plaintext, address or identifier (spec 7.3.3; T11, T12).
            if let Some(preview) = preview {
                s.raw(preview);
            }
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

/// Largest wake-up body recorded.
const MAX_WAKE_BODY: usize = 64 * 1024;

async fn record_wake(State(s): State<Shared>, req: Request, next: Next) -> Response {
    let (parts, body) = req.into_parts();
    let bytes = axum::body::to_bytes(body, MAX_WAKE_BODY)
        .await
        .unwrap_or_default();
    {
        let host = parts
            .headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("-");
        let mut surface = lock(&s);
        // The reconstructed absolute URL, so that a check for "the gateway URL appears
        // here" matches what the relay was configured with.
        surface.line(format!(
            "{} http://{host}{}",
            parts.method,
            parts.uri.path()
        ));
        for (name, value) in &parts.headers {
            surface.line(format!(
                "header {name}: {}",
                value.to_str().unwrap_or("<bin>")
            ));
        }
        surface.line(format!("body {}", String::from_utf8_lossy(&bytes)));
        surface.raw(&bytes);
    }
    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

/// The real gateway application, behind a recorder for every request it receives.
pub fn wake_capturing_app(gateway: Gateway, requests: Shared) -> Router {
    xchonnect_gateway::app(gateway)
        .layer(axum::middleware::from_fn_with_state(requests, record_wake))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use xchonnect_relay::store::{Notifier, memory::MemoryStore};

    fn rec() -> MailboxRecord {
        MailboxRecord {
            read_hash: [1; 32],
            write_hash: [2; 32],
            push: Some(PushReg {
                gateway_url: "https://push.example/v1/wake".into(),
                sealed_token: vec![9; 48],
            }),
            customer: Some("acme".into()),
            created_day: 1,
            last_used_day: 1,
        }
    }

    #[tokio::test]
    async fn the_transcript_holds_every_written_value() {
        let transcript = shared("database");
        let inner = Arc::new(MemoryStore::new(Notifier::default()));
        let store = RecordingStore::new(inner, transcript.clone());
        let id = MailboxId([3; 16]);
        store.create(id, rec()).await.unwrap();
        let msg = StoredMessage {
            msg_id: [4; 16],
            envelope: vec![5; 64],
        };
        let limits = QueueLimits {
            max_messages: 8,
            max_bytes: 4096,
        };
        store.enqueue(&id, msg, 10, 20, limits).await.unwrap();
        store.put_ticket([6; 32], "acme", 30).await.unwrap();
        let text = snapshot(&transcript).text;
        for needle in [
            &id.to_b64(),
            &b64::encode(&[1_u8; 32]),
            &b64::encode(&[9_u8; 48]),
            &b64::encode(&[4_u8; 16]),
            &b64::encode(&[5_u8; 64]),
            &"acme".to_owned(),
            &"https://push.example/v1/wake".to_owned(),
        ] {
            assert!(text.contains(needle.as_str()), "missing {needle} in {text}");
        }
        // Raw bytes are recorded too, so a dump that is not base64 is covered.
        assert!(
            snapshot(&transcript)
                .bytes
                .windows(16)
                .any(|w| w == [3_u8; 16])
        );
    }
}
