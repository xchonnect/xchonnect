//! In-memory store for development, tests and small self-hosted relays.
//! All data is lost on restart.

use super::{
    MailboxRecord, MailboxStore, Notifier, PushReg, QueueLimits, StoreError, StoredMessage,
    SweepStats,
};
use async_trait::async_trait;
use std::collections::{HashMap, VecDeque};
use tokio::sync::Mutex;
use xchonnect_core::crypto::MailboxId;

#[derive(Debug)]
struct Entry {
    rec: MailboxRecord,
    queue: VecDeque<(StoredMessage, u64)>,
    bytes: usize,
}

/// In-memory backend.
#[derive(Debug)]
pub struct MemoryStore {
    map: Mutex<HashMap<MailboxId, Entry>>,
    tickets: Mutex<HashMap<[u8; 32], (String, u64)>>,
    notifier: Notifier,
}

impl MemoryStore {
    /// Create an empty store that signals `notifier` on enqueue.
    pub fn new(notifier: Notifier) -> Self {
        MemoryStore {
            map: Mutex::new(HashMap::new()),
            tickets: Mutex::new(HashMap::new()),
            notifier,
        }
    }
}

#[async_trait]
impl MailboxStore for MemoryStore {
    async fn create(&self, id: MailboxId, rec: MailboxRecord) -> Result<(), StoreError> {
        let mut m = self.map.lock().await;
        if m.contains_key(&id) {
            return Err(StoreError::Backend("mailbox id collision"));
        }
        m.insert(
            id,
            Entry {
                rec,
                queue: VecDeque::new(),
                bytes: 0,
            },
        );
        Ok(())
    }

    async fn get(&self, id: &MailboxId) -> Result<Option<MailboxRecord>, StoreError> {
        Ok(self.map.lock().await.get(id).map(|e| e.rec.clone()))
    }

    async fn touch(&self, id: &MailboxId, day: u32) -> Result<(), StoreError> {
        let mut m = self.map.lock().await;
        let e = m.get_mut(id).ok_or(StoreError::NotFound)?;
        e.rec.last_used_day = e.rec.last_used_day.max(day);
        Ok(())
    }

    async fn delete(&self, id: &MailboxId) -> Result<(), StoreError> {
        self.map.lock().await.remove(id);
        Ok(())
    }

    async fn set_push(&self, id: &MailboxId, push: Option<PushReg>) -> Result<(), StoreError> {
        let mut m = self.map.lock().await;
        m.get_mut(id).ok_or(StoreError::NotFound)?.rec.push = push;
        Ok(())
    }

    async fn enqueue(
        &self,
        id: &MailboxId,
        msg: StoredMessage,
        expires_at: u64,
        limits: QueueLimits,
    ) -> Result<(), StoreError> {
        {
            let mut m = self.map.lock().await;
            let e = m.get_mut(id).ok_or(StoreError::NotFound)?;
            if e.queue.len() >= limits.max_messages
                || e.bytes + msg.envelope.len() > limits.max_bytes
            {
                return Err(StoreError::MailboxFull);
            }
            e.bytes += msg.envelope.len();
            e.queue.push_back((msg, expires_at));
        }
        self.notifier.notify(id);
        Ok(())
    }

    async fn fetch(
        &self,
        id: &MailboxId,
        limit: usize,
        now: u64,
    ) -> Result<Vec<StoredMessage>, StoreError> {
        let m = self.map.lock().await;
        let e = m.get(id).ok_or(StoreError::NotFound)?;
        Ok(e.queue
            .iter()
            .filter(|(_, exp)| *exp >= now)
            .take(limit)
            .map(|(msg, _)| msg.clone())
            .collect())
    }

    async fn ack(&self, id: &MailboxId, msg_ids: &[[u8; 16]]) -> Result<(), StoreError> {
        let mut m = self.map.lock().await;
        let e = m.get_mut(id).ok_or(StoreError::NotFound)?;
        let mut freed = 0;
        e.queue.retain(|(msg, _)| {
            let drop = msg_ids.contains(&msg.msg_id);
            if drop {
                freed += msg.envelope.len();
            }
            !drop
        });
        e.bytes -= freed;
        Ok(())
    }

    async fn sweep(&self, now: u64, inactive_before_day: u32) -> Result<SweepStats, StoreError> {
        let mut m = self.map.lock().await;
        let mut st = SweepStats::default();
        let before = m.len();
        m.retain(|_, e| e.rec.last_used_day >= inactive_before_day);
        st.mailboxes = (before - m.len()) as u64;
        for e in m.values_mut() {
            let n = e.queue.len();
            let mut freed = 0;
            e.queue.retain(|(msg, exp)| {
                let keep = *exp >= now;
                if !keep {
                    freed += msg.envelope.len();
                }
                keep
            });
            e.bytes -= freed;
            st.messages += (n - e.queue.len()) as u64;
        }
        Ok(st)
    }

    async fn mailbox_count(&self) -> Result<u64, StoreError> {
        Ok(self.map.lock().await.len() as u64)
    }

    async fn put_ticket(
        &self,
        ticket_hash: [u8; 32],
        customer: &str,
        expires_at: u64,
    ) -> Result<(), StoreError> {
        let mut t = self.tickets.lock().await;
        t.retain(|_, (_, exp)| *exp >= expires_at.saturating_sub(3600));
        t.insert(ticket_hash, (customer.to_owned(), expires_at));
        Ok(())
    }

    async fn take_ticket(
        &self,
        ticket_hash: &[u8; 32],
        now: u64,
    ) -> Result<Option<String>, StoreError> {
        Ok(self
            .tickets
            .lock()
            .await
            .remove(ticket_hash)
            .filter(|(_, exp)| *exp >= now)
            .map(|(c, _)| c))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn passes_suite() {
        let s = MemoryStore::new(Notifier::default());
        crate::store::suite::run(&s).await;
    }
}
