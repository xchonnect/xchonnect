//! Postgres backend (TASK-28). Long-polls on other relay nodes are woken through
//! `LISTEN/NOTIFY`. Errors are mapped to static descriptions so database messages
//! (which may quote parameter values such as mailbox ids) never reach logs.
//!
//! Operators: disable statement and parameter logging on the database server
//! (`log_statement = none`, `log_min_duration_statement = -1`), since bound parameters
//! include mailbox ids and token hashes.

use super::{
    MailboxRecord, MailboxStore, Notifier, PushReg, QueueLimits, StoreError, StoredMessage,
    SweepStats,
};
use async_trait::async_trait;
use sqlx::Row;
use sqlx::postgres::{PgListener, PgPool, PgPoolOptions};
use xchonnect_core::crypto::MailboxId;

const CHANNEL: &str = "xchonnect_mailbox";

/// Postgres-backed store.
#[derive(Debug, Clone)]
pub struct PostgresStore {
    pool: PgPool,
}

fn be(_: sqlx::Error) -> StoreError {
    StoreError::Backend("database error")
}

fn day_i32(d: u32) -> i32 {
    i32::try_from(d).unwrap_or(i32::MAX)
}

fn i64_of(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

impl PostgresStore {
    /// Connect, run migrations and start the notification listener feeding `notifier`.
    pub async fn connect(url: &str, notifier: Notifier) -> Result<Self, String> {
        let pool = PgPoolOptions::new()
            .max_connections(16)
            .connect(url)
            .await
            .map_err(|_| "cannot connect to database".to_owned())?;
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(|e| format!("migration failed: {e}"))?;
        let mut listener = PgListener::connect_with(&pool)
            .await
            .map_err(|_| "cannot open LISTEN connection".to_owned())?;
        listener
            .listen(CHANNEL)
            .await
            .map_err(|_| "LISTEN failed".to_owned())?;
        tokio::spawn(async move {
            loop {
                match listener.recv().await {
                    Ok(n) => {
                        if let Ok(id) = MailboxId::from_b64(n.payload()) {
                            notifier.notify(&id);
                        }
                    }
                    Err(_) => {
                        tracing::warn!("notification listener error; reconnecting");
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
        });
        Ok(PostgresStore { pool })
    }

    /// The underlying pool (tests, health checks).
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[async_trait]
impl MailboxStore for PostgresStore {
    async fn create(&self, id: MailboxId, rec: MailboxRecord) -> Result<(), StoreError> {
        sqlx::query("INSERT INTO mailboxes (id, read_hash, write_hash, push_url, push_token, customer, created_day, last_used_day) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(&id.0[..])
            .bind(&rec.read_hash[..])
            .bind(&rec.write_hash[..])
            .bind(rec.push.as_ref().map(|p| p.gateway_url.clone()))
            .bind(rec.push.as_ref().map(|p| p.sealed_token.clone()))
            .bind(rec.customer)
            .bind(day_i32(rec.created_day))
            .bind(day_i32(rec.last_used_day))
            .execute(&self.pool)
            .await
            .map_err(|_| StoreError::Backend("mailbox insert failed"))?;
        Ok(())
    }

    async fn get(&self, id: &MailboxId) -> Result<Option<MailboxRecord>, StoreError> {
        let row = sqlx::query("SELECT read_hash, write_hash, push_url, push_token, customer, created_day, last_used_day FROM mailboxes WHERE id = $1")
            .bind(&id.0[..])
            .fetch_optional(&self.pool)
            .await
            .map_err(be)?;
        let Some(r) = row else { return Ok(None) };
        let arr = |b: Vec<u8>| -> Result<[u8; 32], StoreError> {
            b.try_into()
                .map_err(|_| StoreError::Backend("corrupt hash"))
        };
        let push = match (
            r.try_get::<Option<String>, _>("push_url").map_err(be)?,
            r.try_get::<Option<Vec<u8>>, _>("push_token").map_err(be)?,
        ) {
            (Some(gateway_url), Some(sealed_token)) => Some(PushReg {
                gateway_url,
                sealed_token,
            }),
            _ => None,
        };
        Ok(Some(MailboxRecord {
            read_hash: arr(r.try_get("read_hash").map_err(be)?)?,
            write_hash: arr(r.try_get("write_hash").map_err(be)?)?,
            push,
            customer: r.try_get("customer").map_err(be)?,
            created_day: u32::try_from(r.try_get::<i32, _>("created_day").map_err(be)?)
                .unwrap_or(0),
            last_used_day: u32::try_from(r.try_get::<i32, _>("last_used_day").map_err(be)?)
                .unwrap_or(0),
        }))
    }

    async fn touch(&self, id: &MailboxId, day: u32) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE mailboxes SET last_used_day = GREATEST(last_used_day, $2) WHERE id = $1",
        )
        .bind(&id.0[..])
        .bind(day_i32(day))
        .execute(&self.pool)
        .await
        .map_err(be)?;
        Ok(())
    }

    async fn delete(&self, id: &MailboxId) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM mailboxes WHERE id = $1")
            .bind(&id.0[..])
            .execute(&self.pool)
            .await
            .map_err(be)?;
        Ok(())
    }

    async fn set_push(&self, id: &MailboxId, push: Option<PushReg>) -> Result<(), StoreError> {
        let res = sqlx::query("UPDATE mailboxes SET push_url = $2, push_token = $3 WHERE id = $1")
            .bind(&id.0[..])
            .bind(push.as_ref().map(|p| p.gateway_url.clone()))
            .bind(push.map(|p| p.sealed_token))
            .execute(&self.pool)
            .await
            .map_err(be)?;
        if res.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn enqueue(
        &self,
        id: &MailboxId,
        msg: StoredMessage,
        expires_at: u64,
        limits: QueueLimits,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(be)?;
        // Lock the mailbox row so concurrent posts cannot exceed the quota.
        let exists = sqlx::query("SELECT 1 FROM mailboxes WHERE id = $1 FOR UPDATE")
            .bind(&id.0[..])
            .fetch_optional(&mut *tx)
            .await
            .map_err(be)?;
        if exists.is_none() {
            return Err(StoreError::NotFound);
        }
        let q = sqlx::query("SELECT COUNT(*) AS n, COALESCE(SUM(LENGTH(envelope)), 0)::BIGINT AS bytes FROM messages WHERE mailbox_id = $1")
            .bind(&id.0[..])
            .fetch_one(&mut *tx)
            .await
            .map_err(be)?;
        let n: i64 = q.try_get("n").map_err(be)?;
        let bytes: i64 = q.try_get("bytes").map_err(be)?;
        let new_bytes = bytes.saturating_add(i64::try_from(msg.envelope.len()).unwrap_or(i64::MAX));
        if usize::try_from(n).unwrap_or(usize::MAX) >= limits.max_messages
            || usize::try_from(new_bytes).unwrap_or(usize::MAX) > limits.max_bytes
        {
            return Err(StoreError::MailboxFull);
        }
        sqlx::query(
            "INSERT INTO messages (mailbox_id, msg_id, envelope, expires_at) VALUES ($1,$2,$3,$4)",
        )
        .bind(&id.0[..])
        .bind(&msg.msg_id[..])
        .bind(&msg.envelope)
        .bind(i64_of(expires_at))
        .execute(&mut *tx)
        .await
        .map_err(be)?;
        sqlx::query("SELECT pg_notify($1, $2)")
            .bind(CHANNEL)
            .bind(id.to_b64())
            .execute(&mut *tx)
            .await
            .map_err(be)?;
        tx.commit().await.map_err(be)?;
        Ok(())
    }

    async fn fetch(
        &self,
        id: &MailboxId,
        limit: usize,
        now: u64,
    ) -> Result<Vec<StoredMessage>, StoreError> {
        if self.get(id).await?.is_none() {
            return Err(StoreError::NotFound);
        }
        let rows = sqlx::query("SELECT msg_id, envelope FROM messages WHERE mailbox_id = $1 AND expires_at >= $2 ORDER BY seq LIMIT $3")
            .bind(&id.0[..])
            .bind(i64_of(now))
            .bind(i64::try_from(limit).unwrap_or(i64::MAX))
            .fetch_all(&self.pool)
            .await
            .map_err(be)?;
        rows.into_iter()
            .map(|r| {
                let msg_id: Vec<u8> = r.try_get("msg_id").map_err(be)?;
                Ok(StoredMessage {
                    msg_id: msg_id
                        .try_into()
                        .map_err(|_| StoreError::Backend("corrupt msg id"))?,
                    envelope: r.try_get("envelope").map_err(be)?,
                })
            })
            .collect()
    }

    async fn ack(&self, id: &MailboxId, msg_ids: &[[u8; 16]]) -> Result<(), StoreError> {
        if self.get(id).await?.is_none() {
            return Err(StoreError::NotFound);
        }
        let ids: Vec<Vec<u8>> = msg_ids.iter().map(|m| m.to_vec()).collect();
        sqlx::query("DELETE FROM messages WHERE mailbox_id = $1 AND msg_id = ANY($2)")
            .bind(&id.0[..])
            .bind(&ids)
            .execute(&self.pool)
            .await
            .map_err(be)?;
        Ok(())
    }

    async fn sweep(&self, now: u64, inactive_before_day: u32) -> Result<SweepStats, StoreError> {
        let mailboxes = sqlx::query("DELETE FROM mailboxes WHERE last_used_day < $1")
            .bind(day_i32(inactive_before_day))
            .execute(&self.pool)
            .await
            .map_err(be)?
            .rows_affected();
        let messages = sqlx::query("DELETE FROM messages WHERE expires_at < $1")
            .bind(i64_of(now))
            .execute(&self.pool)
            .await
            .map_err(be)?
            .rows_affected();
        sqlx::query("DELETE FROM tickets WHERE expires_at < $1")
            .bind(i64_of(now))
            .execute(&self.pool)
            .await
            .map_err(be)?;
        Ok(SweepStats {
            messages,
            mailboxes,
        })
    }

    async fn mailbox_count(&self) -> Result<u64, StoreError> {
        let n: i64 = sqlx::query("SELECT COUNT(*) AS n FROM mailboxes")
            .fetch_one(&self.pool)
            .await
            .map_err(be)?
            .try_get("n")
            .map_err(be)?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    async fn put_ticket(
        &self,
        ticket_hash: [u8; 32],
        customer: &str,
        expires_at: u64,
    ) -> Result<(), StoreError> {
        sqlx::query("INSERT INTO tickets (hash, customer, expires_at) VALUES ($1,$2,$3)")
            .bind(&ticket_hash[..])
            .bind(customer)
            .bind(i64_of(expires_at))
            .execute(&self.pool)
            .await
            .map_err(be)?;
        Ok(())
    }

    async fn take_ticket(
        &self,
        ticket_hash: &[u8; 32],
        now: u64,
    ) -> Result<Option<String>, StoreError> {
        let row = sqlx::query("DELETE FROM tickets WHERE hash = $1 RETURNING customer, expires_at")
            .bind(&ticket_hash[..])
            .fetch_optional(&self.pool)
            .await
            .map_err(be)?;
        let Some(r) = row else { return Ok(None) };
        let exp: i64 = r.try_get("expires_at").map_err(be)?;
        if exp < i64_of(now) {
            return Ok(None);
        }
        Ok(Some(r.try_get("customer").map_err(be)?))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Set `XCHONNECT_TEST_DATABASE_URL` to an empty, disposable database to run these.
    async fn fresh() -> Option<(PostgresStore, Notifier)> {
        let url = std::env::var("XCHONNECT_TEST_DATABASE_URL").ok()?;
        let pool = PgPoolOptions::new().connect(&url).await.unwrap();
        sqlx::query("DROP TABLE IF EXISTS messages, tickets, mailboxes, _sqlx_migrations")
            .execute(&pool)
            .await
            .unwrap();
        let n = Notifier::default();
        Some((PostgresStore::connect(&url, n.clone()).await.unwrap(), n))
    }

    #[tokio::test]
    async fn postgres_backend() {
        let Some((store, _)) = fresh().await else {
            eprintln!("skipped: XCHONNECT_TEST_DATABASE_URL not set");
            return;
        };
        crate::store::suite::run(&store).await;

        // Cross-node long-poll: a second instance (other node) wakes on enqueue.
        let url = std::env::var("XCHONNECT_TEST_DATABASE_URL").unwrap();
        let notifier_b = Notifier::default();
        let _node_b = PostgresStore::connect(&url, notifier_b.clone())
            .await
            .unwrap();
        let id = MailboxId([0xcc; 16]);
        store
            .create(
                id,
                MailboxRecord {
                    read_hash: [1; 32],
                    write_hash: [2; 32],
                    push: None,
                    customer: None,
                    created_day: 1,
                    last_used_day: 1,
                },
            )
            .await
            .unwrap();
        let rx = notifier_b.subscribe(&id);
        let t = std::time::Instant::now();
        let store2 = store.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            store2
                .enqueue(
                    &id,
                    StoredMessage {
                        msg_id: [1; 16],
                        envelope: vec![0; 10],
                    },
                    u64::MAX / 4,
                    QueueLimits {
                        max_messages: 10,
                        max_bytes: 1000,
                    },
                )
                .await
                .unwrap();
        });
        crate::store::wait(rx, Duration::from_secs(5)).await;
        assert!(
            t.elapsed() < Duration::from_secs(3),
            "node B was woken by node A's enqueue"
        );

        // Data inventory: exactly the expected columns and types.
        let cols = sqlx::query("SELECT table_name, column_name, data_type FROM information_schema.columns WHERE table_schema = 'public' AND table_name IN ('mailboxes','messages','tickets') ORDER BY table_name, ordinal_position")
            .fetch_all(store.pool())
            .await
            .unwrap();
        let got: Vec<String> = cols
            .iter()
            .map(|r| {
                format!(
                    "{}.{}:{}",
                    r.get::<String, _>("table_name"),
                    r.get::<String, _>("column_name"),
                    r.get::<String, _>("data_type")
                )
            })
            .collect();
        assert_eq!(
            got,
            [
                "mailboxes.id:bytea",
                "mailboxes.read_hash:bytea",
                "mailboxes.write_hash:bytea",
                "mailboxes.push_url:text",
                "mailboxes.push_token:bytea",
                "mailboxes.customer:text",
                "mailboxes.created_day:integer",
                "mailboxes.last_used_day:integer",
                "messages.seq:bigint",
                "messages.mailbox_id:bytea",
                "messages.msg_id:bytea",
                "messages.envelope:bytea",
                "messages.expires_at:bigint",
                "tickets.hash:bytea",
                "tickets.customer:text",
                "tickets.expires_at:bigint",
            ]
        );
    }
}
