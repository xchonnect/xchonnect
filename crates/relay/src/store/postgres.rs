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
use sqlx::postgres::{PgArguments, PgListener, PgPool, PgPoolOptions};
use sqlx::query::Query;
use sqlx::{Postgres, Row};
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

    /// Execute a statement on the pool; returns the number of affected rows.
    async fn exec(&self, q: Query<'_, Postgres, PgArguments>) -> Result<u64, StoreError> {
        Ok(q.execute(&self.pool).await.map_err(be)?.rows_affected())
    }

    async fn ensure_exists(&self, id: &MailboxId) -> Result<(), StoreError> {
        self.get(id).await?.map(|_| ()).ok_or(StoreError::NotFound)
    }
}

#[async_trait]
impl MailboxStore for PostgresStore {
    async fn create(&self, id: MailboxId, rec: MailboxRecord) -> Result<(), StoreError> {
        let (url, token) = rec.push.map(|p| (p.gateway_url, p.sealed_token)).unzip();
        sqlx::query("INSERT INTO mailboxes (id, read_hash, write_hash, push_url, push_token, customer, created_day, last_used_day) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(&id.0[..])
            .bind(&rec.read_hash[..])
            .bind(&rec.write_hash[..])
            .bind(url)
            .bind(token)
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
        let hash = |col: &str| -> Result<[u8; 32], StoreError> {
            let b: Vec<u8> = r.try_get(col).map_err(be)?;
            b.try_into()
                .map_err(|_| StoreError::Backend("corrupt hash"))
        };
        let day = |col: &str| -> Result<u32, StoreError> {
            Ok(u32::try_from(r.try_get::<i32, _>(col).map_err(be)?).unwrap_or(0))
        };
        let url: Option<String> = r.try_get("push_url").map_err(be)?;
        let token: Option<Vec<u8>> = r.try_get("push_token").map_err(be)?;
        let push = url.zip(token).map(|(gateway_url, sealed_token)| PushReg {
            gateway_url,
            sealed_token,
        });
        Ok(Some(MailboxRecord {
            read_hash: hash("read_hash")?,
            write_hash: hash("write_hash")?,
            push,
            customer: r.try_get("customer").map_err(be)?,
            created_day: day("created_day")?,
            last_used_day: day("last_used_day")?,
        }))
    }

    async fn touch(&self, id: &MailboxId, day: u32) -> Result<(), StoreError> {
        let q = "UPDATE mailboxes SET last_used_day = GREATEST(last_used_day, $2) WHERE id = $1";
        self.exec(sqlx::query(q).bind(&id.0[..]).bind(day_i32(day)))
            .await?;
        Ok(())
    }

    async fn delete(&self, id: &MailboxId) -> Result<(), StoreError> {
        let q = sqlx::query("DELETE FROM mailboxes WHERE id = $1").bind(&id.0[..]);
        self.exec(q).await?;
        Ok(())
    }

    async fn set_push(&self, id: &MailboxId, push: Option<PushReg>) -> Result<(), StoreError> {
        let (url, token) = push.map(|p| (p.gateway_url, p.sealed_token)).unzip();
        let q = sqlx::query("UPDATE mailboxes SET push_url = $2, push_token = $3 WHERE id = $1")
            .bind(&id.0[..])
            .bind(url)
            .bind(token);
        if self.exec(q).await? == 0 {
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
        self.ensure_exists(id).await?;
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
        self.ensure_exists(id).await?;
        let ids: Vec<Vec<u8>> = msg_ids.iter().map(|m| m.to_vec()).collect();
        let q = sqlx::query("DELETE FROM messages WHERE mailbox_id = $1 AND msg_id = ANY($2)");
        self.exec(q.bind(&id.0[..]).bind(&ids)).await?;
        Ok(())
    }

    async fn sweep(&self, now: u64, inactive_before_day: u32) -> Result<SweepStats, StoreError> {
        let q = sqlx::query("DELETE FROM mailboxes WHERE last_used_day < $1");
        let mailboxes = self.exec(q.bind(day_i32(inactive_before_day))).await?;
        let mut expired = [0; 3];
        for (q, n) in [
            "DELETE FROM messages WHERE expires_at < $1",
            "DELETE FROM pow_spent WHERE expires_at < $1",
            "DELETE FROM tickets WHERE expires_at < $1",
        ]
        .into_iter()
        .zip(&mut expired)
        {
            *n = self.exec(sqlx::query(q).bind(i64_of(now))).await?;
        }
        Ok(SweepStats {
            messages: expired[0],
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
        let q = sqlx::query("INSERT INTO tickets (hash, customer, expires_at) VALUES ($1,$2,$3)");
        let q = q.bind(&ticket_hash[..]).bind(customer);
        self.exec(q.bind(i64_of(expires_at))).await?;
        Ok(())
    }

    async fn spend_pow(&self, key: [u8; 32], expires_at: u64) -> Result<bool, StoreError> {
        let q = "INSERT INTO pow_spent (hash, expires_at) VALUES ($1, $2) ON CONFLICT DO NOTHING";
        let q = sqlx::query(q).bind(&key[..]).bind(i64_of(expires_at));
        Ok(self.exec(q).await? == 1)
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
    use crate::store::suite::{LIM, msg, rec};
    use std::time::Duration;

    #[tokio::test]
    async fn postgres_backend() {
        // Set `XCHONNECT_TEST_DATABASE_URL` to an empty, disposable database to run this.
        let Ok(url) = std::env::var("XCHONNECT_TEST_DATABASE_URL") else {
            eprintln!("skipped: XCHONNECT_TEST_DATABASE_URL not set");
            return;
        };
        let pool = PgPoolOptions::new().connect(&url).await.unwrap();
        let drop = "DROP TABLE IF EXISTS messages, tickets, pow_spent, mailboxes, _sqlx_migrations";
        sqlx::query(drop).execute(&pool).await.unwrap();
        let store = PostgresStore::connect(&url, Notifier::default())
            .await
            .unwrap();
        crate::store::suite::run(&store).await;

        // Cross-node long-poll: a second instance (other node) wakes on enqueue.
        let notifier_b = Notifier::default();
        let _node_b = PostgresStore::connect(&url, notifier_b.clone())
            .await
            .unwrap();
        let id = MailboxId([0xcc; 16]);
        store.create(id, rec(1)).await.unwrap();
        let rx = notifier_b.subscribe(&id);
        let t = std::time::Instant::now();
        let store2 = store.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            store2
                .enqueue(&id, msg(1, 10), u64::MAX / 4, LIM)
                .await
                .unwrap();
        });
        crate::store::wait(rx, Duration::from_secs(5)).await;
        let woken = t.elapsed() < Duration::from_secs(3);
        assert!(woken, "node B was woken by node A's enqueue");

        // Data inventory: exactly the expected columns and types.
        let cols = sqlx::query("SELECT table_name, column_name, data_type FROM information_schema.columns WHERE table_schema = 'public' AND table_name IN ('mailboxes','messages','tickets','pow_spent') ORDER BY table_name, ordinal_position")
            .fetch_all(store.pool())
            .await
            .unwrap();
        let col = |r: &sqlx::postgres::PgRow, c: &str| r.get::<String, _>(c);
        let got: Vec<String> = cols
            .iter()
            .map(|r| {
                format!(
                    "{}.{}:{}",
                    col(r, "table_name"),
                    col(r, "column_name"),
                    col(r, "data_type")
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
                "pow_spent.hash:bytea",
                "pow_spent.expires_at:bigint",
                "tickets.hash:bytea",
                "tickets.customer:text",
                "tickets.expires_at:bigint",
            ]
        );
    }
}
