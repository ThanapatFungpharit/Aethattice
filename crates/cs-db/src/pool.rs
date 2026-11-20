//! Per-domain connection pools and transactions (contract §5, spec §18.1–§18.2).
//!
//! A [`DomainPool`] is bound to exactly one domain and owns its own connection pool built
//! from that domain's configuration, even when several domains point at the same cluster.
//! A transaction is opened only through [`DomainPool::transaction`], which hands the closure a
//! [`DomainTx`] for that one pool: there is no API that can see two domains in one
//! transaction.
//!
//! Transactions run at READ COMMITTED. SQLSTATE 40001 / 40P01 roll back and re-run the whole
//! closure with exponential backoff and full jitter, bounded by attempts and elapsed time.
//! The closure is therefore `Fn` (re-runnable) and must be idempotent; it receives only the
//! transaction handle (no network calls inside transactions, §18.2).
//!
//! Retry budget (contract §5 rev 4): the elapsed-time bound counts only transaction attempts
//! (BEGIN through COMMIT/ROLLBACK) and backoff sleeps. Connection acquisition is excluded; it
//! is bounded separately by the pool's `acquire_timeout_ms`. The migration runner uses its own
//! budget ([`RetryPolicy::migrations_default`], 30 attempts or 120 s).

use crate::error::DbError;
use cs_common::config::{DomainConfig, Policy, PolicyKey};
use cs_common::vector::DomainId;
use futures::future::BoxFuture;
use sqlx::pool::PoolConnection;
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use sqlx::{Connection as _, PgConnection, Postgres};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Bounded retry policy for conflicting transactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub max_elapsed: Duration,
    pub base_delay: Duration,
    pub max_delay: Duration,
}

impl Default for RetryPolicy {
    /// Contract §5 defaults: 10 attempts or 5 s.
    fn default() -> Self {
        Self {
            max_attempts: 10,
            max_elapsed: Duration::from_secs(5),
            base_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(1000),
        }
    }
}

impl RetryPolicy {
    /// Migration-runner defaults (contract §5 rev 4): 30 attempts or 120 s. Concurrent DDL on
    /// YugabyteDB can stall far longer than ordinary transactions.
    pub fn migrations_default() -> Self {
        Self {
            max_attempts: 30,
            max_elapsed: Duration::from_secs(120),
            base_delay: Duration::from_millis(50),
            max_delay: Duration::from_secs(5),
        }
    }

    /// Migration budget from validated policy values.
    pub fn migrations_from_policy(p: &Policy) -> Self {
        Self {
            max_attempts: u32::try_from(p.get(PolicyKey::DbMigrationRetryMaxAttempts))
                .unwrap_or(30),
            max_elapsed: Duration::from_millis(
                u64::try_from(p.get(PolicyKey::DbMigrationRetryMaxElapsedMs)).unwrap_or(120_000),
            ),
            ..Self::migrations_default()
        }
    }

    /// Transaction budget from validated policy values.
    pub fn from_policy(p: &Policy) -> Self {
        Self {
            max_attempts: u32::try_from(p.get(PolicyKey::DbRetryMaxAttempts)).unwrap_or(10),
            max_elapsed: Duration::from_millis(
                u64::try_from(p.get(PolicyKey::DbRetryMaxElapsedMs)).unwrap_or(5000),
            ),
            ..Self::default()
        }
    }

    /// Full-jitter exponential backoff for the given (1-based) attempt that just failed.
    pub fn backoff(&self, attempt: u32) -> Result<Duration, DbError> {
        let exp = self
            .base_delay
            .saturating_mul(
                1u32.checked_shl(attempt.saturating_sub(1).min(20))
                    .unwrap_or(u32::MAX),
            )
            .min(self.max_delay);
        let ms = u64::try_from(exp.as_millis()).unwrap_or(u64::MAX);
        Ok(Duration::from_millis(cs_crypto::rand::u64_inclusive(ms)?))
    }
}

/// Isolation levels offered. There is deliberately no SERIALIZABLE (§18.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Isolation {
    ReadCommitted,
    /// Read-only snapshot for journal reads (§19.2).
    RepeatableReadReadOnly,
}

impl Isolation {
    fn begin_sql(self) -> &'static str {
        match self {
            Isolation::ReadCommitted => "BEGIN ISOLATION LEVEL READ COMMITTED",
            Isolation::RepeatableReadReadOnly => "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY",
        }
    }
}

struct Inner {
    domain: DomainId,
    pool: PgPool,
    retry: RetryPolicy,
    migration_retry: RetryPolicy,
}

/// A connection pool bound to exactly one domain.
#[derive(Clone)]
pub struct DomainPool {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for DomainPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DomainPool")
            .field("domain", &self.inner.domain)
            .finish_non_exhaustive()
    }
}

/// A transaction on one domain. Obtained only from [`DomainPool::transaction`].
///
/// Owns the pooled connection and issues BEGIN / COMMIT / ROLLBACK itself, so that connection
/// acquisition can be kept out of the retry budget. If it is dropped while still open (e.g. a
/// cancelled future), the connection is closed instead of being returned to the pool.
pub struct DomainTx {
    domain: DomainId,
    conn: PoolConnection<Postgres>,
    open: bool,
}

impl Drop for DomainTx {
    fn drop(&mut self) {
        if self.open {
            self.conn.close_on_drop();
        }
    }
}

impl std::fmt::Debug for DomainTx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DomainTx")
            .field("domain", &self.domain)
            .finish_non_exhaustive()
    }
}

impl DomainTx {
    /// The domain this transaction belongs to.
    pub fn domain(&self) -> &DomainId {
        &self.domain
    }

    /// The underlying connection, for executing queries inside the transaction.
    pub fn conn(&mut self) -> &mut PgConnection {
        &mut self.conn
    }

    async fn commit(&mut self) -> Result<(), sqlx::Error> {
        let r = sqlx::raw_sql("COMMIT").execute(&mut *self.conn).await;
        // Whatever happened, the transaction is no longer usable on this connection; on error
        // the connection is closed by Drop (state unknown).
        if r.is_ok() {
            self.open = false;
        }
        r.map(|_| ())
    }

    async fn rollback(&mut self) {
        if sqlx::raw_sql("ROLLBACK")
            .execute(&mut *self.conn)
            .await
            .is_ok()
        {
            self.open = false;
        }
    }
}

/// The closure type accepted by [`DomainPool::transaction`].
pub type TxFuture<'c, T> = BoxFuture<'c, Result<T, DbError>>;

impl DomainPool {
    /// Create a pool for `domain` from its own configuration. Connections are opened lazily,
    /// so an unreachable domain does not prevent startup; readiness reports it.
    pub fn connect_lazy(
        domain: DomainId,
        cfg: &DomainConfig,
        retry: RetryPolicy,
    ) -> Result<Self, DbError> {
        let opts = PgConnectOptions::from_str(cfg.url.expose_secret())
            .map_err(|_| DbError::Invalid(format!("invalid connection URL for domain {domain}")))?
            .options([(
                "statement_timeout",
                cfg.pool.statement_timeout_ms.to_string(),
            )])
            .application_name(&format!("cs/{domain}"));
        Ok(Self::from_options(domain, opts, cfg, retry))
    }

    fn from_options(
        domain: DomainId,
        opts: PgConnectOptions,
        cfg: &DomainConfig,
        retry: RetryPolicy,
    ) -> Self {
        let pool = PgPoolOptions::new()
            .max_connections(cfg.pool.max_connections)
            .min_connections(cfg.pool.min_connections)
            .acquire_timeout(Duration::from_millis(cfg.pool.acquire_timeout_ms))
            .idle_timeout(Duration::from_millis(cfg.pool.idle_timeout_ms))
            .connect_lazy_with(opts);
        Self {
            inner: Arc::new(Inner {
                domain,
                pool,
                retry,
                migration_retry: RetryPolicy::migrations_default(),
            }),
        }
    }

    /// Test harness constructor (explicit connect options instead of a URL).
    #[cfg(feature = "testing")]
    pub(crate) fn from_options_for_tests(
        domain: DomainId,
        opts: PgConnectOptions,
        cfg: &DomainConfig,
        retry: RetryPolicy,
    ) -> Self {
        let opts = opts
            .options([(
                "statement_timeout",
                cfg.pool.statement_timeout_ms.to_string(),
            )])
            .application_name(&format!("cs-test/{domain}"));
        Self::from_options(domain, opts, cfg, retry)
    }

    pub fn domain(&self) -> &DomainId {
        &self.inner.domain
    }

    pub fn retry_policy(&self) -> RetryPolicy {
        self.inner.retry
    }

    /// Budget of the migration runner on this domain (separate from transactions).
    pub fn migration_retry_policy(&self) -> RetryPolicy {
        self.inner.migration_retry
    }

    /// Replace the migration budget (configured from `[policy]`).
    pub fn with_migration_retry(self, policy: RetryPolicy) -> Self {
        let inner = &self.inner;
        Self {
            inner: Arc::new(Inner {
                domain: inner.domain.clone(),
                pool: inner.pool.clone(),
                retry: inner.retry,
                migration_retry: policy,
            }),
        }
    }

    /// Acquire a pooled connection (bounded by the pool's acquire timeout, not by any retry
    /// budget).
    pub(crate) async fn acquire(&self) -> Result<PoolConnection<Postgres>, DbError> {
        Ok(self.inner.pool.acquire().await?)
    }

    /// Check that the domain is reachable.
    pub async fn ping(&self) -> Result<(), DbError> {
        let mut c = self.inner.pool.acquire().await?;
        c.ping().await?;
        Ok(())
    }

    /// Close every connection.
    pub async fn close(&self) {
        self.inner.pool.close().await;
    }

    /// Pool for crate-internal non-transactional statements (migration runner DDL, reads).
    pub(crate) fn raw(&self) -> &PgPool {
        &self.inner.pool
    }

    /// Run `f` in a READ COMMITTED transaction on this domain, retrying the whole closure on
    /// 40001 / 40P01. Business errors (`DbError::App`) and other failures are not retried.
    /// A connection failure during COMMIT yields [`DbError::OutcomeUnknown`].
    pub async fn transaction<T, F>(&self, f: F) -> Result<T, DbError>
    where
        T: Send,
        F: for<'c> Fn(&'c mut DomainTx) -> TxFuture<'c, T> + Send + Sync,
    {
        self.run(Isolation::ReadCommitted, f).await
    }

    /// REPEATABLE READ, READ ONLY snapshot. For journal reads only (§19.2); writes fail.
    pub async fn read_snapshot<T, F>(&self, f: F) -> Result<T, DbError>
    where
        T: Send,
        F: for<'c> Fn(&'c mut DomainTx) -> TxFuture<'c, T> + Send + Sync,
    {
        self.run(Isolation::RepeatableReadReadOnly, f).await
    }

    async fn run<T, F>(&self, iso: Isolation, f: F) -> Result<T, DbError>
    where
        T: Send,
        F: for<'c> Fn(&'c mut DomainTx) -> TxFuture<'c, T> + Send + Sync,
    {
        let policy = self.inner.retry;
        // Time charged to the budget: attempts (excluding connection acquisition) + backoff.
        let mut spent = Duration::ZERO;
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            let conn = self.acquire().await?;
            let started = Instant::now();
            let res = self.attempt(iso, conn, &f).await;
            spent += started.elapsed();
            let err = match res {
                Ok(v) => {
                    if attempt > 1 {
                        tracing::debug!(domain = %self.inner.domain, attempt, "transaction succeeded after retry");
                    }
                    return Ok(v);
                }
                Err(e) if e.is_retryable_conflict() => e,
                Err(e) => return Err(e),
            };
            let sqlstate = err.sqlstate().unwrap_or_default();
            if attempt >= policy.max_attempts || spent >= policy.max_elapsed {
                tracing::warn!(domain = %self.inner.domain, attempt, sqlstate, ?spent, "transaction retry bound exhausted");
                return Err(DbError::RetryExhausted {
                    attempts: attempt,
                    last_sqlstate: sqlstate,
                });
            }
            let delay = policy
                .backoff(attempt)?
                .min(policy.max_elapsed.saturating_sub(spent));
            tracing::debug!(domain = %self.inner.domain, attempt, sqlstate, ?delay, "retrying conflicting transaction");
            tokio::time::sleep(delay).await;
            spent += delay;
        }
    }

    async fn attempt<T, F>(
        &self,
        iso: Isolation,
        conn: PoolConnection<Postgres>,
        f: &F,
    ) -> Result<T, DbError>
    where
        F: for<'c> Fn(&'c mut DomainTx) -> TxFuture<'c, T> + Send + Sync,
    {
        let mut dtx = DomainTx {
            domain: self.inner.domain.clone(),
            conn,
            open: true,
        };
        if let Err(e) = sqlx::raw_sql(iso.begin_sql()).execute(&mut *dtx.conn).await {
            return Err(DbError::Sqlx(e));
        }
        match f(&mut dtx).await {
            Ok(v) => match dtx.commit().await {
                Ok(()) => Ok(v),
                // The server answered: the transaction did not commit.
                Err(e @ sqlx::Error::Database(_)) => Err(DbError::Sqlx(e)),
                // No answer: it may or may not have committed.
                Err(e) => Err(DbError::OutcomeUnknown(e)),
            },
            Err(e) => {
                // Explicit rollback; if it fails the connection is closed by Drop.
                dtx.rollback().await;
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_is_bounded_and_jittered() {
        let p = RetryPolicy::default();
        for attempt in 1..40 {
            let d = p.backoff(attempt).unwrap();
            assert!(d <= p.max_delay, "{attempt} {d:?}");
        }
        assert!(p.backoff(1).unwrap() <= Duration::from_millis(10));
        let samples: std::collections::BTreeSet<_> =
            (0..50).map(|_| p.backoff(8).unwrap()).collect();
        assert!(samples.len() > 1, "no jitter");
    }

    #[test]
    fn backoff_fails_closed_without_csprng() {
        let _g = cs_crypto::rand::inject_failure();
        assert!(RetryPolicy::default().backoff(1).is_err());
    }
}
