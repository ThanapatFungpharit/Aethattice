//! Test harness: one uniquely named database per (test, domain).
//!
//! - `CS_TEST_DATABASE_URL` points at an admin database (e.g.
//!   `postgres://yugabyte@localhost:5433/yugabyte`). When unset, [`TestDomains::create`]
//!   returns `None` and the test should return early (skip).
//! - With `CS_REQUIRE_DB=1`, a missing or unreachable database is a test FAILURE (panic).
//! - Databases are named `cs_test_<16 hex>_<domain>`. [`TestDomains::cleanup`] drops them and
//!   **fails the test** if a database cannot be dropped (QA gate F-1): leaked databases are
//!   never silent.
//!
//! Dropping on YugabyteDB can take from well under a second to several minutes, so:
//! - the admin connection runs with `statement_timeout = 0` (no client-side timeout either);
//! - each DROP is followed by a check against `pg_database`, with bounded retries;
//! - test pools use a short idle timeout and are closed before the drop, so idle sessions do
//!   not hold the database open (`WITH (FORCE)` terminates any that remain);
//! - CREATE and DROP are serialized within a process (concurrent catalog DDL on YugabyteDB
//!   produces spurious errors).
//!
//! The harness only ever drops databases it created itself.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use crate::pool::{DomainPool, RetryPolicy};
use cs_common::config::{DomainConfig, PoolConfig};
use cs_common::secret::Secret;
use cs_common::vector::DomainId;
use sqlx::Connection as _;
use sqlx::postgres::{PgConnectOptions, PgConnection};
use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::Duration;

/// Environment variable with the admin connection URL.
pub const DB_URL_ENV: &str = "CS_TEST_DATABASE_URL";
/// When `1`, a missing database fails the test instead of skipping it.
pub const REQUIRE_DB_ENV: &str = "CS_REQUIRE_DB";
/// Prefix of every database this harness creates.
pub const TEST_DB_PREFIX: &str = "cs_test_";

/// DROP attempts before the harness gives up and fails the test.
const DROP_ATTEMPTS: u32 = 8;
/// Idle timeout of test pools (short, so idle sessions never pin a database).
const TEST_POOL_IDLE_TIMEOUT_MS: u64 = 1_000;

/// The admin URL, or `None` to skip. Panics when the DB is required but not configured.
pub fn admin_url() -> Option<String> {
    match std::env::var(DB_URL_ENV) {
        Ok(u) if !u.is_empty() => Some(u),
        _ => {
            if std::env::var(REQUIRE_DB_ENV).as_deref() == Ok("1") {
                panic!("{REQUIRE_DB_ENV}=1 but {DB_URL_ENV} is not set");
            }
            eprintln!("skipping DB test: {DB_URL_ENV} not set");
            None
        }
    }
}

/// Serializes CREATE / DROP DATABASE within this process.
static DDL_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Admin connection without any statement timeout (DROP may legitimately take minutes).
async fn admin_conn(url: &str) -> Result<PgConnection, String> {
    let opts = PgConnectOptions::from_str(url)
        .map_err(|e| format!("invalid {DB_URL_ENV}: {e}"))?
        .options([("statement_timeout", "0"), ("lock_timeout", "0")]);
    PgConnection::connect_with(&opts)
        .await
        .map_err(|e| format!("cannot connect to test database ({DB_URL_ENV}): {e}"))
}

async fn database_exists(conn: &mut PgConnection, name: &str) -> Result<bool, String> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)")
        .bind(name)
        .fetch_one(conn)
        .await
        .map_err(|e| e.to_string())
}

async fn create_database(admin_url: &str, name: &str) -> Result<(), String> {
    let _guard = DDL_LOCK.lock().await;
    let mut last = String::new();
    for attempt in 1..=20u32 {
        match admin_conn(admin_url).await {
            Ok(mut conn) => {
                match sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
                    .execute(&mut conn)
                    .await
                {
                    Ok(_) => {
                        let _ = conn.close().await;
                        return Ok(());
                    }
                    Err(e) => last = e.to_string(),
                }
                // The name is random: if it exists and accepts connections, the create
                // succeeded despite the error (YugabyteDB internal retry).
                if database_exists(&mut conn, name).await.unwrap_or(false) {
                    let opts = PgConnectOptions::from_str(admin_url)
                        .map_err(|e| e.to_string())?
                        .database(name);
                    if let Ok(c) = PgConnection::connect_with(&opts).await {
                        let _ = c.close().await;
                        let _ = conn.close().await;
                        return Ok(());
                    }
                }
                let _ = conn.close().await;
            }
            Err(e) => last = e,
        }
        tokio::time::sleep(Duration::from_millis(100 * u64::from(attempt))).await;
    }
    Err(format!(
        "CREATE DATABASE {name} failed after retries: {last}"
    ))
}

/// Drop `name` and verify it is gone. Bounded retries; an error names the database.
async fn drop_database(admin_url: &str, name: &str) -> Result<(), String> {
    if !name.starts_with(TEST_DB_PREFIX) {
        return Err(format!("refusing to drop {name}: not a harness database"));
    }
    let _guard = DDL_LOCK.lock().await;
    let mut last = String::from("no attempt made");
    for attempt in 1..=DROP_ATTEMPTS {
        match admin_conn(admin_url).await {
            Ok(mut conn) => {
                // No timeout: on YugabyteDB this can take minutes and must not be abandoned.
                if let Err(e) = sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                    "DROP DATABASE IF EXISTS {name} WITH (FORCE)"
                )))
                .execute(&mut conn)
                .await
                {
                    last = format!("DROP failed: {e}");
                }
                match database_exists(&mut conn, name).await {
                    Ok(false) => {
                        let _ = conn.close().await;
                        return Ok(());
                    }
                    Ok(true) => last = format!("{last}; database still listed in pg_database"),
                    Err(e) => last = format!("verification failed: {e}"),
                }
                let _ = conn.close().await;
            }
            Err(e) => last = e,
        }
        tokio::time::sleep(Duration::from_secs(u64::from(attempt).min(10))).await;
    }
    Err(format!(
        "test database {name} could not be dropped after {DROP_ATTEMPTS} attempts ({last}); \
         it is LEAKED and must be removed manually"
    ))
}

/// A set of per-test domain databases.
#[derive(Debug)]
pub struct TestDomains {
    admin_url: String,
    pools: BTreeMap<DomainId, DomainPool>,
    /// Every database this instance created (or attempted to create).
    databases: Vec<String>,
    names: BTreeMap<DomainId, String>,
    cleaned: bool,
}

impl TestDomains {
    /// Create one fresh database per domain with the default retry policy.
    pub async fn create(domains: &[DomainId]) -> Option<Self> {
        Self::create_with(domains, RetryPolicy::default()).await
    }

    /// Create one fresh database per domain.
    pub async fn create_with(domains: &[DomainId], retry: RetryPolicy) -> Option<Self> {
        let admin_url = admin_url()?;
        let tag = format!("{:016x}", cs_crypto::rand::u64().expect("csprng"));
        // Built incrementally so that a failure part-way still drops what was created.
        let mut me = Self {
            admin_url,
            pools: BTreeMap::new(),
            databases: Vec::new(),
            names: BTreeMap::new(),
            cleaned: false,
        };
        for d in domains {
            let name = format!(
                "{TEST_DB_PREFIX}{tag}_{}",
                d.as_str().replace(['.', '-'], "_")
            );
            me.databases.push(name.clone());
            if let Err(e) = create_database(&me.admin_url, &name).await {
                panic!("{e}");
            }
            me.names.insert(d.clone(), name.clone());
            let opts = PgConnectOptions::from_str(&me.admin_url)
                .expect("admin url")
                .database(&name);
            let cfg = DomainConfig {
                url: Secret::new(String::new()),
                pool: PoolConfig {
                    max_connections: 8,
                    min_connections: 0,
                    idle_timeout_ms: TEST_POOL_IDLE_TIMEOUT_MS,
                    ..PoolConfig::default()
                },
            };
            me.pools.insert(
                d.clone(),
                DomainPool::from_options_for_tests(d.clone(), opts, &cfg, retry),
            );
        }
        Some(me)
    }

    pub fn pool(&self, d: &DomainId) -> &DomainPool {
        self.pools
            .get(d)
            .unwrap_or_else(|| panic!("no test pool for domain {d}"))
    }

    /// Name of the database backing `d`.
    pub fn database_name(&self, d: &DomainId) -> &str {
        self.names
            .get(d)
            .unwrap_or_else(|| panic!("no test database for domain {d}"))
    }

    /// Admin connection URL (for tests that need raw access to other databases).
    pub fn admin_url(&self) -> &str {
        &self.admin_url
    }

    /// Close pools and drop the databases. Panics (failing the test) if any database cannot
    /// be dropped.
    pub async fn cleanup(mut self) {
        for p in self.pools.values() {
            p.close().await;
        }
        let dbs = std::mem::take(&mut self.databases);
        self.cleaned = true;
        let mut failures = Vec::new();
        for name in &dbs {
            if let Err(e) = drop_database(&self.admin_url, name).await {
                failures.push(e);
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }
}

impl Drop for TestDomains {
    fn drop(&mut self) {
        if self.cleaned || self.databases.is_empty() {
            return;
        }
        // Fallback (a test panicked or forgot cleanup): drop from a separate runtime, since
        // Drop cannot await. Pools are still alive here; WITH (FORCE) terminates their sessions.
        let url = self.admin_url.clone();
        let dbs = std::mem::take(&mut self.databases);
        let failures = std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    return vec![format!("cannot start cleanup runtime: {e}; leaked {dbs:?}")];
                }
            };
            rt.block_on(async move {
                let mut failures = Vec::new();
                for name in &dbs {
                    if let Err(e) = drop_database(&url, name).await {
                        failures.push(e);
                    }
                }
                failures
            })
        })
        .join()
        .unwrap_or_else(|_| vec!["cleanup thread panicked".to_owned()]);
        let msg = failures.join("\n");
        if std::thread::panicking() {
            // The test has already failed; report loudly without a double panic.
            if !failures.is_empty() {
                eprintln!("LEAKED TEST DATABASES:\n{msg}");
            }
        } else if !failures.is_empty() {
            panic!("{msg}");
        } else {
            panic!(
                "TestDomains dropped without cleanup(): call `t.cleanup().await` at the end of the test"
            );
        }
    }
}
