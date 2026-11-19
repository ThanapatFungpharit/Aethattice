//! Test harness: one uniquely named database per (test, domain).
//!
//! - `CS_TEST_DATABASE_URL` points at an admin database (e.g.
//!   `postgres://yugabyte@localhost:5433/yugabyte`). When unset, [`TestDomains::create`]
//!   returns `None` and the test should return early (skip).
//! - With `CS_REQUIRE_DB=1`, a missing or unreachable database is a test FAILURE (panic).
//! - Databases are named `cs_test_<16 hex>_<domain>` and dropped by [`TestDomains::cleanup`]
//!   (or, as a fallback, on drop), so tests run in parallel with each other and with other
//!   suites against the same cluster.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use crate::pool::{DomainPool, RetryPolicy};
use cs_common::config::{DomainConfig, PoolConfig};
use cs_common::secret::Secret;
use cs_common::vector::DomainId;
use sqlx::Connection as _;
use sqlx::postgres::{PgConnectOptions, PgConnection};
use std::collections::BTreeMap;
use std::str::FromStr;

/// Environment variable with the admin connection URL.
pub const DB_URL_ENV: &str = "CS_TEST_DATABASE_URL";
/// When `1`, a missing database fails the test instead of skipping it.
pub const REQUIRE_DB_ENV: &str = "CS_REQUIRE_DB";

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

/// A set of per-test domain databases.
#[derive(Debug)]
pub struct TestDomains {
    admin_url: String,
    pools: BTreeMap<DomainId, DomainPool>,
    databases: Vec<String>,
    names: BTreeMap<DomainId, String>,
    cleaned: bool,
}

async fn admin_conn(url: &str) -> PgConnection {
    match PgConnection::connect(url).await {
        Ok(c) => c,
        Err(e) => panic!("cannot connect to test database ({DB_URL_ENV}): {e}"),
    }
}

/// Serializes CREATE DATABASE within this process; YugabyteDB handles concurrent catalog
/// DDL poorly (spurious "already exists" / conflict errors). Other processes are covered by
/// the retry loop below.
static CREATE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn create_database(conn: &mut PgConnection, admin_url: &str, name: &str) {
    let _guard = CREATE_LOCK.lock().await;
    let mut last = String::new();
    for attempt in 0..20u32 {
        match sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&mut *conn)
            .await
        {
            Ok(_) => return,
            Err(e) => last = e.to_string(),
        }
        // The name is random: if it exists and accepts connections, the create succeeded
        // despite the error (YugabyteDB internal retry).
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)")
                .bind(name)
                .fetch_one(&mut *conn)
                .await
                .unwrap_or(false);
        if exists {
            let opts = PgConnectOptions::from_str(admin_url)
                .expect("admin url")
                .database(name);
            if let Ok(c) = PgConnection::connect_with(&opts).await {
                let _ = c.close().await;
                return;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(
            100 * u64::from(attempt + 1),
        ))
        .await;
    }
    panic!("CREATE DATABASE {name} failed after retries: {last}");
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
        let mut conn = admin_conn(&admin_url).await;
        let mut pools = BTreeMap::new();
        let mut databases = Vec::new();
        let mut names = BTreeMap::new();
        for d in domains {
            let name = format!("cs_test_{tag}_{}", d.as_str().replace(['.', '-'], "_"));
            create_database(&mut conn, &admin_url, &name).await;
            databases.push(name.clone());
            names.insert(d.clone(), name.clone());
            let opts = PgConnectOptions::from_str(&admin_url)
                .expect("admin url")
                .database(&name);
            let cfg = DomainConfig {
                url: Secret::new(String::new()),
                pool: PoolConfig {
                    max_connections: 8,
                    ..PoolConfig::default()
                },
            };
            pools.insert(
                d.clone(),
                DomainPool::from_options_for_tests(d.clone(), opts, &cfg, retry),
            );
        }
        let _ = conn.close().await;
        Some(Self {
            admin_url,
            pools,
            databases,
            names,
            cleaned: false,
        })
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

    /// Close pools and drop the databases.
    pub async fn cleanup(mut self) {
        for p in self.pools.values() {
            p.close().await;
        }
        let mut conn = admin_conn(&self.admin_url).await;
        for name in &self.databases {
            if let Err(e) = sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                "DROP DATABASE IF EXISTS {name} WITH (FORCE)"
            )))
            .execute(&mut conn)
            .await
            {
                eprintln!("warning: could not drop test database {name}: {e}");
            }
        }
        let _ = conn.close().await;
        self.cleaned = true;
    }
}

impl Drop for TestDomains {
    fn drop(&mut self) {
        if self.cleaned || self.databases.is_empty() {
            return;
        }
        // Fallback for panicking tests: drop the databases from a separate runtime.
        let url = self.admin_url.clone();
        let dbs = std::mem::take(&mut self.databases);
        let _ = std::thread::spawn(move || {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            rt.block_on(async move {
                if let Ok(mut c) = PgConnection::connect(&url).await {
                    for name in dbs {
                        let _ = sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                            "DROP DATABASE IF EXISTS {name} WITH (FORCE)"
                        )))
                        .execute(&mut c)
                        .await;
                    }
                }
            });
        })
        .join();
    }
}
