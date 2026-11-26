//! Test harness: a bounded, reused pool of databases per domain.
//!
//! - `CS_TEST_DATABASE_URL` points at an admin database (e.g.
//!   `postgres://yugabyte@localhost:5433/yugabyte`). When unset, [`TestDomains::create`]
//!   returns `None` and the test should return early (skip).
//! - With `CS_REQUIRE_DB=1`, a missing or unreachable database is a test FAILURE (panic).
//!
//! Why a pool: on YugabyteDB, `CREATE DATABASE` / `DROP DATABASE` per test bloats the master's
//! sys catalog and degrades the whole dev cluster (docs/design/M0-backend.md decision record).
//! The harness therefore never drops databases. Each domain has `CS_TEST_POOL_SIZE` (default 8)
//! databases named `cs_test_pool_<domain>_<n>`, created once on first use and reused forever:
//!
//! - **Lease.** A test leases one database per domain with a session-level advisory lock held
//!   on a dedicated admin connection (cross-process: other test binaries and other worktrees
//!   share the pool). The lock dies with the connection, so a crashed test process never pins
//!   a database. Domains are leased in sorted order (no lease cycles, no deadlock); when every
//!   database of a domain is leased the test waits (`CS_TEST_POOL_WAIT_SECS`, default 900).
//! - **Reset.** [`TestDomains::cleanup`] terminates leftover sessions, drops every object
//!   (`DROP SCHEMA … CASCADE` for `public` and any other user schema, then re-creates
//!   `public`) and **verifies the database is empty**; it fails the test otherwise (QA gate
//!   F-1: leaks are never silent). A database found non-empty at lease time (its previous
//!   holder crashed) is reset before use, with a loud warning. Tests then run migrations as
//!   before, on an empty database.
//! - A `TestDomains` dropped without `cleanup()` still resets its databases from a fallback
//!   thread and then panics.
//! - `CS_TEST_POOL_LOG=<file>` appends one line per `create`/`lease`/`reset` (used to measure
//!   catalog churn).
//!
//! The harness only ever touches databases named with [`TEST_DB_PREFIX`].

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use crate::pool::{DomainPool, RetryPolicy};
use cs_common::config::{DomainConfig, PoolConfig};
use cs_common::secret::Secret;
use cs_common::vector::DomainId;
use sqlx::Connection as _;
use sqlx::postgres::{PgConnectOptions, PgConnection};
use std::collections::BTreeMap;
use std::io::Write as _;
use std::str::FromStr;
use std::time::{Duration, Instant};

/// Environment variable with the admin connection URL.
pub const DB_URL_ENV: &str = "CS_TEST_DATABASE_URL";
/// When `1`, a missing database fails the test instead of skipping it.
pub const REQUIRE_DB_ENV: &str = "CS_REQUIRE_DB";
/// Databases per domain in the pool.
pub const POOL_SIZE_ENV: &str = "CS_TEST_POOL_SIZE";
/// How long a test waits for a free pool database before failing.
pub const POOL_WAIT_ENV: &str = "CS_TEST_POOL_WAIT_SECS";
/// Optional churn log (one line per create / lease / reset).
pub const POOL_LOG_ENV: &str = "CS_TEST_POOL_LOG";
/// Prefix of every database this harness uses.
pub const TEST_DB_PREFIX: &str = "cs_test_";
/// Prefix of pool databases.
pub const POOL_DB_PREFIX: &str = "cs_test_pool_";

const DEFAULT_POOL_SIZE: u32 = 8;
const DEFAULT_POOL_WAIT_SECS: u64 = 900;
/// Advisory-lock class for pool leases ("cstp").
const LEASE_LOCK_CLASS: i32 = 0x6373_7470;
/// Reset attempts (catalog DDL can hit transient 40001 on YugabyteDB).
const RESET_ATTEMPTS: u32 = 8;
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

fn pool_size() -> u32 {
    std::env::var(POOL_SIZE_ENV)
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_POOL_SIZE)
}

fn pool_wait() -> Duration {
    Duration::from_secs(
        std::env::var(POOL_WAIT_ENV)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_POOL_WAIT_SECS),
    )
}

fn churn_log(event: &str, name: &str) {
    if let Ok(path) = std::env::var(POOL_LOG_ENV)
        && let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
    {
        // One write(2) per line: O_APPEND keeps concurrent writers' lines intact.
        let _ = f.write_all(format!("{event} {name}\n").as_bytes());
    }
}

/// Pool database name for `(domain, n)`.
pub fn pool_database_name(d: &DomainId, n: u32) -> String {
    format!(
        "{POOL_DB_PREFIX}{}_{n}",
        d.as_str().replace(['.', '-'], "_")
    )
}

fn lease_key(name: &str) -> i32 {
    let h = blake3::hash(name.as_bytes());
    let b = h.as_bytes();
    i32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// Serializes CREATE DATABASE within this process (concurrent catalog DDL on YugabyteDB
/// produces spurious errors).
static DDL_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Connection without any statement timeout (catalog DDL may legitimately take minutes).
async fn conn_to(url: &str, database: Option<&str>) -> Result<PgConnection, String> {
    let mut opts = PgConnectOptions::from_str(url)
        .map_err(|e| format!("invalid {DB_URL_ENV}: {e}"))?
        .options([("statement_timeout", "0"), ("lock_timeout", "0")])
        .application_name("cs-test-harness");
    if let Some(db) = database {
        opts = opts.database(db);
    }
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

/// Create the pool database `name` unless it exists. Only called while holding its lease.
async fn ensure_database(admin_url: &str, name: &str) -> Result<(), String> {
    let _guard = DDL_LOCK.lock().await;
    let mut last = String::new();
    for attempt in 1..=30u32 {
        match conn_to(admin_url, None).await {
            Ok(mut conn) => {
                if database_exists(&mut conn, name).await.unwrap_or(false) {
                    // Exists (possibly created despite an error on a previous attempt, a
                    // YugabyteDB internal retry): usable once it accepts connections.
                    if let Ok(c) = conn_to(admin_url, Some(name)).await {
                        let _ = c.close().await;
                        let _ = conn.close().await;
                        return Ok(());
                    }
                    let _ = conn.close().await;
                } else {
                    churn_log("create", name);
                    let r = sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
                        .execute(&mut conn)
                        .await;
                    let _ = conn.close().await;
                    match r {
                        // Re-check through pg_database on the next iteration, without delay.
                        Ok(_) => continue,
                        // A failed CREATE can leave a DocDB keyspace behind that YugabyteDB
                        // rolls back asynchronously ("Keyspace ... already exists" while
                        // pg_database does not list it): back off and retry.
                        Err(e) => {
                            last = e.to_string();
                            eprintln!("CREATE DATABASE {name} attempt {attempt}: {last}");
                        }
                    }
                }
            }
            Err(e) => last = e,
        }
        tokio::time::sleep(Duration::from_millis(500 * u64::from(attempt.min(20)))).await;
    }
    Err(format!(
        "CREATE DATABASE {name} failed after retries: {last}"
    ))
}

/// Number of user objects left in `conn`'s database (relations, types, functions in `public`,
/// plus any non-system schema).
async fn leftover_objects(conn: &mut PgConnection) -> Result<i64, String> {
    sqlx::query_scalar(
        "SELECT \
           (SELECT count(*) FROM pg_class WHERE relnamespace = 'public'::regnamespace) \
         + (SELECT count(*) FROM pg_type WHERE typnamespace = 'public'::regnamespace) \
         + (SELECT count(*) FROM pg_proc WHERE pronamespace = 'public'::regnamespace) \
         + (SELECT count(*) FROM pg_namespace WHERE nspname NOT IN \
              ('public', 'information_schema', 'pg_catalog', 'pg_toast') \
              AND nspname NOT LIKE 'pg\\_temp\\_%' AND nspname NOT LIKE 'pg\\_toast\\_temp\\_%')",
    )
    .fetch_one(conn)
    .await
    .map_err(|e| e.to_string())
}

/// Drop every object in pool database `name` and verify it is empty. Bounded retries; an
/// error names the database.
async fn reset_database(admin_url: &str, name: &str) -> Result<(), String> {
    if !name.starts_with(POOL_DB_PREFIX) {
        return Err(format!("refusing to reset {name}: not a pool database"));
    }
    let mut last = String::from("no attempt made");
    for attempt in 1..=RESET_ATTEMPTS {
        // Sessions left by the test (extra pools, child processes) would block the drop.
        if let Ok(mut admin) = conn_to(admin_url, None).await {
            let _ = sqlx::query(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
                 WHERE datname = $1 AND pid <> pg_backend_pid()",
            )
            .bind(name)
            .execute(&mut admin)
            .await;
            let _ = admin.close().await;
        }
        match conn_to(admin_url, Some(name)).await {
            Ok(mut conn) => {
                match leftover_objects(&mut conn).await {
                    Ok(0) => {
                        let _ = conn.close().await;
                        return Ok(());
                    }
                    Ok(_) => {}
                    Err(e) => last = format!("inspection failed: {e}"),
                }
                churn_log("reset", name);
                let schemas: Vec<String> = sqlx::query_scalar(
                    "SELECT nspname::text FROM pg_namespace WHERE nspname NOT IN \
                       ('information_schema', 'pg_catalog', 'pg_toast') \
                       AND nspname NOT LIKE 'pg\\_temp\\_%' \
                       AND nspname NOT LIKE 'pg\\_toast\\_temp\\_%'",
                )
                .fetch_all(&mut conn)
                .await
                .unwrap_or_else(|_| vec!["public".to_owned()]);
                let mut sql = String::new();
                for s in &schemas {
                    sql.push_str(&format!("DROP SCHEMA IF EXISTS \"{s}\" CASCADE;"));
                }
                sql.push_str("CREATE SCHEMA IF NOT EXISTS public;");
                if let Err(e) = sqlx::raw_sql(sqlx::AssertSqlSafe(sql))
                    .execute(&mut conn)
                    .await
                {
                    last = format!("reset failed: {e}");
                }
                match leftover_objects(&mut conn).await {
                    Ok(0) => {
                        let _ = conn.close().await;
                        return Ok(());
                    }
                    Ok(n) => last = format!("{last}; {n} objects remain"),
                    Err(e) => last = format!("verification failed: {e}"),
                }
                let _ = conn.close().await;
            }
            Err(e) => last = e,
        }
        tokio::time::sleep(Duration::from_secs(u64::from(attempt).min(10))).await;
    }
    Err(format!(
        "test database {name} could not be reset after {RESET_ATTEMPTS} attempts ({last}); \
         it still holds test objects"
    ))
}

/// A held lease: the admin connection owning the advisory lock.
#[derive(Debug)]
struct Lease {
    name: String,
    conn: PgConnection,
}

/// Lease a free pool database for `d` (waiting while all are leased).
async fn lease(admin_url: &str, d: &DomainId) -> Result<Lease, String> {
    let size = pool_size();
    let deadline = Instant::now() + pool_wait();
    let mut conn = conn_to(admin_url, None).await?;
    loop {
        for n in 0..size {
            let name = pool_database_name(d, n);
            let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1, $2)")
                .bind(LEASE_LOCK_CLASS)
                .bind(lease_key(&name))
                .fetch_one(&mut conn)
                .await
                .map_err(|e| format!("lease lock on {name}: {e}"))?;
            if !got {
                continue;
            }
            churn_log("lease", &name);
            ensure_database(admin_url, &name).await?;
            // Normally a no-op (verified empty at the previous cleanup); non-empty means the
            // previous holder crashed before cleanup.
            let mut c = conn_to(admin_url, Some(&name)).await?;
            let left = leftover_objects(&mut c).await.unwrap_or(1);
            let _ = c.close().await;
            if left != 0 {
                eprintln!(
                    "WARNING: pool database {name} was not reset by its previous holder; \
                     resetting it now"
                );
                reset_database(admin_url, &name).await?;
            }
            return Ok(Lease { name, conn });
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "no free pool database for domain {d} after {:?} ({size} leased; raise \
                 {POOL_SIZE_ENV})",
                pool_wait()
            ));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Reset the named databases (leases still held by the caller); returns the failures.
async fn reset_all(admin_url: &str, names: &[String]) -> Vec<String> {
    let mut failures = Vec::new();
    for name in names {
        if let Err(e) = reset_database(admin_url, name).await {
            failures.push(e);
        }
    }
    failures
}

/// A set of leased per-test domain databases.
#[derive(Debug)]
pub struct TestDomains {
    admin_url: String,
    pools: BTreeMap<DomainId, DomainPool>,
    leases: Vec<Lease>,
    names: BTreeMap<DomainId, String>,
    cleaned: bool,
}

impl TestDomains {
    /// Lease one empty database per domain with the default retry policy.
    pub async fn create(domains: &[DomainId]) -> Option<Self> {
        Self::create_with(domains, RetryPolicy::default()).await
    }

    /// Lease one empty database per domain.
    pub async fn create_with(domains: &[DomainId], retry: RetryPolicy) -> Option<Self> {
        let admin_url = admin_url()?;
        let mut me = Self {
            admin_url,
            pools: BTreeMap::new(),
            leases: Vec::new(),
            names: BTreeMap::new(),
            cleaned: false,
        };
        // Sorted, de-duplicated acquisition order: no lease cycles between tests.
        let mut sorted: Vec<DomainId> = domains.to_vec();
        sorted.sort_by_key(|d| d.as_str().into_owned());
        sorted.dedup();
        for d in sorted {
            let l = match lease(&me.admin_url, &d).await {
                Ok(l) => l,
                Err(e) => panic!("{e}"),
            };
            let name = l.name.clone();
            me.leases.push(l);
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

    /// Close pools, reset the databases (verified empty) and release the leases. Panics
    /// (failing the test) if any database cannot be reset.
    pub async fn cleanup(mut self) {
        for p in self.pools.values() {
            p.close().await;
        }
        let leases = std::mem::take(&mut self.leases);
        self.cleaned = true;
        let names: Vec<String> = leases.iter().map(|l| l.name.clone()).collect();
        let failures = reset_all(&self.admin_url, &names).await;
        // Only now release the leases (closing the session drops the advisory lock).
        for l in leases {
            let _ = l.conn.close().await;
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }
}

impl Drop for TestDomains {
    fn drop(&mut self) {
        if self.cleaned || self.leases.is_empty() {
            return;
        }
        // Fallback (a test panicked or forgot cleanup): reset from a separate runtime, since
        // Drop cannot await. Leftover sessions are terminated by the reset. The lease sessions
        // stay open (owned by this runtime) until the reset is done.
        let url = self.admin_url.clone();
        let leases = std::mem::take(&mut self.leases);
        let names: Vec<String> = leases.iter().map(|l| l.name.clone()).collect();
        let failures = std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    return vec![format!(
                        "cannot start cleanup runtime: {e}; not reset: {names:?}"
                    )];
                }
            };
            rt.block_on(reset_all(&url, &names))
        })
        .join()
        .unwrap_or_else(|_| vec!["cleanup thread panicked".to_owned()]);
        // Dropping the sessions releases the advisory locks.
        drop(leases);
        let msg = failures.join("\n");
        if std::thread::panicking() {
            // The test has already failed; report loudly without a double panic.
            if !failures.is_empty() {
                eprintln!("TEST DATABASES NOT RESET:\n{msg}");
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
