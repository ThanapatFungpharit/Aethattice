//! Database fixtures: leased, reused and reset databases (no CREATE/DROP DATABASE per test).
//!
//! On YugabyteDB, `CREATE DATABASE` / `DROP DATABASE` per test bloats the master's sys catalog
//! and degrades the whole dev cluster (docs/design/M0-backend.md decision record; M0 gate F-4).
//! The QA harness therefore uses the same lease-and-reset approach as `cs_db::testing`, with
//! its own pool, so QA never depends on engineer test code:
//!
//! * **Pool.** Up to `CS_QA_POOL_SIZE` (default 24) databases named `qa_pool_<n>`, created once
//!   on first use (lowest free index first, so only the peak concurrency is ever created) and
//!   never dropped by the harness.
//! * **Lease.** `TestDb::create` takes a session-level advisory lock (class "qatp") on a
//!   dedicated admin connection. It is cross-process (other test binaries and worktrees share
//!   the pool) and dies with the connection, so a crashed test never pins a database. When
//!   every database is leased the test waits up to `CS_QA_POOL_WAIT_SECS` (default 900 s).
//! * **Reset.** `drop_now` re-enables connections, terminates leftover sessions, drops every
//!   non-system schema (`DROP SCHEMA … CASCADE`), re-creates `public` and **verifies the
//!   database is empty** before the lease is released. A failure is loud (`QA HARNESS LEAK`,
//!   counted in [`LEAKED`], and the test fails). A database found non-empty at lease time (its
//!   previous holder crashed) is reset first, with a warning. A `TestDb` dropped without
//!   `drop_now` (panic path) is reset from a fallback thread.
//! * `CS_QA_POOL_LOG=<file>` appends one line per `create` / `lease` / `reset` / `release`; the
//!   gate report counts catalog churn from it.
//!
//! The harness only ever touches databases whose name starts with [`POOL_PREFIX`].
//!
//! Environment:
//! * `CS_TEST_DATABASE_URL` — admin URL (e.g. `postgres://yugabyte@localhost:5433/yugabyte`).
//! * `CS_REQUIRE_DB=1` — a missing or unreachable database is a test failure, not a skip.
//! * `CS_QA_DB_WAIT_SECS` — how long to wait for YugabyteDB to accept connections (default 90 s
//!   when `CS_REQUIRE_DB=1`, otherwise 3 s).

use sqlx::{AssertSqlSafe, Connection, Executor, PgConnection, Row};
use std::time::{Duration, Instant};
use tokio::sync::OnceCell;

static ADMIN: OnceCell<Option<String>> = OnceCell::const_new();
static CREATE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static DDL_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Prefix of every database the QA harness touches.
pub const POOL_PREFIX: &str = "qa_pool_";
const DEFAULT_POOL_SIZE: u32 = 24;
const DEFAULT_POOL_WAIT_SECS: u64 = 900;
/// Advisory-lock class for QA pool leases ("qatp"); distinct from `cs_db::testing` ("cstp").
const LEASE_LOCK_CLASS: i32 = 0x7161_7470;
const RESET_ATTEMPTS: u32 = 8;

/// YugabyteDB DDL contends on the cluster-wide catalog (40001) when tests running in parallel
/// migrate their own databases at the same time. Fixture setup (migrations, QA tables) holds
/// this guard.
pub async fn ddl_guard() -> tokio::sync::MutexGuard<'static, ()> {
    DDL_LOCK.lock().await
}

fn require_db() -> bool {
    std::env::var("CS_REQUIRE_DB")
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// The admin URL if a database is reachable; `None` means "skip". Panics if `CS_REQUIRE_DB=1`
/// and the database is not reachable within the wait budget.
pub async fn admin_url() -> Option<String> {
    ADMIN
        .get_or_init(|| async {
            let Ok(url) = std::env::var("CS_TEST_DATABASE_URL") else {
                assert!(
                    !require_db(),
                    "CS_REQUIRE_DB=1 but CS_TEST_DATABASE_URL is not set"
                );
                return None;
            };
            let default_wait = if require_db() { 90 } else { 3 };
            let wait = std::env::var("CS_QA_DB_WAIT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default_wait);
            let deadline = Instant::now() + Duration::from_secs(wait);
            let mut last_err = String::new();
            while Instant::now() < deadline {
                match PgConnection::connect(&url).await {
                    Ok(mut c) => {
                        if c.execute("SELECT 1").await.is_ok() {
                            let _ = c.close().await;
                            return Some(url);
                        }
                    }
                    Err(e) => last_err = e.to_string(),
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            assert!(
                !require_db(),
                "CS_REQUIRE_DB=1 but database unreachable after {wait}s: {last_err}"
            );
            None
        })
        .await
        .clone()
}

/// Replace the database name in a postgres URL, keeping the query string.
pub fn with_db_name(url: &str, db: &str) -> String {
    let (base, query) = match url.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (url, None),
    };
    let scheme_end = base.find("://").map(|i| i + 3).unwrap_or(0);
    let path_start = base[scheme_end..].find('/').map(|i| i + scheme_end);
    let root = match path_start {
        Some(i) => &base[..i],
        None => base,
    };
    match query {
        Some(q) => format!("{root}/{db}?{q}"),
        None => format!("{root}/{db}"),
    }
}

fn pool_size() -> u32 {
    std::env::var("CS_QA_POOL_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_POOL_SIZE)
}

fn pool_wait() -> Duration {
    Duration::from_secs(
        std::env::var("CS_QA_POOL_WAIT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_POOL_WAIT_SECS),
    )
}

/// One line per pool event (`create`, `lease`, `reset`, `release`) to `$CS_QA_POOL_LOG`.
fn churn_log(event: &str, name: &str) {
    use std::io::Write as _;
    if let Ok(path) = std::env::var("CS_QA_POOL_LOG")
        && let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
    {
        // One write(2) per line: O_APPEND keeps concurrent writers' lines intact.
        let _ = f.write_all(format!("{event} {name}\n").as_bytes());
    }
}

/// Lease key: FNV-1a (stable across processes and toolchains, unlike `DefaultHasher`).
fn lease_key(name: &str) -> i32 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for x in name.as_bytes() {
        h ^= u64::from(*x);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    let b = h.to_le_bytes();
    i32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

async fn conn(url: &str) -> Result<PgConnection, String> {
    PgConnection::connect(url).await.map_err(|e| e.to_string())
}

/// User objects left in the database: relations, types and functions in `public`, plus any
/// non-system schema.
async fn leftover_objects(c: &mut PgConnection) -> Result<i64, String> {
    sqlx::query_scalar(
        "SELECT \
           (SELECT count(*) FROM pg_class WHERE relnamespace = 'public'::regnamespace) \
         + (SELECT count(*) FROM pg_type WHERE typnamespace = 'public'::regnamespace) \
         + (SELECT count(*) FROM pg_proc WHERE pronamespace = 'public'::regnamespace) \
         + (SELECT count(*) FROM pg_namespace WHERE nspname NOT IN \
              ('public', 'information_schema', 'pg_catalog', 'pg_toast') \
              AND nspname NOT LIKE 'pg\\_temp\\_%' AND nspname NOT LIKE 'pg\\_toast\\_temp\\_%')",
    )
    .fetch_one(c)
    .await
    .map_err(|e| e.to_string())
}

async fn enable_connections(admin: &str, name: &str) {
    if let Ok(mut c) = conn(admin).await {
        let allowed: bool =
            sqlx::query_scalar("SELECT datallowconn FROM pg_database WHERE datname = $1")
                .bind(name)
                .fetch_optional(&mut c)
                .await
                .ok()
                .flatten()
                .unwrap_or(true);
        if !allowed {
            let _ = sqlx::query(AssertSqlSafe(format!(
                "ALTER DATABASE {name} ALLOW_CONNECTIONS true"
            )))
            .execute(&mut c)
            .await;
        }
        let _ = c.close().await;
    }
}

/// Create pool database `name` unless it exists (only while holding its lease).
async fn ensure_database(admin: &str, name: &str) -> Result<(), String> {
    let _guard = CREATE_LOCK.lock().await;
    let mut last = String::new();
    for attempt in 1..=30u64 {
        match conn(admin).await {
            Ok(mut c) => {
                // An inspection error must never be read as "missing": that turned a degraded
                // cluster into a CREATE retry storm (dozens of failed CREATEs for existing pool
                // databases, 2026-11-26 full run). Retry the inspection instead.
                let exists: bool = match sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)",
                )
                .bind(name)
                .fetch_one(&mut c)
                .await
                {
                    Ok(b) => b,
                    Err(e) => {
                        last = e.to_string();
                        let _ = c.close().await;
                        tokio::time::sleep(Duration::from_millis(500 * attempt.min(20))).await;
                        continue;
                    }
                };
                if exists {
                    let _ = c.close().await;
                    // A previous holder may have disabled connections (readiness stimulus)
                    // and crashed before its reset.
                    enable_connections(admin, name).await;
                    if let Ok(t) = conn(&with_db_name(admin, name)).await {
                        let _ = t.close().await;
                        return Ok(());
                    }
                } else {
                    churn_log("create", name);
                    let r = sqlx::query(AssertSqlSafe(format!("CREATE DATABASE {name}")))
                        .execute(&mut c)
                        .await;
                    let _ = c.close().await;
                    match r {
                        // Re-check through pg_database on the next iteration.
                        Ok(_) => continue,
                        Err(e) => {
                            last = e.to_string();
                            eprintln!("CREATE DATABASE {name} attempt {attempt}: {last}");
                        }
                    }
                }
            }
            Err(e) => last = e,
        }
        tokio::time::sleep(Duration::from_millis(500 * attempt.min(20))).await;
    }
    Err(format!(
        "CREATE DATABASE {name} failed after retries: {last}"
    ))
}

/// Drop every object in pool database `name` and verify it is empty.
async fn reset_database(admin: &str, name: &str) -> Result<(), String> {
    if !name.starts_with(POOL_PREFIX) {
        return Err(format!("refusing to reset {name}: not a QA pool database"));
    }
    let url = with_db_name(admin, name);
    let mut last = String::from("no attempt made");
    for attempt in 1..=RESET_ATTEMPTS {
        enable_connections(admin, name).await;
        if let Ok(mut a) = conn(admin).await {
            let _ = sqlx::query(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
                 WHERE datname = $1 AND pid <> pg_backend_pid()",
            )
            .bind(name)
            .execute(&mut a)
            .await;
            let _ = a.close().await;
        }
        match conn(&url).await {
            Ok(mut c) => {
                if let Ok(0) = leftover_objects(&mut c).await {
                    let _ = c.close().await;
                    return Ok(());
                }
                churn_log("reset", name);
                let schemas: Vec<String> = sqlx::query_scalar(
                    "SELECT nspname::text FROM pg_namespace WHERE nspname NOT IN \
                       ('information_schema', 'pg_catalog', 'pg_toast') \
                       AND nspname NOT LIKE 'pg\\_temp\\_%' \
                       AND nspname NOT LIKE 'pg\\_toast\\_temp\\_%'",
                )
                .fetch_all(&mut c)
                .await
                .unwrap_or_else(|_| vec!["public".to_owned()]);
                let mut sql = String::new();
                for s in &schemas {
                    sql.push_str(&format!("DROP SCHEMA IF EXISTS \"{s}\" CASCADE;"));
                }
                sql.push_str("CREATE SCHEMA IF NOT EXISTS public;");
                if let Err(e) = sqlx::raw_sql(AssertSqlSafe(sql)).execute(&mut c).await {
                    last = format!("reset failed: {e}");
                }
                match leftover_objects(&mut c).await {
                    Ok(0) => {
                        let _ = c.close().await;
                        return Ok(());
                    }
                    Ok(n) => last = format!("{last}; {n} objects remain"),
                    Err(e) => last = format!("verification failed: {e}"),
                }
                let _ = c.close().await;
            }
            Err(e) => last = e,
        }
        tokio::time::sleep(Duration::from_secs(attempt.min(10).into())).await;
    }
    Err(format!(
        "QA pool database {name} could not be reset after {RESET_ATTEMPTS} attempts ({last})"
    ))
}

/// A leased pool database owned by one test until `drop_now`.
#[derive(Debug)]
pub struct TestDb {
    pub name: String,
    pub url: String,
    admin: String,
    /// The admin session holding the advisory lock (the lease).
    lease: Option<PgConnection>,
}

impl TestDb {
    /// Lease an empty pool database. `label` (`[a-z0-9_]`) names the user in the churn log.
    pub async fn create(admin: &str, label: &str) -> TestDb {
        assert!(
            label
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        );
        let size = pool_size();
        let deadline = Instant::now() + pool_wait();
        let mut lc = conn(admin).await.expect("admin connect (lease session)");
        loop {
            for n in 0..size {
                let name = format!("{POOL_PREFIX}{n}");
                let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1, $2)")
                    .bind(LEASE_LOCK_CLASS)
                    .bind(lease_key(&name))
                    .fetch_one(&mut lc)
                    .await
                    .unwrap_or_else(|e| panic!("lease lock on {name}: {e}"));
                if !got {
                    continue;
                }
                churn_log("lease", &format!("{name} {label}"));
                ensure_database(admin, &name)
                    .await
                    .unwrap_or_else(|e| panic!("{e}"));
                let url = with_db_name(admin, &name);
                let mut c = conn(&url).await.expect("connect leased database");
                let left = leftover_objects(&mut c).await.unwrap_or(1);
                let _ = c.close().await;
                if left != 0 {
                    eprintln!(
                        "WARNING: QA pool database {name} was not reset by its previous \
                         holder; resetting it now"
                    );
                    reset_database(admin, &name)
                        .await
                        .unwrap_or_else(|e| panic!("{e}"));
                }
                return TestDb {
                    name,
                    url,
                    admin: admin.to_string(),
                    lease: Some(lc),
                };
            }
            assert!(
                Instant::now() < deadline,
                "no free QA pool database after {:?} ({size} leased; raise CS_QA_POOL_SIZE)",
                pool_wait()
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    pub async fn connect(&self) -> PgConnection {
        PgConnection::connect(&self.url)
            .await
            .expect("connect test db")
    }

    /// Run a batch of SQL (QA fixture DDL / inspection). Not used for product schema.
    pub async fn exec(&self, sql: &str) {
        fixture_sql(&self.url, sql)
            .await
            .unwrap_or_else(|e| panic!("QA fixture SQL failed: {e}\n{sql}"));
    }

    pub async fn scalar_i64(&self, sql: &str) -> i64 {
        let mut c = self.connect().await;
        let row = sqlx::query(AssertSqlSafe(sql.to_string()))
            .fetch_one(&mut c)
            .await
            .expect(sql);
        let v: i64 = row.try_get(0).expect("i64 column");
        let _ = c.close().await;
        v
    }

    /// Make the database refuse new connections and end the existing ones (readiness
    /// stimulus "a domain database disappears"). The reset re-enables connections.
    pub async fn make_unavailable(&self) {
        let mut c = conn(&self.admin).await.expect("admin connect");
        sqlx::query(AssertSqlSafe(format!(
            "ALTER DATABASE {} ALLOW_CONNECTIONS false",
            self.name
        )))
        .execute(&mut c)
        .await
        .expect("disable connections");
        let _ = sqlx::query(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
             WHERE datname = $1 AND pid <> pg_backend_pid()",
        )
        .bind(&self.name)
        .execute(&mut c)
        .await;
        let _ = c.close().await;
    }

    /// Reset several databases concurrently and release their leases.
    pub async fn drop_all(dbs: Vec<TestDb>) {
        futures::future::join_all(dbs.into_iter().map(TestDb::drop_now)).await;
    }

    /// Reset this database (verified empty) and release the lease. Fails the test loudly if
    /// the reset fails (the database would carry state into the next test).
    pub async fn drop_now(mut self) {
        let lease = self.lease.take();
        let r = reset_database(&self.admin, &self.name).await;
        if let Some(l) = lease {
            let _ = l.close().await;
        }
        churn_log("release", &self.name);
        if let Err(e) = r {
            eprintln!("QA HARNESS LEAK: {e}");
            LEAKED.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            panic!("QA HARNESS LEAK: {e}");
        }
    }

    /// Whether this value still holds its lease (harness self-test).
    pub fn is_leased(&self) -> bool {
        self.lease.is_some()
    }
}

/// Number of pool databases this process failed to reset (checked by the harness self-test).
pub static LEAKED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

impl Drop for TestDb {
    fn drop(&mut self) {
        let Some(lease) = self.lease.take() else {
            return;
        };
        // A test panicked (or forgot `drop_now`): reset from a fresh runtime/thread while the
        // lease is still held, then release it.
        let admin = self.admin.clone();
        let name = self.name.clone();
        let r = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            rt.block_on(reset_database(&admin, &name))
        })
        .join()
        .unwrap_or_else(|_| Err("reset thread panicked".into()));
        drop(lease);
        churn_log("release", &self.name);
        if let Err(e) = r {
            eprintln!("QA HARNESS LEAK: {e}");
            LEAKED.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if !std::thread::panicking() {
                panic!("QA HARNESS LEAK: {e}");
            }
        }
    }
}

/// Unreachable database URL (closed port on localhost) for readiness tests.
pub fn unreachable_url(db: &str) -> String {
    format!("postgres://qa_user:qa_secret_must_not_leak@127.0.0.1:1/{db}")
}

/// Run QA fixture SQL (test-only DDL/DML, never product schema). YugabyteDB aborts DDL with
/// 40001 when it races catalog changes made by tests running in parallel, so 40001 is retried
/// (bounded). Every fixture statement is idempotent or runs on an empty database.
pub async fn fixture_sql(url: &str, sql: &str) -> Result<(), String> {
    let mut attempt: u64 = 0;
    loop {
        let mut c = PgConnection::connect(url)
            .await
            .map_err(|e| e.to_string())?;
        let r = sqlx::raw_sql(AssertSqlSafe(sql.to_string()))
            .execute(&mut c)
            .await;
        let _ = c.close().await;
        match r {
            Ok(_) => return Ok(()),
            Err(sqlx::Error::Database(e))
                if e.code().as_deref() == Some("40001") && attempt < 20 =>
            {
                attempt += 1;
                tokio::time::sleep(Duration::from_millis(100 * attempt)).await;
            }
            Err(e) => return Err(e.to_string()),
        }
    }
}
