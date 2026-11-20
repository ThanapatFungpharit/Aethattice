//! Database fixtures. Every test creates its own uniquely named databases and drops them.
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

/// YugabyteDB DDL contends on the cluster-wide catalog (40001) when tests running in parallel
/// migrate their own databases at the same time. Fixture setup (migrations, QA tables) holds
/// this guard; it shares the lock with database creation, so callers must not hold it while
/// calling `TestDb::create`.
pub async fn ddl_guard() -> tokio::sync::MutexGuard<'static, ()> {
    CREATE_LOCK.lock().await
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

/// A uniquely named database owned by one test.
#[derive(Debug)]
pub struct TestDb {
    pub name: String,
    pub url: String,
    admin: String,
    dropped: bool,
}

impl TestDb {
    /// Create `qa_<label>_<random>`. Labels must be `[a-z0-9_]`.
    pub async fn create(admin: &str, label: &str) -> TestDb {
        assert!(
            label
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        );
        // YugabyteDB DDL on the shared catalog conflicts under concurrency (40001 "could not
        // serialize access"), and a failed CREATE can leave the name half-created. So creates
        // are serialized within this process, each attempt uses a fresh name, and a failed
        // name is dropped best-effort.
        let _guard = CREATE_LOCK.lock().await;
        let mut c = PgConnection::connect(admin).await.expect("admin connect");
        let mut attempt: u64 = 0;
        let name = loop {
            let suffix = uuid::Uuid::new_v4().simple().to_string();
            let name = format!("qa_{label}_{}", &suffix[..12]);
            match sqlx::query(AssertSqlSafe(format!("CREATE DATABASE {name}")))
                .execute(&mut c)
                .await
            {
                Ok(_) => break name,
                Err(e) if attempt < 10 => {
                    attempt += 1;
                    eprintln!("CREATE DATABASE {name} attempt {attempt} failed: {e}");
                    drop_database_unlocked(admin, &name).await;
                    tokio::time::sleep(Duration::from_millis(300 * attempt)).await;
                }
                Err(e) => panic!("CREATE DATABASE {name}: {e}"),
            }
        };
        let _ = c.close().await;
        TestDb {
            url: with_db_name(admin, &name),
            name,
            admin: admin.to_string(),
            dropped: false,
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

    /// Drop several databases concurrently (on YugabyteDB concurrent DROPs complete in the same
    /// barrier cycle, so this is much faster than dropping them one after another).
    pub async fn drop_all(dbs: Vec<TestDb>) {
        futures::future::join_all(dbs.into_iter().map(TestDb::drop_now)).await;
    }

    /// Drop this database now, or, with `CS_QA_DEFER_DROP=1`, record it for a batch cleanup
    /// after the run (on a degraded YugabyteDB a single DROP DATABASE can take minutes). The
    /// gate's leftover check (docs/qa/M0-gate.md §3.5) runs after that cleanup.
    pub async fn drop_now(mut self) {
        if defer_drop() {
            record_deferred(&self.name);
            self.dropped = true;
            return;
        }
        self.drop_forced().await;
    }

    /// Always drops immediately and verifies, regardless of `CS_QA_DEFER_DROP` (used by the
    /// harness self-test so drop correctness is always exercised).
    pub async fn drop_forced(mut self) {
        let before = LEAKED.load(std::sync::atomic::Ordering::SeqCst);
        drop_database(&self.admin, &self.name).await;
        self.dropped = true;
        assert_eq!(
            LEAKED.load(std::sync::atomic::Ordering::SeqCst),
            before,
            "QA harness could not drop test database {} (would leak)",
            self.name
        );
    }
}

/// Drop a test database: retried, verified and time-bounded. A database that still exists
/// afterwards is reported loudly (`QA HARNESS LEAK`) instead of being silently leaked; leaked
/// databases slow the whole cluster and skew timing-sensitive tests. Not serialized with the
/// harness lock: a stalled DROP must never block every other test.
async fn drop_database(admin: &str, name: &str) {
    drop_database_unlocked(admin, name).await;
}

/// One attempt: terminate attached backends, DROP, then verify. On the dev YugabyteDB
/// (2026.1) a DROP DATABASE waits on a cluster-wide ProcSignalBarrier and was measured at
/// 0.1–98 s (typically ~60 s after a cluster restart), so no statement timeout is set: cancelling
/// a slow DROP only restarts the wait. The caller bounds each attempt instead.
async fn drop_attempt(admin: &str, name: &str) -> Result<bool, String> {
    let mut c = PgConnection::connect(admin)
        .await
        .map_err(|e| e.to_string())?;
    let _ = sqlx::query(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
         WHERE datname = $1 AND pid <> pg_backend_pid()",
    )
    .bind(name)
    .execute(&mut c)
    .await;

    let r = sqlx::query(AssertSqlSafe(format!(
        "DROP DATABASE IF EXISTS {name} WITH (FORCE)"
    )))
    .execute(&mut c)
    .await;
    let gone = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM pg_database WHERE datname = $1")
        .bind(name)
        .fetch_one(&mut c)
        .await
        .map(|n| n == 0)
        .map_err(|e| e.to_string())?;
    let _ = c.close().await;
    match (gone, r) {
        (true, _) => Ok(true),
        (false, Err(e)) => Err(e.to_string()),
        (false, Ok(_)) => Ok(false),
    }
}

async fn drop_database_unlocked(admin: &str, name: &str) {
    // On a healthy cluster DROP is fast but often aborts with 40001 ("could not serialize
    // access due to concurrent update") while parallel tests run catalog DDL. Retry with a
    // capped exponential backoff, de-synchronized per database so concurrent drops do not
    // collide again in lockstep (5 attempts / ~3 s was not enough: TL gate rerun 2026-11-21).
    use std::hash::{Hash as _, Hasher as _};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    name.hash(&mut h);
    let spread = h.finish() % 250;
    let mut last = String::new();
    for attempt in 0..30u64 {
        match tokio::time::timeout(Duration::from_secs(180), drop_attempt(admin, name)).await {
            Ok(Ok(true)) => return,
            Ok(Ok(false)) => last = "still present".into(),
            Ok(Err(e)) => last = e,
            Err(_) => last = "drop attempt timed out after 180 s".into(),
        }
        let backoff = (250u64 << attempt.min(5)).min(5_000) + (spread * (attempt + 1)) % 500;
        tokio::time::sleep(Duration::from_millis(backoff)).await;
    }
    eprintln!("QA HARNESS LEAK: could not drop test database {name}: {last}");
    LEAKED.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

/// Number of test databases this process failed to drop (checked by the harness self-test).
pub static LEAKED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

impl Drop for TestDb {
    fn drop(&mut self) {
        if self.dropped {
            return;
        }
        if defer_drop() {
            record_deferred(&self.name);
            return;
        }
        // Best effort when a test panics before `drop_now`: drop on a fresh runtime/thread.
        let admin = self.admin.clone();
        let name = self.name.clone();
        let _ = std::thread::spawn(move || {
            if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                rt.block_on(drop_database(&admin, &name));
            }
        })
        .join();
    }
}

/// Unreachable database URL (closed port on localhost) for readiness tests.
pub fn unreachable_url(db: &str) -> String {
    format!("postgres://qa_user:qa_secret_must_not_leak@127.0.0.1:1/{db}")
}

/// Run QA fixture SQL (test-only DDL/DML, never product schema). YugabyteDB aborts DDL with
/// 40001 when it races catalog changes made by tests running in parallel, so 40001 is retried
/// (bounded). Every fixture statement is idempotent or runs on a fresh database.
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

/// `CS_QA_DEFER_DROP=1`: record test databases instead of dropping them (batch cleanup later).
pub fn defer_drop() -> bool {
    std::env::var("CS_QA_DEFER_DROP")
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// Append a database name to `$CS_QA_DEFER_FILE` (default `target/qa-deferred-drops.txt`).
fn record_deferred(name: &str) {
    use std::io::Write as _;
    let path = std::env::var("CS_QA_DEFER_FILE").unwrap_or_else(|_| {
        format!(
            "{}/../../target/qa-deferred-drops.txt",
            env!("CARGO_MANIFEST_DIR")
        )
    });
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(f, "{name}");
    }
}
