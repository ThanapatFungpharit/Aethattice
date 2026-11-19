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
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let name = format!("qa_{label}_{}", &suffix[..12]);
        let mut c = PgConnection::connect(admin).await.expect("admin connect");
        // CREATE DATABASE can transiently fail on YugabyteDB while the catalog is busy; retry.
        let mut attempt = 0;
        loop {
            match sqlx::query(AssertSqlSafe(format!("CREATE DATABASE {name}")))
                .execute(&mut c)
                .await
            {
                Ok(_) => break,
                Err(e) if attempt < 5 => {
                    attempt += 1;
                    eprintln!("CREATE DATABASE {name} retry {attempt}: {e}");
                    tokio::time::sleep(Duration::from_millis(500 * attempt)).await;
                }
                Err(e) => panic!("CREATE DATABASE {name}: {e}"),
            }
        }
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
        let mut c = self.connect().await;
        sqlx::raw_sql(AssertSqlSafe(sql.to_string()))
            .execute(&mut c)
            .await
            .unwrap_or_else(|e| panic!("QA fixture SQL failed: {e}\n{sql}"));
        let _ = c.close().await;
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

    pub async fn drop_now(mut self) {
        drop_database(&self.admin, &self.name).await;
        self.dropped = true;
    }
}

async fn drop_database(admin: &str, name: &str) {
    if let Ok(mut c) = PgConnection::connect(admin).await {
        let forced = sqlx::query(AssertSqlSafe(format!(
            "DROP DATABASE IF EXISTS {name} WITH (FORCE)"
        )))
        .execute(&mut c)
        .await;
        if forced.is_err() {
            let _ = sqlx::query(AssertSqlSafe(format!("DROP DATABASE IF EXISTS {name}")))
                .execute(&mut c)
                .await;
        }
        let _ = c.close().await;
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        if self.dropped {
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
