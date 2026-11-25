//! Self-tests of the QA harness (no implementation needed). Runs under both features so the
//! fixtures are proven before they are trusted by the contract tests.
#![cfg(any(feature = "m0-contract", feature = "qa-selfcheck"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[macro_use]
mod support;

use support::db::{TestDb, with_db_name};

#[test]
fn with_db_name_rewrites_only_the_database() {
    assert_eq!(
        with_db_name("postgres://u@h:5433/yugabyte", "qa_x"),
        "postgres://u@h:5433/qa_x"
    );
    assert_eq!(
        with_db_name("postgres://u:p@h:5433/yugabyte?sslmode=disable", "qa_x"),
        "postgres://u:p@h:5433/qa_x?sslmode=disable"
    );
    assert_eq!(
        with_db_name("postgres://u@h:5433", "qa_x"),
        "postgres://u@h:5433/qa_x"
    );
}

async fn exists(admin: &str, name: &str) -> bool {
    use sqlx::Connection;
    let mut c = sqlx::PgConnection::connect(admin).await.unwrap();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_database WHERE datname = $1")
        .bind(name)
        .fetch_one(&mut c)
        .await
        .unwrap();
    n == 1
}

async fn objects(url: &str) -> i64 {
    use sqlx::Connection;
    let mut c = sqlx::PgConnection::connect(url).await.unwrap();
    let n: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM pg_class WHERE relnamespace = 'public'::regnamespace) \
         + (SELECT count(*) FROM pg_namespace WHERE nspname = 'qa_extra')",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    let _ = c.close().await;
    n
}

/// Pooled harness (no CREATE/DROP DATABASE per test): two live leases are distinct and
/// isolated; both the explicit reset and the panic-path reset leave the database empty and
/// connectable (a disabled database is re-enabled) without dropping it.
#[tokio::test]
async fn test_db_is_leased_isolated_and_reset() {
    let admin = require_db!();
    let a = TestDb::create(&admin, "harness").await;
    let b = TestDb::create(&admin, "harness").await;
    assert_ne!(a.name, b.name, "two live leases must be different databases");
    assert!(a.name.starts_with(support::db::POOL_PREFIX));
    a.exec(
        "CREATE TABLE t (id int PRIMARY KEY); INSERT INTO t VALUES (1); \
         CREATE SCHEMA qa_extra; CREATE TABLE qa_extra.u (id int PRIMARY KEY)",
    )
    .await;
    assert_eq!(a.scalar_i64("SELECT count(*)::bigint FROM t").await, 1);
    assert_eq!(
        b.scalar_i64(
            "SELECT count(*)::bigint FROM information_schema.tables WHERE table_name = 't'"
        )
        .await,
        0
    );
    b.exec("CREATE TABLE w (id int PRIMARY KEY)").await;
    b.make_unavailable().await;
    let (na, nb, ua, ub) = (a.name.clone(), b.name.clone(), a.url.clone(), b.url.clone());
    let leaked = support::db::LEAKED.load(std::sync::atomic::Ordering::SeqCst);
    a.drop_now().await;
    assert!(
        exists(&admin, &na).await,
        "pool database {na} must be reused, not dropped"
    );
    assert_eq!(objects(&ua).await, 0, "explicit reset left objects in {na}");
    // Implicit reset (the panic path) also cleans up and re-enables connections.
    assert!(b.is_leased());
    drop(b);
    assert!(exists(&admin, &nb).await);
    assert_eq!(objects(&ub).await, 0, "Drop guard left objects in {nb}");
    assert_eq!(
        support::db::LEAKED.load(std::sync::atomic::Ordering::SeqCst),
        leaked,
        "QA HARNESS LEAK reported"
    );
}

#[tokio::test]
async fn unreachable_url_is_unreachable() {
    use sqlx::Connection;
    let r = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        sqlx::PgConnection::connect(&support::db::unreachable_url("cs_identity")),
    )
    .await;
    assert!(
        matches!(r, Ok(Err(_)) | Err(_)),
        "the 'unreachable' URL accepted a connection"
    );
}
