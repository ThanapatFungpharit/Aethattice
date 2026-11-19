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

#[tokio::test]
async fn test_db_is_created_isolated_and_dropped() {
    let admin = require_db!();
    let a = TestDb::create(&admin, "harness").await;
    let b = TestDb::create(&admin, "harness").await;
    assert_ne!(a.name, b.name, "database names must be unique per test");
    a.exec("CREATE TABLE t (id int PRIMARY KEY); INSERT INTO t VALUES (1)")
        .await;
    assert_eq!(a.scalar_i64("SELECT count(*)::bigint FROM t").await, 1);
    assert_eq!(
        b.scalar_i64(
            "SELECT count(*)::bigint FROM information_schema.tables WHERE table_name = 't'"
        )
        .await,
        0
    );
    let (na, nb) = (a.name.clone(), b.name.clone());
    a.drop_now().await;
    assert!(!exists(&admin, &na).await, "explicit drop left {na}");
    // Implicit drop (the panic path) also cleans up.
    drop(b);
    assert!(!exists(&admin, &nb).await, "Drop guard left {nb}");
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
