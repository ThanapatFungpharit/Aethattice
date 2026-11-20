//! cs-db integration tests against YugabyteDB. Skipped when `CS_TEST_DATABASE_URL` is unset;
//! failing when `CS_REQUIRE_DB=1` and the database is missing.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use cs_common::error::ErrorCode;
use cs_common::id::{PrincipalId, TenantId};
use cs_common::idempotency::IdempotencyKey;
use cs_common::vector::DomainId;
use cs_db::idempotency::{
    Begin, IdempotencyRecords, IdempotencyScope, RequestBody, StoredResponse, request_digest,
};
use cs_db::migrate::{MigrationError, MigrationSet, Migrator, common_migrations};
use cs_db::outbox::{NewEvent, Outbox};
use cs_db::testing::TestDomains;
use cs_db::{DbError, DomainPool, RetryPolicy};
use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use uuid::Uuid;

const D: DomainId = DomainId::Resources;

async fn setup() -> Option<TestDomains> {
    setup_with(RetryPolicy::default()).await
}

async fn setup_with(retry: RetryPolicy) -> Option<TestDomains> {
    let t = TestDomains::create_with(&[D], retry).await?;
    Migrator::run(t.pool(&D), &common_migrations().unwrap())
        .await
        .unwrap();
    Some(t)
}

fn sqlstate(e: &DbError) -> String {
    e.sqlstate().unwrap_or_default()
}

const RAISE_40001: &str = "DO $$ BEGIN RAISE EXCEPTION 'injected' USING ERRCODE = '40001'; END $$";
const RAISE_40P01: &str = "DO $$ BEGIN RAISE EXCEPTION 'injected' USING ERRCODE = '40P01'; END $$";

async fn exec(pool: &DomainPool, sql: &'static str) {
    pool.transaction(move |tx| {
        Box::pin(async move {
            sqlx::raw_sql(sql).execute(tx.conn()).await?;
            Ok(())
        })
    })
    .await
    .unwrap();
}

async fn count(pool: &DomainPool, sql: &'static str) -> i64 {
    pool.transaction(move |tx| {
        Box::pin(async move {
            Ok(sqlx::query_scalar::<_, i64>(sql)
                .fetch_one(tx.conn())
                .await?)
        })
    })
    .await
    .unwrap()
}

// ---------------------------------------------------------------------------------------------
// Transactions and retry
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn retries_40001_and_40p01_then_succeeds_with_failed_attempts_rolled_back() {
    let Some(t) = setup().await else { return };
    let pool = t.pool(&D);
    exec(
        pool,
        "CREATE TABLE IF NOT EXISTS t_retry (id int PRIMARY KEY)",
    )
    .await;
    let attempts = Arc::new(AtomicU32::new(0));
    let a = attempts.clone();
    let out = pool
        .transaction(move |tx| {
            let a = a.clone();
            Box::pin(async move {
                let n = a.fetch_add(1, Ordering::SeqCst) + 1;
                // every attempt writes; only the successful one may persist
                sqlx::query("INSERT INTO t_retry (id) VALUES ($1)")
                    .bind(i32::try_from(n).unwrap())
                    .execute(tx.conn())
                    .await?;
                match n {
                    1 => sqlx::raw_sql(RAISE_40001).execute(tx.conn()).await?,
                    2 => sqlx::raw_sql(RAISE_40P01).execute(tx.conn()).await?,
                    _ => Default::default(),
                };
                Ok(n)
            })
        })
        .await
        .unwrap();
    assert_eq!(out, 3);
    assert_eq!(attempts.load(Ordering::SeqCst), 3);
    assert_eq!(count(pool, "SELECT count(*) FROM t_retry").await, 1);
    assert_eq!(count(pool, "SELECT max(id)::bigint FROM t_retry").await, 3);
    t.cleanup().await;
}

#[tokio::test]
async fn retry_exhaustion_is_bounded_by_attempts() {
    let policy = RetryPolicy {
        max_attempts: 4,
        max_elapsed: Duration::from_secs(30),
        base_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(5),
    };
    let Some(t) = setup_with(policy).await else {
        return;
    };
    let attempts = Arc::new(AtomicU32::new(0));
    let a = attempts.clone();
    let err = t
        .pool(&D)
        .transaction(move |tx| {
            a.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                sqlx::raw_sql(RAISE_40001).execute(tx.conn()).await?;
                Ok(())
            })
        })
        .await
        .unwrap_err();
    assert!(
        matches!(err, DbError::RetryExhausted { attempts: 4, ref last_sqlstate } if last_sqlstate == "40001"),
        "{err:?}"
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 4);
    let api: cs_common::Error = err.into();
    assert_eq!(api.code(), &cs_common::Code::Core(ErrorCode::Unavailable));
    assert!(api.retryable());
    t.cleanup().await;
}

#[tokio::test]
async fn retry_exhaustion_is_bounded_by_elapsed_time() {
    let policy = RetryPolicy {
        max_attempts: 1000,
        max_elapsed: Duration::from_millis(300),
        base_delay: Duration::from_millis(20),
        max_delay: Duration::from_millis(50),
    };
    // No migrations needed; the tiny budget would otherwise apply to the setup DDL too.
    let Some(t) = TestDomains::create_with(&[D], policy).await else {
        return;
    };
    let started = std::time::Instant::now();
    let err = t
        .pool(&D)
        .transaction(|tx| {
            Box::pin(async move {
                sqlx::raw_sql(RAISE_40001).execute(tx.conn()).await?;
                Ok(())
            })
        })
        .await
        .unwrap_err();
    assert!(matches!(err, DbError::RetryExhausted { attempts, .. } if attempts < 1000));
    assert!(started.elapsed() < Duration::from_secs(5));
    t.cleanup().await;
}

#[tokio::test]
async fn non_retryable_errors_are_not_retried_and_roll_back() {
    let Some(t) = setup().await else { return };
    let pool = t.pool(&D);
    exec(pool, "CREATE TABLE IF NOT EXISTS t_nr (id int PRIMARY KEY)").await;
    exec(pool, "INSERT INTO t_nr VALUES (1)").await;
    // unique violation (23505): not retried
    let attempts = Arc::new(AtomicU32::new(0));
    let a = attempts.clone();
    let err = pool
        .transaction(move |tx| {
            a.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                sqlx::query("INSERT INTO t_nr VALUES (1)")
                    .execute(tx.conn())
                    .await?;
                Ok(())
            })
        })
        .await
        .unwrap_err();
    assert_eq!(sqlstate(&err), "23505");
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    // business error: not retried, effects rolled back
    let attempts = Arc::new(AtomicU32::new(0));
    let a = attempts.clone();
    let err = pool
        .transaction(move |tx| {
            a.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                sqlx::query("INSERT INTO t_nr VALUES (2)")
                    .execute(tx.conn())
                    .await?;
                Err::<(), _>(DbError::app(ErrorCode::Conflict))
            })
        })
        .await
        .unwrap_err();
    assert!(matches!(err, DbError::App(_)));
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    assert_eq!(count(pool, "SELECT count(*) FROM t_nr").await, 1);
    t.cleanup().await;
}

#[tokio::test]
async fn real_write_conflicts_are_retried_to_completion() {
    let Some(t) = setup().await else { return };
    let pool = t.pool(&D).clone();
    exec(
        &pool,
        "CREATE TABLE IF NOT EXISTS t_ctr (id int PRIMARY KEY, n bigint NOT NULL)",
    )
    .await;
    exec(&pool, "INSERT INTO t_ctr VALUES (1, 0)").await;
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let p = pool.clone();
        tasks.push(tokio::spawn(async move {
            p.transaction(|tx| {
                Box::pin(async move {
                    let n: i64 = sqlx::query_scalar("SELECT n FROM t_ctr WHERE id = 1 FOR UPDATE")
                        .fetch_one(tx.conn())
                        .await?;
                    sqlx::query("UPDATE t_ctr SET n = $1 WHERE id = 1")
                        .bind(n + 1)
                        .execute(tx.conn())
                        .await?;
                    Ok(())
                })
            })
            .await
        }));
    }
    for task in tasks {
        task.await.unwrap().unwrap();
    }
    assert_eq!(count(&pool, "SELECT n FROM t_ctr WHERE id = 1").await, 16);
    t.cleanup().await;
}

#[tokio::test]
async fn isolation_levels() {
    let Some(t) = setup().await else { return };
    let pool = t.pool(&D);
    let level: String = pool
        .transaction(|tx| {
            Box::pin(async move {
                Ok(
                    sqlx::query_scalar("SELECT current_setting('transaction_isolation')")
                        .fetch_one(tx.conn())
                        .await?,
                )
            })
        })
        .await
        .unwrap();
    assert_eq!(level, "read committed");
    let (level, effective): (String, Option<String>) = pool
        .transaction(|tx| Box::pin(async move {
            Ok(sqlx::query_as("SELECT current_setting('transaction_isolation'), current_setting('yb_effective_transaction_isolation_level', true)")
                .fetch_one(tx.conn())
                .await?)
        }))
        .await
        .unwrap();
    assert_eq!(level, "read committed");
    if let Some(e) = effective {
        assert_eq!(
            e, "read committed",
            "YugabyteDB downgraded READ COMMITTED; enable yb_enable_read_committed_isolation"
        );
    }
    let snap: String = pool
        .read_snapshot(|tx| {
            Box::pin(async move {
                Ok(
                    sqlx::query_scalar("SELECT current_setting('transaction_isolation')")
                        .fetch_one(tx.conn())
                        .await?,
                )
            })
        })
        .await
        .unwrap();
    assert_eq!(snap, "repeatable read");
    let err = pool
        .read_snapshot(|tx| {
            Box::pin(async move {
                sqlx::query("INSERT INTO outbox_counters VALUES ('00000000-0000-0000-0000-000000000000', 999, 1)")
                    .execute(tx.conn())
                    .await?;
                Ok(())
            })
        })
        .await
        .unwrap_err();
    assert_eq!(
        sqlstate(&err),
        "25006",
        "read-only snapshot must refuse writes"
    );
    t.cleanup().await;
}

#[tokio::test]
async fn unreachable_domain_maps_to_unavailable() {
    if cs_db::testing::admin_url().is_none() {
        return;
    }
    let cfg = cs_common::config::DomainConfig {
        url: cs_common::Secret::new("postgres://nobody@127.0.0.1:1/none".to_owned()),
        pool: cs_common::config::PoolConfig {
            acquire_timeout_ms: 300,
            ..Default::default()
        },
    };
    let pool = DomainPool::connect_lazy(D, &cfg, RetryPolicy::default()).unwrap();
    assert!(pool.ping().await.is_err());
    let err = pool
        .transaction(|_tx| Box::pin(async { Ok(()) }))
        .await
        .unwrap_err();
    let api: cs_common::Error = err.into();
    assert_eq!(api.code(), &cs_common::Code::Core(ErrorCode::Unavailable));
}

// ---------------------------------------------------------------------------------------------
// Migrations
// ---------------------------------------------------------------------------------------------

fn set(files: &[(&str, &str)]) -> MigrationSet {
    MigrationSet::from_files(files).unwrap()
}

/// Common migrations (already applied by `setup`) plus `files`.
fn with_common(files: &[(&str, &str)]) -> MigrationSet {
    common_migrations().unwrap().merge(set(files)).unwrap()
}

#[tokio::test]
async fn migrations_are_idempotent_and_report_status() {
    let Some(t) = setup().await else { return };
    let pool = t.pool(&D);
    let s = common_migrations().unwrap();
    let r = Migrator::run(pool, &s).await.unwrap();
    assert!(r.applied.is_empty());
    assert_eq!(r.already_applied, vec![1, 2, 3]);
    let st = Migrator::status(pool, &s).await.unwrap();
    assert!(st.is_current());
    let more = s
        .clone()
        .merge(set(&[(
            "0100_extra.expand.sql",
            "CREATE TABLE IF NOT EXISTS extras (id uuid PRIMARY KEY);",
        )]))
        .unwrap();
    let st = Migrator::status(pool, &more).await.unwrap();
    assert_eq!(st.pending, vec![100]);
    assert_eq!(st.expected_version, 100);
    assert_eq!(Migrator::run(pool, &more).await.unwrap().applied, vec![100]);
    assert!(Migrator::status(pool, &more).await.unwrap().is_current());
    // older binary (without 0100) tolerates the newer applied migration
    assert!(Migrator::status(pool, &s).await.unwrap().is_current());
    t.cleanup().await;
}

#[tokio::test]
async fn checksum_mismatch_is_a_hard_error() {
    let Some(t) = setup().await else { return };
    let pool = t.pool(&D);
    let v1 = with_common(&[(
        "0100_t.expand.sql",
        "CREATE TABLE IF NOT EXISTS t_cs (id int PRIMARY KEY);",
    )]);
    Migrator::run(pool, &v1).await.unwrap();
    let tampered = with_common(&[
        (
            "0100_t.expand.sql",
            "CREATE TABLE IF NOT EXISTS t_cs (id int PRIMARY KEY, x int);",
        ),
        (
            "0101_u.expand.sql",
            "CREATE TABLE IF NOT EXISTS t_after (id int PRIMARY KEY);",
        ),
    ]);
    let err = Migrator::run(pool, &tampered).await.unwrap_err();
    assert!(
        matches!(
            err,
            DbError::Migration(MigrationError::ChecksumMismatch { version: 100, .. })
        ),
        "{err:?}"
    );
    assert!(matches!(
        Migrator::status(pool, &tampered).await,
        Err(DbError::Migration(MigrationError::ChecksumMismatch { .. }))
    ));
    // nothing after the mismatch was applied
    assert_eq!(
        count(
            pool,
            "SELECT count(*) FROM schema_migrations WHERE version = 101"
        )
        .await,
        0
    );
    assert_eq!(
        count(
            pool,
            "SELECT (to_regclass('t_after') IS NOT NULL)::int::bigint"
        )
        .await,
        0
    );
    // renamed/reclassified file with identical SQL is also rejected
    let renamed = with_common(&[(
        "0100_other.expand.sql",
        "CREATE TABLE IF NOT EXISTS t_cs (id int PRIMARY KEY);",
    )]);
    assert!(matches!(
        Migrator::run(pool, &renamed).await,
        Err(DbError::Migration(MigrationError::Mismatch { .. }))
    ));
    t.cleanup().await;
}

#[tokio::test]
async fn contract_requires_finalized_release() {
    let Some(t) = setup().await else { return };
    let pool = t.pool(&D);
    let s = with_common(&[
        (
            "0100_add_new.expand.sql",
            "CREATE TABLE IF NOT EXISTS t_old (id int PRIMARY KEY);\nCREATE TABLE IF NOT EXISTS t_new (id int PRIMARY KEY);",
        ),
        (
            "0101_drop_old.contract.sql",
            "-- requires_finalized: 0.1.0\nDROP TABLE IF EXISTS t_old;",
        ),
    ]);
    let err = Migrator::run(pool, &s).await.unwrap_err();
    assert!(
        matches!(err, DbError::Migration(MigrationError::ContractNotFinalized { version: 101, ref release, .. }) if release == "0.1.0"),
        "{err:?}"
    );
    // the expand part was applied, the contract part was not
    assert_eq!(Migrator::status(pool, &s).await.unwrap().pending, vec![101]);
    assert_eq!(
        count(
            pool,
            "SELECT (to_regclass('t_old') IS NOT NULL)::int::bigint"
        )
        .await,
        1
    );
    Migrator::finalize_release(pool, "0.0.9").await.unwrap();
    assert!(
        Migrator::run(pool, &s).await.is_err(),
        "a different release does not unlock it"
    );
    Migrator::finalize_release(pool, "0.1.0").await.unwrap();
    Migrator::finalize_release(pool, "0.1.0").await.unwrap(); // idempotent
    assert_eq!(Migrator::run(pool, &s).await.unwrap().applied, vec![101]);
    assert_eq!(
        count(
            pool,
            "SELECT (to_regclass('t_old') IS NOT NULL)::int::bigint"
        )
        .await,
        0
    );
    t.cleanup().await;
}

#[tokio::test]
async fn interrupted_migration_resumes() {
    let Some(t) = setup().await else { return };
    let pool = t.pool(&D);
    let sql = "CREATE TABLE IF NOT EXISTS t_resume (id int PRIMARY KEY);\nINSERT INTO t_resume VALUES (1) ON CONFLICT DO NOTHING;";
    // Simulate a crash after executing the migration but before recording it.
    exec(
        pool,
        "CREATE TABLE IF NOT EXISTS t_resume (id int PRIMARY KEY)",
    )
    .await;
    exec(
        pool,
        "INSERT INTO t_resume VALUES (1) ON CONFLICT DO NOTHING",
    )
    .await;
    let s = with_common(&[("0100_resume.expand.sql", sql)]);
    assert_eq!(Migrator::run(pool, &s).await.unwrap().applied, vec![100]);
    assert_eq!(count(pool, "SELECT count(*) FROM t_resume").await, 1);
    t.cleanup().await;
}

#[tokio::test]
async fn unknown_applied_version_below_head_is_rejected() {
    let Some(t) = setup().await else { return };
    let pool = t.pool(&D);
    exec(pool, "INSERT INTO schema_migrations (version, name, class, checksum) VALUES (50, 'ghost', 'expand', '\\x00')").await;
    let err = Migrator::run(
        pool,
        &common_migrations()
            .unwrap()
            .merge(set(&[("0100_x.expand.sql", "SELECT 1;")]))
            .unwrap(),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, DbError::Migration(MigrationError::UnknownApplied(50))),
        "{err:?}"
    );
    t.cleanup().await;
}

// ---------------------------------------------------------------------------------------------
// Outbox
// ---------------------------------------------------------------------------------------------

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
struct Ev {
    n: u32,
}

async fn append(
    pool: &DomainPool,
    tenant: TenantId,
    key: Uuid,
    n: u32,
) -> cs_db::outbox::OutboxPosition {
    pool.transaction(move |tx| {
        Box::pin(async move {
            Outbox::append(
                tx,
                NewEvent {
                    tenant_id: Some(tenant),
                    event_type: "test.happened",
                    event_version: 1,
                    partition_key: key,
                    payload: &Ev { n },
                },
            )
            .await
        })
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn outbox_sequences_are_contiguous_and_read_in_order() {
    let Some(t) = setup().await else { return };
    let pool = t.pool(&D).clone();
    let tenant = TenantId::generate().unwrap();
    let key = Uuid::from_bytes([3; 16]);
    // concurrent appenders on the same partition
    let mut tasks = Vec::new();
    for i in 0..20u32 {
        let p = pool.clone();
        tasks.push(tokio::spawn(
            async move { append(&p, tenant, key, i).await },
        ));
    }
    let mut positions = Vec::new();
    for task in tasks {
        positions.push(task.await.unwrap());
    }
    let partition = positions[0].partition;
    assert!(
        positions
            .iter()
            .all(|p| p.partition == partition && p.domain == D)
    );
    let mut seqs: Vec<i64> = positions.iter().map(|p| p.sequence).collect();
    seqs.sort();
    assert_eq!(seqs, (1..=20).collect::<Vec<_>>());
    // several events in one transaction
    let multi = pool
        .transaction(move |tx| {
            Box::pin(async move {
                let a = Outbox::append(
                    tx,
                    NewEvent {
                        tenant_id: Some(tenant),
                        event_type: "test.happened",
                        event_version: 1,
                        partition_key: key,
                        payload: &Ev { n: 100 },
                    },
                )
                .await?;
                let b = Outbox::append(
                    tx,
                    NewEvent {
                        tenant_id: Some(tenant),
                        event_type: "test.happened",
                        event_version: 1,
                        partition_key: key,
                        payload: &Ev { n: 101 },
                    },
                )
                .await?;
                Ok((a.sequence, b.sequence))
            })
        })
        .await
        .unwrap();
    assert_eq!(multi, (21, 22));
    let rows = Outbox::read(&pool, tenant.into_uuid(), partition, 0, 100)
        .await
        .unwrap();
    assert_eq!(rows.len(), 22);
    assert!(rows.windows(2).all(|w| w[1].sequence == w[0].sequence + 1));
    let last: Ev = cs_crypto::cbor::from_canonical(&rows[21].payload, 1024).unwrap();
    assert_eq!(last, Ev { n: 101 });
    // paging
    let page = Outbox::read(&pool, tenant.into_uuid(), partition, 10, 5)
        .await
        .unwrap();
    assert_eq!(
        page.iter().map(|r| r.sequence).collect::<Vec<_>>(),
        vec![11, 12, 13, 14, 15]
    );
    t.cleanup().await;
}

#[tokio::test]
async fn outbox_rolled_back_append_leaves_no_gap() {
    let Some(t) = setup().await else { return };
    let pool = t.pool(&D);
    let tenant = TenantId::generate().unwrap();
    let key = Uuid::from_bytes([4; 16]);
    let err = pool
        .transaction(move |tx| {
            Box::pin(async move {
                Outbox::append(
                    tx,
                    NewEvent {
                        tenant_id: Some(tenant),
                        event_type: "test.happened",
                        event_version: 1,
                        partition_key: key,
                        payload: &Ev { n: 0 },
                    },
                )
                .await?;
                Err::<(), _>(DbError::app(ErrorCode::Conflict))
            })
        })
        .await;
    assert!(err.is_err());
    let p = append(pool, tenant, key, 1).await;
    assert_eq!(p.sequence, 1);
    assert_eq!(
        Outbox::read(pool, tenant.into_uuid(), p.partition, 0, 10)
            .await
            .unwrap()
            .len(),
        1
    );
    t.cleanup().await;
}

#[tokio::test]
async fn outbox_gap_detection() {
    let Some(t) = setup().await else { return };
    let pool = t.pool(&D);
    let tenant = TenantId::generate().unwrap();
    let key = Uuid::from_bytes([5; 16]);
    let mut part = 0;
    for i in 0..4 {
        part = append(pool, tenant, key, i).await.partition;
    }
    // simulate a lost row in the middle
    pool.transaction(move |tx| {
        Box::pin(async move {
            sqlx::query(
                "DELETE FROM outbox WHERE partition = $1 AND sequence = 2 AND tenant_id = $2",
            )
            .bind(part)
            .bind(tenant.into_uuid())
            .execute(tx.conn())
            .await?;
            Ok(())
        })
    })
    .await
    .unwrap();
    let err = Outbox::read(pool, tenant.into_uuid(), part, 0, 10)
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            DbError::OutboxGap {
                expected: 2,
                found: Some(3),
                ..
            }
        ),
        "{err:?}"
    );
    // reading past the gap works
    assert_eq!(
        Outbox::read(pool, tenant.into_uuid(), part, 2, 10)
            .await
            .unwrap()
            .len(),
        2
    );
    // simulate a lost tail row
    pool.transaction(move |tx| {
        Box::pin(async move {
            sqlx::query(
                "DELETE FROM outbox WHERE partition = $1 AND sequence = 4 AND tenant_id = $2",
            )
            .bind(part)
            .bind(tenant.into_uuid())
            .execute(tx.conn())
            .await?;
            Ok(())
        })
    })
    .await
    .unwrap();
    let err = Outbox::read(pool, tenant.into_uuid(), part, 2, 10)
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            DbError::OutboxGap {
                expected: 4,
                found: None,
                ..
            }
        ),
        "{err:?}"
    );
    t.cleanup().await;
}

#[tokio::test]
async fn outbox_rejects_invalid_events() {
    let Some(t) = setup().await else { return };
    let pool = t.pool(&D);
    let tenant = TenantId::generate().unwrap();
    let big = vec![0u8; 70 * 1024];
    let err = pool
        .transaction(move |tx| {
            let big = big.clone();
            Box::pin(async move {
                Outbox::append(
                    tx,
                    NewEvent {
                        tenant_id: Some(tenant),
                        event_type: "test.big",
                        event_version: 1,
                        partition_key: Uuid::nil(),
                        payload: &serde_bytes_like(big),
                    },
                )
                .await
            })
        })
        .await
        .unwrap_err();
    assert!(matches!(err, DbError::Invalid(_)));
    let err = pool
        .transaction(move |tx| {
            Box::pin(async move {
                Outbox::append(
                    tx,
                    NewEvent {
                        tenant_id: Some(tenant),
                        event_type: "Bad",
                        event_version: 1,
                        partition_key: Uuid::nil(),
                        payload: &1u8,
                    },
                )
                .await
            })
        })
        .await
        .unwrap_err();
    assert!(matches!(err, DbError::Invalid(_)));
    t.cleanup().await;
}

fn serde_bytes_like(v: Vec<u8>) -> Vec<u32> {
    v.into_iter().map(u32::from).collect()
}

// ---------------------------------------------------------------------------------------------
// Idempotency records
// ---------------------------------------------------------------------------------------------

fn scope(tenant: TenantId, key: &str) -> IdempotencyScope {
    IdempotencyScope {
        tenant_id: tenant,
        principal_id: PrincipalId::generate().unwrap(),
        key: IdempotencyKey::parse(key).unwrap(),
    }
}

fn digest(body: &[u8]) -> [u8; 32] {
    request_digest(
        "POST",
        "/api/v2/things",
        &BTreeMap::new(),
        RequestBody::Raw(body),
    )
    .unwrap()
}

/// A single-domain operation: begin + effect + complete in one transaction.
async fn do_op(
    pool: &DomainPool,
    s: &IdempotencyScope,
    body: &'static [u8],
) -> Result<StoredResponse, DbError> {
    let s = s.clone();
    pool.transaction(move |tx| {
        let s = s.clone();
        Box::pin(async move {
            match IdempotencyRecords::begin(tx, &s, &digest(body), 24).await? {
                Begin::Replay(r) => Ok(r),
                Begin::Started => {
                    sqlx::query("INSERT INTO t_effects (tenant_id) VALUES ($1)")
                        .bind(s.tenant_id.as_uuid())
                        .execute(tx.conn())
                        .await?;
                    let r = StoredResponse {
                        status: 201,
                        body: body.to_vec(),
                    };
                    IdempotencyRecords::complete(tx, &s, &r).await?;
                    Ok(r)
                }
            }
        })
    })
    .await
}

fn code(e: DbError) -> ErrorCode {
    match cs_common::Error::from(e).code() {
        cs_common::Code::Core(c) => *c,
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn idempotency_replay_mismatch_and_rollback() {
    let Some(t) = setup().await else { return };
    let pool = t.pool(&D);
    exec(pool, "CREATE TABLE IF NOT EXISTS t_effects (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL)").await;
    let tenant = TenantId::generate().unwrap();
    let s = scope(tenant, "key-1");
    let first = do_op(pool, &s, b"{\"a\":1}").await.unwrap();
    let again = do_op(pool, &s, b"{\"a\":1}").await.unwrap();
    assert_eq!(first, again);
    assert_eq!(
        count(pool, "SELECT count(*) FROM t_effects").await,
        1,
        "duplicate must not re-apply the effect"
    );
    // same key, different body
    let err = do_op(pool, &s, b"{\"a\":2}").await.unwrap_err();
    assert_eq!(code(err), ErrorCode::IdempotencyMismatch);
    // the key is scoped by principal: another principal may use the same key
    let other = IdempotencyScope {
        principal_id: PrincipalId::generate().unwrap(),
        ..s.clone()
    };
    do_op(pool, &other, b"{\"a\":2}").await.unwrap();
    assert_eq!(count(pool, "SELECT count(*) FROM t_effects").await, 2);
    // a rolled-back operation leaves no record behind
    let s3 = scope(tenant, "key-3");
    let s3c = s3.clone();
    let _ = pool
        .transaction(move |tx| {
            let s = s3c.clone();
            Box::pin(async move {
                IdempotencyRecords::begin(tx, &s, &digest(b"x"), 24).await?;
                Err::<(), _>(DbError::app(ErrorCode::Conflict))
            })
        })
        .await;
    do_op(pool, &s3, b"y").await.unwrap();
    t.cleanup().await;
}

#[tokio::test]
async fn idempotency_in_progress_is_outcome_unknown() {
    let Some(t) = setup().await else { return };
    let pool = t.pool(&D);
    let tenant = TenantId::generate().unwrap();
    let s = scope(tenant, "inflight");
    // A caller that commits the record separately from its effect (e.g. before a saga).
    let sc = s.clone();
    let started = pool
        .transaction(move |tx| {
            let s = sc.clone();
            Box::pin(async move { IdempotencyRecords::begin(tx, &s, &digest(b"b"), 24).await })
        })
        .await
        .unwrap();
    assert_eq!(started, Begin::Started);
    for expected in [ErrorCode::OutcomeUnknown, ErrorCode::OutcomeUnknown] {
        let sc = s.clone();
        let err = pool
            .transaction(move |tx| {
                let s = sc.clone();
                Box::pin(async move { IdempotencyRecords::begin(tx, &s, &digest(b"b"), 24).await })
            })
            .await
            .unwrap_err();
        let api = cs_common::Error::from(err);
        assert_eq!(api.code(), &cs_common::Code::Core(expected));
        assert_eq!(api.status(), 504);
        assert!(api.retryable());
    }
    // mismatch takes precedence over in-progress
    let sc = s.clone();
    let err = pool
        .transaction(move |tx| {
            let s = sc.clone();
            Box::pin(async move { IdempotencyRecords::begin(tx, &s, &digest(b"other"), 24).await })
        })
        .await
        .unwrap_err();
    assert_eq!(code(err), ErrorCode::IdempotencyMismatch);
    t.cleanup().await;
}

#[tokio::test]
async fn idempotency_expired_record_is_reclaimed_and_large_responses_refused() {
    let Some(t) = setup().await else { return };
    let pool = t.pool(&D);
    exec(pool, "CREATE TABLE IF NOT EXISTS t_effects (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL)").await;
    let tenant = TenantId::generate().unwrap();
    let s = scope(tenant, "old");
    do_op(pool, &s, b"one").await.unwrap();
    exec(
        pool,
        "UPDATE idempotency_records SET expires_at = now() - interval '1 second'",
    )
    .await;
    // after expiry the key may be reused, even with a different body
    do_op(pool, &s, b"two").await.unwrap();
    assert_eq!(count(pool, "SELECT count(*) FROM t_effects").await, 2);
    let s2 = scope(tenant, "big");
    let sc = s2.clone();
    let err = pool
        .transaction(move |tx| {
            let s = sc.clone();
            Box::pin(async move {
                IdempotencyRecords::begin(tx, &s, &digest(b"z"), 24).await?;
                IdempotencyRecords::complete(
                    tx,
                    &s,
                    &StoredResponse {
                        status: 200,
                        body: vec![0; 70_000],
                    },
                )
                .await
            })
        })
        .await
        .unwrap_err();
    assert!(matches!(err, DbError::Invalid(_)));
    t.cleanup().await;
}

#[tokio::test]
async fn idempotency_concurrent_duplicates_apply_once() {
    let Some(t) = setup().await else { return };
    let pool = t.pool(&D).clone();
    exec(&pool, "CREATE TABLE IF NOT EXISTS t_effects (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL)").await;
    let s = scope(TenantId::generate().unwrap(), "race");
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let p = pool.clone();
        let s = s.clone();
        tasks.push(tokio::spawn(async move { do_op(&p, &s, b"same").await }));
    }
    let mut results = Vec::new();
    for task in tasks {
        results.push(task.await.unwrap().unwrap());
    }
    assert!(results.iter().all(|r| r == &results[0]));
    assert_eq!(count(&pool, "SELECT count(*) FROM t_effects").await, 1);
    t.cleanup().await;
}

#[tokio::test]
async fn server_error_at_commit_is_definitive_not_unknown() {
    let Some(t) = setup().await else { return };
    let pool = t.pool(&D);
    let err = pool
        .transaction(|tx| {
            Box::pin(async move {
                // The server terminates the idle session and says so (FATAL 25P03): the
                // transaction definitely did not commit.
                sqlx::query("SET LOCAL idle_in_transaction_session_timeout = '50ms'")
                    .execute(tx.conn())
                    .await?;
                tokio::time::sleep(Duration::from_millis(500)).await;
                Ok(())
            })
        })
        .await
        .unwrap_err();
    assert_eq!(sqlstate(&err), "25P03", "{err:?}");
    t.cleanup().await;
}

/// TCP proxy that, once `cut` is set, forwards the next client bytes (the COMMIT) to the
/// server but drops the connection before any reply reaches the client.
async fn lossy_proxy(target: String, cut: Arc<std::sync::atomic::AtomicBool>) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((client, _)) = listener.accept().await else {
                return;
            };
            let server = tokio::net::TcpStream::connect(&target).await.unwrap();
            let cut = cut.clone();
            tokio::spawn(async move {
                let (mut cr, mut cw) = client.into_split();
                let (mut sr, mut sw) = server.into_split();
                let dead = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let d2 = dead.clone();
                let up = tokio::spawn(async move {
                    let mut buf = vec![0u8; 16384];
                    loop {
                        let n = match cr.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        let cutting = cut.load(Ordering::SeqCst);
                        if sw.write_all(&buf[..n]).await.is_err() {
                            return;
                        }
                        if cutting {
                            d2.store(true, Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(300)).await; // let the server commit
                            return;
                        }
                    }
                });
                let mut buf = vec![0u8; 16384];
                loop {
                    let n = tokio::select! {
                        r = sr.read(&mut buf) => match r { Ok(0) | Err(_) => break, Ok(n) => n },
                        _ = tokio::time::sleep(Duration::from_millis(20)) => { if dead.load(Ordering::SeqCst) { break } else { continue } }
                    };
                    if dead.load(Ordering::SeqCst) {
                        break;
                    }
                    if cw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                let _ = cw.shutdown().await;
                drop(cw);
                let _ = up.await;
            });
        }
    });
    port
}

#[tokio::test]
async fn lost_commit_reply_is_outcome_unknown() {
    let Some(t) = setup().await else { return };
    exec(
        t.pool(&D),
        "CREATE TABLE IF NOT EXISTS t_unknown (id int PRIMARY KEY)",
    )
    .await;
    let admin = sqlx::postgres::PgConnectOptions::from_str(t.admin_url()).unwrap();
    let target = format!("{}:{}", admin.get_host(), admin.get_port());
    let cut = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let port = lossy_proxy(target, cut.clone()).await;
    let cfg = cs_common::config::DomainConfig {
        url: cs_common::Secret::new(format!(
            "postgres://{}@127.0.0.1:{port}/{}",
            admin.get_username(),
            t.database_name(&D)
        )),
        pool: cs_common::config::PoolConfig {
            max_connections: 1,
            ..Default::default()
        },
    };
    let pool = DomainPool::connect_lazy(D, &cfg, RetryPolicy::default()).unwrap();
    let attempts = Arc::new(AtomicU32::new(0));
    let a = attempts.clone();
    let c = cut.clone();
    let err = pool
        .transaction(move |tx| {
            a.fetch_add(1, Ordering::SeqCst);
            let c = c.clone();
            Box::pin(async move {
                sqlx::query("INSERT INTO t_unknown VALUES (1)")
                    .execute(tx.conn())
                    .await?;
                c.store(true, Ordering::SeqCst); // the next client message is COMMIT
                Ok(())
            })
        })
        .await
        .unwrap_err();
    assert!(matches!(err, DbError::OutcomeUnknown(_)), "{err:?}");
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        1,
        "an unknown outcome is never retried blindly"
    );
    let api: cs_common::Error = err.into();
    assert_eq!(
        api.code(),
        &cs_common::Code::Core(ErrorCode::OutcomeUnknown)
    );
    assert!(api.retryable());
    // The write did commit: this is exactly why a timeout is never treated as failure.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(count(t.pool(&D), "SELECT count(*) FROM t_unknown").await, 1);
    pool.close().await;
    t.cleanup().await;
}

#[tokio::test]
async fn outbox_sequences_are_per_tenant_and_domain_events_use_nil_tenant() {
    let Some(t) = setup().await else { return };
    let pool = t.pool(&D);
    let (t1, t2) = (TenantId::generate().unwrap(), TenantId::generate().unwrap());
    let key = Uuid::from_bytes([6; 16]);
    let a1 = append(pool, t1, key, 1).await;
    let b1 = append(pool, t2, key, 1).await;
    let a2 = append(pool, t1, key, 2).await;
    assert_eq!((a1.sequence, b1.sequence, a2.sequence), (1, 1, 2));
    assert_eq!(
        a1.partition, b1.partition,
        "same key, same partition number"
    );
    let d = pool
        .transaction(move |tx| {
            Box::pin(async move {
                Outbox::append(
                    tx,
                    NewEvent {
                        tenant_id: None,
                        event_type: "domain.ticked",
                        event_version: 1,
                        partition_key: key,
                        payload: &Ev { n: 0 },
                    },
                )
                .await
            })
        })
        .await
        .unwrap();
    assert_eq!((d.tenant_id, d.sequence), (Uuid::nil(), 1));
    assert_eq!(
        Outbox::read(pool, Uuid::nil(), d.partition, 0, 10)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        Outbox::read(pool, t1.into_uuid(), a1.partition, 0, 10)
            .await
            .unwrap()
            .len(),
        2
    );
    // an unknown source partition is simply empty
    assert!(
        Outbox::read(pool, TenantId::generate().unwrap().into_uuid(), 0, 0, 10)
            .await
            .unwrap()
            .is_empty()
    );
    t.cleanup().await;
}

#[tokio::test]
async fn idempotency_execute_helper_and_oversized_response_is_internal() {
    let Some(t) = setup().await else { return };
    let pool = t.pool(&D);
    exec(pool, "CREATE TABLE IF NOT EXISTS t_effects (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL)").await;
    let s = scope(TenantId::generate().unwrap(), "exec");
    let dg = digest(b"payload");
    let runs = Arc::new(AtomicU32::new(0));
    for _ in 0..3 {
        let r = runs.clone();
        let tenant = s.tenant_id;
        let resp = IdempotencyRecords::execute(pool, &s, dg, 24, move |tx| {
            r.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                sqlx::query("INSERT INTO t_effects (tenant_id) VALUES ($1)")
                    .bind(tenant.as_uuid())
                    .execute(tx.conn())
                    .await?;
                Ok(StoredResponse {
                    status: 201,
                    body: b"made".to_vec(),
                })
            })
        })
        .await
        .unwrap();
        assert_eq!(resp.body, b"made");
    }
    assert_eq!(
        runs.load(Ordering::SeqCst),
        1,
        "effect ran once; duplicates replayed"
    );
    assert_eq!(count(pool, "SELECT count(*) FROM t_effects").await, 1);
    let big = scope(s.tenant_id, "big-exec");
    let err = IdempotencyRecords::execute(pool, &big, digest(b"z"), 24, |_tx| {
        Box::pin(async move {
            Ok(StoredResponse {
                status: 200,
                body: vec![7; 70_000],
            })
        })
    })
    .await
    .unwrap_err();
    assert_eq!(
        code(err),
        ErrorCode::Internal,
        "never truncated, never stored"
    );
    t.cleanup().await;
}

// ---------------------------------------------------------------------------------------------
// Retry budgets (contract §5 rev 4, QA gate F-2)
// ---------------------------------------------------------------------------------------------

/// A second pool on the test database with its own size and retry policy.
fn side_pool(t: &TestDomains, max_connections: u32, retry: RetryPolicy) -> DomainPool {
    let base = t.admin_url().rsplit_once('/').unwrap().0.to_owned();
    let cfg = cs_common::config::DomainConfig {
        url: cs_common::Secret::new(format!("{base}/{}", t.database_name(&D))),
        pool: cs_common::config::PoolConfig {
            max_connections,
            acquire_timeout_ms: 60_000,
            idle_timeout_ms: 1_000,
            ..Default::default()
        },
    };
    DomainPool::connect_lazy(D, &cfg, retry).unwrap()
}

#[tokio::test]
async fn retry_budget_excludes_connection_acquisition() {
    let Some(t) = setup().await else { return };
    // 1 s budget, generous attempts. Every retry has to wait ~600 ms for a connection held by
    // another task, so acquisition alone exceeds the budget; only attempt + backoff time counts.
    let policy = RetryPolicy {
        max_attempts: 50,
        max_elapsed: Duration::from_secs(1),
        base_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(5),
    };
    let pool = side_pool(&t, 1, policy);
    let attempts = Arc::new(AtomicU32::new(0));
    let holders = Arc::new(std::sync::Mutex::new(Vec::new()));
    let started = std::time::Instant::now();
    let (a, h, p) = (attempts.clone(), holders.clone(), pool.clone());
    let n = pool
        .transaction(move |tx| {
            let n = a.fetch_add(1, Ordering::SeqCst) + 1;
            if n <= 3 {
                // Queue a competitor for the only connection; it gets it as soon as this
                // attempt rolls back and holds it for 600 ms.
                let p2 = p.clone();
                h.lock().unwrap().push(tokio::spawn(async move {
                    p2.transaction(|_tx| {
                        Box::pin(async move {
                            tokio::time::sleep(Duration::from_millis(600)).await;
                            Ok(())
                        })
                    })
                    .await
                }));
            }
            Box::pin(async move {
                if n <= 3 {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    sqlx::raw_sql(RAISE_40001).execute(tx.conn()).await?;
                }
                Ok(n)
            })
        })
        .await
        .unwrap();
    let total = started.elapsed();
    assert_eq!(n, 4, "three conflicts, then success");
    assert!(
        total >= Duration::from_millis(1500),
        "acquisition waits did happen ({total:?}) yet did not exhaust the 1 s budget"
    );
    let handles: Vec<_> = std::mem::take(&mut *holders.lock().unwrap());
    for hd in handles {
        hd.await.unwrap().unwrap();
    }
    pool.close().await;
    t.cleanup().await;
}

#[tokio::test]
async fn migration_budget_is_separate_and_configurable() {
    let Some(t) = setup().await else { return };
    let pool = t.pool(&D).clone();
    // defaults: transactions 10 attempts / 5 s, migrations 30 attempts / 120 s
    assert_eq!(pool.retry_policy().max_attempts, 10);
    assert_eq!(pool.retry_policy().max_elapsed, Duration::from_secs(5));
    assert_eq!(
        pool.migration_retry_policy(),
        RetryPolicy::migrations_default()
    );
    assert_eq!(pool.migration_retry_policy().max_attempts, 30);
    assert_eq!(
        pool.migration_retry_policy().max_elapsed,
        Duration::from_secs(120)
    );
    let always_conflicting = with_common(&[(
        "0100_conflict.expand.sql",
        "DO $$ BEGIN RAISE EXCEPTION 'injected' USING ERRCODE = '40001'; END $$;",
    )]);
    // A configured migration budget (12 attempts) applies, not the transaction budget (10).
    let fast = RetryPolicy {
        max_attempts: 12,
        max_elapsed: Duration::from_secs(60),
        base_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(5),
    };
    let err = Migrator::run(
        &pool.clone().with_migration_retry(fast),
        &always_conflicting,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, DbError::RetryExhausted { attempts: 12, ref last_sqlstate } if last_sqlstate == "40001"),
        "{err:?}"
    );
    // The elapsed bound of the migration budget applies too.
    let short = RetryPolicy {
        max_attempts: 100_000,
        max_elapsed: Duration::from_millis(300),
        base_delay: Duration::from_millis(20),
        max_delay: Duration::from_millis(50),
    };
    let err = Migrator::run(
        &pool.clone().with_migration_retry(short),
        &always_conflicting,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, DbError::RetryExhausted { attempts, .. } if attempts < 100_000),
        "{err:?}"
    );
    // Nothing was recorded for the failing migration; the transaction budget is unchanged.
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM schema_migrations WHERE version = 100"
        )
        .await,
        0
    );
    let tx_attempts = Arc::new(AtomicU32::new(0));
    let a = tx_attempts.clone();
    let err = pool
        .transaction(move |tx| {
            a.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                sqlx::raw_sql(RAISE_40001).execute(tx.conn()).await?;
                Ok(())
            })
        })
        .await
        .unwrap_err();
    assert!(
        matches!(err, DbError::RetryExhausted { attempts: 10, .. }),
        "{err:?}"
    );
    assert_eq!(tx_attempts.load(Ordering::SeqCst), 10);
    t.cleanup().await;
}

#[test]
fn migration_budget_comes_from_policy() {
    let toml = format!(
        "[node]\nid = \"{}\"\nroles = [\"api\"]\n[api]\nlisten = \"127.0.0.1:1\"\nadmin_listen = \"127.0.0.1:2\"\ndeployment_domain = \"x.test\"\n[policy]\ndb_migration_retry_max_attempts = 7\ndb_migration_retry_max_elapsed_ms = 9000\n",
        cs_common::id::NodeId::generate().unwrap()
    );
    let cfg = cs_common::config::Config::from_toml_str(&toml).unwrap();
    let m = RetryPolicy::migrations_from_policy(&cfg.policy);
    assert_eq!((m.max_attempts, m.max_elapsed), (7, Duration::from_secs(9)));
    let tx = RetryPolicy::from_policy(&cfg.policy);
    assert_eq!(
        (tx.max_attempts, tx.max_elapsed),
        (10, Duration::from_secs(5))
    );
    let bad = toml.replace("= 7", "= 0");
    assert!(cs_common::config::Config::from_toml_str(&bad).is_err());
}

// ---------------------------------------------------------------------------------------------
// Test harness hygiene (QA gate F-1)
// ---------------------------------------------------------------------------------------------

async fn listed(admin: &str, names: &[String]) -> i64 {
    use sqlx::Connection as _;
    let mut c = sqlx::PgConnection::connect(admin).await.unwrap();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_database WHERE datname = ANY($1)")
        .bind(names)
        .fetch_one(&mut c)
        .await
        .unwrap();
    let _ = c.close().await;
    n
}

#[tokio::test]
async fn harness_cleanup_verifies_databases_are_gone() {
    let Some(t) = TestDomains::create(&[DomainId::Identity, DomainId::Audit]).await else {
        return;
    };
    let admin = t.admin_url().to_owned();
    let names = vec![
        t.database_name(&DomainId::Identity).to_owned(),
        t.database_name(&DomainId::Audit).to_owned(),
    ];
    assert_eq!(listed(&admin, &names).await, 2);
    // open sessions must not prevent the drop
    t.pool(&DomainId::Identity).ping().await.unwrap();
    t.cleanup().await;
    assert_eq!(listed(&admin, &names).await, 0);
}

#[tokio::test]
#[should_panic(expected = "dropped without cleanup")]
async fn harness_forgotten_cleanup_fails_loudly() {
    let Some(t) = TestDomains::create(&[DomainId::Plugins]).await else {
        panic!("dropped without cleanup (skipped: no database)");
    };
    // The databases are still dropped by the fallback before the panic.
    drop(t);
}
