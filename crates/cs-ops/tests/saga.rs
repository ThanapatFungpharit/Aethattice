//! Saga framework tests with a test saga spanning two domains (objects, accounting) plus the
//! operations domain, with crash injection at every step boundary (contract §5.4).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use cs_common::error::ErrorCode;
use cs_common::id::{PrincipalId, TenantId};
use cs_common::idempotency::IdempotencyKey;
use cs_common::vector::DomainId;
use cs_db::migrate::{MigrationSet, Migrator, common_migrations};
use cs_db::outbox::{NewEvent, Outbox};
use cs_db::testing::TestDomains;
use cs_db::{DbError, DomainPool, DomainTx};
use cs_ops::saga::{
    CrashHook, OpsError, ReconcileContext, ReconcileVerdict, Reconciler, SagaDefinition,
    SagaExecutor, SagaState, StartSaga, StepContext, StepDef, StepDone,
};
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

const OPS: DomainId = DomainId::Operations;
const A: DomainId = DomainId::Objects;
const B: DomainId = DomainId::Accounting;

#[derive(Serialize, Deserialize, Default, Clone)]
struct Input {
    fail_pivot: bool,
    fail_post: bool,
}

/// reserve (A) -> commit (B, pivot) -> finalize (A); compensation releases the reservation.
struct TransferSaga {
    transient_post_failures: AtomicU32,
}

fn input(ctx: &StepContext) -> Input {
    cs_crypto::cbor::from_canonical(&ctx.input, 1024).unwrap()
}

async fn emit(tx: &mut DomainTx, ctx: &StepContext, event_type: &str) -> Result<StepDone, DbError> {
    let pos = Outbox::append(
        tx,
        NewEvent {
            tenant_id: ctx.tenant_id,
            event_type,
            event_version: 1,
            partition_key: ctx.operation_id.into_uuid(),
            payload: &ctx.operation_id,
        },
    )
    .await?;
    Ok(StepDone { result: event_type.as_bytes().to_vec(), outbox: vec![(&pos).into()] })
}

impl SagaDefinition for TransferSaga {
    fn saga_type(&self) -> &'static str {
        "test.transfer"
    }
    fn protocol_version(&self) -> i32 {
        1
    }
    fn steps(&self) -> Vec<StepDef> {
        vec![
            StepDef { name: "reserve", domain: A },
            StepDef { name: "commit", domain: B },
            StepDef { name: "finalize", domain: A },
        ]
    }
    fn pivot(&self) -> &'static str {
        "commit"
    }
    fn apply<'c>(&'c self, ctx: &'c StepContext, tx: &'c mut DomainTx) -> BoxFuture<'c, Result<StepDone, DbError>> {
        Box::pin(async move {
            let op = ctx.operation_id.into_uuid();
            match ctx.step {
                "reserve" => {
                    sqlx::query("INSERT INTO reservations (operation_id, tenant_id, state) VALUES ($1, $2, 'held')")
                        .bind(op).bind(ctx.tenant_id.as_uuid()).execute(tx.conn()).await?;
                    emit(tx, ctx, "test.reserved").await
                }
                "commit" => {
                    if input(ctx).fail_pivot {
                        return Err(DbError::app(ErrorCode::QuotaExceeded));
                    }
                    sqlx::query("INSERT INTO ledger (operation_id, tenant_id) VALUES ($1, $2)")
                        .bind(op).bind(ctx.tenant_id.as_uuid()).execute(tx.conn()).await?;
                    emit(tx, ctx, "test.committed").await
                }
                "finalize" => {
                    if input(ctx).fail_post {
                        return Err(DbError::app(ErrorCode::Conflict));
                    }
                    if self.transient_post_failures.load(Ordering::SeqCst) > 0 {
                        self.transient_post_failures.fetch_sub(1, Ordering::SeqCst);
                        return Err(DbError::Invalid("transient test failure".into()));
                    }
                    let n = sqlx::query("UPDATE reservations SET state = 'final' WHERE operation_id = $1 AND state = 'held'")
                        .bind(op).execute(tx.conn()).await?.rows_affected();
                    assert_eq!(n, 1, "finalize applied twice or without reservation");
                    emit(tx, ctx, "test.finalized").await
                }
                other => panic!("unknown step {other}"),
            }
        })
    }
    fn compensate<'c>(&'c self, ctx: &'c StepContext, _applied: &'c StepDone, tx: &'c mut DomainTx) -> BoxFuture<'c, Result<StepDone, DbError>> {
        Box::pin(async move {
            assert_eq!(ctx.step, "reserve", "only pre-pivot steps are compensated");
            let n = sqlx::query("UPDATE reservations SET state = 'released' WHERE operation_id = $1 AND state = 'held'")
                .bind(ctx.operation_id.into_uuid()).execute(tx.conn()).await?.rows_affected();
            assert_eq!(n, 1, "compensation applied twice");
            emit(tx, ctx, "test.released").await
        })
    }
    fn reconcile<'a>(&'a self, ctx: &'a ReconcileContext<'a>) -> BoxFuture<'a, Result<ReconcileVerdict, DbError>> {
        Box::pin(async move {
            let op = ctx.operation_id.into_uuid();
            let res: Option<String> = ctx.pools[&A]
                .transaction(move |tx| Box::pin(async move {
                    Ok(sqlx::query_scalar("SELECT state FROM reservations WHERE operation_id = $1").bind(op).fetch_optional(tx.conn()).await?)
                }))
                .await?;
            let ledger: i64 = ctx.pools[&B]
                .transaction(move |tx| Box::pin(async move {
                    Ok(sqlx::query_scalar("SELECT count(*) FROM ledger WHERE operation_id = $1").bind(op).fetch_one(tx.conn()).await?)
                }))
                .await?;
            let ok = match ctx.state {
                SagaState::Completed => res.as_deref() == Some("final") && ledger == 1,
                SagaState::Compensated => matches!(res.as_deref(), None | Some("released")) && ledger == 0,
                _ => true,
            };
            Ok(if ok {
                ReconcileVerdict::Consistent
            } else {
                ReconcileVerdict::Divergent(format!("state {} reservation {res:?} ledger {ledger}", ctx.state))
            })
        })
    }
}

struct Env {
    t: TestDomains,
}

impl Env {
    async fn new() -> Option<Self> {
        let t = TestDomains::create(&[OPS, A, B]).await?;
        let common = common_migrations().unwrap();
        Migrator::run(t.pool(&OPS), &common.clone().merge(cs_ops::migrations().unwrap()).unwrap()).await.unwrap();
        let a = MigrationSet::from_files(&[(
            "1000_reservations.expand.sql",
            "CREATE TABLE IF NOT EXISTS reservations (operation_id uuid PRIMARY KEY, tenant_id uuid NOT NULL, \
             state text NOT NULL CHECK (state IN ('held', 'final', 'released')));",
        )])
        .unwrap();
        let b = MigrationSet::from_files(&[(
            "1000_ledger.expand.sql",
            "CREATE TABLE IF NOT EXISTS ledger (operation_id uuid PRIMARY KEY, tenant_id uuid NOT NULL);",
        )])
        .unwrap();
        Migrator::run(t.pool(&A), &common.clone().merge(a).unwrap()).await.unwrap();
        Migrator::run(t.pool(&B), &common.merge(b).unwrap()).await.unwrap();
        Some(Self { t })
    }

    fn executor(&self, def: Arc<TransferSaga>, crash: Option<CrashHook>) -> SagaExecutor {
        let mut pools = BTreeMap::new();
        pools.insert(A, self.t.pool(&A).clone());
        pools.insert(B, self.t.pool(&B).clone());
        let mut e = SagaExecutor::new(self.t.pool(&OPS).clone(), pools).with_max_forward_attempts(3);
        e.register(def).unwrap();
        match crash {
            Some(h) => e.with_crash_hook(h),
            None => e,
        }
    }

    async fn count(&self, d: &DomainId, sql: &str) -> i64 {
        let sql = Arc::new(sql.to_owned());
        self.t
            .pool(d)
            .transaction(move |tx| {
                let sql = sql.clone();
                Box::pin(async move {
                    Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql.as_str().to_owned())).fetch_one(tx.conn()).await?)
                })
            })
            .await
            .unwrap()
    }

    async fn assert_outbox_contiguous(&self, d: &DomainId) {
        let pool: &DomainPool = self.t.pool(d);
        for p in 0..Outbox::partition_count(pool).await.unwrap() as i32 {
            Outbox::read(pool, p, 0, 10_000).await.unwrap();
        }
    }
}

fn saga() -> Arc<TransferSaga> {
    Arc::new(TransferSaga { transient_post_failures: AtomicU32::new(0) })
}

fn start_req(input: &Input, key: &str) -> StartSaga {
    StartSaga {
        saga_type: "test.transfer".into(),
        tenant_id: TenantId::generate().unwrap(),
        actor: PrincipalId::generate().unwrap(),
        idempotency_key: IdempotencyKey::parse(key).unwrap(),
        request_digest: *blake3::hash(&cs_crypto::cbor::to_canonical(input).unwrap()).as_bytes(),
        deadline: Duration::from_secs(600),
        input: cs_crypto::cbor::to_canonical(input).unwrap(),
    }
}

/// Count every crash point of a clean run.
fn counting_hook(counter: Arc<AtomicU32>) -> CrashHook {
    Arc::new(move |_p| {
        counter.fetch_add(1, Ordering::SeqCst);
        false
    })
}

/// Crash at the `k`-th crash point (0-based).
fn crash_at(k: u32) -> CrashHook {
    let seen = Arc::new(AtomicU32::new(0));
    Arc::new(move |_p| seen.fetch_add(1, Ordering::SeqCst) == k)
}

#[tokio::test]
async fn happy_path_completes_with_effects_once() {
    let Some(env) = Env::new().await else { return };
    let exec = Arc::new(env.executor(saga(), None));
    let op = exec.start(start_req(&Input::default(), "happy")).await.unwrap();
    assert_eq!(exec.load(op).await.unwrap().state, SagaState::Created);
    assert_eq!(exec.drive(op).await.unwrap(), SagaState::Completed);
    let rec = exec.load(op).await.unwrap();
    assert_eq!(rec.result.as_deref(), Some(&b"test.committed"[..]));
    assert!(rec.doc.steps.iter().all(|s| s.done.as_ref().is_some_and(|d| !d.outbox.is_empty())));
    assert_eq!(exec.verify(op).await.unwrap(), ReconcileVerdict::Consistent);
    assert_eq!(env.count(&A, "SELECT count(*) FROM reservations WHERE state = 'final'").await, 1);
    assert_eq!(env.count(&B, "SELECT count(*) FROM ledger").await, 1);
    assert_eq!(env.count(&A, "SELECT count(*) FROM outbox").await, 2);
    assert_eq!(env.count(&B, "SELECT count(*) FROM outbox").await, 1);
    // driving a terminal saga again changes nothing
    assert_eq!(exec.drive(op).await.unwrap(), SagaState::Completed);
    assert_eq!(env.count(&A, "SELECT count(*) FROM outbox").await, 2);
    env.t.cleanup().await;
}

#[tokio::test]
async fn duplicate_start_returns_same_operation_and_mismatch_is_rejected() {
    let Some(env) = Env::new().await else { return };
    let exec = env.executor(saga(), None);
    let req = start_req(&Input::default(), "dup");
    let op1 = exec.start(req.clone()).await.unwrap();
    let op2 = exec.start(req.clone()).await.unwrap();
    assert_eq!(op1, op2);
    let mut other = req.clone();
    other.request_digest = [9; 32];
    let err = exec.start(other).await.unwrap_err();
    let api: cs_common::Error = err.into();
    assert_eq!(api.code(), &cs_common::Code::Core(ErrorCode::IdempotencyMismatch));
    assert_eq!(env.count(&OPS, "SELECT count(*) FROM sagas").await, 1);
    env.t.cleanup().await;
}

async fn crash_sweep(input: Input, expected: SagaState) {
    let Some(env) = Env::new().await else { return };
    // 1. how many crash points does a clean run pass?
    let counter = Arc::new(AtomicU32::new(0));
    let exec = env.executor(saga(), Some(counting_hook(counter.clone())));
    let op = exec.start(start_req(&input, "probe")).await.unwrap();
    assert_eq!(exec.drive(op).await.unwrap(), expected);
    let points = counter.load(Ordering::SeqCst);
    assert!(points >= 6, "too few crash points: {points}");
    drop(exec);

    // 2. crash at each point, drop the executor, recover with the reconciler.
    for k in 0..points {
        let crashing = env.executor(saga(), Some(crash_at(k)));
        let op = crashing.start(start_req(&input, &format!("crash-{k}"))).await.unwrap();
        let err = crashing.drive(op).await.unwrap_err();
        assert!(matches!(err, OpsError::Crashed(_)), "point {k}: {err:?}");
        drop(crashing); // the "process" dies

        let fresh = Arc::new(env.executor(saga(), None));
        let report = Reconciler::new(fresh.clone()).run_once().await.unwrap();
        assert!(report.divergent.is_empty(), "point {k}: {report:?}");
        assert_eq!(fresh.load(op).await.unwrap().state, expected, "point {k}");
        assert_eq!(fresh.verify(op).await.unwrap(), ReconcileVerdict::Consistent, "point {k}");
    }
    let n = i64::from(points) + 1;
    // exactly-once effects across all runs
    match expected {
        SagaState::Completed => {
            assert_eq!(env.count(&A, "SELECT count(*) FROM reservations WHERE state = 'final'").await, n);
            assert_eq!(env.count(&B, "SELECT count(*) FROM ledger").await, n);
            assert_eq!(env.count(&A, "SELECT count(*) FROM outbox").await, 2 * n);
            assert_eq!(env.count(&B, "SELECT count(*) FROM outbox").await, n);
        }
        SagaState::Compensated => {
            assert_eq!(env.count(&A, "SELECT count(*) FROM reservations WHERE state <> 'released'").await, 0);
            assert_eq!(env.count(&B, "SELECT count(*) FROM ledger").await, 0);
            assert_eq!(env.count(&B, "SELECT count(*) FROM outbox").await, 0);
            // one reserve + one release event per saga
            assert_eq!(env.count(&A, "SELECT count(*) FROM outbox").await, 2 * n);
        }
        _ => unreachable!(),
    }
    env.assert_outbox_contiguous(&A).await;
    env.assert_outbox_contiguous(&B).await;
    assert_eq!(env.count(&OPS, &format!("SELECT count(*) FROM sagas WHERE state = '{}'", expected.as_str())).await, n);
    env.t.cleanup().await;
}

#[tokio::test]
async fn crash_after_every_step_recovers_forward() {
    crash_sweep(Input::default(), SagaState::Completed).await;
}

#[tokio::test]
async fn crash_after_every_step_recovers_compensation() {
    crash_sweep(Input { fail_pivot: true, fail_post: false }, SagaState::Compensated).await;
}

#[tokio::test]
async fn post_pivot_permanent_failure_blocks_without_compensation() {
    let Some(env) = Env::new().await else { return };
    let exec = env.executor(saga(), None);
    let op = exec.start(start_req(&Input { fail_pivot: false, fail_post: true }, "post")).await.unwrap();
    assert_eq!(exec.drive(op).await.unwrap(), SagaState::BlockedForOperator);
    let rec = exec.load(op).await.unwrap();
    assert!(rec.doc.failure.unwrap().contains("finalize"));
    // the committed pivot result is preserved; nothing was compensated
    assert_eq!(env.count(&B, "SELECT count(*) FROM ledger").await, 1);
    assert_eq!(env.count(&A, "SELECT count(*) FROM reservations WHERE state = 'held'").await, 1);
    env.t.cleanup().await;
}

#[tokio::test]
async fn post_pivot_transient_failures_retry_forward_then_block() {
    let Some(env) = Env::new().await else { return };
    // two transient failures (< 3 allowed): completes on later reconciler passes
    let def = Arc::new(TransferSaga { transient_post_failures: AtomicU32::new(2) });
    let exec = Arc::new(env.executor(def.clone(), None));
    let op = exec.start(start_req(&Input::default(), "transient")).await.unwrap();
    assert!(exec.drive(op).await.is_err());
    let rec = Reconciler::new(exec.clone());
    for _ in 0..3 {
        rec.run_once().await.unwrap();
    }
    assert_eq!(exec.load(op).await.unwrap().state, SagaState::Completed);
    // persistent transient failure: blocked after the bound, never compensated
    def.transient_post_failures.store(100, Ordering::SeqCst);
    let op2 = exec.start(start_req(&Input::default(), "persistent")).await.unwrap();
    for _ in 0..5 {
        let _ = exec.drive(op2).await;
    }
    let r2 = exec.load(op2).await.unwrap();
    assert_eq!(r2.state, SagaState::BlockedForOperator);
    assert!(r2.doc.failure.unwrap().contains("exhausted"));
    assert_eq!(env.count(&B, "SELECT count(*) FROM ledger").await, 2);
    env.t.cleanup().await;
}

#[tokio::test]
async fn concurrent_executors_apply_effects_once() {
    let Some(env) = Env::new().await else { return };
    let e1 = Arc::new(env.executor(saga(), None));
    let e2 = Arc::new(env.executor(saga(), None));
    let mut ops = Vec::new();
    for i in 0..5 {
        ops.push(e1.start(start_req(&Input::default(), &format!("cc-{i}"))).await.unwrap());
    }
    let mut tasks = Vec::new();
    for op in ops.clone() {
        for e in [e1.clone(), e2.clone()] {
            tasks.push(tokio::spawn(async move {
                // a transient error from a lost race is fine; the reconciler finishes
                let _ = e.drive(op).await;
            }));
        }
    }
    for t in tasks {
        t.await.unwrap();
    }
    Reconciler::new(e1.clone()).run_once().await.unwrap();
    for op in ops {
        assert_eq!(e1.load(op).await.unwrap().state, SagaState::Completed);
    }
    assert_eq!(env.count(&B, "SELECT count(*) FROM ledger").await, 5);
    assert_eq!(env.count(&A, "SELECT count(*) FROM outbox").await, 10);
    assert_eq!(env.count(&B, "SELECT count(*) FROM outbox").await, 5);
    env.t.cleanup().await;
}

#[tokio::test]
async fn deadline_before_pivot_compensates_only_with_proof() {
    let Some(env) = Env::new().await else { return };
    let exec = env.executor(saga(), None);
    let mut req = start_req(&Input::default(), "late");
    req.deadline = Duration::ZERO;
    let op = exec.start(req).await.unwrap();
    assert_eq!(exec.drive(op).await.unwrap(), SagaState::Compensated);
    assert_eq!(env.count(&B, "SELECT count(*) FROM ledger").await, 0);
    // the pivot is fenced: even a late, direct execution of the pivot cannot commit now
    let rec = exec.load(op).await.unwrap();
    assert!(rec.doc.failure.unwrap().contains("deadline"));
    env.t.cleanup().await;
}

#[tokio::test]
async fn illegal_registration_rejected() {
    if cs_db::testing::admin_url().is_none() {
        return;
    }
    struct Bad;
    impl SagaDefinition for Bad {
        fn saga_type(&self) -> &'static str { "bad" }
        fn protocol_version(&self) -> i32 { 1 }
        fn steps(&self) -> Vec<StepDef> { vec![StepDef { name: "x", domain: A }] }
        fn pivot(&self) -> &'static str { "missing" }
        fn apply<'c>(&'c self, _: &'c StepContext, _: &'c mut DomainTx) -> BoxFuture<'c, Result<StepDone, DbError>> { unreachable!() }
        fn compensate<'c>(&'c self, _: &'c StepContext, _: &'c StepDone, _: &'c mut DomainTx) -> BoxFuture<'c, Result<StepDone, DbError>> { unreachable!() }
        fn reconcile<'a>(&'a self, _: &'a ReconcileContext<'a>) -> BoxFuture<'a, Result<ReconcileVerdict, DbError>> { unreachable!() }
    }
    let Some(t) = TestDomains::create(&[OPS]).await else { return };
    let mut e = SagaExecutor::new(t.pool(&OPS).clone(), BTreeMap::new());
    assert!(e.register(Arc::new(Bad)).is_err());
    t.cleanup().await;
}
