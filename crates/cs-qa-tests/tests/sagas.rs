//! Saga framework (§18.4, App. C rules C1/C3/C9, App. F, App. L.6 saga fault injection,
//! contract §5.4). Uses the QA two-domain test saga defined in support/contract.rs:
//!   step 0 (A) hold → step 1 (B) prepare credit → step 2 (A) PIVOT commit hold → step 3 (B) apply credit.
//! Traceability: 2.6-9, 18.4-1..18.4-9, 18.4-13, 18.4-14, C.2-1, C.2-3, C.2-9, C.3-8, E-3, E-5, F-1,
//! L.6-3, CT.M0-22, CT.M0-23.
#![cfg(any(feature = "m0-contract", feature = "qa-selfcheck"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[macro_use]
mod support;

use sqlx::Row;
use support::contract as c;
use support::db::TestDb;
use support::types::{DriveOutcome, Fault, SagaRow};
use uuid::Uuid;

const PRE_PIVOT_STATES: &[&str] = &["created", "running_pre_pivot"];
const ALL_STATES: &[&str] = &[
    "created",
    "running_pre_pivot",
    "pivot_committed",
    "completing",
    "completed",
    "compensating",
    "compensated",
    "blocked_for_operator",
];

struct Fx {
    ops: TestDb,
    a: TestDb,
    b: TestDb,
    env: c::SagaEnv,
    tenant: Uuid,
}

async fn fx(admin: &str) -> Fx {
    let ops = TestDb::create(admin, "saga_ops").await;
    let a = TestDb::create(admin, "saga_a").await;
    let b = TestDb::create(admin, "saga_b").await;
    let env = {
        let _g = support::db::ddl_guard().await;
        c::saga_env(&ops.url, &a.url, &b.url).await.unwrap()
    };
    Fx {
        ops,
        a,
        b,
        env,
        tenant: Uuid::now_v7(),
    }
}

impl Fx {
    async fn done(self) {
        // Release the saga environment's pools before dropping the databases.
        let Fx { ops, a, b, env, .. } = self;
        {
            let _env = env; // dropped at the end of this block
        }
        TestDb::drop_all(vec![ops, a, b]).await;
    }
    async fn row(&self, op: Uuid) -> SagaRow {
        let mut conn = self.ops.connect().await;
        let r = sqlx::query(
            "SELECT operation_id, state, version, pivot, result FROM sagas WHERE operation_id = $1",
        )
        .bind(op)
        .fetch_one(&mut conn)
        .await
        .unwrap();
        SagaRow {
            operation_id: r.get(0),
            state: r.get(1),
            version: r.get(2),
            pivot: r.get(3),
            result: r.get(4),
        }
    }
    async fn hold(&self, op: Uuid) -> Option<String> {
        let mut conn = self.a.connect().await;
        sqlx::query("SELECT state FROM qa_holds WHERE op = $1")
            .bind(op)
            .fetch_optional(&mut conn)
            .await
            .unwrap()
            .map(|r| r.get(0))
    }
    async fn credit(&self, op: Uuid) -> Option<String> {
        let mut conn = self.b.connect().await;
        sqlx::query("SELECT state FROM qa_credits WHERE op = $1")
            .bind(op)
            .fetch_optional(&mut conn)
            .await
            .unwrap()
            .map(|r| r.get(0))
    }
    async fn balance(&self) -> (i64, i64) {
        let mut conn = self.b.connect().await;
        sqlx::query("SELECT balance, applications FROM qa_balance WHERE tenant_id = $1")
            .bind(self.tenant)
            .fetch_optional(&mut conn)
            .await
            .unwrap()
            .map(|r| (r.get(0), r.get(1)))
            .unwrap_or((0, 0))
    }
    async fn step_commits(&self, op: Uuid, step: i32) -> i64 {
        let db = if step == 0 || step == 2 {
            &self.a
        } else {
            &self.b
        };
        db.scalar_i64(&format!("SELECT coalesce(max(commits), 0)::bigint FROM qa_step_commits WHERE op = '{op}' AND step = {step}")).await
    }

    /// Cross-domain invariants that must hold once a saga is terminal.
    async fn assert_converged(&self, op: Uuid, amount: i64, expect_completed: Option<bool>) {
        let row = self.row(op).await;
        let (hold, credit, (bal, apps)) = (
            self.hold(op).await,
            self.credit(op).await,
            self.balance().await,
        );
        match row.state.as_str() {
            "completed" => {
                assert_eq!(
                    hold.as_deref(),
                    Some("committed"),
                    "{op}: completed but hold {hold:?}"
                );
                assert_eq!(
                    credit.as_deref(),
                    Some("applied"),
                    "{op}: completed but credit {credit:?}"
                );
                assert_eq!(
                    (bal, apps),
                    (amount, 1),
                    "{op}: credit applied {apps} times (balance {bal})"
                );
            }
            "compensated" => {
                assert!(
                    matches!(hold.as_deref(), None | Some("voided")),
                    "{op}: compensated but hold {hold:?}"
                );
                assert!(
                    matches!(credit.as_deref(), None | Some("voided")),
                    "{op}: compensated but credit {credit:?}"
                );
                assert_eq!((bal, apps), (0, 0), "{op}: compensated saga moved money");
            }
            s => panic!("{op}: saga not terminal after reconciliation: {s}"),
        }
        if let Some(want) = expect_completed {
            assert_eq!(
                row.state == "completed",
                want,
                "{op}: final state {}",
                row.state
            );
        }
    }
}

#[tokio::test]
async fn saga_schema_matches_contract() {
    let admin = require_db!();
    let f = fx(&admin).await;
    let n = f
        .ops
        .scalar_i64(
            "SELECT count(*) FROM information_schema.columns WHERE table_name = 'sagas' AND column_name IN
             ('operation_id','tenant_id','saga_type','protocol_version','actor','idempotency_key','request_digest','state',
              'pivot','steps','deadline','result','version','created_at','updated_at')",
        )
        .await;
    assert_eq!(n, 15, "sagas columns differ from contract §5.4");
    let uniq = f
        .ops
        .scalar_i64(
            "SELECT count(*) FROM pg_constraint k JOIN pg_class t ON t.oid = k.conrelid WHERE t.relname = 'sagas' AND k.contype = 'u'
             AND (SELECT array_agg(a.attname::text ORDER BY a.attname) FROM unnest(k.conkey) x(n)
                  JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = x.n) = ARRAY['idempotency_key','saga_type','tenant_id']",
        )
        .await;
    assert_eq!(
        uniq, 1,
        "UNIQUE (tenant_id, saga_type, idempotency_key) missing"
    );
    f.done().await;
}

#[tokio::test]
async fn happy_path_reaches_completed() {
    let admin = require_db!();
    let f = fx(&admin).await;
    let op = f.env.start(f.tenant, "happy", 50).await.unwrap();
    let row = f.row(op).await;
    assert_eq!(
        row.state, "created",
        "operation record must exist (state created) before any side effect"
    );
    assert_eq!(
        f.hold(op).await,
        None,
        "side effect before the operation record was driven"
    );
    assert_eq!(f.env.drive(op, Fault::None).await, DriveOutcome::Completed);
    let row = f.row(op).await;
    assert_eq!(row.state, "completed");
    assert!(!row.pivot.is_empty(), "named pivot missing");
    assert!(row.version > 0, "CAS version never advanced");
    f.assert_converged(op, 50, Some(true)).await;
    for s in 0..c::QA_SAGA_STEPS as i32 {
        assert_eq!(
            f.step_commits(op, s).await,
            1,
            "step {s} committed more than once on the happy path"
        );
    }
    f.done().await;
}

#[tokio::test]
async fn crash_after_each_pre_pivot_step_converges() {
    let admin = require_db!();
    let f = fx(&admin).await;
    for step in 0..c::QA_SAGA_PIVOT {
        let op = f
            .env
            .start(f.tenant, &format!("crash-pre-{step}"), 10)
            .await
            .unwrap();
        assert_eq!(
            f.env.drive(op, Fault::CrashAfterStep(step)).await,
            DriveOutcome::Crashed
        );
        let mid = f.row(op).await;
        assert!(
            PRE_PIVOT_STATES.contains(&mid.state.as_str()),
            "after crash at pre-pivot step {step}: state {}",
            mid.state
        );
        f.env.reconcile(5).await.unwrap();
        // No permanent failure happened, so either forward completion or a clean compensation
        // is acceptable, never a mixture.
        f.assert_converged(op, 10, None).await;
        for s in 0..c::QA_SAGA_STEPS as i32 {
            assert!(
                f.step_commits(op, s).await <= 1,
                "crash at step {step}: step {s} committed twice after recovery"
            );
        }
        // Reset the shared balance for the next iteration.
        f.b.exec(&format!(
            "DELETE FROM qa_balance WHERE tenant_id = '{}'",
            f.tenant
        ))
        .await;
    }
    f.done().await;
}

#[tokio::test]
async fn crash_after_pivot_converges_forward() {
    let admin = require_db!();
    let f = fx(&admin).await;
    for step in c::QA_SAGA_PIVOT..c::QA_SAGA_STEPS {
        let op = f
            .env
            .start(f.tenant, &format!("crash-post-{step}"), 7)
            .await
            .unwrap();
        assert_eq!(
            f.env.drive(op, Fault::CrashAfterStep(step)).await,
            DriveOutcome::Crashed
        );
        let mid = f.row(op).await;
        assert!(
            !PRE_PIVOT_STATES.contains(&mid.state.as_str())
                || f.hold(op).await.as_deref() == Some("committed")
        );
        f.env.reconcile(5).await.unwrap();
        f.assert_converged(op, 7, Some(true)).await;
        assert!(
            f.env.compensation_log(op).is_empty(),
            "compensation ran after the pivot committed (step {step})"
        );
        f.b.exec(&format!(
            "DELETE FROM qa_balance WHERE tenant_id = '{}'",
            f.tenant
        ))
        .await;
    }
    f.done().await;
}

#[tokio::test]
async fn lost_ack_after_step_is_idempotent() {
    let admin = require_db!();
    let f = fx(&admin).await;
    for step in 0..c::QA_SAGA_STEPS {
        let op = f
            .env
            .start(f.tenant, &format!("lost-ack-{step}"), 3)
            .await
            .unwrap();
        let out = f.env.drive(op, Fault::LoseAckAfterStep(step)).await;
        if out != DriveOutcome::Completed {
            f.env.reconcile(5).await.unwrap();
        }
        f.assert_converged(op, 3, Some(true)).await;
        assert_eq!(
            f.step_commits(op, step as i32).await,
            1,
            "step {step} committed twice after a lost acknowledgement"
        );
        f.b.exec(&format!(
            "DELETE FROM qa_balance WHERE tenant_id = '{}'",
            f.tenant
        ))
        .await;
    }
    f.done().await;
}

#[tokio::test]
async fn failure_before_pivot_compensates_in_reverse() {
    let admin = require_db!();
    let f = fx(&admin).await;
    // Permanent failure AT the pivot: steps 0 and 1 committed, pivot did not.
    let op = f.env.start(f.tenant, "fail-pivot", 9).await.unwrap();
    assert_eq!(
        f.env
            .drive(op, Fault::FailPermanentlyAt(c::QA_SAGA_PIVOT))
            .await,
        DriveOutcome::Compensated
    );
    assert_eq!(f.row(op).await.state, "compensated");
    assert_eq!(
        f.env.compensation_log(op),
        vec![1, 0],
        "compensation must run in reverse dependency order"
    );
    f.assert_converged(op, 9, Some(false)).await;
    // Permanent failure at step 1: only step 0 committed and is compensated; the failed step
    // itself committed nothing and needs no compensation.
    let op = f.env.start(f.tenant, "fail-1", 9).await.unwrap();
    assert_eq!(
        f.env.drive(op, Fault::FailPermanentlyAt(1)).await,
        DriveOutcome::Compensated
    );
    assert_eq!(f.env.compensation_log(op), vec![0]);
    assert_eq!(f.credit(op).await, None);
    f.done().await;
}

#[tokio::test]
async fn no_compensation_after_pivot() {
    let admin = require_db!();
    let f = fx(&admin).await;
    let op = f.env.start(f.tenant, "fail-post", 4).await.unwrap();
    let out = f
        .env
        .drive(op, Fault::FailPermanentlyAt(c::QA_SAGA_STEPS - 1))
        .await;
    assert_eq!(
        out,
        DriveOutcome::Blocked,
        "permanent post-pivot failure must end in blocked_for_operator"
    );
    let row = f.row(op).await;
    assert_eq!(row.state, "blocked_for_operator");
    assert!(
        f.env.compensation_log(op).is_empty(),
        "compensation after pivot"
    );
    assert_eq!(
        f.hold(op).await.as_deref(),
        Some("committed"),
        "committed user-visible result not preserved"
    );
    // The framework must refuse an explicit attempt to compensate after the pivot.
    for to in [
        "compensating",
        "compensated",
        "running_pre_pivot",
        "created",
    ] {
        let e = f.env.try_transition(op, row.version, to).await.unwrap_err();
        assert_eq!(
            e.code, "conflict",
            "transition blocked_for_operator -> {to} must be rejected with conflict"
        );
    }
    // Reconciliation keeps it blocked or completes it forward; never compensates.
    f.env.reconcile(3).await.unwrap();
    let s = f.row(op).await.state;
    assert!(
        s == "blocked_for_operator" || s == "completed",
        "post-pivot saga moved to {s}"
    );
    assert!(f.env.compensation_log(op).is_empty());
    f.done().await;
}

#[tokio::test]
async fn duplicate_step_delivery_is_idempotent() {
    let admin = require_db!();
    let f = fx(&admin).await;
    let op = f.env.start(f.tenant, "dup", 5).await.unwrap();
    assert_eq!(f.env.drive(op, Fault::None).await, DriveOutcome::Completed);
    for step in 0..c::QA_SAGA_STEPS {
        let original = f
            .env
            .step_result(op, step)
            .await
            .expect("recorded step result");
        for _ in 0..3 {
            let again = f.env.redeliver_step(op, step).await.unwrap();
            assert_eq!(
                again, original,
                "duplicate delivery of step {step} did not return the original result"
            );
        }
        assert_eq!(
            f.step_commits(op, step as i32).await,
            1,
            "duplicate delivery re-ran step {step}'s transaction"
        );
    }
    f.assert_converged(op, 5, Some(true)).await;
    f.done().await;
}

#[tokio::test]
async fn duplicate_saga_start_same_key_returns_same_operation() {
    let admin = require_db!();
    let f = fx(&admin).await;
    let a = f.env.start(f.tenant, "same-key", 1).await.unwrap();
    let b = f.env.start(f.tenant, "same-key", 1).await.unwrap();
    assert_eq!(a, b);
    // Concurrent duplicates also converge on one operation.
    let futs = (0..10).map(|_| f.env.start(f.tenant, "same-key-race", 2));
    let ids: Vec<Uuid> = futures::future::join_all(futs)
        .await
        .into_iter()
        .filter_map(Result::ok)
        .collect();
    assert!(
        !ids.is_empty() && ids.iter().all(|i| *i == ids[0]),
        "concurrent starts created different operations: {ids:?}"
    );
    assert_eq!(
        f.ops
            .scalar_i64("SELECT count(*) FROM sagas WHERE idempotency_key = 'same-key-race'")
            .await,
        1
    );
    // Same key in another tenant is a different operation.
    let other = f.env.start(Uuid::now_v7(), "same-key", 1).await.unwrap();
    assert_ne!(other, a);
    f.done().await;
}

#[tokio::test]
async fn same_key_different_digest_is_mismatch() {
    let admin = require_db!();
    let f = fx(&admin).await;
    f.env.start(f.tenant, "digest", 1).await.unwrap();
    let e = f.env.start(f.tenant, "digest", 2).await.unwrap_err();
    assert_eq!(
        (e.code.as_str(), e.status),
        ("idempotency_mismatch", 422),
        "App. C rule C4 / OQ-2"
    );
    f.done().await;
}

#[tokio::test]
async fn state_check_constraint_rejects_unknown_state() {
    let admin = require_db!();
    let f = fx(&admin).await;
    let op = f.env.start(f.tenant, "check", 1).await.unwrap();
    let mut conn = f.ops.connect().await;
    for bad in ["bogus", "failed", "superseded", "COMPLETED", ""] {
        let r = sqlx::query("UPDATE sagas SET state = $1 WHERE operation_id = $2")
            .bind(bad)
            .bind(op)
            .execute(&mut conn)
            .await;
        assert!(r.is_err(), "sagas.state accepted {bad:?}");
    }
    for ok in ALL_STATES {
        // Every contract state is admissible to the CHECK constraint (transition rules are the framework's job).
        let r = sqlx::query("UPDATE sagas SET state = $1 WHERE operation_id = $2")
            .bind(ok)
            .bind(op)
            .execute(&mut conn)
            .await;
        assert!(r.is_ok(), "sagas.state rejected contract state {ok}");
    }
    f.done().await;
}

#[tokio::test]
async fn cas_rejects_stale_version() {
    let admin = require_db!();
    let f = fx(&admin).await;
    let op = f.env.start(f.tenant, "cas", 1).await.unwrap();
    let v = f.row(op).await.version;
    f.env
        .try_transition(op, v, "running_pre_pivot")
        .await
        .unwrap();
    let e = f
        .env
        .try_transition(op, v, "running_pre_pivot")
        .await
        .unwrap_err();
    assert_eq!(
        e.code, "conflict",
        "transition with a stale version must fail the compare-and-set"
    );
    assert_eq!(
        f.row(op).await.version,
        v + 1,
        "version must advance exactly once"
    );
    f.done().await;
}

#[tokio::test]
async fn illegal_transitions_rejected() {
    let admin = require_db!();
    let f = fx(&admin).await;
    // Completed is terminal (App. F: terminal states never change).
    let op = f.env.start(f.tenant, "terminal", 1).await.unwrap();
    assert_eq!(f.env.drive(op, Fault::None).await, DriveOutcome::Completed);
    let v = f.row(op).await.version;
    for to in ALL_STATES.iter().filter(|s| **s != "completed") {
        let e = f.env.try_transition(op, v, to).await.unwrap_err();
        assert_eq!(e.code, "conflict", "completed -> {to} accepted");
    }
    // Compensated is terminal.
    let op = f.env.start(f.tenant, "terminal-comp", 1).await.unwrap();
    assert_eq!(
        f.env.drive(op, Fault::FailPermanentlyAt(0)).await,
        DriveOutcome::Compensated
    );
    let v = f.row(op).await.version;
    for to in ALL_STATES.iter().filter(|s| **s != "compensated") {
        assert_eq!(
            f.env.try_transition(op, v, to).await.unwrap_err().code,
            "conflict",
            "compensated -> {to} accepted"
        );
    }
    // Skipping the pivot is illegal: created -> completed / completing.
    let op = f.env.start(f.tenant, "skip", 1).await.unwrap();
    let v = f.row(op).await.version;
    for to in ["completed", "completing"] {
        assert_eq!(
            f.env.try_transition(op, v, to).await.unwrap_err().code,
            "conflict",
            "created -> {to} accepted"
        );
    }
    f.done().await;
}

#[tokio::test]
async fn reconciler_does_not_infer_failure_from_deadline() {
    let admin = require_db!();
    let f = fx(&admin).await;
    let op = f.env.start(f.tenant, "deadline", 6).await.unwrap();
    assert_eq!(
        f.env
            .drive(op, Fault::CrashAfterStep(c::QA_SAGA_PIVOT))
            .await,
        DriveOutcome::Crashed
    );
    assert_eq!(
        f.hold(op).await.as_deref(),
        Some("committed"),
        "precondition: pivot committed before the crash"
    );
    // Deadline long past, executor gone: authoritative state says the pivot committed, so the
    // only legal outcome is forward completion.
    f.ops
        .exec(&format!(
            "UPDATE sagas SET deadline = now() - interval '1 day' WHERE operation_id = '{op}'"
        ))
        .await;
    f.env.reconcile(5).await.unwrap();
    f.assert_converged(op, 6, Some(true)).await;
    assert!(
        f.env.compensation_log(op).is_empty(),
        "reconciler compensated a saga whose pivot committed"
    );
    f.done().await;
}
