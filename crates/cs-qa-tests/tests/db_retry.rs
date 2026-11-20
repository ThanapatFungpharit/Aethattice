//! Whole-transaction retry of SQLSTATE 40001/40P01 (§18.2, contract §5). The failures are real
//! errors raised by the database, not mocks.
//! Traceability: 18.2-3, CT.M0-14.
#![cfg(any(feature = "m0-contract", feature = "qa-selfcheck"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[macro_use]
mod support;

use support::contract as c;
use support::db::TestDb;

async fn fx(admin: &str) -> (TestDb, c::Domain) {
    let db = TestDb::create(admin, "retry").await;
    let dom = c::domain_open("resources", &db.url).await.unwrap();
    (db, dom)
}

/// Measure the retry wrapper without environmental interference: the contract's bound is
/// "10 attempts or 5 s" of elapsed time, so the measurement must not include the first
/// connection to a just-created database or catalog stalls caused by other tests running
/// CREATE/DROP DATABASE in parallel. The harness DDL guard is held during the probe, and the
/// pool is warmed by one successful transaction first. The assertions themselves are unchanged.
async fn probe(
    dom: &c::Domain,
    sqlstate: &str,
    fail_first: u32,
) -> (
    u32,
    Result<(), support::types::ErrorView>,
    std::time::Duration,
) {
    let _quiet = support::db::ddl_guard().await;
    let (warm, r) = c::retry_probe(dom, sqlstate, 0).await;
    assert_eq!((warm, r.is_ok()), (1, true), "warm-up transaction failed");
    // Time only the measured call (not the wait for the guard or the warm-up).
    let t = std::time::Instant::now();
    let (attempts, res) = c::retry_probe(dom, sqlstate, fail_first).await;
    (attempts, res, t.elapsed())
}

#[tokio::test]
async fn retries_40001_until_success() {
    let admin = require_db!();
    let (db, dom) = fx(&admin).await;
    let (attempts, res, _) = probe(&dom, "40001", 3).await;
    res.unwrap_or_else(|e| panic!("40001 x3 then success must succeed; got {e:?}"));
    assert_eq!(attempts, 4, "expected 3 failed attempts plus 1 success");
    db.drop_now().await;
}

#[tokio::test]
async fn retries_40p01() {
    let admin = require_db!();
    let (db, dom) = fx(&admin).await;
    let (attempts, res, _) = probe(&dom, "40P01", 2).await;
    res.unwrap();
    assert_eq!(attempts, 3);
    db.drop_now().await;
}

#[tokio::test]
async fn retry_bounded() {
    let admin = require_db!();
    let (db, dom) = fx(&admin).await;
    let (attempts, res, elapsed) = probe(&dom, "40001", u32::MAX).await;
    let e = res.expect_err("endless serialization failures must give up");
    assert!(
        attempts <= 10,
        "contract bound is 10 attempts; made {attempts}"
    );
    assert!(
        attempts >= 2,
        "40001 was not retried at all (attempts {attempts}, error {e:?})"
    );
    assert!(
        elapsed <= std::time::Duration::from_secs(7),
        "contract bound is ~5 s; took {elapsed:?}"
    );
    // OQ-14: exhaustion is a retryable server-side condition, not a client conflict.
    assert!(
        e.retryable,
        "exhausted retry must map to a retryable code, got {e:?}"
    );
    assert_ne!(e.code, "conflict");
    db.drop_now().await;
}

#[tokio::test]
async fn non_retryable_sqlstate_not_retried() {
    let admin = require_db!();
    let (db, dom) = fx(&admin).await;
    for state in ["23505", "23514", "42P01", "22012"] {
        let (attempts, res, _) = probe(&dom, state, 1).await;
        assert!(res.is_err(), "{state}: error swallowed");
        assert_eq!(
            attempts, 1,
            "{state} must not be retried (only 40001/40P01 are)"
        );
    }
    db.drop_now().await;
}
