//! Idempotency records (App. D.3, App. C rule C4, contract §5.3).
//! Traceability: D.3-2, D.3-3, D.2-6, D.2-11, C.2-4, 18.2-4, E-10, CT.M0-20, CT.M0-21.
#![cfg(any(feature = "m0-contract", feature = "qa-selfcheck"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[macro_use]
mod support;

use std::sync::Arc;
use support::contract as c;
use support::db::TestDb;
use support::spec;
use support::types::{IdemRequest, IdemResponse};
use uuid::Uuid;

struct Fx {
    db: TestDb,
    dom: c::Domain,
    tenant: Uuid,
    principal: Uuid,
}

async fn fx(admin: &str) -> Fx {
    let db = TestDb::create(admin, "idem").await;
    let dom = c::domain_open("resources", &db.url).await.unwrap();
    {
        let _g = support::db::ddl_guard().await;
        c::domain_migrate(&dom).await.unwrap();
        db.exec("CREATE TABLE qa_effects (tenant_id uuid NOT NULL, effect_id uuid NOT NULL, tag text NOT NULL, PRIMARY KEY (tenant_id, effect_id))")
            .await;
    }
    Fx {
        db,
        dom,
        tenant: Uuid::now_v7(),
        principal: Uuid::now_v7(),
    }
}

fn req(body: &str) -> IdemRequest {
    IdemRequest {
        method: "POST".into(),
        route_template: "/api/v2/spaces/{space_id}/things".into(),
        path_params: vec![(
            "space_id".into(),
            "0190a0a0-0000-7000-8000-000000000001".into(),
        )],
        body: body.as_bytes().to_vec(),
    }
}

async fn effects(f: &Fx, tag: &str) -> i64 {
    f.db.scalar_i64(&format!(
        "SELECT count(*) FROM qa_effects WHERE tag = '{tag}'"
    ))
    .await
}

fn key() -> String {
    format!("qa-{}", Uuid::new_v4())
}

#[tokio::test]
async fn schema_matches_contract() {
    let admin = require_db!();
    let f = fx(&admin).await;
    let cols = f
        .db
        .scalar_i64(
            "SELECT count(*) FROM information_schema.columns WHERE table_name = 'idempotency_records' AND
             (column_name, data_type) IN (('tenant_id','uuid'),('principal_id','uuid'),('key','text'),('request_digest','bytea'),
             ('state','text'),('response','bytea'),('expires_at','timestamp with time zone'))",
        )
        .await;
    assert_eq!(
        cols, 7,
        "idempotency_records columns differ from contract §5.3"
    );
    let pk = f
        .db
        .scalar_i64(
            "SELECT count(*) FROM pg_index i JOIN pg_class t ON t.oid = i.indrelid
             WHERE t.relname = 'idempotency_records' AND i.indisprimary AND
             (SELECT array_agg(a.attname::text ORDER BY k.ord) FROM unnest(i.indkey) WITH ORDINALITY k(attnum, ord)
              JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum) = ARRAY['tenant_id','principal_id','key']",
        )
        .await;
    assert_eq!(
        pk, 1,
        "primary key must be (tenant_id, principal_id, key) with tenant_id first (App. E)"
    );
    // CHECK constraint on state (App. E).
    let mut conn = f.db.connect().await;
    let bad = sqlx::query(
        "INSERT INTO idempotency_records (tenant_id, principal_id, key, request_digest, state, expires_at)
         VALUES (gen_random_uuid(), gen_random_uuid(), 'k', '\\x00', 'bogus', now())",
    )
    .execute(&mut conn)
    .await;
    assert!(bad.is_err(), "state CHECK constraint missing");
    f.db.drop_now().await;
}

#[tokio::test]
async fn replay_returns_identical_response() {
    let admin = require_db!();
    let f = fx(&admin).await;
    let k = key();
    let first = c::idem_execute(
        &f.dom,
        f.tenant,
        f.principal,
        &k,
        &req("{\"a\":1}"),
        "replay",
        false,
    )
    .await
    .unwrap();
    for _ in 0..3 {
        let again = c::idem_execute(
            &f.dom,
            f.tenant,
            f.principal,
            &k,
            &req("{\"a\":1}"),
            "replay",
            false,
        )
        .await
        .unwrap();
        assert_eq!(
            again, first,
            "replay must return the byte-identical stored response"
        );
    }
    assert_eq!(
        effects(&f, "replay").await,
        1,
        "replay re-executed the effect"
    );
    f.db.drop_now().await;
}

#[tokio::test]
async fn different_digest_is_idempotency_mismatch_422() {
    let admin = require_db!();
    let f = fx(&admin).await;
    let k = key();
    c::idem_execute(
        &f.dom,
        f.tenant,
        f.principal,
        &k,
        &req("{\"a\":1}"),
        "mm",
        false,
    )
    .await
    .unwrap();
    let e = c::idem_execute(
        &f.dom,
        f.tenant,
        f.principal,
        &k,
        &req("{\"a\":2}"),
        "mm",
        false,
    )
    .await
    .unwrap_err();
    assert_eq!(
        (e.code.as_str(), e.status, e.retryable),
        ("idempotency_mismatch", 422, false)
    );
    assert_eq!(effects(&f, "mm").await, 1);
    // The original stays replayable after a mismatch attempt.
    c::idem_execute(
        &f.dom,
        f.tenant,
        f.principal,
        &k,
        &req("{\"a\":1}"),
        "mm",
        false,
    )
    .await
    .unwrap();
    assert_eq!(effects(&f, "mm").await, 1);
    f.db.drop_now().await;
}

#[test]
fn digest_covers_method_route_params_and_body() {
    let base = req("{\"a\":1}");
    let d0 = c::idem_digest(&base);
    assert_eq!(d0.len(), 32, "BLAKE3-256 digest expected");
    assert_eq!(
        d0,
        c::idem_digest(&base.clone()),
        "digest must be deterministic"
    );
    let mut variants = Vec::new();
    let mut v = base.clone();
    v.method = "PUT".into();
    variants.push(("method", v));
    let mut v = base.clone();
    v.route_template = "/api/v2/spaces/{space_id}/other".into();
    variants.push(("route", v));
    let mut v = base.clone();
    v.path_params[0].1 = "0190a0a0-0000-7000-8000-000000000002".into();
    variants.push(("path param value", v));
    let mut v = base.clone();
    v.path_params[0].0 = "parent_id".into();
    variants.push(("path param name", v));
    let mut v = base.clone();
    v.body = b"{\"a\":2}".to_vec();
    variants.push(("body", v));
    // Ambiguity attacks: shifting bytes between fields must not collide.
    let mut v = base.clone();
    v.route_template = "/api/v2/spaces/{space_id}/thingsP".into();
    v.method = "OST".into();
    variants.push(("field boundary", v));
    for (what, r) in variants {
        assert_ne!(c::idem_digest(&r), d0, "digest ignores {what}");
    }
    // Contract rev 2 (OQ-5 resolved): the JSON body is canonicalized with RFC 8785 (JCS), so
    // key order and insignificant whitespace do not change the digest, but values do.
    let body = |b: &[u8]| IdemRequest {
        body: b.to_vec(),
        ..req("")
    };
    assert_eq!(
        c::idem_digest(&body(b"{\"b\":2,\"a\":1}")),
        c::idem_digest(&body(b"{ \"a\" : 1, \"b\" : 2 }")),
        "JCS: key order / whitespace must not change the digest"
    );
    assert_ne!(
        c::idem_digest(&body(b"{\"a\":1}")),
        c::idem_digest(&body(b"{\"a\":\"1\"}")),
        "JCS: number vs string must change the digest"
    );
    // Absent body digests as the empty string; an empty JSON object is a different body.
    assert_ne!(c::idem_digest(&body(b"")), c::idem_digest(&body(b"{}")));
}

#[tokio::test]
async fn concurrent_identical_requests_single_effect() {
    let admin = require_db!();
    let f = Arc::new(fx(&admin).await);
    for round in 0..5 {
        let k = key();
        let tag = format!("race{round}");
        let n = 24;
        let barrier = Arc::new(tokio::sync::Barrier::new(n));
        let mut tasks = Vec::new();
        for _ in 0..n {
            let (f, k, tag, barrier) = (f.clone(), k.clone(), tag.clone(), barrier.clone());
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                c::idem_execute(
                    &f.dom,
                    f.tenant,
                    f.principal,
                    &k,
                    &req("{\"race\":true}"),
                    &tag,
                    false,
                )
                .await
            }));
        }
        let mut ok: Vec<IdemResponse> = Vec::new();
        for t in tasks {
            match t.await.unwrap() {
                Ok(r) => ok.push(r),
                // Contract rev 3: a concurrent duplicate blocks and then receives the stored
                // result; outcome_unknown (504, retryable) is the only other admissible outcome.
                Err(e) => assert!(
                    e.code == "outcome_unknown" && e.retryable && e.status == 504,
                    "race loser got unexpected error {e:?}"
                ),
            }
        }
        assert!(!ok.is_empty(), "no racer succeeded");
        assert!(
            ok.windows(2).all(|w| w[0] == w[1]),
            "racers received different responses: exactly one effect must be visible"
        );
        assert_eq!(
            effects(&f, &tag).await,
            1,
            "round {round}: {n} identical concurrent requests produced more than one effect"
        );
        // After the race settles every retry is a replay of the single result.
        let settled = c::idem_execute(
            &f.dom,
            f.tenant,
            f.principal,
            &k,
            &req("{\"race\":true}"),
            &tag,
            false,
        )
        .await
        .unwrap();
        assert_eq!(settled, ok[0]);
    }
    if let Ok(f) = Arc::try_unwrap(f) {
        f.db.drop_now().await;
    }
}

#[tokio::test]
async fn in_progress_record_is_outcome_unknown() {
    let admin = require_db!();
    let f = fx(&admin).await;
    let k = key();
    let digest = c::idem_digest(&req("{\"a\":1}"));
    // Saga-backed operations persist an in_progress record before completion (contract §5.3).
    let mut conn = f.db.connect().await;
    sqlx::query(
        "INSERT INTO idempotency_records (tenant_id, principal_id, key, request_digest, state, expires_at)
         VALUES ($1, $2, $3, $4, 'in_progress', now() + interval '24 hours')",
    )
    .bind(f.tenant)
    .bind(f.principal)
    .bind(&k)
    .bind(&digest)
    .execute(&mut conn)
    .await
    .unwrap();
    let e = c::idem_execute(
        &f.dom,
        f.tenant,
        f.principal,
        &k,
        &req("{\"a\":1}"),
        "inprog",
        false,
    )
    .await
    .unwrap_err();
    // Contract rev 3: a visible (separately committed) in_progress record yields
    // outcome_unknown (504, retryable).
    assert!(
        e.code == "outcome_unknown" && e.status == 504 && e.retryable,
        "visible in-progress record must give outcome_unknown (504, retryable); got {e:?}"
    );
    assert_eq!(
        effects(&f, "inprog").await,
        0,
        "duplicate executed while original in progress"
    );
    // Different digest while in progress is still a mismatch, not a conflict.
    let e = c::idem_execute(
        &f.dom,
        f.tenant,
        f.principal,
        &k,
        &req("{\"a\":9}"),
        "inprog",
        false,
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, "idempotency_mismatch");
    f.db.drop_now().await;
}

#[tokio::test]
async fn key_scoped_to_tenant_and_principal() {
    let admin = require_db!();
    let f = fx(&admin).await;
    let k = key();
    let a = c::idem_execute(
        &f.dom,
        f.tenant,
        f.principal,
        &k,
        &req("{\"a\":1}"),
        "scope",
        false,
    )
    .await
    .unwrap();
    // Same key, other principal in the same tenant: independent, never sees A's response.
    let other_principal = Uuid::now_v7();
    let b = c::idem_execute(
        &f.dom,
        f.tenant,
        other_principal,
        &k,
        &req("{\"a\":1}"),
        "scope",
        false,
    )
    .await
    .unwrap();
    assert_ne!(
        a, b,
        "response of another principal replayed (cross-principal leak)"
    );
    // Same key and principal id, other tenant: independent.
    let other_tenant = Uuid::now_v7();
    let t = c::idem_execute(
        &f.dom,
        other_tenant,
        f.principal,
        &k,
        &req("{\"a\":1}"),
        "scope",
        false,
    )
    .await
    .unwrap();
    assert_ne!(
        a, t,
        "response of another tenant replayed (cross-tenant leak)"
    );
    assert_eq!(effects(&f, "scope").await, 3);
    // A different body under another principal is not a mismatch with A's record.
    c::idem_execute(
        &f.dom,
        f.tenant,
        Uuid::now_v7(),
        &k,
        &req("{\"z\":0}"),
        "scope",
        false,
    )
    .await
    .unwrap();
    f.db.drop_now().await;
}

#[tokio::test]
async fn invalid_keys_rejected() {
    let admin = require_db!();
    let f = fx(&admin).await;
    let long = "k".repeat(spec::IDEMPOTENCY_KEY_MAX_LEN + 1);
    let max = "k".repeat(spec::IDEMPOTENCY_KEY_MAX_LEN);
    for bad in [
        "",
        " ",
        "has space",
        "tab\tkey",
        "nl\nkey",
        "nul\0key",
        "caf\u{e9}",
        "\u{7f}del",
        long.as_str(),
    ] {
        let e = c::idem_execute(
            &f.dom,
            f.tenant,
            f.principal,
            bad,
            &req("{}"),
            "badkey",
            false,
        )
        .await
        .unwrap_err();
        assert_eq!(
            (e.code.as_str(), e.status),
            ("invalid_request", 400),
            "key {bad:?}"
        );
    }
    assert_eq!(effects(&f, "badkey").await, 0);
    for good in [
        "a",
        "!~",
        max.as_str(),
        "0190a0a0-0000-7000-8000-000000000001",
    ] {
        c::idem_execute(
            &f.dom,
            f.tenant,
            f.principal,
            good,
            &req("{}"),
            "goodkey",
            false,
        )
        .await
        .unwrap_or_else(|e| panic!("valid key {good:?} rejected: {e:?}"));
    }
    f.db.drop_now().await;
}

#[tokio::test]
async fn expired_record_not_replayed() {
    let admin = require_db!();
    let f = fx(&admin).await;
    let k = key();
    let first = c::idem_execute(
        &f.dom,
        f.tenant,
        f.principal,
        &k,
        &req("{\"a\":1}"),
        "exp",
        false,
    )
    .await
    .unwrap();
    // Retention is 24 h (D.3 policy): the stored expiry must be now()+24h within tolerance.
    let hours = f
        .db
        .scalar_i64(&format!(
            "SELECT round(extract(epoch FROM (expires_at - now())) / 3600)::bigint FROM idempotency_records WHERE key = '{k}'"
        ))
        .await;
    assert_eq!(
        hours,
        spec::IDEMPOTENCY_RETENTION_HOURS,
        "expires_at must be now() + 24 h"
    );
    f.db.exec(&format!(
        "UPDATE idempotency_records SET expires_at = now() - interval '1 second' WHERE key = '{k}'"
    ))
    .await;
    // OQ-21: after expiry the key is treated as new.
    let second = c::idem_execute(
        &f.dom,
        f.tenant,
        f.principal,
        &k,
        &req("{\"a\":1}"),
        "exp",
        false,
    )
    .await
    .unwrap();
    assert_ne!(first, second, "expired record was replayed");
    assert_eq!(effects(&f, "exp").await, 2);
    f.db.drop_now().await;
}

#[tokio::test]
async fn record_written_in_same_transaction_as_effect() {
    let admin = require_db!();
    let f = fx(&admin).await;
    let k = key();
    let e = c::idem_execute(
        &f.dom,
        f.tenant,
        f.principal,
        &k,
        &req("{\"a\":1}"),
        "atomic",
        true,
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, "invalid_request");
    assert_eq!(
        effects(&f, "atomic").await,
        0,
        "failed effect left a row behind"
    );
    let recs =
        f.db.scalar_i64(&format!(
            "SELECT count(*) FROM idempotency_records WHERE key = '{k}'"
        ))
        .await;
    assert_eq!(
        recs, 0,
        "idempotency record survived the rollback of its effect"
    );
    // The key is free: the corrected retry executes once.
    c::idem_execute(
        &f.dom,
        f.tenant,
        f.principal,
        &k,
        &req("{\"a\":1}"),
        "atomic",
        false,
    )
    .await
    .unwrap();
    assert_eq!(effects(&f, "atomic").await, 1);
    f.db.drop_now().await;
}

#[tokio::test]
async fn oversized_response_refused_as_internal() {
    // Contract rev 2: stored responses are <= 64 KiB; an operation whose response could be
    // larger must return a reference. Exceeding the limit is an `internal` error, never
    // truncation, and (record and effect sharing one transaction) leaves no effect behind.
    let admin = require_db!();
    let f = fx(&admin).await;
    let k = key();
    let e = c::idem_execute(
        &f.dom,
        f.tenant,
        f.principal,
        &k,
        &req("{}"),
        "big:1",
        false,
    )
    .await
    .expect_err("a > 64 KiB stored response must be refused");
    assert_eq!(e.code, "internal", "{e:?}");
    assert_eq!(
        effects(&f, "big:1").await,
        0,
        "effect committed although its response was refused"
    );
    let max_row =
        f.db.scalar_i64(
            "SELECT coalesce(max(octet_length(response)), 0)::bigint FROM idempotency_records",
        )
        .await;
    assert!(
        max_row as usize <= spec::MAX_ROW_PAYLOAD,
        "response column holds {max_row} bytes (> 64 KiB, App. E)"
    );
    f.db.drop_now().await;
}
