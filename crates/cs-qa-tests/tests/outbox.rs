//! Transactional outbox (App. C rule C2, App. E, §11.1, §18.4, contract §5.2).
//! Traceability: 2.4-4, 11.1-2, 18.4-10, C.2-2, C.3-7, E-8, E-10, CT.M0-18, CT.M0-19.
#![cfg(any(feature = "m0-contract", feature = "qa-selfcheck"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[macro_use]
mod support;

use sqlx::Row;
use std::collections::BTreeMap;
use std::sync::Arc;
use support::contract as c;
use support::db::TestDb;
use support::spec;
use uuid::Uuid;

async fn fx(admin: &str, label: &str) -> (TestDb, c::Domain) {
    let db = TestDb::create(admin, label).await;
    let dom = c::domain_open("resources", &db.url).await.unwrap();
    c::domain_migrate(&dom).await.unwrap();
    (db, dom)
}

/// All (partition, sequence) pairs in the outbox, via plain SQL on the frozen schema.
async fn sequences(db: &TestDb) -> BTreeMap<i32, Vec<i64>> {
    let mut conn = db.connect().await;
    let rows = sqlx::query("SELECT partition, sequence FROM outbox ORDER BY partition, sequence")
        .fetch_all(&mut conn)
        .await
        .unwrap();
    let mut m: BTreeMap<i32, Vec<i64>> = BTreeMap::new();
    for r in rows {
        m.entry(r.get::<i32, _>(0))
            .or_default()
            .push(r.get::<i64, _>(1));
    }
    m
}

fn assert_contiguous(m: &BTreeMap<i32, Vec<i64>>) {
    for (p, seqs) in m {
        for w in seqs.windows(2) {
            assert_eq!(
                w[1],
                w[0] + 1,
                "partition {p}: gap or duplicate between {} and {}",
                w[0],
                w[1]
            );
        }
        assert!(
            seqs[0] <= 1,
            "partition {p}: first sequence {} (expected 0 or 1; earlier values lost?)",
            seqs[0]
        );
    }
}

#[tokio::test]
async fn outbox_schema_matches_contract() {
    let admin = require_db!();
    let (db, _dom) = fx(&admin, "obx_schema").await;
    let cols = db
        .scalar_i64(
            "SELECT count(*) FROM information_schema.columns WHERE table_name = 'outbox' AND (column_name, data_type, is_nullable) IN (
              ('tenant_id','uuid','NO'),('partition','integer','NO'),('sequence','bigint','NO'),('event_id','uuid','NO'),
              ('event_type','text','NO'),('event_version','integer','NO'),('partition_key','uuid','NO'),('payload','bytea','NO'),
              ('created_at','timestamp with time zone','NO'))",
        )
        .await;
    assert_eq!(cols, 9, "outbox columns differ from contract §5.2");
    let counters = db
        .scalar_i64(
            "SELECT count(*) FROM information_schema.columns WHERE table_name = 'outbox_counters' AND
             (column_name, data_type) IN (('partition','integer'),('next_sequence','bigint'))",
        )
        .await;
    assert_eq!(
        counters, 2,
        "outbox_counters columns differ from contract §5.2"
    );
    let created_default = db
        .scalar_i64(
            "SELECT count(*) FROM information_schema.columns WHERE table_name = 'outbox' AND column_name = 'created_at'
             AND column_default ILIKE '%now()%'",
        )
        .await;
    assert_eq!(
        created_default, 1,
        "created_at must default to now() (DB-set time, App. E)"
    );
    db.drop_now().await;
}

#[tokio::test]
async fn concurrent_writers_contiguous_sequences() {
    let admin = require_db!();
    let (db, dom) = fx(&admin, "obx_conc").await;
    let dom = Arc::new(dom);
    let tenant = Uuid::now_v7();
    // A few partition keys so several writers contend on the same partition counter.
    let keys: Vec<Uuid> = (0..4).map(|_| Uuid::now_v7()).collect();
    let writers = 16;
    let per_writer = 25;
    let mut tasks = Vec::new();
    for w in 0..writers {
        let (dom, keys) = (dom.clone(), keys.clone());
        tasks.push(tokio::spawn(async move {
            let mut committed = Vec::new();
            for i in 0..per_writer {
                let commit = (w + i) % 5 != 0; // every 5th transaction rolls back
                let key = keys[(w * 7 + i) % keys.len()];
                match c::outbox_append(
                    &dom,
                    tenant,
                    key,
                    "qa.event",
                    vec![w as u8, i as u8],
                    commit,
                )
                .await
                {
                    Ok(Some(a)) => committed.push(a),
                    Ok(None) => {}
                    Err(e) => assert!(e.retryable, "non-retryable error under contention: {e:?}"),
                }
            }
            committed
        }));
    }
    let mut acked = Vec::new();
    for t in tasks {
        acked.extend(t.await.unwrap());
    }
    let m = sequences(&db).await;
    assert_contiguous(&m);
    let total: usize = m.values().map(Vec::len).sum();
    assert_eq!(
        total,
        acked.len(),
        "rows in outbox != acknowledged appends (lost or phantom events)"
    );
    let mut seen = std::collections::HashSet::new();
    for a in &acked {
        assert!(
            seen.insert((a.partition, a.sequence)),
            "duplicate (partition, sequence) {a:?}"
        );
        assert!(
            m[&a.partition].contains(&a.sequence),
            "acknowledged {a:?} not in table"
        );
    }
    db.drop_now().await;
}

#[tokio::test]
async fn rollback_leaves_no_gap() {
    let admin = require_db!();
    let (db, dom) = fx(&admin, "obx_rb").await;
    let tenant = Uuid::now_v7();
    let key = Uuid::now_v7();
    let a = c::outbox_append(&dom, tenant, key, "qa.event", vec![1], true)
        .await
        .unwrap()
        .unwrap();
    for _ in 0..3 {
        assert!(
            c::outbox_append(&dom, tenant, key, "qa.event", vec![2], false)
                .await
                .unwrap()
                .is_none()
        );
    }
    let b = c::outbox_append(&dom, tenant, key, "qa.event", vec![3], true)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(a.partition, b.partition);
    assert_eq!(
        b.sequence,
        a.sequence + 1,
        "rolled-back appends consumed sequence numbers"
    );
    let rows = c::outbox_read(&dom, a.partition, a.sequence - 1, 100)
        .await
        .unwrap();
    assert_eq!(
        rows.iter().map(|r| r.0).collect::<Vec<_>>(),
        vec![a.sequence, b.sequence]
    );
    assert_eq!(
        db.scalar_i64("SELECT count(*) FROM outbox").await,
        2,
        "rolled-back event persisted"
    );
    db.drop_now().await;
}

#[tokio::test]
async fn gap_detected_after_row_deletion() {
    let admin = require_db!();
    let (db, dom) = fx(&admin, "obx_gap").await;
    let tenant = Uuid::now_v7();
    let key = Uuid::now_v7();
    let mut appended = Vec::new();
    for i in 0..5u8 {
        appended.push(
            c::outbox_append(&dom, tenant, key, "qa.event", vec![i], true)
                .await
                .unwrap()
                .unwrap(),
        );
    }
    let p = appended[0].partition;
    let victim = appended[2].sequence;
    db.exec(&format!(
        "DELETE FROM outbox WHERE partition = {p} AND sequence = {victim}"
    ))
    .await;
    let r = c::outbox_read(&dom, p, appended[0].sequence - 1, 100).await;
    assert!(
        r.is_err(),
        "reader silently skipped deleted sequence {victim}: {r:?}"
    );
    // Reading past the gap must not hide it either.
    let r = c::outbox_read(&dom, p, appended[1].sequence, 100).await;
    assert!(
        r.is_err(),
        "reader starting right before the gap did not detect it: {r:?}"
    );
    // Reading entirely before the gap is fine.
    let ok = c::outbox_read(&dom, p, appended[0].sequence - 1, 2)
        .await
        .unwrap();
    assert_eq!(ok.len(), 2);
    db.drop_now().await;
}

#[tokio::test]
async fn same_partition_key_same_partition() {
    let admin = require_db!();
    let (db, dom) = fx(&admin, "obx_part").await;
    let tenant = Uuid::now_v7();
    let mut partitions = std::collections::HashSet::new();
    for _ in 0..64 {
        let key = Uuid::now_v7();
        let a = c::outbox_append(&dom, tenant, key, "qa.event", vec![], true)
            .await
            .unwrap()
            .unwrap();
        let b = c::outbox_append(&dom, Uuid::now_v7(), key, "qa.other", vec![], true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            a.partition, b.partition,
            "partition depends on something other than the partition key"
        );
        assert!(a.partition >= 0);
        partitions.insert(a.partition);
    }
    let p_count = db.scalar_i64("SELECT count(*) FROM outbox_counters").await;
    assert!(
        partitions.len() as i64 <= p_count.max(1),
        "more partitions used than counters exist"
    );
    db.drop_now().await;
}

#[tokio::test]
async fn oversized_payload_rejected() {
    let admin = require_db!();
    let (db, dom) = fx(&admin, "obx_big").await;
    let tenant = Uuid::now_v7();
    let key = Uuid::now_v7();
    let e = c::outbox_append(
        &dom,
        tenant,
        key,
        "qa.event",
        vec![0u8; spec::MAX_ROW_PAYLOAD + 1],
        true,
    )
    .await
    .unwrap_err();
    assert!(
        !e.retryable,
        "oversized payload must be a permanent error, got {e:?}"
    );
    assert_eq!(db.scalar_i64("SELECT count(*) FROM outbox").await, 0);
    // The failed append must not burn a sequence number either.
    let a = c::outbox_append(&dom, tenant, key, "qa.event", vec![1], true)
        .await
        .unwrap()
        .unwrap();
    let b = c::outbox_append(&dom, tenant, key, "qa.event", vec![2], true)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(b.sequence, a.sequence + 1);
    assert!(
        a.sequence <= 1,
        "failed oversized append consumed a sequence"
    );
    db.drop_now().await;
}

#[tokio::test]
async fn event_ids_are_uuidv7() {
    let admin = require_db!();
    let (db, dom) = fx(&admin, "obx_ids").await;
    let tenant = Uuid::now_v7();
    let mut prev: Option<Uuid> = None;
    for _ in 0..20 {
        let a = c::outbox_append(&dom, tenant, Uuid::now_v7(), "qa.event", vec![], true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            a.event_id.get_version_num(),
            7,
            "event_id {} is not UUIDv7",
            a.event_id
        );
        if let Some(p) = prev {
            assert_ne!(p, a.event_id);
        }
        prev = Some(a.event_id);
    }
    db.drop_now().await;
}
