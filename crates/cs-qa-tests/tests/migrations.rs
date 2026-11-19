//! Migration runner (App. E, §7.5, §24, App. L.3, contract §5.1).
//! Traceability: E-1, E-4, E-6, E-11..E-14, 24-2, 24-4, L.3-2, CT.M0-16, CT.M0-17.
#![cfg(any(feature = "m0-contract", feature = "qa-selfcheck"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[macro_use]
mod support;

use sqlx::Row;
use std::path::Path;
use std::time::Duration;
use support::contract as c;
use support::db::TestDb;
use support::spec;

const DOMAIN: &str = "resources";

fn write(dir: &Path, file: &str, sql: &str) {
    std::fs::write(dir.join(file), sql).unwrap();
}

const M1: &str = "CREATE TABLE IF NOT EXISTS qa_widgets (tenant_id uuid NOT NULL, widget_id uuid NOT NULL, name text NOT NULL,
  version bigint NOT NULL DEFAULT 0, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id, widget_id));\n";
const M2: &str = "ALTER TABLE qa_widgets ADD COLUMN IF NOT EXISTS colour text;\n";
const M3: &str =
    "CREATE INDEX IF NOT EXISTS qa_widgets_name_idx ON qa_widgets (tenant_id, name);\n";

async fn applied(db: &TestDb) -> Vec<(i32, String, String, Vec<u8>, String)> {
    let mut conn = db.connect().await;
    sqlx::query("SELECT version, name, class, checksum, applied_at::text FROM schema_migrations ORDER BY version")
        .fetch_all(&mut conn)
        .await
        .unwrap()
        .into_iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3), r.get(4)))
        .collect()
}

async fn table_exists(db: &TestDb, t: &str) -> bool {
    db.scalar_i64(&format!(
        "SELECT count(*) FROM information_schema.tables WHERE table_name = '{t}'"
    ))
    .await
        == 1
}

#[tokio::test]
async fn applies_in_order_and_records_checksums() {
    let admin = require_db!();
    let db = TestDb::create(&admin, "mig_order").await;
    let dir = tempfile::tempdir().unwrap();
    // Written out of order on purpose; the runner must order by version.
    write(dir.path(), "0003_widgets_name_idx.expand.sql", M3);
    write(dir.path(), "0001_widgets.expand.sql", M1);
    write(dir.path(), "0002_widgets_colour.expand.sql", M2);
    let ran = c::migrate_dir(&db.url, DOMAIN, dir.path()).await.unwrap();
    assert_eq!(ran, vec![1, 2, 3]);
    let rows = applied(&db).await;
    assert_eq!(rows.iter().map(|r| r.0).collect::<Vec<_>>(), vec![1, 2, 3]);
    assert!(
        rows.iter().all(|r| r.2 == "expand"),
        "class not recorded: {rows:?}"
    );
    assert!(
        rows.iter().all(|r| !r.3.is_empty()),
        "checksum not recorded"
    );
    assert_ne!(
        rows[0].3, rows[1].3,
        "different files must have different checksums"
    );
    assert!(table_exists(&db, "qa_widgets").await);
    db.drop_now().await;
}

#[tokio::test]
async fn rerun_is_noop() {
    let admin = require_db!();
    let db = TestDb::create(&admin, "mig_noop").await;
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "0001_widgets.expand.sql", M1);
    write(dir.path(), "0002_widgets_colour.expand.sql", M2);
    c::migrate_dir(&db.url, DOMAIN, dir.path()).await.unwrap();
    let before = applied(&db).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    for _ in 0..3 {
        let ran = c::migrate_dir(&db.url, DOMAIN, dir.path()).await.unwrap();
        assert!(ran.is_empty(), "re-run applied {ran:?}");
    }
    assert_eq!(
        applied(&db).await,
        before,
        "re-run modified schema_migrations (applied_at/checksum)"
    );
    db.drop_now().await;
}

#[tokio::test]
async fn checksum_tamper_is_hard_error() {
    let admin = require_db!();
    let db = TestDb::create(&admin, "mig_tamper").await;
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "0001_widgets.expand.sql", M1);
    c::migrate_dir(&db.url, DOMAIN, dir.path()).await.unwrap();
    let before = applied(&db).await;
    // Even a comment-only change to an applied file is tampering.
    for tampered in [
        format!("{M1}-- edited\n"),
        M1.replace("name text", "name  text"),
        String::new(),
    ] {
        write(dir.path(), "0001_widgets.expand.sql", &tampered);
        write(dir.path(), "0002_widgets_colour.expand.sql", M2);
        let r = c::migrate_dir(&db.url, DOMAIN, dir.path()).await;
        let err = r.expect_err("checksum mismatch on an applied migration must be a hard error");
        assert!(
            err.to_lowercase().contains("checksum"),
            "error should name the checksum mismatch: {err}"
        );
        assert_eq!(
            applied(&db).await,
            before,
            "runner applied later migrations despite tampering"
        );
    }
    // Deleting an applied file is also not silently accepted (fail closed).
    std::fs::remove_file(dir.path().join("0001_widgets.expand.sql")).unwrap();
    assert!(
        c::migrate_dir(&db.url, DOMAIN, dir.path()).await.is_err(),
        "missing applied migration file accepted"
    );
    db.drop_now().await;
}

#[tokio::test]
async fn failed_migration_not_recorded_and_retry_applies() {
    let admin = require_db!();
    let db = TestDb::create(&admin, "mig_fail").await;
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "0001_widgets.expand.sql", M1);
    write(
        dir.path(),
        "0002_widgets_colour.expand.sql",
        &format!(
            "{M2}INSERT INTO qa_widgets (tenant_id, widget_id, name) VALUES (gen_random_uuid(), gen_random_uuid(), 'x');\nSELECT 1/0;\n"
        ),
    );
    write(dir.path(), "0003_widgets_name_idx.expand.sql", M3);
    assert!(c::migrate_dir(&db.url, DOMAIN, dir.path()).await.is_err());
    let rows = applied(&db).await;
    assert_eq!(
        rows.iter().map(|r| r.0).collect::<Vec<_>>(),
        vec![1],
        "failed or later migrations were recorded"
    );
    assert_eq!(
        db.scalar_i64("SELECT count(*) FROM qa_widgets").await,
        0,
        "partial effects of the failed migration were kept"
    );
    let v1_applied_at = rows[0].4.clone();
    // Fixed file (not yet applied, so changing it is legitimate): resume from version 2.
    write(dir.path(), "0002_widgets_colour.expand.sql", M2);
    assert_eq!(
        c::migrate_dir(&db.url, DOMAIN, dir.path()).await.unwrap(),
        vec![2, 3]
    );
    assert_eq!(
        applied(&db).await[0].4,
        v1_applied_at,
        "version 1 re-applied"
    );
    db.drop_now().await;
}

#[tokio::test]
async fn interrupted_migration_resumes() {
    let admin = require_db!();
    let db = TestDb::create(&admin, "mig_crash").await;
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "0001_widgets.expand.sql", M1);
    // Slow, idempotent migration: the runner is killed in the middle of it.
    write(
        dir.path(),
        "0002_widgets_colour.expand.sql",
        &format!(
            "{M2}SELECT pg_sleep(3);\nCREATE TABLE IF NOT EXISTS qa_after_sleep (tenant_id uuid PRIMARY KEY);\n"
        ),
    );
    write(dir.path(), "0003_widgets_name_idx.expand.sql", M3);
    let url = db.url.clone();
    let path = dir.path().to_path_buf();
    let run = tokio::spawn(async move { c::migrate_dir(&url, DOMAIN, &path).await });
    tokio::time::sleep(Duration::from_millis(1200)).await;
    run.abort(); // simulated crash: the runner's future and connection are dropped mid-migration
    let _ = run.await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mid = applied(&db).await.iter().map(|r| r.0).collect::<Vec<_>>();
    assert!(
        mid == vec![1] || mid.is_empty(),
        "interrupted migration recorded as applied: {mid:?}"
    );
    // Same files (unchanged checksums): a fresh run must complete everything.
    let ran = c::migrate_dir(&db.url, DOMAIN, dir.path())
        .await
        .expect("resume after crash");
    assert!(ran.contains(&2) && ran.contains(&3), "resume ran {ran:?}");
    assert_eq!(
        applied(&db).await.iter().map(|r| r.0).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert!(table_exists(&db, "qa_after_sleep").await);
    db.drop_now().await;
}

#[tokio::test]
async fn contract_before_finalized_expand_refused() {
    let admin = require_db!();
    let db = TestDb::create(&admin, "mig_contract").await;
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "0001_widgets.expand.sql", M1);
    write(dir.path(), "0002_widgets_colour.expand.sql", M2);
    write(
        dir.path(),
        "0003_drop_colour.contract.sql",
        &format!(
            "{}ALTER TABLE qa_widgets DROP COLUMN IF EXISTS colour;\n",
            c::requires_finalized_header(2)
        ),
    );
    // Expand applied in the same (unfinalized) run: contract must be refused.
    let r = c::migrate_dir(&db.url, DOMAIN, dir.path()).await;
    assert!(
        r.is_err(),
        "contract migration applied before its expand was finalized"
    );
    let versions: Vec<i32> = applied(&db).await.iter().map(|r| r.0).collect();
    assert!(!versions.contains(&3), "contract recorded: {versions:?}");
    // The runner may refuse the whole run up front or apply the expands first; either way the
    // contract's effect must not happen.
    if versions.contains(&2) {
        let colour = db.scalar_i64("SELECT count(*) FROM information_schema.columns WHERE table_name='qa_widgets' AND column_name='colour'").await;
        assert_eq!(colour, 1, "column dropped by a refused contract migration");
    }
    // Contract without any requires_finalized header is refused too.
    write(
        dir.path(),
        "0003_drop_colour.contract.sql",
        "ALTER TABLE qa_widgets DROP COLUMN IF EXISTS colour;\n",
    );
    assert!(
        c::migrate_dir(&db.url, DOMAIN, dir.path()).await.is_err(),
        "contract migration without requires_finalized accepted"
    );
    // Contract that names a version that is not an expand (or does not exist) is refused.
    write(
        dir.path(),
        "0003_drop_colour.contract.sql",
        &format!(
            "{}ALTER TABLE qa_widgets DROP COLUMN IF EXISTS colour;\n",
            c::requires_finalized_header(9)
        ),
    );
    c::finalize_current_release(&db.url, DOMAIN).await.unwrap();
    assert!(
        c::migrate_dir(&db.url, DOMAIN, dir.path()).await.is_err(),
        "contract naming unknown expand 0009 accepted"
    );
    db.drop_now().await;
}

#[tokio::test]
async fn contract_after_finalized_expand_applies() {
    let admin = require_db!();
    let db = TestDb::create(&admin, "mig_contract_ok").await;
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "0001_widgets.expand.sql", M1);
    write(dir.path(), "0002_widgets_colour.expand.sql", M2);
    c::migrate_dir(&db.url, DOMAIN, dir.path()).await.unwrap();
    c::finalize_current_release(&db.url, DOMAIN).await.unwrap();
    write(
        dir.path(),
        "0003_drop_colour.contract.sql",
        &format!(
            "{}ALTER TABLE qa_widgets DROP COLUMN IF EXISTS colour;\n",
            c::requires_finalized_header(2)
        ),
    );
    assert_eq!(
        c::migrate_dir(&db.url, DOMAIN, dir.path()).await.unwrap(),
        vec![3]
    );
    let rows = applied(&db).await;
    assert_eq!(rows.last().map(|r| r.2.as_str()), Some("contract"));
    db.drop_now().await;
}

#[tokio::test]
async fn invalid_filename_or_class_rejected() {
    let admin = require_db!();
    for (i, bad) in [
        "0001_widgets.sql",
        "0001_widgets.destroy.sql",
        "abcd_widgets.expand.sql",
        "1_widgets.expand.sql",
        "0001-widgets.expand.sql",
        "0001_Widgets.expand.sql",
    ]
    .iter()
    .enumerate()
    {
        let db = TestDb::create(&admin, &format!("mig_name{i}")).await;
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), bad, M1);
        let r = c::migrate_dir(&db.url, DOMAIN, dir.path()).await;
        assert!(
            r.is_err(),
            "file {bad:?} accepted (fail closed: a misnamed migration must not be silently skipped)"
        );
        assert!(
            !table_exists(&db, "qa_widgets").await,
            "{bad}: migration content executed"
        );
        db.drop_now().await;
    }
}

#[tokio::test]
async fn duplicate_version_rejected() {
    let admin = require_db!();
    let db = TestDb::create(&admin, "mig_dup").await;
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "0001_widgets.expand.sql", M1);
    write(dir.path(), "0001_other.expand.sql", M2);
    assert!(
        c::migrate_dir(&db.url, DOMAIN, dir.path()).await.is_err(),
        "two migrations with version 0001 accepted"
    );
    assert!(
        applied(&db).await.is_empty(),
        "runner applied something despite a duplicate version"
    );
    db.drop_now().await;
}

#[tokio::test]
async fn schema_migrations_class_check_constraint() {
    let admin = require_db!();
    let db = TestDb::create(&admin, "mig_check").await;
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "0001_widgets.expand.sql", M1);
    c::migrate_dir(&db.url, DOMAIN, dir.path()).await.unwrap();
    let mut conn = db.connect().await;
    let r = sqlx::query("INSERT INTO schema_migrations (version, name, class, checksum) VALUES (99, 'x', 'destroy', '\\x00')")
        .execute(&mut conn)
        .await;
    assert!(
        r.is_err(),
        "schema_migrations.class accepts values outside expand|migrate|contract"
    );
    db.drop_now().await;
}

/// App. E conventions on every core table created by the embedded M0 migrations of each
/// domain. Exceptions are listed explicitly (OQ-16).
#[tokio::test]
async fn core_tables_follow_appendix_e() {
    let admin = require_db!();
    let not_tenant_first = ["outbox", "outbox_counters", "sagas", "schema_migrations"];
    let mut problems = Vec::new();
    for d in spec::DOMAINS {
        let db = TestDb::create(&admin, &format!("mig_e_{d}")).await;
        let dom = c::domain_open(d, &db.url).await.unwrap();
        c::domain_migrate(&dom).await.unwrap();
        let mut conn = db.connect().await;
        let tables: Vec<String> = sqlx::query(
            "SELECT table_name::text FROM information_schema.tables WHERE table_schema = 'public'",
        )
        .fetch_all(&mut conn)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.get(0))
        .collect();
        for t in &tables {
            if !t
                .chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
            {
                problems.push(format!("{d}.{t}: not snake_case"));
            }
            let cols: Vec<(String, String)> = sqlx::query(
                "SELECT column_name::text, data_type::text FROM information_schema.columns WHERE table_name = $1 ORDER BY ordinal_position",
            )
            .bind(t)
            .fetch_all(&mut conn)
            .await
            .unwrap()
            .into_iter()
            .map(|r| (r.get(0), r.get(1)))
            .collect();
            for (cname, ty) in &cols {
                if ty == "timestamp without time zone" {
                    problems.push(format!(
                        "{d}.{t}.{cname}: timestamp without time zone (App. E requires timestamptz)"
                    ));
                }
                if ty == "json" {
                    problems.push(format!(
                        "{d}.{t}.{cname}: json (use jsonb only for extension data)"
                    ));
                }
            }
            let has_tenant = cols.iter().any(|(n, _)| n == "tenant_id");
            if has_tenant && !not_tenant_first.contains(&t.as_str()) {
                let first_pk: Option<String> = sqlx::query(
                    "SELECT a.attname::text FROM pg_index i JOIN pg_class c ON c.oid = i.indrelid
                     JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = i.indkey[0]
                     WHERE c.relname = $1 AND i.indisprimary",
                )
                .bind(t)
                .fetch_optional(&mut conn)
                .await
                .unwrap()
                .map(|r| r.get(0));
                if first_pk.as_deref() != Some("tenant_id") {
                    problems.push(format!(
                        "{d}.{t}: tenant-scoped table whose first PK column is {first_pk:?}"
                    ));
                }
            }
        }
        let idx: Vec<(String, String)> = sqlx::query(
            "SELECT tablename::text, indexname::text FROM pg_indexes i WHERE schemaname = 'public' AND NOT EXISTS (
               SELECT 1 FROM pg_constraint k WHERE k.conname = i.indexname)",
        )
        .fetch_all(&mut conn)
        .await
        .unwrap()
        .into_iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
        for (t, i) in idx {
            if !(i.starts_with(&format!("{t}_")) && i.ends_with("_idx")) {
                problems.push(format!(
                    "{d}: index {i} on {t} not named <table>_<columns>_idx"
                ));
            }
        }
        let seqs = db
            .scalar_i64("SELECT count(*) FROM pg_sequences WHERE schemaname = 'public'")
            .await;
        if seqs > 0 {
            problems.push(format!(
                "{d}: {seqs} database sequence(s) (App. E: no DB sequences for identifiers)"
            ));
        }
        let fks = db
            .scalar_i64("SELECT count(*) FROM pg_constraint WHERE contype = 'f' AND connamespace = 'public'::regnamespace AND confrelid = 0")
            .await;
        if fks > 0 {
            problems.push(format!("{d}: foreign keys to unknown relations"));
        }
        drop(conn);
        db.drop_now().await;
    }
    assert!(
        problems.is_empty(),
        "App. E violations:\n{}",
        problems.join("\n")
    );
}
