//! Identity domain schema and administration tests (M1 contract §0, §1; spec §5.1, §6.4,
//! App. E, J.4 step 4). Each test uses its own databases (cs_db::testing) and cleans up.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use cs_common::error::{Code, ErrorCode};
use cs_common::id::{GroupId, TenantId, UserId};
use cs_common::vector::DomainId;
use cs_db::DomainPool;
use cs_db::migrate::{MigrationSet, Migrator, common_migrations};
use cs_db::testing::TestDomains;
use cs_identity::admin::{
    GROUP_COMPLEXITY_LIMIT, GROUP_CYCLE, GroupLimits, IdentityAdmin, Member, NewUser, UserKind,
    UserStatus,
};
use cs_identity::token;
use sqlx::Row;

const ID: DomainId = DomainId::Identity;

fn set() -> MigrationSet {
    common_migrations()
        .unwrap()
        .merge(cs_identity::migrations().unwrap())
        .unwrap()
}

async fn setup() -> Option<(TestDomains, IdentityAdmin)> {
    let t = TestDomains::create(&[ID]).await?;
    Migrator::run(t.pool(&ID), &set()).await.unwrap();
    let a = IdentityAdmin::new(t.pool(&ID).clone()).unwrap();
    Some((t, a))
}

fn code(e: &cs_common::Error) -> ErrorCode {
    match e.code() {
        Code::Core(c) => *c,
        Code::App(a) => panic!("unexpected app code {a}"),
    }
}

/// (event_type, payload) of the tenant's outbox, in sequence order per partition.
async fn events(p: &DomainPool, tenant: TenantId) -> Vec<(String, Vec<u8>)> {
    p.read_snapshot(move |tx| {
        Box::pin(async move {
            Ok(sqlx::query_as(
                "SELECT event_type, payload FROM outbox WHERE tenant_id = $1 ORDER BY partition, sequence",
            )
            .bind(tenant.as_uuid())
            .fetch_all(tx.conn())
            .await?)
        })
    })
    .await
    .unwrap()
}

async fn exec(p: &DomainPool, sql: impl Into<String>) -> Result<u64, cs_db::DbError> {
    let sql: String = sql.into();
    p.transaction(move |tx| {
        let sql = sql.clone();
        Box::pin(async move {
            Ok(sqlx::raw_sql(sqlx::AssertSqlSafe(sql))
                .execute(tx.conn())
                .await?
                .rows_affected())
        })
    })
    .await
}

async fn rows(p: &DomainPool, sql: &'static str) -> Vec<sqlx::postgres::PgRow> {
    p.read_snapshot(move |tx| {
        Box::pin(async move { Ok(sqlx::query(sql).fetch_all(tx.conn()).await?) })
    })
    .await
    .unwrap()
}

fn user(login: &str) -> NewUser {
    NewUser {
        login: login.into(),
        kind: UserKind::Member,
        display_name: None,
    }
}

#[tokio::test]
async fn schema_follows_contract_and_appendix_e() {
    let Some((t, _a)) = setup().await else { return };
    let p = t.pool(&ID);
    // re-run is a no-op (idempotent, resumable)
    let r = Migrator::run(p, &set()).await.unwrap();
    assert!(r.applied.is_empty(), "{:?}", r.applied);

    let tables: Vec<String> = rows(
        p,
        "SELECT table_name::text FROM information_schema.tables WHERE table_schema = 'public' ORDER BY 1",
    )
    .await
    .iter()
    .map(|r| r.get(0))
    .collect();
    for want in [
        "tenants",
        "users",
        "groups",
        "group_members",
        "opaque_registrations",
        "webauthn_credentials",
        "sessions",
        "refresh_tokens",
        "dpop_jti",
        "recovery_codes",
        "recovery_requests",
        "setup_links",
        "outbox",
        "outbox_counters",
        "idempotency_records",
    ] {
        assert!(tables.iter().any(|t| t == want), "missing table {want}");
    }

    // App. E: tenant_id is the first PK column of every tenant-scoped table; timestamptz only.
    let pk_first = rows(
        p,
        "SELECT c.relname::text, a.attname::text FROM pg_index i JOIN pg_class c ON c.oid = i.indrelid \
         JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = i.indkey[0] \
         JOIN pg_namespace n ON n.oid = c.relnamespace WHERE i.indisprimary AND n.nspname = 'public'",
    )
    .await;
    for r in &pk_first {
        let (table, col): (String, String) = (r.get(0), r.get(1));
        if table == "schema_migrations" || table == "finalized_releases" {
            continue;
        }
        assert_eq!(col, "tenant_id", "{table}: first PK column");
    }
    let bad_ts = rows(
        p,
        "SELECT table_name::text || '.' || column_name::text FROM information_schema.columns \
         WHERE table_schema = 'public' AND data_type IN ('timestamp without time zone', 'json')",
    )
    .await;
    assert!(bad_ts.is_empty());
    let idx: Vec<(String, String)> = rows(
        p,
        "SELECT tablename::text, indexname::text FROM pg_indexes i WHERE schemaname = 'public' \
         AND NOT EXISTS (SELECT 1 FROM pg_constraint k WHERE k.conname = i.indexname)",
    )
    .await
    .iter()
    .map(|r| (r.get(0), r.get(1)))
    .collect();
    for (t, i) in &idx {
        assert!(
            i.starts_with(&format!("{t}_")) && i.ends_with("_idx"),
            "index {i} on {t}"
        );
    }
    assert!(idx.iter().any(|(_, i)| i == "users_login_idx"));
    let seqs = rows(p, "SELECT 1 FROM pg_sequences WHERE schemaname = 'public'").await;
    assert!(seqs.is_empty(), "no database sequences (App. E)");

    // Contract rev 2 columns and keys.
    let cols: Vec<String> = rows(
        p,
        "SELECT table_name::text || '.' || column_name::text FROM information_schema.columns WHERE table_schema = 'public'",
    )
    .await
    .iter()
    .map(|r| r.get(0))
    .collect();
    for c in [
        "refresh_tokens.rotated_at",
        "refresh_tokens.rotation_idempotency_key",
        "refresh_tokens.family_generation",
        "setup_links.token_hash",
        "setup_links.expires_at",
        "dpop_jti.expires_at",
        "recovery_requests.not_before",
        "recovery_requests.grant_hash",
        "recovery_requests.grant_expires_at",
        "sessions.generation",
        "groups.membership_version",
        "opaque_registrations.ksf_m_kib",
        "webauthn_credentials.prf_supported",
        "tenants.version",
        "users.version",
    ] {
        assert!(cols.iter().any(|x| x == c), "missing column {c}");
    }
    let pk_cols: Vec<String> = rows(
        p,
        "SELECT c.relname::text || ':' || string_agg(a.attname::text, ',' ORDER BY k.ord) \
         FROM pg_index i JOIN pg_class c ON c.oid = i.indrelid \
         CROSS JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS k(attnum, ord) \
         JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = k.attnum \
         WHERE i.indisprimary AND c.relname IN ('setup_links', 'refresh_tokens', 'dpop_jti', 'group_members') \
         GROUP BY c.relname ORDER BY 1",
    )
    .await
    .iter()
    .map(|r| r.get(0))
    .collect();
    assert_eq!(
        pk_cols,
        [
            "dpop_jti:tenant_id,jkt,jti",
            "group_members:tenant_id,group_id,member_id",
            "refresh_tokens:tenant_id,token_hash",
            "setup_links:tenant_id,token_hash",
        ]
    );

    // CHECK-constrained states (including the rev 2 `granted` recovery state).
    let tid = TenantId::generate().unwrap();
    let uid = UserId::generate().unwrap();
    let tq = format!(
        "INSERT INTO tenants (tenant_id, name, state, policy, version) VALUES ('{tid}', 't', 'active', '\\xa0', 1); \
         INSERT INTO users (tenant_id, user_id, login, status, kind, version) VALUES ('{tid}', '{uid}', 'u', 'invited', 'member', 1);"
    );
    exec(p, tq).await.unwrap();
    for bad in [
        format!(
            "INSERT INTO tenants (tenant_id, name, state, policy, version) VALUES ('{}', 't', 'paused', '\\xa0', 1)",
            TenantId::generate().unwrap()
        ),
        format!("UPDATE users SET status = 'locked' WHERE user_id = '{uid}'"),
        format!("UPDATE users SET kind = 'admin' WHERE user_id = '{uid}'"),
        format!(
            "INSERT INTO recovery_requests (tenant_id, request_id, user_id, method, state, not_before, version) VALUES ('{tid}', '{}', '{uid}', 'email', 'approved', now(), 1)",
            UserId::generate().unwrap()
        ),
        // granted without a grant hash
        format!(
            "INSERT INTO recovery_requests (tenant_id, request_id, user_id, method, state, not_before, version) VALUES ('{tid}', '{}', '{uid}', 'email', 'granted', now(), 1)",
            UserId::generate().unwrap()
        ),
        format!(
            "INSERT INTO setup_links (tenant_id, token_hash, user_id, purpose, state, expires_at, version) VALUES ('{tid}', '\\x00', '{uid}', 'first_admin', 'active', now(), 1)"
        ),
        format!(
            "INSERT INTO dpop_jti (tenant_id, jkt, jti, expires_at) VALUES ('{tid}', '\\x00', 'j', now())"
        ),
    ] {
        let e = exec(p, bad.clone()).await;
        assert!(e.is_err(), "accepted: {bad}");
    }
    // granted with hash + expiry is accepted
    let ok = format!(
        "INSERT INTO recovery_requests (tenant_id, request_id, user_id, method, state, not_before, grant_hash, grant_expires_at, version) \
         VALUES ('{tid}', '{}', '{uid}', 'email', 'granted', now(), '\\x{}', now() + interval '15 minutes', 1)",
        UserId::generate().unwrap(),
        "ab".repeat(32)
    );
    exec(p, ok).await.unwrap();
    // dpop_jti replay fallback: ON CONFLICT DO NOTHING reports the replay as 0 rows
    let jkt = "cd".repeat(32);
    let ins = format!(
        "INSERT INTO dpop_jti (tenant_id, jkt, jti, expires_at) VALUES ('{tid}', '\\x{jkt}', 'jti-1', now() + interval '120 seconds') ON CONFLICT DO NOTHING"
    );
    assert_eq!(exec(p, ins.clone()).await.unwrap(), 1);
    assert_eq!(exec(p, ins).await.unwrap(), 0);
    t.cleanup().await;
}

#[tokio::test]
async fn tenants_and_users_one_transaction_one_event() {
    let Some((t, a)) = setup().await else { return };
    let p = t.pool(&ID).clone();
    let ten = a.create_tenant("Acme").await.unwrap();
    assert_eq!(a.tenant(ten.tenant_id).await.unwrap().unwrap(), ten);
    assert_eq!(events(&p, ten.tenant_id).await.len(), 1);
    assert_eq!(
        events(&p, ten.tenant_id).await[0].0,
        "identity.tenant.created"
    );

    let u = a
        .create_user(
            ten.tenant_id,
            NewUser {
                login: "Alice@Example.com".into(),
                kind: UserKind::Member,
                display_name: Some("Alice".into()),
            },
        )
        .await
        .unwrap();
    assert_eq!(u.login, "alice@example.com");
    assert_eq!(u.status, UserStatus::Invited);
    assert_eq!(a.user(ten.tenant_id, u.user_id).await.unwrap().unwrap(), u);
    // normalized login is unique per tenant
    let e = a
        .create_user(ten.tenant_id, user("ALICE@example.com"))
        .await
        .unwrap_err();
    assert_eq!(code(&e), ErrorCode::Conflict);
    // ... but not across tenants
    let other = a.create_tenant("Other").await.unwrap();
    a.create_user(other.tenant_id, user("alice@example.com"))
        .await
        .unwrap();
    let g = a
        .create_user(
            ten.tenant_id,
            NewUser {
                login: "guest@else.org".into(),
                kind: UserKind::Guest,
                display_name: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(g.kind, UserKind::Guest);
    let ev = events(&p, ten.tenant_id).await;
    assert_eq!(
        ev.iter()
            .filter(|(t, _)| t == "identity.user.created")
            .count(),
        2,
        "one event per successful action, none for the rejected one"
    );

    // validation and tenant checks
    assert_eq!(
        code(&a.create_user(ten.tenant_id, user("a b")).await.unwrap_err()),
        ErrorCode::InvalidRequest
    );
    assert_eq!(
        code(&a.create_tenant("").await.unwrap_err()),
        ErrorCode::InvalidRequest
    );
    assert_eq!(
        code(
            &a.create_user(TenantId::generate().unwrap(), user("x"))
                .await
                .unwrap_err()
        ),
        ErrorCode::NotFound
    );
    let sus = format!(
        "UPDATE tenants SET state = 'suspended', version = version + 1 WHERE tenant_id = '{}'",
        other.tenant_id
    );
    exec(&p, sus).await.unwrap();
    assert_eq!(
        code(&a.create_user(other.tenant_id, user("y")).await.unwrap_err()),
        ErrorCode::Conflict
    );
    assert_eq!(
        code(&a.create_group(other.tenant_id, "g").await.unwrap_err()),
        ErrorCode::Conflict
    );
    t.cleanup().await;
}

#[tokio::test]
async fn membership_is_versioned_and_emits_events() {
    let Some((t, a)) = setup().await else { return };
    let p = t.pool(&ID).clone();
    let ten = a.create_tenant("Acme").await.unwrap().tenant_id;
    let u = a.create_user(ten, user("u1")).await.unwrap().user_id;
    let g = a.create_group(ten, "Eng").await.unwrap();
    assert_eq!(g.membership_version, 1);
    let sub = a.create_group(ten, "Eng/Backend").await.unwrap().group_id;

    let c1 = a
        .add_member(ten, g.group_id, Member::User(u), Some(1))
        .await
        .unwrap();
    assert_eq!(c1.membership_version, 2);
    let c2 = a
        .add_member(ten, g.group_id, Member::Group(sub), None)
        .await
        .unwrap();
    assert_eq!(c2.membership_version, 3);
    let mut m = a.members(ten, g.group_id).await.unwrap();
    m.sort_by_key(Member::id);
    let mut want = vec![Member::User(u), Member::Group(sub)];
    want.sort_by_key(Member::id);
    assert_eq!(m, want);

    // compare-and-set on membership_version
    let e = a
        .remove_member(ten, g.group_id, Member::User(u), Some(2))
        .await
        .unwrap_err();
    assert_eq!(code(&e), ErrorCode::PreconditionFailed);
    // duplicate member, unknown member, unknown group, non-member removal
    assert_eq!(
        code(
            &a.add_member(ten, g.group_id, Member::User(u), None)
                .await
                .unwrap_err()
        ),
        ErrorCode::Conflict
    );
    assert_eq!(
        code(
            &a.add_member(
                ten,
                g.group_id,
                Member::User(UserId::generate().unwrap()),
                None
            )
            .await
            .unwrap_err()
        ),
        ErrorCode::NotFound
    );
    assert_eq!(
        code(
            &a.add_member(ten, GroupId::generate().unwrap(), Member::User(u), None)
                .await
                .unwrap_err()
        ),
        ErrorCode::NotFound
    );
    let c3 = a
        .remove_member(ten, g.group_id, Member::User(u), Some(3))
        .await
        .unwrap();
    assert_eq!(c3.membership_version, 4);
    assert_eq!(
        code(
            &a.remove_member(ten, g.group_id, Member::User(u), None)
                .await
                .unwrap_err()
        ),
        ErrorCode::NotFound
    );
    assert_eq!(
        a.group(ten, g.group_id)
            .await
            .unwrap()
            .unwrap()
            .membership_version,
        4
    );

    // events: exactly one per successful change, carrying the new membership_version
    let ev: Vec<_> = events(&p, ten)
        .await
        .into_iter()
        .filter(|(t, _)| t == "identity.group.membership_changed")
        .collect();
    assert_eq!(ev.len(), 3);
    let mut versions = Vec::new();
    #[derive(serde::Deserialize)]
    struct Changed {
        membership_version: i64,
    }
    for (_, payload) in &ev {
        let c: Changed = cs_crypto::cbor::from_canonical(payload, 65536).unwrap();
        versions.push(c.membership_version);
    }
    versions.sort_unstable();
    assert_eq!(versions, [2, 3, 4]);
    t.cleanup().await;
}

#[tokio::test]
async fn group_cycles_rejected_and_nothing_written() {
    let Some((t, a)) = setup().await else { return };
    let p = t.pool(&ID).clone();
    let ten = a.create_tenant("Acme").await.unwrap().tenant_id;
    let ga = a.create_group(ten, "A").await.unwrap().group_id;
    let gb = a.create_group(ten, "B").await.unwrap().group_id;
    let gc = a.create_group(ten, "C").await.unwrap().group_id;
    // A ⊃ B ⊃ C
    a.add_member(ten, ga, Member::Group(gb), None)
        .await
        .unwrap();
    a.add_member(ten, gb, Member::Group(gc), None)
        .await
        .unwrap();
    let before = events(&p, ten).await.len();
    for (parent, child) in [(ga, ga), (gb, ga), (gc, ga), (gc, gb)] {
        let e = a
            .add_member(ten, parent, Member::Group(child), None)
            .await
            .unwrap_err();
        assert_eq!(code(&e), ErrorCode::InvalidRequest, "{parent} <- {child}");
        assert_eq!(e.field_errors()[0].code, GROUP_CYCLE, "{parent} <- {child}");
    }
    assert_eq!(
        events(&p, ten).await.len(),
        before,
        "rejected writes wrote events"
    );
    assert_eq!(
        a.group(ten, gc).await.unwrap().unwrap().membership_version,
        1
    );
    assert!(a.members(ten, gc).await.unwrap().is_empty());
    // a diamond is not a cycle
    let gd = a.create_group(ten, "D").await.unwrap().group_id;
    a.add_member(ten, ga, Member::Group(gd), None)
        .await
        .unwrap();
    a.add_member(ten, gd, Member::Group(gc), None)
        .await
        .unwrap();
    t.cleanup().await;
}

#[tokio::test]
async fn concurrent_opposite_nesting_never_creates_a_cycle() {
    let Some((t, a)) = setup().await else { return };
    let ten = a.create_tenant("Acme").await.unwrap().tenant_id;
    for _ in 0..5 {
        let x = a.create_group(ten, "X").await.unwrap().group_id;
        let y = a.create_group(ten, "Y").await.unwrap().group_id;
        let (a1, a2) = (a.clone(), a.clone());
        let (r1, r2) = tokio::join!(
            tokio::spawn(async move { a1.add_member(ten, x, Member::Group(y), None).await }),
            tokio::spawn(async move { a2.add_member(ten, y, Member::Group(x), None).await }),
        );
        let (r1, r2) = (r1.unwrap(), r2.unwrap());
        assert!(
            r1.is_ok() != r2.is_ok(),
            "exactly one of the opposite nestings must win: {r1:?} / {r2:?}"
        );
        let loser = r1.err().or(r2.err()).unwrap();
        assert_eq!(code(&loser), ErrorCode::InvalidRequest, "{loser:?}");
    }
    t.cleanup().await;
}

#[tokio::test]
async fn depth_and_cardinality_limits_return_typed_error() {
    let Some((t, a)) = setup().await else { return };
    let p = t.pool(&ID).clone();
    let a = a.with_group_limits(GroupLimits {
        max_depth: 2,
        max_closure: 3,
    });
    let ten = a.create_tenant("Acme").await.unwrap().tenant_id;
    let g: Vec<GroupId> = {
        let mut v = Vec::new();
        for i in 0..5 {
            v.push(
                a.create_group(ten, &format!("G{i}"))
                    .await
                    .unwrap()
                    .group_id,
            );
        }
        v
    };
    // depth: G0 ⊃ G1 ⊃ G2 is depth 2 (allowed); G2 ⊃ G3 would be depth 3
    a.add_member(ten, g[0], Member::Group(g[1]), None)
        .await
        .unwrap();
    a.add_member(ten, g[1], Member::Group(g[2]), None)
        .await
        .unwrap();
    let before = events(&p, ten).await.len();
    let e = a
        .add_member(ten, g[2], Member::Group(g[3]), None)
        .await
        .unwrap_err();
    assert_eq!(code(&e), ErrorCode::InvalidRequest);
    assert_eq!(e.field_errors()[0].code, GROUP_COMPLEXITY_LIMIT);
    // also when the deep part hangs below the new member
    a.add_member(ten, g[3], Member::Group(g[4]), None)
        .await
        .unwrap();
    let e = a
        .add_member(ten, g[1], Member::Group(g[3]), None)
        .await
        .unwrap_err();
    assert_eq!(e.field_errors()[0].code, GROUP_COMPLEXITY_LIMIT);
    assert_eq!(events(&p, ten).await.len(), before + 1);

    // cardinality: G0's closure is {G1, G2} (2); one user makes 3 (allowed), a second breaches
    // the limit even though it is added to G2, two levels below G0.
    let u1 = a.create_user(ten, user("u1")).await.unwrap().user_id;
    let u2 = a.create_user(ten, user("u2")).await.unwrap().user_id;
    a.add_member(ten, g[2], Member::User(u1), None)
        .await
        .unwrap();
    let v = a
        .group(ten, g[2])
        .await
        .unwrap()
        .unwrap()
        .membership_version;
    let e = a
        .add_member(ten, g[2], Member::User(u2), None)
        .await
        .unwrap_err();
    assert_eq!(code(&e), ErrorCode::InvalidRequest);
    assert_eq!(e.field_errors()[0].code, GROUP_COMPLEXITY_LIMIT);
    assert_eq!(
        a.group(ten, g[2])
            .await
            .unwrap()
            .unwrap()
            .membership_version,
        v,
        "no partial write"
    );
    // a user already in the closure does not grow it
    a.add_member(ten, g[1], Member::User(u1), None)
        .await
        .unwrap();
    t.cleanup().await;
}

#[tokio::test]
async fn setup_link_is_rt1_stored_as_sha256_single_active() {
    let Some((t, a)) = setup().await else { return };
    let p = t.pool(&ID).clone();
    let ten = a.create_tenant("Acme").await.unwrap().tenant_id;
    let u = a
        .create_user(ten, user("admin@acme.test"))
        .await
        .unwrap()
        .user_id;

    let l1 = a.issue_setup_link(ten, u).await.unwrap();
    let s1 = l1.token.expose_secret().clone();
    let parsed = token::parse(&s1).unwrap();
    assert_eq!(parsed.tenant_id, ten, "tenant comes from the token");
    assert_eq!(
        a.setup_link_state(ten, parsed.hash).await.unwrap(),
        Some(("active".to_owned(), u))
    );
    assert_eq!(l1.revoked_previous, 0);

    // A second issuance revokes the first: at most one valid link per user.
    let l2 = a.issue_setup_link(ten, u).await.unwrap();
    assert_eq!(l2.revoked_previous, 1);
    assert_eq!(
        a.setup_link_state(ten, parsed.hash)
            .await
            .unwrap()
            .unwrap()
            .0,
        "revoked"
    );
    let h2 = token::parse(l2.token.expose_secret()).unwrap().hash;
    assert_eq!(
        a.setup_link_state(ten, h2).await.unwrap().unwrap().0,
        "active"
    );

    // Only the hash is stored; neither the token nor its random part appears in any row or
    // event payload.
    let random = s1.rsplit('.').next().unwrap().to_owned();
    let dump = rows(
        &p,
        "SELECT encode(token_hash, 'hex') || state || expires_at::text FROM setup_links",
    )
    .await;
    for r in dump {
        let s: String = r.get(0);
        assert!(!s.contains(&random));
    }
    let hashes = rows(&p, "SELECT token_hash FROM setup_links").await;
    for r in hashes {
        let h: Vec<u8> = r.get(0);
        assert_eq!(h.len(), 32);
    }
    for (ty, payload) in events(&p, ten).await {
        let needle = s1.as_bytes();
        assert!(!payload.windows(needle.len()).any(|w| w == needle), "{ty}");
        assert!(
            !payload
                .windows(32)
                .any(|w| w == parsed.hash.as_bytes().as_slice()),
            "{ty} carries the token hash"
        );
    }
    assert_eq!(
        events(&p, ten)
            .await
            .iter()
            .filter(|(t, _)| t == "identity.setup_link.issued")
            .count(),
        2
    );

    // guests cannot be first administrators; only invited users get links
    let g = a
        .create_user(
            ten,
            NewUser {
                login: "g@else.org".into(),
                kind: UserKind::Guest,
                display_name: None,
            },
        )
        .await
        .unwrap()
        .user_id;
    assert_eq!(
        code(&a.issue_setup_link(ten, g).await.unwrap_err()),
        ErrorCode::InvalidRequest
    );
    let act =
        format!("UPDATE users SET status = 'active', version = version + 1 WHERE user_id = '{u}'");
    exec(&p, act).await.unwrap();
    assert_eq!(
        code(&a.issue_setup_link(ten, u).await.unwrap_err()),
        ErrorCode::Conflict
    );
    assert_eq!(
        code(
            &a.issue_setup_link(ten, UserId::generate().unwrap())
                .await
                .unwrap_err()
        ),
        ErrorCode::NotFound
    );
    t.cleanup().await;
}

#[tokio::test]
async fn setup_link_lifetime_and_group_limits_follow_policy() {
    use cs_common::config::{Policy, PolicyKey};
    let Some((t, _)) = setup().await else { return };
    let p = t.pool(&ID).clone();
    let policy = Policy::default()
        .with_value(PolicyKey::SetupLinkLifetimeSecs, 900)
        .unwrap()
        .with_value(PolicyKey::GroupMaxDepth, 4)
        .unwrap()
        .with_value(PolicyKey::GroupMaxClosure, 1_000)
        .unwrap();
    // Outside C13 ranges is refused, exactly like check-config.
    assert!(
        Policy::default()
            .with_value(PolicyKey::SetupLinkLifetimeSecs, 899)
            .is_err()
    );
    assert!(
        Policy::default()
            .with_value(PolicyKey::GroupMaxDepth, 65)
            .is_err()
    );
    let a = IdentityAdmin::with_policy(p.clone(), &policy).unwrap();
    assert_eq!(
        a.group_limits(),
        GroupLimits {
            max_depth: 4,
            max_closure: 1_000
        }
    );
    assert_eq!(
        IdentityAdmin::new(p.clone()).unwrap().group_limits(),
        GroupLimits {
            max_depth: 32,
            max_closure: 10_000
        }
    );
    let ten = a.create_tenant("Acme").await.unwrap().tenant_id;
    let u = a
        .create_user(ten, user("admin@acme.test"))
        .await
        .unwrap()
        .user_id;
    let l = a.issue_setup_link(ten, u).await.unwrap();
    let r = rows(
        &p,
        "SELECT extract(epoch FROM (expires_at - created_at))::float8 FROM setup_links",
    )
    .await;
    let secs: f64 = r[0].get(0);
    assert!((secs - 900.0).abs() < 5.0, "lifetime {secs}");
    drop(l);
    t.cleanup().await;
}
