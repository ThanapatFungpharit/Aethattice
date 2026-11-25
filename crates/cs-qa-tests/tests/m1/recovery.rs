//! Account recovery (§4 [R5], rev 10/12; M0-gate §6.1 "Recovery").
use crate::fx::*;
use cs_identity::session::SessionPolicy;
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

fn k() -> String {
    uuid::Uuid::new_v4().to_string()
}

async fn active_sessions(e: &Env, u: &User) -> i64 {
    e.i64(&format!(
        "SELECT count(*) FROM sessions WHERE user_id = '{}' AND state = 'active'",
        u.id.as_uuid()
    ))
    .await
}

/// [R5]: register/finish under a recovery grant replaces the password, revokes every session
/// and refresh family and consumes the code and the grant in ONE transaction. A concurrent
/// observer never sees the new registration together with a live old session; before
/// completion the old sessions keep working.
#[tokio::test]
async fn r5_completion_is_atomic() {
    let Some(e) = Env::default().await else { return };
    let t = e.tenant().await;
    let u = e.user(t, "rob", "pw-old-1").await;
    let s1 = e.login(&u).await;
    let s2 = e.login(&u).await;
    let codes = e.recovery_codes(&s1).await;
    let g = e
        .call(Req::post("/api/v2/auth/recovery/start")
            .json(json!({"tenant": u.t(), "login": "rob", "method": "recovery_code", "code": codes[0]})))
        .await;
    g.expect(200);
    assert_eq!(g.body["state"], "granted");
    let gexp = g.body["grant_expires_in"].as_i64().unwrap();
    assert!((1..=900).contains(&gexp), "grant lifetime {gexp} s (15 min fixed)");
    let grant = g.body["grant"].as_str().unwrap().to_owned();
    // An abandoned recovery leaves the account usable.
    let r = e.call(s2.refresh_req(&k())).await;
    r.expect(200);
    let s2 = Session::from_auth(&r, None);
    assert_eq!(active_sessions(&e, &u).await, 2);
    let reg_v0 = e
        .i64(&format!("SELECT version FROM opaque_registrations WHERE user_id = '{}'", u.id.as_uuid()))
        .await;

    // Observer: snapshot reads of (registration version, active sessions) in one statement.
    let stop = Arc::new(AtomicBool::new(false));
    let bad = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let url = e.db.as_ref().unwrap().url.clone();
    let uid = u.id.as_uuid().to_string();
    let obs = {
        let (stop, bad) = (stop.clone(), bad.clone());
        tokio::spawn(async move {
            use sqlx::Connection as _;
            let mut c = sqlx::PgConnection::connect(&url).await.unwrap();
            let q = format!(
                "SELECT (SELECT version FROM opaque_registrations WHERE user_id = '{uid}'), \
                        (SELECT count(*) FROM sessions WHERE user_id = '{uid}' AND state = 'active'), \
                        (SELECT count(*) FROM refresh_tokens r JOIN sessions s ON s.tenant_id = r.tenant_id AND s.session_id = r.session_id \
                          WHERE s.user_id = '{uid}' AND r.state = 'active')"
            );
            let mut n = 0u64;
            while !stop.load(Ordering::SeqCst) {
                let row: (i64, i64, i64) = sqlx::query_as(sqlx::AssertSqlSafe(q.clone()))
                    .fetch_one(&mut c)
                    .await
                    .unwrap();
                n += 1;
                if row.0 > reg_v0 && (row.1 > 0 || row.2 > 0) {
                    bad.lock().unwrap().push(format!("{row:?}"));
                }
            }
            n
        })
    };
    let (st, c) = Env::reg_start(&e.nodes[0], json!({"grant": grant, "login": "rob"}), "pw-new-1").await;
    st.expect(200);
    let fin = Env::reg_finish(&e.nodes[0], &st, c, &u.t(), "rob", "pw-new-1", None).await;
    fin.expect(204);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    stop.store(true, Ordering::SeqCst);
    let reads = obs.await.unwrap();
    assert!(reads > 0);
    let bad = bad.lock().unwrap().clone();
    assert!(bad.is_empty(), "[R5] new password visible with live sessions/tokens: {bad:?}");

    assert_eq!(active_sessions(&e, &u).await, 0, "all sessions revoked");
    e.call(s1.refresh_req(&k())).await.expect_unauth();
    e.call(s2.refresh_req(&k())).await.expect_unauth();
    let (_, old) = Env::login_raw(&e.nodes[0], &u.t(), "rob", "pw-old-1", None).await;
    old.expect_unauth();
    let nu = User { pw: "pw-new-1".into(), ..u.clone() };
    let _ = e.login(&nu).await;
    // Code consumed, grant single use, outbox events written.
    let again = e
        .call(Req::post("/api/v2/auth/recovery/start")
            .json(json!({"tenant": u.t(), "login": "rob", "method": "recovery_code", "code": codes[0]})))
        .await;
    again.expect_unauth();
    let (st, _) = Env::reg_start(&e.nodes[0], json!({"grant": grant, "login": "rob"}), "pw-new-2").await;
    assert!(st.status == 401 || st.status == 403, "used grant accepted: {}", st.body);
    assert!(
        e.i64("SELECT count(*) FROM outbox WHERE event_type = 'identity.credentials.changed'").await >= 1
    );
    assert!(
        e.i64("SELECT count(*) FROM outbox WHERE event_type = 'identity.session.revoked'").await >= 2,
        "one identity.session.revoked per session"
    );
    // Old access tokens: the session generation moved on. Recorded (see gate report) rather
    // than asserted: M1 access tokens are self-contained JWTs valid until exp (≤ 600 s).
    let me = e.call(s1.req(Req::get("/api/v2/me"))).await;
    eprintln!("QA observation: old access token after [R5] completion on GET /me -> {}", me.status);
    let ms = e.call(s1.req(Req::get("/api/v2/me/sessions"))).await;
    eprintln!("QA observation: old access token after [R5] completion on GET /me/sessions -> {}", ms.status);
    e.finish().await;
}

/// An expired grant is refused and returns the request to `expired`; nothing changes.
#[tokio::test]
async fn expired_grant_changes_nothing() {
    let Some(e) = Env::default().await else { return };
    let t = e.tenant().await;
    let u = e.user(t, "exp", "pw-old-2").await;
    let s = e.login(&u).await;
    let codes = e.recovery_codes(&s).await;
    let g = e
        .call(Req::post("/api/v2/auth/recovery/start")
            .json(json!({"tenant": u.t(), "login": "exp", "method": "recovery_code", "code": codes[0]})))
        .await;
    let grant = g.body["grant"].as_str().unwrap().to_owned();
    e.exec("UPDATE recovery_requests SET grant_expires_at = now() - interval '1 second' WHERE grant_hash IS NOT NULL").await;
    let r = e.register(&e.nodes[0], &grant, "exp", "pw-new-x").await;
    assert!(r.status == 401 || r.status == 403, "expired grant accepted: {}", r.body);
    assert_eq!(active_sessions(&e, &u).await, 1);
    let _ = e.login(&u).await;
    assert_eq!(
        e.i64("SELECT count(*) FROM recovery_requests WHERE state = 'completed'").await,
        0
    );
    e.finish().await;
}

/// Email method: the waiting period cannot be shortened by polling; cancellation from any
/// session of the user kills the request; MFA users must add a recovery code.
#[tokio::test]
async fn email_waiting_period_cancel_and_mfa_factor() {
    let Some(e) = Env::default().await else { return };
    let t = e.tenant().await;
    let u = e.user(t, "eve", "pw-old-3").await;
    e.admin.set_email(t, u.id, "eve@qa.example", true).await.unwrap();
    let s = e.login(&u).await;
    let start = || Req::post("/api/v2/auth/recovery/start")
        .json(json!({"tenant": u.t(), "login": "eve", "method": "email"}));
    e.call(start()).await.expect(202);
    let link = e.outbox.links.lock().unwrap().last().unwrap().1.clone();
    let st = e.call(Req::post("/api/v2/auth/recovery/status").json(json!({"token": link}))).await;
    st.expect(200);
    assert_eq!(st.body["state"], "pending");
    assert!(st.body.get("grant").is_none(), "grant before the waiting period: {}", st.body);
    let avail = st.body["available_at"].as_str().unwrap().to_owned();
    assert!(avail.ends_with('Z') || avail.contains("+00:00"), "RFC 3339 UTC: {avail}");
    // A client-supplied shorter wait is ignored (unknown member refused or ignored).
    let st2 = e
        .call(Req::post("/api/v2/auth/recovery/status").json(json!({"token": link, "not_before": "1970-01-01T00:00:00Z"})))
        .await;
    assert!(st2.body.get("grant").is_none(), "{}", st2.body);
    // Cancel from the signed-in session.
    let list = e.call(s.req(Req::get("/api/v2/me/recovery-requests"))).await;
    let id = list.body["items"][0]["id"].as_str().unwrap().to_owned();
    e.call(s.req(Req::delete(&format!("/api/v2/me/recovery-requests/{id}")))).await.expect(204);
    e.exec("UPDATE recovery_requests SET not_before = now() - interval '1 second'").await;
    let st3 = e.call(Req::post("/api/v2/auth/recovery/status").json(json!({"token": link}))).await;
    assert!(st3.body.get("grant").is_none(), "cancelled request granted: {}", st3.body);

    // New request, waiting period over: granted. With MFA (a passkey) a code is required.
    let mut a = Authenticator::new();
    let _ = e.add_passkey(&s, &mut a).await;
    let codes = e.recovery_codes(&s).await;
    e.call(start()).await.expect(202);
    let link2 = e.outbox.links.lock().unwrap().last().unwrap().1.clone();
    assert_ne!(link2, link);
    e.exec("UPDATE recovery_requests SET not_before = now() - interval '1 second' WHERE state = 'pending'").await;
    let no_code = e.call(Req::post("/api/v2/auth/recovery/status").json(json!({"token": link2}))).await;
    assert!(no_code.body.get("grant").is_none(), "MFA user granted without second factor: {}", no_code.body);
    let with = e
        .call(Req::post("/api/v2/auth/recovery/status").json(json!({"token": link2, "code": codes[0]})))
        .await;
    with.expect(200);
    assert_eq!(with.body["state"], "granted", "{}", with.body);
    assert!(with.body["grant"].as_str().unwrap().starts_with("rt1."));
    e.finish().await;
}

/// Device approval needs step-up on the approving session and skips the waiting period;
/// the waiting period of the email method is the configured policy value.
#[tokio::test]
async fn device_approval_and_waiting_period_policy() {
    let policy = SessionPolicy {
        recovery_wait_secs: 3600,
        ..SessionPolicy::default()
    };
    let Some(e) = Env::new(Opts { policy, ..Opts::default() }).await else { return };
    let t = e.tenant().await;
    let u = e.user(t, "dev", "pw-old-4").await;
    e.admin.set_email(t, u.id, "dev@qa.example", true).await.unwrap();
    let s = e.login(&u).await;
    e.call(Req::post("/api/v2/auth/recovery/start")
        .json(json!({"tenant": u.t(), "login": "dev", "method": "email"})))
        .await
        .expect(202);
    let wait = e
        .i64("SELECT extract(epoch FROM (not_before - created_at))::bigint FROM recovery_requests WHERE method = 'email'")
        .await;
    assert!((3590..=3610).contains(&wait), "waiting period {wait} s, policy 3600 s");
    let st = e
        .call(Req::post("/api/v2/auth/recovery/start")
            .json(json!({"tenant": u.t(), "login": "dev", "method": "device_approval"})))
        .await;
    let txn = st.body["recovery_txn"].as_str().unwrap().to_owned();
    let poll = || Req::post("/api/v2/auth/recovery/status").json(json!({"recovery_txn": txn}));
    assert!(e.call(poll()).await.body.get("grant").is_none());
    let list = e.call(s.req(Req::get("/api/v2/me/recovery-requests"))).await;
    let id = list.body["items"].as_array().unwrap().iter()
        .find(|i| i["method"] == "device_approval").unwrap()["id"].as_str().unwrap().to_owned();
    e.age_strong_auth(&s, 301).await;
    let ap = e.call(s.req(Req::post(&format!("/api/v2/me/recovery-requests/{id}/approve")).json(json!({})))).await;
    assert_eq!(ap.status, 401);
    e.age_strong_auth(&s, 10).await;
    e.call(s.req(Req::post(&format!("/api/v2/me/recovery-requests/{id}/approve")).json(json!({})))).await.expect(204);
    let g = e.call(poll()).await;
    g.expect(200);
    assert_eq!(g.body["state"], "granted", "{}", g.body);
    // rev 12: each poll rotates the grant; the previous one dies; expiry is not extended.
    let g1 = g.body["grant"].as_str().unwrap().to_owned();
    let g2b = e.call(poll()).await;
    let g2 = g2b.body["grant"].as_str().unwrap().to_owned();
    assert_ne!(g1, g2);
    assert!(g2b.body["grant_expires_in"].as_i64().unwrap() <= g.body["grant_expires_in"].as_i64().unwrap());
    let old = e.register(&e.nodes[0], &g1, "dev", "pw-new-4").await;
    assert!(old.status == 401 || old.status == 403, "superseded grant accepted: {}", old.body);
    e.register(&e.nodes[0], &g2, "dev", "pw-new-4").await.expect(204);
    assert_eq!(active_sessions(&e, &u).await, 0);
    e.finish().await;
}

/// Password change by a step-up session (rev 9) revokes every OTHER session, keeps the
/// current one, and the old password stops working.
#[tokio::test]
async fn password_change_revokes_other_sessions() {
    let Some(e) = Env::default().await else { return };
    let t = e.tenant().await;
    let u = e.user(t, "pat", "pw-old-5").await;
    let cur = e.login(&u).await;
    let other = e.login(&u).await;
    let (st, c) = Env::reg_start_session(&e.nodes[0], &cur, "password_change", "pw-new-5").await;
    st.expect(200);
    let fin = Env::reg_finish(&e.nodes[0], &st, c, &u.t(), "pat", "pw-new-5", Some(&cur)).await;
    fin.expect(204);
    e.call(other.refresh_req(&k())).await.expect_unauth();
    e.call(cur.refresh_req(&k())).await.expect(200);
    let (_, old) = Env::login_raw(&e.nodes[0], &u.t(), "pat", "pw-old-5", None).await;
    old.expect_unauth();
    // A login in the body is refused for a session re-registration.
    let (st, _) = Env::reg_start(
        &e.nodes[0],
        json!({"purpose": "password_change", "login": "pat"}),
        "pw-x",
    )
    .await;
    assert!(st.status >= 400, "{}", st.body);
    e.finish().await;
}
