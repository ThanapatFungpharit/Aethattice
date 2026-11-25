//! Cross-tenant identity isolation (spec App. L.5; M0-gate §6.1 "Cross-tenant"): tokens,
//! sessions, txns, grants, recovery codes, passkeys and groups of tenant A are never usable
//! or visible in tenant B. Both tenants have a user with the same login and password.
use crate::fx::*;
use cs_identity::admin::Member;
use serde_json::json;

const PW: &str = "pw-shared-same-in-both";

fn swap(token: &str, to: cs_common::id::TenantId) -> String {
    let p: Vec<&str> = token.split('.').collect();
    format!("rt1.{}.{}", b64(to.as_uuid().as_bytes()), p[2])
}

struct Two {
    a: User,
    b: User,
    sa: Session,
    sb: Session,
}

async fn two(e: &Env) -> Two {
    let (ta, tb) = (e.tenant().await, e.tenant().await);
    let a = e.user(ta, "alice", PW).await;
    let b = e.user(tb, "alice", PW).await;
    let sa = e.login(&a).await;
    let sb = e.login(&b).await;
    Two { a, b, sa, sb }
}

/// Sessions: B cannot see or revoke A's sessions (even with step-up); A's refresh token with
/// the tenant segment swapped to B is dead and does not touch A's session.
#[tokio::test]
async fn sessions_and_refresh_tokens_isolated() {
    let Some(e) = Env::default().await else { return };
    let x = two(&e).await;
    let list = e.call(x.sb.req(Req::get("/api/v2/me/sessions"))).await;
    list.expect(200);
    let sids: Vec<String> = list.body["items"].as_array().unwrap().iter()
        .map(|i| i["sid"].as_str().unwrap().to_owned()).collect();
    assert!(!sids.contains(&x.sa.sid), "B lists A's session");
    let del = e
        .call(x.sb.req(Req::delete(&format!("/api/v2/me/sessions/{}", x.sa.sid))))
        .await;
    assert!(del.status == 404 || del.status == 403 || del.status == 401, "B revoked A's session? {}", del.status);
    e.call(x.sa.req(Req::get("/api/v2/me"))).await.expect(200);
    let r = e
        .call(Req::post("/api/v2/auth/token/refresh").cookie(&swap(&x.sa.rt, x.b.tenant)).idem("k1"))
        .await;
    r.expect_unauth();
    let r = e.call(x.sa.refresh_req("k2")).await;
    r.expect(200);
    let me = e.call(Session::from_auth(&r, None).req(Req::get("/api/v2/me"))).await;
    assert_eq!(me.body["tenant_id"], x.a.t());
    e.finish().await;
}

/// login_txn and setup links: tenant segment swaps find nothing; A's txn finished with B's
/// user data does not authenticate.
#[tokio::test]
async fn txns_and_setup_links_isolated() {
    let Some(e) = Env::default().await else { return };
    let (ta, tb) = (e.tenant().await, e.tenant().await);
    let (_, link_a) = e.invite(ta, "carol").await;
    let _ = e.invite(tb, "carol").await;
    // A's setup link moved to tenant B: refused; B's carol stays unregistered.
    let r = e.register(&e.nodes[0], &swap(&link_a, tb), "carol", PW).await;
    assert_eq!(r.status, 403, "{}", r.body);
    let a = User { tenant: ta, id: cs_common::id::UserId::generate().unwrap(), login: "carol".into(), pw: PW.into() };
    e.register(&e.nodes[0], &link_a, "carol", PW).await.expect(204);
    // A's login txn with its tenant segment swapped to B.
    let n = &e.nodes[0];
    let (st, c) = Env::login_start(n, &a.t(), "carol", PW).await;
    st.expect(200);
    let fin = Env::finalization(&st, c, &a.t(), "carol", PW);
    let txn = st.body["login_txn"].as_str().unwrap();
    let r = n
        .call(Req::post("/api/v2/auth/opaque/login/finish")
            .json(json!({"login_txn": swap(txn, tb), "credential_finalization": fin.clone()})))
        .await;
    r.expect_unauth();
    // The original still works once (the swap did not consume it), and only once.
    let ok = n
        .call(Req::post("/api/v2/auth/opaque/login/finish")
            .json(json!({"login_txn": txn, "credential_finalization": fin.clone()})))
        .await;
    ok.expect(200);
    assert_eq!(claims_of(ok.body["access_token"].as_str().unwrap())["tid"], a.t());
    let again = n
        .call(Req::post("/api/v2/auth/opaque/login/finish")
            .json(json!({"login_txn": txn, "credential_finalization": fin})))
        .await;
    again.expect_unauth();
    e.finish().await;
}

/// login_txn single use, 60 s TTL, bound to the source; a tampered finalization fails.
#[tokio::test]
async fn login_txn_expiry_source_binding_and_tamper() {
    let Some(e) = Env::default().await else { return };
    let t = e.tenant().await;
    let u = e.user(t, "tx", PW).await;
    let n = &e.nodes[0];
    // Tampered credential_finalization.
    let (st, c) = Env::login_start(n, &u.t(), "tx", PW).await;
    let fin = Env::finalization(&st, c, &u.t(), "tx", PW);
    let mut raw = unb64(&fin);
    raw[5] ^= 0x40;
    n.call(Req::post("/api/v2/auth/opaque/login/finish")
        .json(json!({"login_txn": st.body["login_txn"], "credential_finalization": b64(&raw)})))
        .await
        .expect_unauth();
    // Expired txn (61 s).
    let (st, c) = Env::login_start(n, &u.t(), "tx", PW).await;
    let fin = Env::finalization(&st, c, &u.t(), "tx", PW);
    e.exec("UPDATE auth_txns SET expires_at = now() - interval '1 second'").await;
    n.call(Req::post("/api/v2/auth/opaque/login/finish")
        .json(json!({"login_txn": st.body["login_txn"], "credential_finalization": fin})))
        .await
        .expect_unauth();
    // Finished from another source.
    let (st, c) = Env::login_start_from(n, &u.t(), "tx", PW, Some("203.0.113.1")).await;
    let fin = Env::finalization(&st, c, &u.t(), "tx", PW);
    let r = n
        .call(Req::post("/api/v2/auth/opaque/login/finish")
            .json(json!({"login_txn": st.body["login_txn"], "credential_finalization": fin}))
            .from("198.51.100.200"))
        .await;
    assert_eq!(r.status, 401, "login_txn finished from another source: {}", r.body);
    e.finish().await;
}

/// Recovery codes and grants of A are useless in B (same login, same password).
#[tokio::test]
async fn recovery_codes_and_grants_isolated() {
    let Some(e) = Env::default().await else { return };
    let x = two(&e).await;
    let codes = e.recovery_codes(&x.sa).await;
    let r = e
        .call(Req::post("/api/v2/auth/recovery/start")
            .json(json!({"tenant": x.b.t(), "login": "alice", "method": "recovery_code", "code": codes[0]})))
        .await;
    r.expect_unauth();
    let g = e
        .call(Req::post("/api/v2/auth/recovery/start")
            .json(json!({"tenant": x.a.t(), "login": "alice", "method": "recovery_code", "code": codes[1]})))
        .await;
    g.expect(200);
    let grant = g.body["grant"].as_str().unwrap().to_owned();
    // A's grant re-addressed to tenant B cannot register B's alice.
    let r = e.register(&e.nodes[0], &swap(&grant, x.b.tenant), "alice", "pw-taken-over").await;
    assert_eq!(r.status, 403, "{}", r.body);
    e.call(x.sb.req(Req::get("/api/v2/me"))).await.expect(200);
    let (_, f) = Env::login_raw(&e.nodes[0], &x.b.t(), "alice", PW, None).await;
    f.expect(200);
    let _ = x.sb;
    e.finish().await;
}

/// Passkeys: B cannot list, delete or sign in with A's passkey.
#[tokio::test]
async fn passkeys_isolated() {
    let Some(e) = Env::default().await else { return };
    let x = two(&e).await;
    let mut auth_a = Authenticator::new();
    let id = e.add_passkey(&x.sa, &mut auth_a).await;
    let lb = e.call(x.sb.req(Req::get("/api/v2/me/passkeys"))).await;
    lb.expect(200);
    assert!(lb.body["items"].as_array().unwrap().is_empty(), "B sees A's passkey");
    let del = e.call(x.sb.req(Req::delete(&format!("/api/v2/me/passkeys/{id}")))).await;
    assert!(del.status == 404 || del.status == 403, "B deleting A's passkey: {} {}", del.status, del.body);
    let la = e.call(x.sa.req(Req::get("/api/v2/me/passkeys"))).await;
    assert_eq!(la.body["items"].as_array().unwrap().len(), 1, "A's passkey gone");
    // Passwordless sign-in to tenant B with A's discoverable credential.
    let st = e
        .call(Req::post("/api/v2/auth/webauthn/login/start").json(json!({"tenant": x.b.t()})))
        .await;
    st.expect(200);
    let cred = auth_a.get(&st.body["public_key"]);
    let f = e
        .call(Req::post("/api/v2/auth/webauthn/login/finish")
            .json(json!({"login_txn": st.body["login_txn"], "credential": cred})))
        .await;
    f.expect_unauth();
    // And in tenant A it works (control).
    let st = e
        .call(Req::post("/api/v2/auth/webauthn/login/start").json(json!({"tenant": x.a.t()})))
        .await;
    let cred = auth_a.get(&st.body["public_key"]);
    let f = e
        .call(Req::post("/api/v2/auth/webauthn/login/finish")
            .json(json!({"login_txn": st.body["login_txn"], "credential": cred})))
        .await;
    f.expect(200);
    assert_eq!(claims_of(f.body["access_token"].as_str().unwrap())["tid"], x.a.t());
    e.finish().await;
}

/// Recovery requests: B cannot list, approve or cancel A's pending request.
#[tokio::test]
async fn recovery_requests_isolated() {
    let Some(e) = Env::default().await else { return };
    let x = two(&e).await;
    let st = e
        .call(Req::post("/api/v2/auth/recovery/start")
            .json(json!({"tenant": x.a.t(), "login": "alice", "method": "device_approval"})))
        .await;
    assert_eq!(st.status, 202, "{}", st.body);
    let la = e.call(x.sa.req(Req::get("/api/v2/me/recovery-requests"))).await;
    la.expect(200);
    let id = la.body["items"][0]["id"].as_str().unwrap().to_owned();
    let lb = e.call(x.sb.req(Req::get("/api/v2/me/recovery-requests"))).await;
    assert!(lb.body["items"].as_array().unwrap().is_empty(), "B sees A's request");
    let ap = e
        .call(x.sb.req(Req::post(&format!("/api/v2/me/recovery-requests/{id}/approve")).json(json!({}))))
        .await;
    assert!(ap.status == 404 || ap.status == 403, "B approved A's request: {} {}", ap.status, ap.body);
    let de = e
        .call(x.sb.req(Req::delete(&format!("/api/v2/me/recovery-requests/{id}"))))
        .await;
    assert!(de.status == 404 || de.status == 403, "B cancelled A's request: {} {}", de.status, de.body);
    let poll = e
        .call(Req::post("/api/v2/auth/recovery/status").json(json!({"recovery_txn": st.body["recovery_txn"]})))
        .await;
    poll.expect(200);
    assert_eq!(poll.body["state"], "pending", "{}", poll.body);
    assert!(poll.body.get("grant").is_none());
    e.finish().await;
}

/// Groups (CLI API, §0): members and groups of tenant A cannot join tenant B's groups.
#[tokio::test]
async fn groups_isolated() {
    let Some(e) = Env::default().await else { return };
    let (ta, tb) = (e.tenant().await, e.tenant().await);
    let (ua, _) = e.invite(ta, "gina").await;
    let ga = e.admin.create_group(ta, "staff").await.unwrap();
    let gb = e.admin.create_group(tb, "staff").await.unwrap();
    assert!(e.admin.add_member(tb, gb.group_id, Member::User(ua), None).await.is_err(), "A's user joined B's group");
    assert!(e.admin.add_member(tb, gb.group_id, Member::Group(ga.group_id), None).await.is_err(), "A's group joined B's group");
    assert!(e.admin.add_member(tb, ga.group_id, Member::User(ua), None).await.is_err(), "B's tenant addressed A's group");
    assert!(e.admin.members(tb, gb.group_id).await.unwrap().is_empty());
    assert!(e.admin.group(tb, ga.group_id).await.unwrap().is_none(), "A's group visible in B");
    e.admin.add_member(ta, ga.group_id, Member::User(ua), None).await.unwrap();
    e.finish().await;
}
