//! Step-up (§2.3 [R2], spec §5.5) and the enrolment-only scope (rev 11) on every route.
use crate::fx::*;
use cs_identity::session::SessionPolicy;
use serde_json::json;

/// Every M1 route with an access token: (method, path template).
pub const AUTHED_ROUTES: &[(&str, &str)] = &[
    ("GET", "/api/v2/me"),
    ("POST", "/api/v2/auth/logout"),
    ("POST", "/api/v2/auth/opaque/reauth/start"),
    ("POST", "/api/v2/auth/opaque/reauth/finish"),
    ("POST", "/api/v2/auth/opaque/register/start"),
    ("POST", "/api/v2/auth/opaque/register/finish"),
    ("POST", "/api/v2/auth/webauthn/register/start"),
    ("POST", "/api/v2/auth/webauthn/register/finish"),
    ("POST", "/api/v2/auth/webauthn/assert/start"),
    ("POST", "/api/v2/auth/webauthn/assert/finish"),
    ("GET", "/api/v2/me/sessions"),
    ("DELETE", "/api/v2/me/sessions/{id}"),
    ("GET", "/api/v2/me/passkeys"),
    ("DELETE", "/api/v2/me/passkeys/{id}"),
    ("GET", "/api/v2/me/recovery-codes"),
    ("POST", "/api/v2/me/recovery-codes"),
    ("GET", "/api/v2/me/recovery-requests"),
    ("DELETE", "/api/v2/me/recovery-requests/{id}"),
    ("POST", "/api/v2/me/recovery-requests/{id}/approve"),
];

/// A request for route `(m, p)` with `{id}` = `id` and a well-formed body, so a body-parse
/// rejection cannot mask an authentication or scope check.
pub fn route_req(m: &str, p: &str, id: &str) -> Req {
    let path = p.replace("{id}", id);
    let mut r = Req::new(m, &path);
    if m == "POST" {
        let txn = format!(
            "rt1.{}.{}",
            b64(&rand_bytes::<16>()),
            b64(&rand_bytes::<32>())
        );
        let msg = b64(&rand_bytes::<32>());
        let body = match p {
            "/api/v2/auth/opaque/reauth/start" => json!({"credential_request": msg}),
            "/api/v2/auth/opaque/reauth/finish" => {
                json!({"reauth_txn": txn, "credential_finalization": msg})
            }
            "/api/v2/auth/opaque/register/start" => {
                json!({"purpose": "password_change", "registration_request": msg})
            }
            "/api/v2/auth/opaque/register/finish" => {
                json!({"registration_txn": txn, "registration_upload": msg})
            }
            "/api/v2/auth/webauthn/assert/finish" => {
                json!({"assert_txn": txn, "credential": {"id": msg, "rawId": msg, "type": "public-key", "response": {"authenticatorData": msg, "clientDataJSON": msg, "signature": msg}, "clientExtensionResults": {}}})
            }
            _ => json!({}),
        };
        r = r.json(body);
    }
    r
}

fn is_step_up(r: &Resp) -> bool {
    r.status == 401 && r.err_codes().iter().any(|c| c == "step_up_required")
}

/// Sensitive operations at 5 min + 1 s since the last strong authentication answer 401 with
/// `errors[].code = step_up_required`; at 4 min 59 s they pass the step-up guard.
#[tokio::test]
async fn step_up_enforced_on_every_sensitive_route() {
    let Some(e) = Env::default().await else {
        return;
    };
    let t = e.tenant().await;
    let u = e.user(t, "sten", "pw-step-1").await;
    let s = e.login(&u).await;
    let other = e.login(&u).await;
    let mut a = Authenticator::new();
    let pk = e.add_passkey(&s, &mut a).await;
    let st = e
        .call(
            Req::post("/api/v2/auth/recovery/start")
                .json(json!({"tenant": u.t(), "login": "sten", "method": "device_approval"})),
        )
        .await;
    assert_eq!(st.status, 202);
    let rr = e
        .call(s.req(Req::get("/api/v2/me/recovery-requests")))
        .await;
    let rid = rr.body["items"][0]["id"].as_str().unwrap().to_owned();
    let reg = || {
        let c = cs_identity_wire::opaque_ke::ClientRegistration::<cs_identity_wire::Suite>::start(
            &mut rand_core_06::OsRng,
            b"pw-new",
        )
        .unwrap();
        b64(&c.message.serialize())
    };
    let sensitive: Vec<(&str, Req)> = vec![
        (
            "webauthn/register/start",
            Req::post("/api/v2/auth/webauthn/register/start").json(json!({})),
        ),
        (
            "DELETE passkey",
            Req::delete(&format!("/api/v2/me/passkeys/{pk}")),
        ),
        (
            "register/start password_change",
            Req::post("/api/v2/auth/opaque/register/start")
                .json(json!({"purpose": "password_change", "registration_request": reg()})),
        ),
        (
            "register/start ksf_upgrade",
            Req::post("/api/v2/auth/opaque/register/start")
                .json(json!({"purpose": "ksf_upgrade", "registration_request": reg()})),
        ),
        (
            "DELETE other session",
            Req::delete(&format!("/api/v2/me/sessions/{}", other.sid)),
        ),
        (
            "POST recovery-codes",
            Req::post("/api/v2/me/recovery-codes").json(json!({})),
        ),
        (
            "approve recovery request",
            Req::post(&format!("/api/v2/me/recovery-requests/{rid}/approve")).json(json!({})),
        ),
    ];
    e.age_strong_auth(&s, 301).await;
    let mut missing = Vec::new();
    for (name, r) in &sensitive {
        let resp = e.call(s.req(r.clone())).await;
        if !is_step_up(&resp) {
            missing.push(format!("{name}: {} {}", resp.status, resp.body));
        } else {
            assert_eq!(resp.code(), "unauthenticated");
        }
    }
    assert!(
        missing.is_empty(),
        "step-up not enforced at 5 min + 1 s:\n{}",
        missing.join("\n")
    );
    // Not sensitive: reading stays possible with an old strong auth.
    for p in [
        "/api/v2/me",
        "/api/v2/me/sessions",
        "/api/v2/me/passkeys",
        "/api/v2/me/recovery-codes",
    ] {
        e.call(s.req(Req::get(p))).await.expect(200);
    }
    // Inside the window: 4 min (not 4 min 59 s: on a loaded host the seven requests below
    // can take several seconds, which would push the session past the window).
    e.age_strong_auth(&s, 240).await;
    for (name, r) in &sensitive {
        let resp = e.call(s.req(r.clone())).await;
        assert!(
            !is_step_up(&resp),
            "{name}: step-up demanded inside the window: {}",
            resp.body
        );
    }
    e.finish().await;
}

/// Password reauth restores the step-up window on the existing session without a new
/// session or refresh token (rev 7).
#[tokio::test]
async fn reauth_restores_step_up_without_new_session() {
    let Some(e) = Env::default().await else {
        return;
    };
    let t = e.tenant().await;
    let u = e.user(t, "reau", "pw-step-2").await;
    let s = e.login(&u).await;
    e.age_strong_auth(&s, 400).await;
    let before = e.i64("SELECT count(*) FROM sessions").await;
    let c = cs_identity_wire::opaque_ke::ClientLogin::<cs_identity_wire::Suite>::start(
        &mut rand_core_06::OsRng,
        u.pw.as_bytes(),
    )
    .unwrap();
    let st = e
        .call(
            s.req(
                Req::post("/api/v2/auth/opaque/reauth/start")
                    .json(json!({"credential_request": b64(&c.message.serialize())})),
            ),
        )
        .await;
    st.expect(200);
    let mut body = st.body.clone();
    body["login_txn"] = body["reauth_txn"].clone();
    let st2 = Resp { body, ..st.clone() };
    let fin = Env::finalization(&st2, c.state, &u.t(), &u.login, &u.pw);
    let f = e
        .call(
            s.req(Req::post("/api/v2/auth/opaque/reauth/finish").json(
                json!({"reauth_txn": st.body["reauth_txn"], "credential_finalization": fin}),
            )),
        )
        .await;
    f.expect(204);
    assert!(f.rt().is_none(), "reauth must not issue a refresh token");
    assert_eq!(
        e.i64("SELECT count(*) FROM sessions").await,
        before,
        "reauth created a session"
    );
    let r = e
        .call(s.req(Req::post("/api/v2/me/recovery-codes").json(json!({}))))
        .await;
    r.expect(200);
    e.finish().await;
}

/// rev 11: an enrolment-only session (`scp: mfa_enrolment`) may call only
/// `webauthn/register/*`, `me/recovery-codes`, `GET /me` and logout; every other route
/// answers 401 with `mfa_required`. Its refresh keeps the scope.
#[tokio::test]
async fn enrolment_only_scope_on_every_route() {
    let policy = SessionPolicy {
        mfa_required: true,
        ..SessionPolicy::default()
    };
    let Some(e) = Env::new(Opts {
        policy,
        ..Opts::default()
    })
    .await
    else {
        return;
    };
    let t = e.tenant().await;
    let u = e.user(t, "enrol", "pw-enrol-1").await;
    let (_, f) = Env::login_raw(&e.nodes[0], &u.t(), &u.login, &u.pw, None).await;
    f.expect(200);
    assert_eq!(f.body["state"], "authenticated", "{}", f.body);
    let s = Session::from_auth(&f, None);
    assert_eq!(s.claims["scp"], "mfa_enrolment", "{}", s.claims);
    let allowed = [
        ("POST", "/api/v2/auth/webauthn/register/start"),
        ("POST", "/api/v2/auth/webauthn/register/finish"),
        ("GET", "/api/v2/me/recovery-codes"),
        ("POST", "/api/v2/me/recovery-codes"),
        ("GET", "/api/v2/me"),
        ("POST", "/api/v2/auth/logout"),
    ];
    let fake = uuid::Uuid::now_v7().to_string();
    let mut leaks = Vec::new();
    for (m, p) in AUTHED_ROUTES {
        if allowed.contains(&(*m, *p)) {
            continue;
        }
        let r = route_req(m, p, &fake);
        let resp = e.call(s.req(r)).await;
        if !(resp.status == 401 && resp.err_codes().iter().any(|c| c == "mfa_required")) {
            leaks.push(format!("{m} {p}: {} {}", resp.status, resp.body));
        }
    }
    assert!(
        leaks.is_empty(),
        "enrolment-only token accepted outside its routes:\n{}",
        leaks.join("\n")
    );
    e.call(s.req(Req::get("/api/v2/me"))).await.expect(200);
    e.call(s.req(Req::get("/api/v2/me/recovery-codes")))
        .await
        .expect(200);
    let r = e.call(s.refresh_req("enrol-1")).await;
    r.expect(200);
    let s2 = Session::from_auth(&r, None);
    assert_eq!(
        s2.claims["scp"], "mfa_enrolment",
        "refresh widened the scope"
    );
    let resp = e.call(s2.req(Req::get("/api/v2/me/sessions"))).await;
    assert_eq!(resp.status, 401);
    // After enrolling recovery codes, the next sign-in requires MFA (no session yet).
    let codes = e.recovery_codes(&s2).await;
    let (_, f) = Env::login_raw(&e.nodes[0], &u.t(), &u.login, &u.pw, None).await;
    f.expect(200);
    assert_eq!(f.body["state"], "mfa_required", "{}", f.body);
    assert!(f.body.get("access_token").is_none() && f.rt().is_none());
    let auth_txn = f.body["auth_txn"].as_str().unwrap().to_owned();
    // auth_txn presented to the wrong endpoint: 401 mfa_required.
    let wrong = e
        .call(
            Req::post("/api/v2/auth/token/refresh")
                .cookie(&auth_txn)
                .idem("w1"),
        )
        .await;
    assert_eq!(wrong.status, 401);
    assert!(
        wrong.err_codes().iter().any(|c| c == "mfa_required"),
        "{}",
        wrong.body
    );
    let ok = e
        .call(
            Req::post("/api/v2/auth/mfa/recovery-code")
                .json(json!({"auth_txn": auth_txn, "code": codes[0]})),
        )
        .await;
    ok.expect(200);
    let full = claims_of(ok.body["access_token"].as_str().unwrap());
    assert!(
        full.get("scp").is_none(),
        "full session still scoped: {full}"
    );
    // auth_txn single use.
    let again = e
        .call(
            Req::post("/api/v2/auth/mfa/recovery-code")
                .json(json!({"auth_txn": auth_txn, "code": codes[1]})),
        )
        .await;
    again.expect_unauth();
    e.finish().await;
}
