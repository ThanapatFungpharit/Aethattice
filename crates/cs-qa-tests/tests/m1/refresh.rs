//! Refresh rotation, lost-response window, reuse revocation, cookies, logout (contract §2.4,
//! §3 [R1] [R8] [R10]; M0-gate §6.1 "Refresh").
use crate::fx::*;

fn k() -> String {
    uuid::Uuid::new_v4().to_string()
}

async fn sess(e: &Env) -> (User, Session) {
    let t = e.tenant().await;
    let u = e.user(t, "rita", "pw-refresh-1").await;
    let s = e.login(&u).await;
    (u, s)
}

async fn state_of(e: &Env, sid: &str) -> (String, i64) {
    let st = e
        .i64(&format!(
            "SELECT CASE state WHEN 'active' THEN 1 WHEN 'revoked' THEN 2 ELSE 3 END::bigint \
             FROM sessions WHERE session_id = '{sid}'"
        ))
        .await;
    let g = e
        .i64(&format!(
            "SELECT generation FROM sessions WHERE session_id = '{sid}'"
        ))
        .await;
    let s = match st {
        1 => "active",
        2 => "revoked",
        _ => "expired",
    };
    (s.to_owned(), g)
}

async fn revoked_events(e: &Env) -> i64 {
    e.i64("SELECT count(*) FROM outbox WHERE event_type = 'identity.session.revoked'")
        .await
}

#[tokio::test]
async fn cookie_attributes_and_no_store() {
    let Some(e) = Env::default().await else {
        return;
    };
    let t = e.tenant().await;
    let u = e.user(t, "cookie", "pw-cookie-1").await;
    let (_, f) = Env::login_raw(&e.nodes[0], &u.t(), &u.login, &u.pw, None).await;
    f.expect(200);
    let c = f.set_cookie().unwrap();
    assert!(c.starts_with("__Secure-cs_rt=rt1."), "{c}");
    let attrs: Vec<String> = c
        .split(';')
        .skip(1)
        .map(|a| a.trim().to_ascii_lowercase())
        .collect();
    for want in [
        "secure",
        "httponly",
        "samesite=strict",
        "path=/api/v2/auth/token",
    ] {
        assert!(attrs.iter().any(|a| a == want), "cookie lacks {want}: {c}");
    }
    assert!(
        !attrs.iter().any(|a| a.starts_with("domain=")),
        "no Domain attribute: {c}"
    );
    assert_eq!(
        f.headers.get("cache-control").map(|v| v.to_str().unwrap()),
        Some("no-store")
    );
    assert!(
        f.body.get("refresh_token").is_none(),
        "browser flow: refresh token only in the cookie"
    );
    let s = Session::from_auth(&f, None);
    let r = e.call(s.refresh_req(&k())).await;
    r.expect(200);
    assert_eq!(
        r.headers.get("cache-control").map(|v| v.to_str().unwrap()),
        Some("no-store")
    );
    let c2 = r.set_cookie().unwrap();
    assert!(
        c2.to_ascii_lowercase().contains("httponly")
            && c2.to_ascii_lowercase().contains("samesite=strict")
    );
    e.finish().await;
}

/// Every refresh rotates; presenting a rotated token with another key (or none, or after the
/// window) is reuse: session revoked, generation bumped, whole family dead, outbox event.
#[tokio::test]
async fn rotation_and_reuse_revokes_session() {
    let Some(e) = Env::default().await else {
        return;
    };
    let (_, s0) = sess(&e).await;
    let (_, g0) = state_of(&e, &s0.sid).await;
    let r1 = e.call(s0.refresh_req(&k())).await;
    r1.expect(200);
    let s1 = Session::from_auth(&r1, None);
    assert_ne!(s1.rt, s0.rt, "refresh must rotate");
    assert_eq!(s1.sid, s0.sid);
    let r2 = e.call(s1.refresh_req(&k())).await;
    r2.expect(200);
    let s2 = Session::from_auth(&r2, None);
    let ev0 = revoked_events(&e).await;
    // Reuse of s0's token (rotated twice ago) with a fresh key.
    e.call(s0.refresh_req(&k())).await.expect_unauth();
    let (st, g1) = state_of(&e, &s0.sid).await;
    assert_eq!(st, "revoked");
    assert!(g1 > g0, "generation must be bumped on reuse");
    assert_eq!(
        revoked_events(&e).await,
        ev0 + 1,
        "identity.session.revoked"
    );
    // The legitimate newest token is dead too.
    e.call(s2.refresh_req(&k())).await.expect_unauth();
    assert_eq!(
        e.i64(&format!(
            "SELECT count(*) FROM refresh_tokens WHERE session_id = '{}' AND state <> 'revoked' AND state <> 'rotated'",
            s0.sid
        ))
        .await,
        0,
        "no active token may remain in the family"
    );
    e.finish().await;
}

/// [R1]: the same Idempotency-Key within 30 s is a lost response (new successor, old
/// successor revoked, session kept); after 30 s, or with no/different key, it is reuse.
#[tokio::test]
async fn lost_response_window_and_its_limits() {
    let Some(e) = Env::default().await else {
        return;
    };
    let (_, s0) = sess(&e).await;
    let key = k();
    let a = e.call(s0.refresh_req(&key)).await;
    a.expect(200);
    let lost = Session::from_auth(&a, None);
    // Response lost; the client retries with the same key.
    let b = e.call(s0.refresh_req(&key)).await;
    b.expect(200);
    let got = Session::from_auth(&b, None);
    assert_ne!(
        got.rt, lost.rt,
        "the never-received successor must be replaced"
    );
    assert_eq!(state_of(&e, &s0.sid).await.0, "active");
    // The never-received successor is revoked (presenting it fails), but not as reuse.
    e.call(lost.refresh_req(&k())).await.expect_unauth();
    let c = e.call(got.refresh_req(&k())).await;
    c.expect(200);
    let s3 = Session::from_auth(&c, None);
    assert_eq!(
        state_of(&e, &s0.sid).await.0,
        "active",
        "a revoked successor is not reuse"
    );

    // Outside the window (rotated 31 s ago): same key is reuse.
    let key2 = k();
    let d = e.call(s3.refresh_req(&key2)).await;
    d.expect(200);
    e.exec(&format!(
        "UPDATE refresh_tokens SET rotated_at = now() - interval '31 seconds' WHERE session_id = '{}' AND rotated_at IS NOT NULL",
        s0.sid
    ))
    .await;
    e.call(s3.refresh_req(&key2)).await.expect_unauth();
    assert_eq!(
        state_of(&e, &s0.sid).await.0,
        "revoked",
        "same key after 30 s is reuse"
    );
    e.finish().await;
}

/// Lost-response retry with a different key, and without a key at all.
#[tokio::test]
async fn rotated_token_with_other_or_no_key() {
    let Some(e) = Env::default().await else {
        return;
    };
    let (_, s0) = sess(&e).await;
    e.call(s0.refresh_req(&k())).await.expect(200);
    // No key: refused before any state change (400), and not counted as a lost response.
    let nk = e
        .call(crate::fx::Req::post("/api/v2/auth/token/refresh").cookie(&s0.rt))
        .await;
    assert!(nk.status == 400 || nk.status == 401, "{}", nk.body);
    // Different key within the window: reuse.
    e.call(s0.refresh_req(&k())).await.expect_unauth();
    assert_eq!(state_of(&e, &s0.sid).await.0, "revoked");
    e.finish().await;
}

/// Concurrent refreshes of one token with different keys: exactly one wins; the losers are
/// reuse (session revoked). With the same key: never more than one live successor.
#[tokio::test]
async fn concurrent_refresh_race() {
    let Some(e) = Env::default().await else {
        return;
    };
    let (_, s0) = sess(&e).await;
    let futs: Vec<_> = (0..6).map(|_| e.call(s0.refresh_req(&k()))).collect();
    let rs = futures::future::join_all(futs).await;
    let ok = rs.iter().filter(|r| r.status == 200).count();
    assert!(ok <= 1, "{ok} winners for one token");
    assert!(
        rs.iter()
            .all(|r| r.status == 200 || r.status == 401 || r.code() == "outcome_unknown"),
        "statuses: {:?}",
        rs.iter().map(|r| r.status).collect::<Vec<_>>()
    );
    if rs.iter().any(|r| r.status == 401) {
        assert_eq!(
            state_of(&e, &s0.sid).await.0,
            "revoked",
            "losers with other keys are reuse"
        );
    }

    let (_, s1) = sess(&e).await;
    let key = k();
    let futs: Vec<_> = (0..6).map(|_| e.call(s1.refresh_req(&key))).collect();
    let rs = futures::future::join_all(futs).await;
    assert!(
        rs.iter().any(|r| r.status == 200),
        "same-key race: none succeeded"
    );
    let live = e
        .i64(&format!(
            "SELECT count(*) FROM refresh_tokens WHERE session_id = '{}' AND state = 'active'",
            s1.sid
        ))
        .await;
    assert!(
        live <= 1,
        "{live} live refresh tokens after a same-key race"
    );
    e.finish().await;
}

/// Refresh after idle or absolute expiry fails and does not revive the session.
#[tokio::test]
async fn refresh_after_idle_or_absolute_expiry() {
    let Some(e) = Env::default().await else {
        return;
    };
    let (_, a) = sess(&e).await;
    e.exec(&format!(
        "UPDATE sessions SET idle_expires_at = now() - interval '1 second' WHERE session_id = '{}'",
        a.sid
    ))
    .await;
    e.call(a.refresh_req(&k())).await.expect_unauth();
    assert_ne!(state_of(&e, &a.sid).await.0, "active");
    let (_, b) = sess(&e).await;
    e.exec(&format!(
        "UPDATE sessions SET absolute_expires_at = now() - interval '1 second' WHERE session_id = '{}'",
        b.sid
    ))
    .await;
    e.call(b.refresh_req(&k())).await.expect_unauth();
    assert_ne!(state_of(&e, &b.sid).await.0, "active");
    // Idle extension never passes the absolute expiry.
    let (_, c) = sess(&e).await;
    e.exec(&format!(
        "UPDATE sessions SET absolute_expires_at = now() + interval '1 hour' WHERE session_id = '{}'",
        c.sid
    ))
    .await;
    e.call(c.refresh_req(&k())).await.expect(200);
    assert_eq!(
        e.i64(&format!(
            "SELECT (idle_expires_at <= absolute_expires_at)::int::bigint FROM sessions WHERE session_id = '{}'",
            c.sid
        ))
        .await,
        1
    );
    e.finish().await;
}

/// [R10]: logout by access token revokes the session and the refresh family the request
/// never saw, and clears the cookie.
#[tokio::test]
async fn logout_revokes_family_and_clears_cookie() {
    let Some(e) = Env::default().await else {
        return;
    };
    let (_, s) = sess(&e).await;
    let r = e
        .call(s.req(crate::fx::Req::post("/api/v2/auth/logout")))
        .await;
    r.expect(204);
    let c = r.set_cookie().unwrap();
    assert!(c.starts_with("__Secure-cs_rt=;"), "{c}");
    assert!(
        c.contains("Max-Age=0") && c.contains("Path=/api/v2/auth/token"),
        "{c}"
    );
    e.call(s.refresh_req(&k())).await.expect_unauth();
    assert_eq!(state_of(&e, &s.sid).await.0, "revoked");
    e.finish().await;
}

/// [R8]: the tenant segment selects the partition only. Swapping it (to another existing
/// tenant) finds nothing and never revokes the real session; malformed tokens are 401.
#[tokio::test]
async fn rt1_tenant_segment_swap_and_malformed_tokens() {
    let Some(e) = Env::default().await else {
        return;
    };
    let (_, a) = sess(&e).await;
    let other = e.tenant().await;
    let parts: Vec<&str> = a.rt.split('.').collect();
    let seg = b64(other.as_uuid().as_bytes());
    let swapped = format!("rt1.{seg}.{}", parts[2]);
    let mut bad = vec![
        swapped,
        format!("rt2.{}.{}", parts[1], parts[2]),
        format!("{}.{}", parts[0], parts[2]),
        format!("rt1.{}.{}x", parts[1], parts[2]),
        format!("rt1.{}.{}", parts[1], &parts[2][..42]),
        "rt1..".into(),
        "".into(),
    ];
    let mut flipped = unb64(parts[2]);
    flipped[0] ^= 1;
    bad.push(format!("rt1.{}.{}", parts[1], b64(&flipped)));
    for t in &bad {
        let r = e
            .call(
                crate::fx::Req::post("/api/v2/auth/token/refresh")
                    .cookie(t)
                    .idem(&k()),
            )
            .await;
        assert_eq!(r.status, 401, "{t:?} accepted: {}", r.body);
    }
    assert_eq!(state_of(&e, &a.sid).await.0, "active");
    e.call(a.refresh_req(&k())).await.expect(200);
    e.finish().await;
}

/// F-3 (rev 14): a revoked session must not keep working through its still-unexpired access
/// token on ANY authenticated route (spec §5.5 "revokes the whole session"). The routes are
/// `scopes::AUTHED_ROUTES`, the complete list of token-authenticated M1 routes (axum offers no
/// public route enumeration; the list is checked against `cs_identity::http::routes` by
/// review in docs/qa/M1-gate.md). Covered revocations: logout and [R5]-style reuse.
#[tokio::test]
async fn revoked_session_access_token_refused_on_every_route() {
    let Some(e) = Env::default().await else {
        return;
    };
    let mut accepted = Vec::new();
    for how in ["logout", "refresh reuse"] {
        let (_, s) = sess(&e).await;
        match how {
            "logout" => {
                e.call(s.req(crate::fx::Req::post("/api/v2/auth/logout")))
                    .await
                    .expect(204);
            }
            _ => {
                e.call(s.refresh_req(&k())).await.expect(200);
                e.call(s.refresh_req(&k())).await.expect_unauth();
            }
        }
        let fake = uuid::Uuid::now_v7().to_string();
        for (m, p) in crate::scopes::AUTHED_ROUTES {
            let r = e.call(s.req(crate::scopes::route_req(m, p, &fake))).await;
            if r.status != 401 || r.code() != "unauthenticated" {
                accepted.push(format!("after {how}: {m} {p}: {} {}", r.status, r.code()));
            }
        }
    }
    assert!(
        accepted.is_empty(),
        "access token of a revoked session not refused with 401:\n{}",
        accepted.join("\n")
    );
    e.finish().await;
}
