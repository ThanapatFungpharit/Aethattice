//! DPoP (contract §3 rev 8, [R6]; M0-gate §6.1 "DPoP").
use crate::fx::*;
use serde_json::json;

fn k() -> String {
    uuid::Uuid::new_v4().to_string()
}

async fn bound(e: &Env) -> (User, Session) {
    let t = e.tenant().await;
    let u = e.user(t, "dora", "pw-dpop-1").await;
    let s = e.login_dpop(&u).await;
    (u, s)
}

fn me_with(at: &str, scheme: &str, proof: Option<String>) -> Req {
    let mut r = Req::get("/api/v2/me").header("authorization", &format!("{scheme} {at}"));
    if let Some(p) = proof {
        r = r.header("dpop", &p);
    }
    r
}

/// Binding at login, Bearer refused for a bound token, every proof check.
#[tokio::test]
async fn bound_token_proof_checks() {
    let Some(e) = Env::default().await else { return };
    let (_, s) = bound(&e).await;
    let key = s.key.clone().unwrap();
    assert_eq!(s.claims["cnf"]["jkt"], key.jkt(), "cnf.jkt must be the proof key thumbprint");
    let at = s.at.clone();
    let path = "/api/v2/me";
    let u = htu(path);
    e.call(me_with(&at, "DPoP", Some(key.proof("GET", &u, Some(&at))))).await.expect(200);

    let other = DKey::es256();
    let mut c = key.claims("GET", &u, Some(&at));
    let n = now();
    let mut cases: Vec<(&str, Req)> = vec![
        ("Bearer with a bound token", me_with(&at, "Bearer", None)),
        ("Bearer with a bound token and a proof", me_with(&at, "Bearer", Some(key.proof("GET", &u, Some(&at))))),
        ("DPoP scheme without proof", me_with(&at, "DPoP", None)),
        ("wrong htm", me_with(&at, "DPoP", Some(key.proof("POST", &u, Some(&at))))),
        ("htu other path", me_with(&at, "DPoP", Some(key.proof("GET", &htu("/api/v2/me/sessions"), Some(&at))))),
        ("htu other host", me_with(&at, "DPoP", Some(key.proof("GET", &format!("https://evil.example{path}"), Some(&at))))),
        ("htu http scheme", me_with(&at, "DPoP", Some(key.proof("GET", &format!("http://{DOMAIN}{path}"), Some(&at))))),
        ("htu trailing slash", me_with(&at, "DPoP", Some(key.proof("GET", &format!("{u}/"), Some(&at))))),
        ("missing ath", me_with(&at, "DPoP", Some(key.proof("GET", &u, None)))),
        ("ath of another token", me_with(&at, "DPoP", Some(key.proof("GET", &u, Some("other-token"))))),
        ("proof from another key (jkt mismatch)", me_with(&at, "DPoP", Some(other.proof("GET", &u, Some(&at))))),
        ("Ed25519 key not bound", me_with(&at, "DPoP", Some(DKey::ed25519().proof("GET", &u, Some(&at))))),
    ];
    c["iat"] = json!(n - 61);
    cases.push(("stale iat (-61 s)", me_with(&at, "DPoP", Some(key.sign_raw(&key.header(), &c)))));
    // +62 s: the request reaches the server within a second, so the skew stays > 60 s.
    c["iat"] = json!(n + 62);
    cases.push(("future iat (+62 s)", me_with(&at, "DPoP", Some(key.sign_raw(&key.header(), &c)))));
    let mut c2 = key.claims("GET", &u, Some(&at));
    c2.as_object_mut().unwrap().remove("jti");
    cases.push(("no jti", me_with(&at, "DPoP", Some(key.sign_raw(&key.header(), &c2)))));
    let base = key.claims("GET", &u, Some(&at));
    let mut h = key.header();
    h["typ"] = json!("jwt");
    cases.push(("typ jwt", me_with(&at, "DPoP", Some(key.sign_raw(&h, &base)))));
    let mut h = key.header();
    h["alg"] = json!("none");
    cases.push(("alg none", me_with(&at, "DPoP", Some(key.sign_raw(&h, &base)))));
    let mut h = key.header();
    h["alg"] = json!("RS256");
    cases.push(("alg RS256", me_with(&at, "DPoP", Some(key.sign_raw(&h, &base)))));
    let mut h = key.header();
    h["alg"] = json!("ES384");
    cases.push(("alg ES384", me_with(&at, "DPoP", Some(key.sign_raw(&h, &base)))));
    let mut h = key.header();
    h["jwk"]["d"] = json!(key.private_b64());
    cases.push(("jwk with private member", me_with(&at, "DPoP", Some(key.sign_raw(&h, &base)))));
    let mut h = key.header();
    h["jwk"] = other.jwk();
    cases.push(("jwk of another key, signed by the bound key", me_with(&at, "DPoP", Some(key.sign_raw(&h, &base)))));
    let good = key.proof("GET", &u, Some(&at));
    let mut sp: Vec<String> = good.split('.').map(str::to_owned).collect();
    let mut sig = unb64(&sp[2]);
    sig[3] ^= 1;
    sp[2] = b64(&sig);
    cases.push(("tampered proof signature", me_with(&at, "DPoP", Some(sp.join(".")))));
    cases.push((
        "two DPoP headers",
        me_with(&at, "DPoP", Some(key.proof("GET", &u, Some(&at))))
            .header("dpop", &key.proof("GET", &u, Some(&at))),
    ));
    for (name, r) in cases {
        let resp = e.call(r).await;
        assert_eq!(resp.status, 401, "{name}: accepted ({})", resp.body);
        assert_eq!(resp.code(), "unauthenticated", "{name}");
    }
    // Query strings are not part of htu.
    let r = e
        .call(
            Req::get("/api/v2/me?x=1")
                .header("authorization", &format!("DPoP {at}"))
                .header("dpop", &key.proof("GET", &u, Some(&at))),
        )
        .await;
    r.expect(200);
    e.finish().await;
}

/// Replay of one proof: on the same node, across two nodes sharing Valkey, across two nodes
/// on the table fallback, and across a node whose Valkey is down ([R6]: never per node).
#[tokio::test]
async fn proof_replay_rejected_across_nodes() {
    let Some(e) = Env::new(Opts {
        nodes: vec![Valkey::Real, Valkey::Real, Valkey::None, Valkey::None, Valkey::Down],
        ..Opts::default()
    })
    .await
    else {
        return;
    };
    let (_, s) = bound(&e).await;
    let key = s.key.clone().unwrap();
    let u = htu("/api/v2/me");
    let mut failures = Vec::new();
    for (name, a, b) in [
        ("same node (Valkey)", 0usize, 0usize),
        ("node A -> node B (shared Valkey)", 0, 1),
        ("same node (table)", 2, 2),
        ("node C -> node D (shared dpop_jti table)", 2, 3),
        ("node A (Valkey) -> node E (Valkey down, table fallback)", 0, 4),
        ("node E (table fallback) -> node A (Valkey)", 4, 0),
    ] {
        let p = key.proof("GET", &u, Some(&s.at));
        let first = e.nodes[a].call(me_with(&s.at, "DPoP", Some(p.clone()))).await;
        assert_eq!(first.status, 200, "{name}: first use refused: {}", first.body);
        let second = e.nodes[b].call(me_with(&s.at, "DPoP", Some(p))).await;
        if second.status != 401 {
            failures.push(format!("{name}: replay accepted ({})", second.status));
        }
    }
    assert!(failures.is_empty(), "[R6] DPoP replay accepted:\n{}", failures.join("\n"));
    e.finish().await;
}

/// Both replay stores unavailable: DPoP-bound requests fail closed with 503 unavailable.
#[tokio::test]
async fn replay_store_outage_fails_closed() {
    let Some(e) = Env::default().await else { return };
    let (_, s) = bound(&e).await;
    let dead = pool_for(&crate::support::db::unreachable_url("cs_identity"));
    let store = cs_identity::dpop::ReplayStore::new(dead, Some(VALKEY_DOWN)).unwrap();
    let auth = cs_identity::auth::AuthService::new(
        e.pool.clone(),
        e.kms.clone(),
        DOMAIN,
        cs_identity::session::SessionPolicy::default(),
    )
    .with_replay_store(store);
    let n = Env::node_from(std::sync::Arc::new(auth));
    let r = n.call(s.req(Req::get("/api/v2/me"))).await;
    assert_eq!(r.status, 503, "{}", r.body);
    assert_eq!(r.code(), "unavailable");
    assert_eq!(r.body["retryable"], true, "{}", r.body);
    // Unbound tokens do not need the replay store.
    let t = e.tenant().await;
    let u = e.user(t, "plain", "pw-dpop-2").await;
    let p = e.login(&u).await;
    n.call(p.req(Req::get("/api/v2/me"))).await.expect(200);
    e.finish().await;
}

/// Bound refresh family: a refresh without a proof, or with another key's proof, is theft
/// (refused, session revoked); with the right key it rotates and stays bound.
#[tokio::test]
async fn bound_refresh_requires_same_key() {
    let Some(e) = Env::default().await else { return };
    let (_, s) = bound(&e).await;
    let r = e.call(s.refresh_req(&k())).await;
    r.expect(200);
    let s1 = Session::from_auth(&r, s.key.clone());
    assert_eq!(s1.claims["cnf"]["jkt"], s.key.as_ref().unwrap().jkt());
    // No proof.
    let no_proof = Req::post("/api/v2/auth/token/refresh").cookie(&s1.rt).idem(&k());
    e.call(no_proof).await.expect_unauth();
    let st = e
        .i64(&format!("SELECT (state = 'revoked')::int::bigint FROM sessions WHERE session_id = '{}'", s.sid))
        .await;
    assert_eq!(st, 1, "bound refresh without proof must revoke the session");

    let (_, s2) = bound(&e).await;
    let other = DKey::es256();
    let wrong = Req::post("/api/v2/auth/token/refresh").cookie(&s2.rt).idem(&k()).proof(&other);
    e.call(wrong).await.expect_unauth();
    let st = e
        .i64(&format!("SELECT (state = 'revoked')::int::bigint FROM sessions WHERE session_id = '{}'", s2.sid))
        .await;
    assert_eq!(st, 1, "bound refresh with another key must revoke the session");
    e.finish().await;
}

/// A login/finish proof is single use, and its htu/htm are checked.
#[tokio::test]
async fn login_finish_proof_checks() {
    let Some(e) = Env::default().await else { return };
    let t = e.tenant().await;
    let u = e.user(t, "lena", "pw-dpop-3").await;
    let key = DKey::es256();
    let path = "/api/v2/auth/opaque/login/finish";
    for (name, proof) in [
        ("wrong htu", key.proof("POST", &htu("/api/v2/auth/token/refresh"), None)),
        ("wrong htm", key.proof("GET", &htu(path), None)),
        ("ath on login", key.proof("POST", &htu(path), Some("x"))),
    ] {
        let (st, c) = Env::login_start(&e.nodes[0], &u.t(), &u.login, &u.pw).await;
        st.expect(200);
        let fin = Env::finalization(&st, c, &u.t(), &u.login, &u.pw);
        let r = e
            .call(
                Req::post(path)
                    .json(json!({"login_txn": st.body["login_txn"], "credential_finalization": fin}))
                    .header("dpop", &proof),
            )
            .await;
        assert_eq!(r.status, 401, "{name}: {}", r.body);
    }
    // Replay of a login proof on a second login.
    let p = key.proof("POST", &htu(path), None);
    for i in 0..2 {
        let (st, c) = Env::login_start(&e.nodes[0], &u.t(), &u.login, &u.pw).await;
        let fin = Env::finalization(&st, c, &u.t(), &u.login, &u.pw);
        let r = e
            .call(
                Req::post(path)
                    .json(json!({"login_txn": st.body["login_txn"], "credential_finalization": fin}))
                    .header("dpop", &p),
            )
            .await;
        if i == 0 {
            r.expect(200);
        } else {
            assert_eq!(r.status, 401, "replayed login proof accepted: {}", r.body);
        }
    }
    e.finish().await;
}
