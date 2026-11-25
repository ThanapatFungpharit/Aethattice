//! Enumeration resistance (spec §5.2, contract §2.1 [R3], §4 rev 10, §5, §6; M0-gate §6.1
//! "Enumeration", "Rate limits").
use crate::fx::*;
use cs_identity::ratelimit::RateLimits;
use serde_json::{Value, json};
use std::time::Instant;

fn keys(v: &Value) -> Vec<String> {
    let mut k: Vec<String> = v
        .as_object()
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();
    k.sort();
    k
}

fn shape(r: &Resp) -> Value {
    let mut v = r.shape();
    if let Some(o) = v.as_object_mut() {
        o.remove("retry_after_ms");
    }
    v
}

/// Known, unknown-in-tenant, unknown tenant, disabled and invited users: login/start answers
/// with the same status, body shape and valid, deterministic KSF parameters; login/finish
/// fails identically (status, code, detail, errors) for every failure class, including a
/// wrong password.
#[tokio::test]
async fn login_indistinguishable_for_unknown_disabled_and_wrong_password() {
    let Some(e) = Env::default().await else { return };
    let t = e.tenant().await;
    let _known = e.user(t, "known", "pw-enum-1").await;
    let disabled = e.user(t, "disabled", "pw-enum-2").await;
    e.exec(&format!(
        "UPDATE users SET status = 'disabled' WHERE user_id = '{}'",
        disabled.id.as_uuid()
    ))
    .await;
    let _invited = e.invite(t, "invited").await;
    let ts = t.as_uuid().to_string();
    let unknown_tenant = uuid::Uuid::now_v7().to_string();
    let classes: Vec<(&str, String, String, String)> = vec![
        ("known, wrong password", ts.clone(), "known".into(), "wrong-password".into()),
        ("unknown account", ts.clone(), "nobody".into(), "pw".into()),
        ("unknown tenant", unknown_tenant.clone(), "known".into(), "pw-enum-1".into()),
        ("disabled user, right password", ts.clone(), "disabled".into(), "pw-enum-2".into()),
        ("invited (unregistered) user", ts.clone(), "invited".into(), "pw".into()),
    ];
    let n = &e.nodes[0];
    let (ks, _) = Env::login_start(n, &ts, "known", "pw-enum-1").await;
    ks.expect(200);
    let ref_keys = keys(&ks.body);
    assert_eq!(ref_keys, vec!["credential_response", "ksf_params", "login_txn"]);
    let ref_len = ks.body["credential_response"].as_str().unwrap().len();
    let mut finish_shapes = Vec::new();
    for (name, tenant, login, pw) in &classes {
        let (st, c) = Env::login_start(n, tenant, login, pw).await;
        assert_eq!(st.status, 200, "{name}: login/start {}", st.body);
        assert_eq!(keys(&st.body), ref_keys, "{name}: body members");
        assert_eq!(
            st.body["credential_response"].as_str().unwrap().len(),
            ref_len,
            "{name}: credential_response length"
        );
        assert_eq!(keys(&st.body["ksf_params"]), keys(&ks.body["ksf_params"]), "{name}");
        let _ = ksf_of(&st.body["ksf_params"]);
        // Deterministic PRF: the same unknown login gets the same parameters again.
        let (again, _) = Env::login_start(n, tenant, login, pw).await;
        assert_eq!(again.body["ksf_params"], st.body["ksf_params"], "{name}: ksf_params not stable");
        let fin = Env::finalization(&st, c, tenant, login, pw);
        let f = n
            .call(Req::post("/api/v2/auth/opaque/login/finish").json(
                json!({"login_txn": st.body["login_txn"], "credential_finalization": fin}),
            ))
            .await;
        f.expect_unauth();
        assert!(f.rt().is_none(), "{name}: cookie set on failure");
        finish_shapes.push((name.to_string(), shape(&f)));
    }
    for (name, s) in &finish_shapes[1..] {
        assert_eq!(s, &finish_shapes[0].1, "login/finish for {name} differs from a wrong password");
    }
    e.finish().await;
}

/// Server-side timing of login/start for a known vs an unknown account and an unknown tenant
/// (medians over interleaved samples). The bound is loose (factor 3): it catches a missing
/// dummy path, not micro-differences; the measured medians are printed for the gate report.
#[tokio::test]
async fn login_start_timing_distribution() {
    let Some(e) = Env::default().await else { return };
    let t = e.tenant().await;
    let _ = e.user(t, "timed", "pw-enum-3").await;
    let ts = t.as_uuid().to_string();
    let ut = uuid::Uuid::now_v7().to_string();
    let n = &e.nodes[0];
    let mut samples: [Vec<u128>; 3] = [vec![], vec![], vec![]];
    for i in 0..24 {
        let (tenant, login, slot) = match i % 3 {
            0 => (ts.as_str(), "timed", 0),
            1 => (ts.as_str(), "ghost", 1),
            _ => (ut.as_str(), "timed", 2),
        };
        let t0 = Instant::now();
        let (r, _) = Env::login_start(n, tenant, login, "x").await;
        samples[slot].push(t0.elapsed().as_micros());
        r.expect(200);
    }
    let med = |v: &mut Vec<u128>| {
        v.sort();
        v[v.len() / 2].max(1)
    };
    let (a, b, c) = (med(&mut samples[0]), med(&mut samples[1]), med(&mut samples[2]));
    eprintln!("QA timing login/start median us: known={a} unknown_account={b} unknown_tenant={c}");
    for (name, x) in [("unknown account", b), ("unknown tenant", c)] {
        let ratio = x as f64 / a as f64;
        assert!(
            (1.0 / 3.0..=3.0).contains(&ratio),
            "{name}: median {x} us vs known {a} us (ratio {ratio:.2})"
        );
    }
    e.finish().await;
}

/// Recovery start (rev 10): unknown tenant, unknown account, wrong and used code give the
/// same `unauthenticated`; email and device approval answer 202 with the same shape for
/// unknown accounts and for accounts without a verified email.
#[tokio::test]
async fn recovery_start_indistinguishable() {
    let Some(e) = Env::default().await else { return };
    let t = e.tenant().await;
    let u = e.user(t, "rec", "pw-enum-4").await;
    let noemail = e.user(t, "noemail", "pw-enum-5").await;
    e.admin.set_email(t, u.id, "rec@qa.example", true).await.unwrap();
    let s = e.login(&u).await;
    let codes = e.recovery_codes(&s).await;
    let ts = u.t();
    let start = |tenant: String, login: &str, method: &str, code: Option<&str>| {
        let mut b = json!({"tenant": tenant, "login": login, "method": method});
        if let Some(c) = code {
            b["code"] = json!(c);
        }
        Req::post("/api/v2/auth/recovery/start").json(b)
    };
    // Use one code legitimately.
    let ok = e.call(start(ts.clone(), "rec", "recovery_code", Some(&codes[0]))).await;
    ok.expect(200);
    assert_eq!(ok.body["state"], "granted");
    let wrong = codes[1][..9].to_owned() + &"A".repeat(20);
    let ut = uuid::Uuid::now_v7().to_string();
    // A code is consumed only at [R5] completion (r5_completion_is_atomic covers the consumed
    // code); starting again with it before completion is not a "used code".
    let fails = vec![
        ("wrong secret", e.call(start(ts.clone(), "rec", "recovery_code", Some(&wrong))).await),
        ("unknown code id", e.call(start(ts.clone(), "rec", "recovery_code", Some("AAAAAAAA-AAAAAAAAAAAAAAAAAAAA"))).await),
        ("unknown account", e.call(start(ts.clone(), "ghost", "recovery_code", Some(&codes[1]))).await),
        ("unknown tenant", e.call(start(ut.clone(), "rec", "recovery_code", Some(&codes[1]))).await),
        ("account without codes", e.call(start(ts.clone(), "noemail", "recovery_code", Some(&codes[1]))).await),
    ];
    for (n, r) in &fails {
        r.expect_unauth();
        assert_eq!(shape(r), shape(&fails[0].1), "recovery_code {n} differs from 'wrong secret'");
    }
    let _ = noemail;
    for method in ["email", "device_approval"] {
        let rs = vec![
            ("known", e.call(start(ts.clone(), "rec", method, None)).await),
            ("unknown account", e.call(start(ts.clone(), "ghost", method, None)).await),
            ("unknown tenant", e.call(start(ut.clone(), "rec", method, None)).await),
            ("no verified email", e.call(start(ts.clone(), "noemail", method, None)).await),
        ];
        for (n, r) in &rs {
            assert_eq!(r.status, 202, "{method} {n}: {}", r.body);
            assert_eq!(r.body["state"], "pending", "{method} {n}");
            assert_eq!(keys(&r.body), keys(&rs[0].1.body), "{method} {n}: body members");
            if method == "device_approval" {
                let txn = r.body["recovery_txn"].as_str().unwrap_or("");
                assert!(txn.starts_with("rt1."), "{method} {n}: recovery_txn {txn:?}");
            }
        }
    }
    e.finish().await;
}

/// Per-account limit hits unknown accounts at the same threshold with the same 429 shape and
/// Retry-After; the per-source limit counts across accounts; another source is unaffected.
#[tokio::test]
async fn rate_limits_identical_for_unknown_accounts() {
    let limits = RateLimits {
        source: 8,
        account: 3,
        tenant: 100_000,
        node_count: 1,
    };
    let Some(e) = Env::new(Opts {
        limits: Some((limits, Valkey::None)),
        ..Opts::default()
    })
    .await
    else {
        return;
    };
    let t = e.tenant().await;
    let _ = e.user(t, "limited", "pw-enum-6").await;
    let ts = t.as_uuid().to_string();
    let n = &e.nodes[0];
    let mut first_429 = Vec::new();
    for (login, src) in [("limited", "203.0.113.10"), ("ghost", "203.0.113.11")] {
        let mut statuses = Vec::new();
        let mut last = None;
        for _ in 0..5 {
            let (r, _) = Env::login_start_from(n, &ts, login, "x", Some(src)).await;
            statuses.push(r.status);
            if r.status == 429 {
                last = Some(r);
            }
        }
        let first = statuses.iter().position(|s| *s == 429);
        assert_eq!(first, Some(3), "{login}: statuses {statuses:?} (account limit 3)");
        let r = last.unwrap();
        assert_eq!(r.code(), "rate_limited");
        assert!(r.headers.get("retry-after").is_some(), "{login}: Retry-After missing");
        first_429.push(shape(&r));
    }
    assert_eq!(first_429[0], first_429[1], "429 body differs between known and unknown account");
    // Per source: 8 requests over distinct accounts from one source, then 429.
    let mut statuses = Vec::new();
    for i in 0..10 {
        let (r, _) = Env::login_start_from(n, &ts, &format!("acct{i}"), "x", Some("203.0.113.50")).await;
        statuses.push(r.status);
    }
    assert_eq!(statuses.iter().position(|s| *s == 429), Some(8), "source limit 8: {statuses:?}");
    // [R12] IPv6 /64: another address in the same /64 shares the bucket; another /64 does not.
    for i in 0..8 {
        let (r, _) = Env::login_start_from(n, &ts, &format!("v6a{i}"), "x", Some("2001:db8:1:1::1")).await;
        r.expect(200);
    }
    let (r, _) = Env::login_start_from(n, &ts, "v6b", "x", Some("2001:db8:1:1:ffff::2")).await;
    assert_eq!(r.status, 429, "same /64 must share the source bucket");
    let (r, _) = Env::login_start_from(n, &ts, "v6c", "x", Some("2001:db8:1:2::1")).await;
    r.expect(200);
    e.finish().await;
}

/// Valkey configured but down: local buckets at limit/N, never unlimited.
#[tokio::test]
async fn rate_limit_fallback_is_limit_over_n() {
    let limits = RateLimits {
        source: 1000,
        account: 6,
        tenant: 100_000,
        node_count: 2,
    };
    let Some(e) = Env::new(Opts {
        limits: Some((limits, Valkey::Down)),
        ..Opts::default()
    })
    .await
    else {
        return;
    };
    let ts = e.tenant().await.as_uuid().to_string();
    let mut statuses = Vec::new();
    for _ in 0..6 {
        let (r, _) = Env::login_start_from(&e.nodes[0], &ts, "someone", "x", Some("203.0.113.77")).await;
        statuses.push(r.status);
    }
    assert_eq!(
        statuses.iter().position(|s| *s == 429),
        Some(3),
        "account 6 / N=2 = 3 per node while Valkey is down: {statuses:?}"
    );
    e.finish().await;
}

/// Registration without a valid grant: `permission_denied` with
/// `registration_grant_required` (§6.1), identical for unknown, used and swapped grants.
#[tokio::test]
async fn register_without_valid_grant() {
    let Some(e) = Env::default().await else { return };
    let t = e.tenant().await;
    let (_, link) = e.invite(t, "newbie").await;
    let parts: Vec<&str> = link.split('.').collect();
    let other = e.tenant().await;
    let swapped = format!("rt1.{}.{}", b64(other.as_uuid().as_bytes()), parts[2]);
    let unknown = format!("rt1.{}.{}", parts[1], b64(&rand_bytes::<32>()));
    let mut shapes = Vec::new();
    for (name, g) in [("unknown grant", unknown), ("tenant segment swapped", swapped), ("garbage", "nope".into())] {
        let (r, _) = Env::reg_start(&e.nodes[0], json!({"grant": g, "login": "newbie"}), "pw").await;
        assert_eq!(r.status, 403, "{name}: {}", r.body);
        assert_eq!(r.code(), "permission_denied", "{name}");
        assert!(r.err_codes().contains(&"registration_grant_required".to_owned()), "{name}: {}", r.body);
        shapes.push(shape(&r));
    }
    assert!(shapes.windows(2).all(|w| w[0] == w[1]), "{shapes:?}");
    // The real link with the wrong login is refused too, and stays usable for its user.
    let (r, _) = Env::reg_start(&e.nodes[0], json!({"grant": link, "login": "someone-else"}), "pw").await;
    assert!(r.status == 403 || r.status == 401 || r.status == 400, "{}", r.body);
    e.register(&e.nodes[0], &link, "newbie", "pw-enum-7").await.expect(204);
    let used = e.register(&e.nodes[0], &link, "newbie", "pw-enum-8").await;
    assert_eq!(used.status, 403, "used setup link: {}", used.body);
    e.finish().await;
}

/// rev 13: email recovery start answers 202 without waiting for delivery. With a notifier
/// that takes 3 s per link, a known account answers as fast as an unknown one (no timing
/// oracle), and the body is identical.
#[tokio::test]
async fn recovery_email_202_independent_of_delivery_time() {
    let Some(e) = Env::new(Opts {
        notify_delay_ms: 3000,
        ..Opts::default()
    })
    .await
    else {
        return;
    };
    let t = e.tenant().await;
    let u = e.user(t, "mail", "pw-enum-9").await;
    e.admin.set_email(t, u.id, "mail@qa.example", true).await.unwrap();
    let mut known = Vec::new();
    let mut unknown = Vec::new();
    for i in 0..3 {
        for (login, out) in [("mail", &mut known), ("ghost", &mut unknown)] {
            let t0 = Instant::now();
            let r = e
                .call(Req::post("/api/v2/auth/recovery/start")
                    .json(json!({"tenant": u.t(), "login": login, "method": "email"}))
                    .from(&format!("203.0.113.{}", 100 + i)))
                .await;
            out.push((t0.elapsed().as_millis(), r.status, shape(&r)));
        }
    }
    eprintln!(
        "QA timing recovery/start email ms: known={:?} unknown={:?}",
        known.iter().map(|k| k.0).collect::<Vec<_>>(),
        unknown.iter().map(|k| k.0).collect::<Vec<_>>()
    );
    for (k, u) in known.iter().zip(unknown.iter()) {
        assert_eq!(k.1, 202);
        assert_eq!(u.1, 202);
        assert_eq!(k.2, u.2, "body differs");
        assert!(k.0 < 1500, "known account waited for delivery: {} ms (notifier takes 3000 ms)", k.0);
    }
    e.finish().await;
}
