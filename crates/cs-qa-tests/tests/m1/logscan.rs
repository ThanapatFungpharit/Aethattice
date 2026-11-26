//! Contract §9: no access token, refresh token, setup link, recovery code or grant, OPAQUE
//! message, DPoP proof or key material in any log output. The in-process suites scan the
//! captured TRACE log at the end of every test (`Env::finish`); this file adds the `cs`
//! binary (server log at the most verbose level, and `cs admin` stderr) and a self-test of
//! the scanner.
use crate::fx::*;
use crate::support::contract as c;
use crate::support::server::{Server, free_port, http};
use serde_json::json;

/// The scanner finds every secret kind (it must not pass vacuously).
#[test]
fn scanner_detects_each_secret_shape() {
    let samples = [
        format!("x rt1.{}.{} y", b64(&[1u8; 16]), b64(&[2u8; 32])),
        "token=eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ4In0.c2ln".to_owned(),
        "code ABCDEFGH-ABCDEFGHIJKLMNOPQRST seen".to_owned(),
        r#"{"jwk":{"d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}"#.to_owned(),
    ];
    for s in &samples {
        assert!(!scan_text(s, &[]).is_empty(), "scanner missed: {s}");
    }
    let custom = vec![(
        "OPAQUE message".to_owned(),
        "c2VjcmV0LW9wYXF1ZS1tc2c".to_owned(),
    )];
    assert!(!scan_text("..c2VjcmV0LW9wYXF1ZS1tc2c..", &custom).is_empty());
    assert!(scan_text("tenant 0190a8e2-0000-7000-8000-000000000000 ok", &custom).is_empty());
}

async fn cs_admin(cfg: &std::path::Path, dir: &std::path::Path, args: &[&str]) -> (String, String) {
    let mut a = vec![
        "admin".to_owned(),
        "--config".to_owned(),
        cfg.display().to_string(),
    ];
    a.extend(args.iter().map(|s| s.to_string()));
    let out = tokio::process::Command::new(crate::support::server::cs_binary())
        .args(&a)
        .current_dir(dir)
        .output()
        .await
        .unwrap();
    let (so, se) = (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    );
    assert!(out.status.success(), "cs {a:?}: {so}{se}");
    (so, se)
}

fn field(out: &str, k: &str) -> String {
    out.lines()
        .find_map(|l| l.strip_prefix(&format!("{k}=")))
        .unwrap_or_else(|| panic!("{k} not in {out}"))
        .trim()
        .to_owned()
}

/// Full M1 flows against the real `cs serve` binary at TRACE level (identity domain on a
/// leased database, Valkey configured), then a scan of the complete server log and of
/// `cs admin` stderr.
#[tokio::test]
async fn cs_binary_logs_contain_no_secrets() {
    init_logs();
    let Some(admin) = crate::support::db::admin_url().await else {
        return;
    };
    let db = crate::support::db::TestDb::create(&admin, "m1_logscan").await;
    let state = tempfile::tempdir().unwrap();
    let port = free_port();
    let idurl = db.url.clone();
    let mut cfg = c::config_toml(
        port,
        &["api"],
        &|d| {
            if d == "identity" {
                idurl.clone()
            } else {
                crate::support::db::unreachable_url(&format!("cs_{d}"))
            }
        },
        state.path(),
    );
    cfg = cfg.replace(
        "[telemetry]\nlog_format = \"json\"\n",
        &format!(
            "[telemetry]\nlog_format = \"json\"\nlog_level = \"trace\"\n\n[valkey]\nurl = \"{}\"\n",
            valkey_url()
        ),
    );
    {
        let pool = pool_for(&db.url);
        let _g = crate::support::db::ddl_guard().await;
        let set = cs_db::migrate::common_migrations()
            .unwrap()
            .merge(cs_identity::migrations().unwrap())
            .unwrap();
        cs_db::migrate::Migrator::run(&pool, &set).await.unwrap();
        pool.close().await;
    }
    let s = Server::start(&cfg, port).await;
    let cfg_path = s.dir.path().join("cs.toml");
    let mut admin_stderr = String::new();
    let (o, e1) = cs_admin(
        &cfg_path,
        s.dir.path(),
        &["tenant", "create", "--name", "qa-logscan"],
    )
    .await;
    admin_stderr += &e1;
    let tid = field(&o, "tenant_id");
    let tenant: cs_common::id::TenantId = tid.parse().unwrap();
    let t = tenant.as_uuid().to_string();
    let (o, e2) = cs_admin(
        &cfg_path,
        s.dir.path(),
        &["user", "create", "--tenant", &tid, "--login", "logan"],
    )
    .await;
    admin_stderr += &e2;
    let uid = field(&o, "user_id");
    let (o, e3) = cs_admin(
        &cfg_path,
        s.dir.path(),
        &["setup-link", "--tenant", &tid, "--user", &uid],
    )
    .await;
    admin_stderr += &e3;
    let link = o
        .split(|c: char| c.is_whitespace() || c == '=')
        .find(|w| w.starts_with("rt1."))
        .unwrap_or_else(|| panic!("no setup link in {o}"))
        .to_owned();
    secret("setup link (cs admin)", &link);

    let r = Remote {
        base: s.url(""),
        client: http(),
    };
    let pw = "pw-logscan-1";
    let (st, cr) = Env::reg_start(&r, json!({"grant": link, "login": "logan"}), pw).await;
    st.expect(200);
    Env::reg_finish(&r, &st, cr, &t, "logan", pw, None)
        .await
        .expect(204);
    // Failed logins (wrong password, unknown account, unknown tenant).
    for (tt, l, p) in [
        (&t, "logan", "wrong"),
        (&t, "ghost", pw),
        (&uuid::Uuid::now_v7().to_string(), "logan", pw),
    ] {
        let (_, f) = Env::login_raw(&r, tt, l, p, None).await;
        f.expect_unauth();
    }
    // DPoP-bound login, /me, refresh, sessions.
    let key = DKey::es256();
    let (_, f) = Env::login_raw(&r, &t, "logan", pw, Some(&key)).await;
    f.expect(200);
    let sess = Session::from_auth(&f, Some(key.clone()));
    r.call(sess.req(Req::get("/api/v2/me"))).await.expect(200);
    let rr = r.call(sess.refresh_req("logscan-1")).await;
    rr.expect(200);
    let sess = Session::from_auth(&rr, Some(key.clone()));
    // A replayed proof and a Bearer misuse (rejection paths log too).
    let p = key.proof("GET", &htu("/api/v2/me"), Some(&sess.at));
    for _ in 0..2 {
        let _ = r
            .call(
                Req::get("/api/v2/me")
                    .header("authorization", &format!("DPoP {}", sess.at))
                    .header("dpop", &p),
            )
            .await;
    }
    r.call(Req::get("/api/v2/me").bearer(&sess.at))
        .await
        .expect_unauth();
    // Recovery codes, recovery grant, registration under the grant.
    let codes = r
        .call(sess.req(Req::post("/api/v2/me/recovery-codes").json(json!({}))))
        .await;
    codes.expect(200);
    let code = codes.body["codes"][0].as_str().unwrap().to_owned();
    let g = r
        .call(
            Req::post("/api/v2/auth/recovery/start").json(
                json!({"tenant": t, "login": "logan", "method": "recovery_code", "code": code}),
            ),
        )
        .await;
    g.expect(200);
    let grant = g.body["grant"].as_str().unwrap().to_owned();
    let bad = r
        .call(Req::post("/api/v2/auth/recovery/start")
            .json(json!({"tenant": t, "login": "logan", "method": "recovery_code", "code": format!("{}{}", &code[..9], "A".repeat(20))})))
        .await;
    bad.expect_unauth();
    let pw2 = "pw-logscan-2";
    let (st, cr) = Env::reg_start(&r, json!({"grant": grant, "login": "logan"}), pw2).await;
    st.expect(200);
    Env::reg_finish(&r, &st, cr, &t, "logan", pw2, None)
        .await
        .expect(204);
    // Reuse of a revoked refresh token, then a normal login and logout.
    r.call(sess.refresh_req("logscan-2")).await.expect_unauth();
    let (_, f) = Env::login_raw(&r, &t, "logan", pw2, None).await;
    f.expect(200);
    let s2 = Session::from_auth(&f, None);
    r.call(s2.req(Req::post("/api/v2/auth/logout")))
        .await
        .expect(204);
    // Admin-assisted recovery prints its token on stdout (by design); stderr must be clean.
    let (o, e4) = cs_admin(
        &cfg_path,
        s.dir.path(),
        &["recovery", "start", "--tenant", &tid, "--user", &uid],
    )
    .await;
    admin_stderr += &e4;
    let rl = field(&o, "recovery_link_token");
    secret("recovery link (cs admin)", &rl);
    r.call(Req::post("/api/v2/auth/recovery/status").json(json!({"token": rl})))
        .await
        .expect(200);

    let log = s.stop().await;
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/qa-m1-logs");
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::write(dir.join("cs-serve-trace.log"), &log);
    db.drop_now().await;
    assert!(
        log.lines().count() > 20,
        "suspiciously small server log ({} lines)",
        log.lines().count()
    );
    eprintln!(
        "QA logscan: server log {} lines, {} secrets registered",
        log.lines().count(),
        secrets_registered()
    );
    let mut found = scan_text(&log, &[]);
    found.extend(
        scan_text(&admin_stderr, &[])
            .into_iter()
            .map(|f| format!("cs admin stderr: {f}")),
    );
    assert!(
        found.is_empty(),
        "contract §9: secrets in cs logs:\n{}",
        found.join("\n")
    );
}
