//! `cs` binary tests: role validation, configuration errors, serve/migrate separation.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use cs_common::id::NodeId;
use cs_common::vector::DomainId;
use cs_db::testing::TestDomains;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const BIN: &str = env!("CARGO_BIN_EXE_cs");

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn config(roles: &str, domains: &str, port: u16, admin: u16, extra: &str) -> String {
    format!(
        "[node]\nid = \"{}\"\nroles = [{roles}]\n\n{domains}\n[api]\nlisten = \"127.0.0.1:{port}\"\nadmin_listen = \"127.0.0.1:{admin}\"\ndeployment_domain = \"test.example\"\n\n[telemetry]\nlog_format = \"json\"\n{extra}",
        NodeId::generate().unwrap()
    )
}

fn write(dir: &Path, text: &str) -> std::path::PathBuf {
    let p = dir.join("cs.toml");
    std::fs::write(&p, text).unwrap();
    p
}

fn run(args: &[&str]) -> (i32, String, String) {
    let o = Command::new(BIN).args(args).output().unwrap();
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

#[test]
fn unimplemented_roles_are_refused_with_a_clear_message() {
    let d = tempfile::tempdir().unwrap();
    for role in ["storage", "edge", "realtime", "worker", "search", "control"] {
        let p = write(
            d.path(),
            &config(
                &format!("\"api\", \"{role}\""),
                "",
                free_port(),
                free_port(),
                "",
            ),
        );
        let (code, _, err) = run(&["serve", "--config", p.to_str().unwrap()]);
        assert_ne!(code, 0, "{role}");
        assert!(
            err.contains(role) && err.contains("not implemented"),
            "{role}: {err}"
        );
    }
}

#[test]
fn invalid_configuration_is_rejected_before_anything_starts() {
    let d = tempfile::tempdir().unwrap();
    let secret_url =
        "[domains.identity]\nurl = \"postgres://u:hunter2@127.0.0.1:1/x\"\nbogus = 1\n";
    let p = write(
        d.path(),
        &config("\"api\"", secret_url, free_port(), free_port(), ""),
    );
    let (code, _, err) = run(&["serve", "--config", p.to_str().unwrap()]);
    assert_ne!(code, 0);
    assert!(err.contains("unknown field"), "{err}");
    assert!(
        !err.contains("hunter2"),
        "secrets must not be echoed: {err}"
    );
    let p = write(
        d.path(),
        &config(
            "\"api\"",
            "",
            free_port(),
            free_port(),
            "\n[policy]\nrevocation_staleness_ms = 31000\n",
        ),
    );
    let (code, _, err) = run(&["check-config", "--config", p.to_str().unwrap()]);
    assert_ne!(code, 0);
    assert!(err.contains("revocation_staleness_ms"), "{err}");
    let (code, _, err) = run(&["serve", "--config", "/nonexistent/cs.toml"]);
    assert_ne!(code, 0);
    assert!(err.contains("cannot read"), "{err}");
}

#[test]
fn kms_root_key_must_be_initialised_explicitly() {
    let d = tempfile::tempdir().unwrap();
    let key = d.path().join("root.key");
    let kms = format!(
        "\n[kms]\nbackend = \"local_software\"\nroot_key_path = \"{}\"\n",
        key.display()
    );
    let p = write(
        d.path(),
        &config("\"api\"", "", free_port(), free_port(), &kms),
    );
    let (code, _, err) = run(&["serve", "--config", p.to_str().unwrap()]);
    assert_ne!(code, 0);
    assert!(err.contains("init-kms"), "{err}");
    let (code, out, _) = run(&["init-kms", "--config", p.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(out.contains("single-node"));
    let (code, _, _) = run(&["init-kms", "--config", p.to_str().unwrap()]);
    assert_ne!(code, 0, "init-kms never overwrites an existing root key");
}

async fn http_get(port: u16, path: &str) -> Option<(u16, String)> {
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .ok()?;
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .ok()?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.ok()?;
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text.split_whitespace().nth(1)?.parse().ok()?;
    Some((status, text))
}

#[tokio::test]
async fn serve_never_migrates_and_readyz_tracks_migrate() {
    let Some(t) = TestDomains::create(&[DomainId::Identity, DomainId::Operations]).await else {
        return;
    };
    let base = t.admin_url().rsplit_once('/').unwrap().0.to_owned();
    let domains = format!(
        "[domains.identity]\nurl = \"{base}/{}\"\n\n[domains.operations]\nurl = \"{base}/{}\"\n",
        t.database_name(&DomainId::Identity),
        t.database_name(&DomainId::Operations)
    );
    let (port, admin) = (free_port(), free_port());
    let d = tempfile::tempdir().unwrap();
    let p = write(d.path(), &config("\"api\"", &domains, port, admin, ""));
    let mut child = Command::new(BIN)
        .args(["serve", "--config", p.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some((200, _)) = http_get(port, "/healthz").await {
            break;
        }
        assert!(Instant::now() < deadline, "server did not start");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // live but not ready: nothing migrated, and serve does not migrate
    let (status, body) = http_get(port, "/readyz").await.unwrap();
    assert_eq!(status, 503, "{body}");
    assert!(body.contains("application/problem+json"));
    assert!(body.contains("/barriers/domain.identity.migrations"));
    assert!(body.contains("/barriers/domain.operations.migrations"));
    assert!(body.to_ascii_lowercase().contains("x-request-id"));
    // metrics only on the admin listener
    assert_eq!(http_get(port, "/metrics").await.unwrap().0, 404);
    assert_eq!(http_get(admin, "/metrics").await.unwrap().0, 200);

    let (code, out, err) = run(&["migrate", "--config", p.to_str().unwrap()]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("domain operations"), "{out}");
    let (status, body) = http_get(port, "/readyz").await.unwrap();
    assert_eq!(status, 200, "{body}");
    // migrate is idempotent
    let (code, out, _) = run(&["migrate", "--config", p.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(out.contains("applied []"), "{out}");

    let _ = child.kill();
    let _ = child.wait();
    t.cleanup().await;
}

fn kv(out: &str, key: &str) -> String {
    out.lines()
        .find_map(|l| l.strip_prefix(&format!("{key}=")))
        .unwrap_or_else(|| panic!("no {key}= in {out:?}"))
        .to_owned()
}

/// `cs admin` (M1 contract §0 [R4]): standalone, identity domain only, no listener and no
/// `control` role needed; refuses an unmigrated schema; each action is one identity-domain
/// transaction with an outbox event (outbox contents are covered by cs-identity's tests).
#[tokio::test]
async fn admin_cli_manages_tenants_users_groups_and_setup_links() {
    let Some(t) = TestDomains::create(&[DomainId::Identity]).await else {
        return;
    };
    let base = t.admin_url().rsplit_once('/').unwrap().0.to_owned();
    let domains = format!(
        "[domains.identity]\nurl = \"{base}/{}\"\n",
        t.database_name(&DomainId::Identity)
    );
    // Hold the configured API port: `cs admin` must never try to listen.
    let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = held.local_addr().unwrap().port();
    let d = tempfile::tempdir().unwrap();
    // `control` is refused by `serve` until M8, but `cs admin` is not a server role.
    let p = write(
        d.path(),
        &config("\"api\", \"control\"", &domains, port, free_port(), ""),
    );
    let cfg = p.to_str().unwrap();
    let admin = |args: &[&str]| {
        let mut v = vec!["admin", "--config", cfg];
        v.extend_from_slice(args);
        run(&v)
    };

    let (code, _, err) = admin(&["tenant", "create", "--name", "Acme"]);
    assert_ne!(code, 0);
    assert!(err.contains("cs migrate"), "{err}");
    let (code, out, err) = run(&["migrate", "--config", cfg]);
    assert_eq!(code, 0, "{out}{err}");

    let (code, out, err) = admin(&["tenant", "create", "--name", "Acme"]);
    assert_eq!(code, 0, "{err}");
    let tenant = kv(&out, "tenant_id");
    let (code, out, err) = admin(&[
        "user",
        "create",
        "--tenant",
        &tenant,
        "--login",
        "Admin@Acme.test",
    ]);
    assert_eq!(code, 0, "{err}");
    let user = kv(&out, "user_id");
    assert_eq!(kv(&out, "login"), "admin@acme.test");
    assert_eq!(kv(&out, "status"), "invited");
    let (code, out, err) = admin(&[
        "user",
        "create",
        "--tenant",
        &tenant,
        "--login",
        "admin@acme.test",
    ]);
    assert_ne!(code, 0, "{out}");
    assert!(err.contains("conflict"), "{err}");

    let (_, out, _) = admin(&["group", "create", "--tenant", &tenant, "--name", "Admins"]);
    let g1 = kv(&out, "group_id");
    let (_, out, _) = admin(&["group", "create", "--tenant", &tenant, "--name", "Ops"]);
    let g2 = kv(&out, "group_id");
    let add = |g: &str, m: &str, kind: &str, extra: &[&str]| {
        let mut v = vec![
            "group",
            "add-member",
            "--tenant",
            &tenant,
            "--group",
            g,
            "--member",
            m,
            "--kind",
            kind,
        ];
        v.extend_from_slice(extra);
        admin(&v)
    };
    let (code, out, err) = add(&g1, &user, "user", &["--expected-version", "1"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(kv(&out, "membership_version"), "2");
    let (code, _, err) = add(&g1, &g2, "group", &["--expected-version", "1"]);
    assert_ne!(code, 0);
    assert!(err.contains("precondition_failed"), "{err}");
    let (code, out, err) = add(&g1, &g2, "group", &[]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(kv(&out, "membership_version"), "3");
    let (code, _, err) = add(&g2, &g1, "group", &[]);
    assert_ne!(code, 0);
    assert!(
        err.contains("invalid_request") && err.contains("cycle"),
        "{err}"
    );
    let (code, out, err) = admin(&[
        "group",
        "remove-member",
        "--tenant",
        &tenant,
        "--group",
        &g1,
        "--member",
        &g2,
        "--kind",
        "group",
    ]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(kv(&out, "membership_version"), "4");

    let (code, out, err) = admin(&["setup-link", "--tenant", &tenant, "--user", &user]);
    assert_eq!(code, 0, "{err}");
    let tok = kv(&out, "setup_token");
    assert!(!err.contains(&tok), "token must not reach stderr");
    let parsed = cs_identity::token::parse(&tok).unwrap();
    assert_eq!(parsed.tenant_id.to_string(), tenant);
    let a = cs_identity::admin::IdentityAdmin::new(t.pool(&DomainId::Identity).clone()).unwrap();
    let (state, u) = a
        .setup_link_state(parsed.tenant_id, parsed.hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((state.as_str(), u.to_string()), ("active", user.clone()));

    drop(held);
    t.cleanup().await;
}
