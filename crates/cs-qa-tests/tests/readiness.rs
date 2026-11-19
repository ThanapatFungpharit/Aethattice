//! Readiness vs liveness (§2.6, §20.5, App. C rule C14, contract §7).
//! Traceability: 2.6-10, 20.5-1, B-9, C.2-14, 23.2-9, CT.M0-26, 18.1-1, 8.3.1-2.
#![cfg(any(feature = "m0-contract", feature = "qa-selfcheck"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[macro_use]
mod support;

use support::contract as c;
use support::db::{self, TestDb};
use support::server::{Server, free_port, http};
use support::spec;

#[tokio::test]
async fn readyz_503_lists_unreachable_domain_barrier() {
    let state = tempfile::tempdir().unwrap();
    let port = free_port();
    let cfg = c::config_toml(
        port,
        &["api"],
        &|d| db::unreachable_url(&format!("cs_{d}")),
        state.path(),
    );
    let s = Server::start(&cfg, port).await;
    let r = http().get(s.url("/readyz")).send().await.unwrap();
    assert_eq!(
        r.status().as_u16(),
        503,
        "readyz must be 503 while domain databases are unreachable"
    );
    let ct = r
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ct.starts_with("application/problem+json"),
        "content-type {ct}"
    );
    let j: serde_json::Value = r.json().await.unwrap();
    assert_eq!(j["code"], "unavailable");
    assert_eq!(j["retryable"], true);
    let barriers = c::readyz_failing_barriers(&j).join("\n");
    for d in spec::DOMAINS {
        assert!(
            barriers.contains(d),
            "failing barrier for domain {d} not listed; barriers:\n{barriers}\nbody: {j}"
        );
    }
    s.stop().await;
}

#[tokio::test]
async fn healthz_200_while_domain_unreachable() {
    let state = tempfile::tempdir().unwrap();
    let port = free_port();
    let cfg = c::config_toml(
        port,
        &["api"],
        &|d| db::unreachable_url(&format!("cs_{d}")),
        state.path(),
    );
    let s = Server::start(&cfg, port).await;
    let cl = http();
    for _ in 0..5 {
        assert_eq!(
            cl.get(s.url("/healthz"))
                .send()
                .await
                .unwrap()
                .status()
                .as_u16(),
            200
        );
        assert_eq!(
            cl.get(s.url("/readyz"))
                .send()
                .await
                .unwrap()
                .status()
                .as_u16(),
            503
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    s.stop().await;
}

#[tokio::test]
async fn readyz_does_not_leak_connection_strings() {
    let state = tempfile::tempdir().unwrap();
    let port = free_port();
    let cfg = c::config_toml(
        port,
        &["api"],
        &|d| db::unreachable_url(&format!("cs_{d}")),
        state.path(),
    );
    let s = Server::start(&cfg, port).await;
    let text = http()
        .get(s.url("/readyz"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    for needle in [
        "qa_secret_must_not_leak",
        "qa_user",
        "postgres://",
        "127.0.0.1:1",
    ] {
        assert!(!text.contains(needle), "readyz leaked {needle}: {text}");
    }
    if let Some(m) = spec::leak_in(&text) {
        panic!("readyz leaked internal detail ({m}): {text}");
    }
    s.stop().await;
}

/// One domain down, ten up: only that domain is a failing barrier; then it comes back.
#[tokio::test]
async fn readyz_lists_only_the_failing_domain() {
    let admin = require_db!();
    let mut dbs = Vec::new();
    for d in spec::DOMAINS {
        let t = TestDb::create(&admin, &format!("rdy_{d}")).await;
        let dom = c::domain_open(d, &t.url).await.unwrap();
        c::domain_migrate(&dom).await.unwrap();
        dbs.push((d.to_string(), t));
    }
    let urls: std::collections::HashMap<String, String> = dbs
        .iter()
        .map(|(d, t)| (d.clone(), t.url.clone()))
        .collect();
    let state = tempfile::tempdir().unwrap();
    let port = free_port();
    let cfg = c::config_toml(
        port,
        &["api"],
        &|d| {
            if d == "audit" {
                db::unreachable_url("cs_audit")
            } else {
                urls[d].clone()
            }
        },
        state.path(),
    );
    let s = Server::start(&cfg, port).await;
    let r = http().get(s.url("/readyz")).send().await.unwrap();
    assert_eq!(r.status().as_u16(), 503);
    let j: serde_json::Value = r.json().await.unwrap();
    let barriers = c::readyz_failing_barriers(&j);
    assert!(
        barriers.iter().any(|b| b.contains("audit")),
        "audit barrier missing: {barriers:?}"
    );
    for d in spec::DOMAINS.iter().filter(|d| **d != "audit") {
        assert!(
            !barriers.iter().any(|b| b.contains(d)),
            "healthy domain {d} reported failing: {barriers:?}"
        );
    }
    s.stop().await;
    for (_, t) in dbs {
        t.drop_now().await;
    }
}

#[tokio::test]
async fn readyz_200_when_all_domains_reachable_and_migrated() {
    let admin = require_db!();
    let mut dbs = Vec::new();
    for d in spec::DOMAINS {
        let t = TestDb::create(&admin, &format!("rdy_{d}")).await;
        // OQ-12: QA migrates explicitly; if `cs` migrates on start this is a no-op.
        let dom = c::domain_open(d, &t.url).await.unwrap();
        c::domain_migrate(&dom).await.unwrap();
        dbs.push((d.to_string(), t));
    }
    let urls: std::collections::HashMap<String, String> = dbs
        .iter()
        .map(|(d, t)| (d.clone(), t.url.clone()))
        .collect();
    let state = tempfile::tempdir().unwrap();
    let port = free_port();
    let cfg = c::config_toml(port, &["api"], &|d| urls[d].clone(), state.path());
    let s = Server::start(&cfg, port).await;
    let cl = http();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let r = cl.get(s.url("/readyz")).send().await.unwrap();
        if r.status().as_u16() == 200 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "never became ready: {}",
            r.text().await.unwrap_or_default()
        );
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    // Readiness must be withdrawn when a domain database disappears (no stale readiness).
    let (_, victim) = dbs.remove(0);
    victim.drop_now().await;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let r = cl.get(s.url("/readyz")).send().await.unwrap();
        if r.status().as_u16() == 503 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "readyz still 200 after a domain database was dropped"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    assert_eq!(
        cl.get(s.url("/healthz"))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );
    s.stop().await;
    for (_, t) in dbs {
        t.drop_now().await;
    }
}
