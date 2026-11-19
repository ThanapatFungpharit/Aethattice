//! Configuration (J.4, §1.4, §6.6, contract §6) and role refusal (§2.2, J.2, contract §6).
//! Traceability: 1.4-1, 1.4-2, 6.6-6, J.4-4, J.4-5, 2.2-1, J.2-1, CT.M0-24, CT.M0-25.
#![cfg(any(feature = "m0-contract", feature = "qa-selfcheck"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::time::Duration;
use support::contract as c;
use support::server::{free_port, port_open, run_expect_exit};
use support::{db, spec};

fn base(port: u16, roles: &[&str], dir: &std::path::Path) -> String {
    c::config_toml(
        port,
        roles,
        &|d| db::unreachable_url(&format!("cs_{d}")),
        dir,
    )
}

#[test]
fn baseline_config_is_valid() {
    // Guards the other tests: if the baseline is invalid, "rejected" proves nothing.
    let dir = tempfile::tempdir().unwrap();
    c::config_validate(&base(free_port(), &["api"], dir.path()))
        .expect("QA baseline config must validate");
}

#[test]
fn unknown_top_level_key_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let b = base(free_port(), &["api"], dir.path());
    for extra in ["\n[qa_unknown_section]\nx = 1\n", "\nqa_unknown_key = 1\n"] {
        // A top-level bare key must come before the first table header to be top-level.
        let cfg = if extra.contains('[') {
            format!("{b}{extra}")
        } else {
            format!("{extra}{b}")
        };
        assert!(
            c::config_validate(&cfg).is_err(),
            "unknown top-level key accepted:\n{extra}"
        );
    }
}

#[test]
fn unknown_nested_key_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let b = base(free_port(), &["api"], dir.path());
    for section in [
        "[node]\n",
        "[api]\n",
        "[telemetry]\n",
        "[kms]\n",
        "[policy]\n",
        "[locks]\n",
        "[domains.identity]\n",
    ] {
        assert!(b.contains(section), "baseline lacks {section}");
        let cfg = b.replacen(section, &format!("{section}qa_unknown_key = 1\n"), 1);
        assert!(
            c::config_validate(&cfg).is_err(),
            "unknown key accepted in {}",
            section.trim()
        );
    }
    // Typo of a real key must not be silently ignored either.
    let cfg = b.replacen(
        "[domains.identity]\n",
        "[domains.identty]\nurl = \"postgres://x@127.0.0.1:1/x\"\n",
        1,
    );
    assert!(
        c::config_validate(&cfg).is_err(),
        "unknown domain name accepted"
    );
}

#[test]
fn revocation_staleness_s_range_enforced() {
    let dir = tempfile::tempdir().unwrap();
    let b = base(free_port(), &["api"], dir.path());
    for ok in [spec::S_DEFAULT_SECS, 1.0, spec::S_MAX_SECS] {
        c::config_validate(&c::config_set_revocation_s(&b, ok))
            .unwrap_or_else(|e| panic!("S = {ok}s rejected: {e}"));
    }
    for bad in [spec::S_MAX_SECS + 1.0, 3600.0, 0.0, -1.0] {
        assert!(
            c::config_validate(&c::config_set_revocation_s(&b, bad)).is_err(),
            "S = {bad}s accepted (§6.6 max 30 s; OQ-6 min)"
        );
    }
}

#[test]
fn policy_defaults_applied() {
    let dir = tempfile::tempdir().unwrap();
    let s = c::config_effective_revocation_s(&base(free_port(), &["api"], dir.path())).unwrap();
    assert!(
        (s - spec::S_DEFAULT_SECS).abs() < 1e-9,
        "default S must be 2 s, got {s}"
    );
}

#[test]
fn locks_section_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let b = base(free_port(), &["api"], dir.path());
    assert!(b.contains("[locks]"));
    c::config_validate(&b).unwrap();
}

#[tokio::test]
async fn unimplemented_role_refused_by_binary() {
    for role in spec::ROLES_NOT_IN_M0 {
        let dir = tempfile::tempdir().unwrap();
        let port = free_port();
        let (status, log) = run_expect_exit(
            &base(port, &["api", role], dir.path()),
            Duration::from_secs(20),
        )
        .await;
        assert!(!status.success(), "role {role}: binary exited 0");
        assert!(
            log.to_lowercase().contains(role),
            "role {role}: refusal message must name the role; output:\n{log}"
        );
        assert!(
            !port_open(port).await,
            "role {role}: API listener left open"
        );
    }
}

#[tokio::test]
async fn unknown_role_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let b = base(free_port(), &["api"], dir.path());
    assert!(
        c::config_validate(&b.replacen("roles = [\"api\"]", "roles = [\"api\", \"superuser\"]", 1))
            .is_err()
    );
    assert!(
        c::config_validate(&b.replacen("roles = [\"api\"]", "roles = []", 1)).is_err(),
        "empty role list accepted"
    );
    let (status, _) = run_expect_exit(
        &b.replacen("roles = [\"api\"]", "roles = [\"api\", \"superuser\"]", 1),
        Duration::from_secs(20),
    )
    .await;
    assert!(!status.success());
}

#[tokio::test]
async fn invalid_config_does_not_start_listener() {
    // Validated in full before anything is applied: an error late in the file must prevent
    // the listener (declared early) from ever opening.
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let cfg = format!(
        "{}\n[qa_unknown_section]\nx = 1\n",
        base(port, &["api"], dir.path())
    );
    let probe = tokio::spawn(async move {
        let mut opened = false;
        for _ in 0..100 {
            if port_open(port).await {
                opened = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        opened
    });
    let (status, _) = run_expect_exit(&cfg, Duration::from_secs(20)).await;
    assert!(!status.success(), "invalid config: exit status 0");
    assert!(
        !probe.await.unwrap(),
        "listener opened before the configuration was fully validated"
    );
}
