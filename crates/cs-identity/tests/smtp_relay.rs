//! SMTP relay notifier against an in-test SMTP server (M1 contract §4, rev 13).

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use common::fake_smtp::{FakeSmtp, link_token};
use cs_common::secret::Secret;
use cs_identity::notify::{Notifier, SmtpRelay};

const TOKEN: &str = "rt1.AAAAAAAAAAAAAAAAAAAAAA.BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

#[tokio::test]
async fn delivers_the_recovery_link_over_smtp() {
    let s = FakeSmtp::start(Duration::ZERO, 0).await;
    let relay = SmtpRelay::start(&s.config(), "cs.example.com").unwrap();
    relay
        .recovery_link("alice@mail.test", &Secret::new(TOKEN.to_owned()))
        .await
        .unwrap();
    let mails = s.wait_for(1, Duration::from_secs(10)).await;
    assert_eq!(mails.len(), 1);
    let m = &mails[0];
    assert!(m.contains("To: alice@mail.test"), "{m}");
    assert!(m.contains("no-reply@cs.example.com"), "{m}");
    assert!(
        m.contains(&format!("https://cs.example.com/#/recover/{TOKEN}")),
        "{m}"
    );
    assert_eq!(link_token(m).as_deref(), Some(TOKEN));
}

/// Rev 13: the caller never waits for SMTP (slow server: 3 s before the greeting).
#[tokio::test]
async fn enqueue_returns_before_smtp_completes() {
    let s = FakeSmtp::start(Duration::from_secs(3), 0).await;
    let relay = SmtpRelay::start(&s.config(), "cs.example.com").unwrap();
    let t0 = Instant::now();
    relay
        .recovery_link("alice@mail.test", &Secret::new(TOKEN.to_owned()))
        .await
        .unwrap();
    assert!(
        t0.elapsed() < Duration::from_millis(500),
        "{:?}",
        t0.elapsed()
    );
    assert!(s.mails.lock().unwrap().is_empty());
    assert_eq!(s.wait_for(1, Duration::from_secs(15)).await.len(), 1);
    assert!(t0.elapsed() >= Duration::from_secs(3));
}

/// A transient `421` greeting is retried with backoff (1 s, 2 s) and then delivered.
#[tokio::test]
async fn transient_smtp_failure_is_retried() {
    let s = FakeSmtp::start(Duration::ZERO, 2).await;
    let relay = SmtpRelay::start(&s.config(), "cs.example.com").unwrap();
    relay
        .recovery_link("alice@mail.test", &Secret::new(TOKEN.to_owned()))
        .await
        .unwrap();
    assert_eq!(s.wait_for(1, Duration::from_secs(15)).await.len(), 1);
    assert_eq!(s.connections.load(Ordering::SeqCst), 3);
}
