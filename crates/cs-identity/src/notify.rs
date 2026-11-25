//! Out-of-band notifications of the identity domain (contract §4, rev 13).
//!
//! The email recovery link (rev 10) is a bearer secret, so it never goes through the outbox,
//! any other durable queue or the API. After the request commits, the service hands it to a
//! [`Notifier`]. Everything without a secret (a recovery was requested, approved, completed) is
//! an outbox event, which the notification service (M4) delivers to all of the user's devices.
//!
//! Implementations:
//! - [`Discard`]: no `[notifier]` configured. The link is dropped and a warning without the
//!   secret is logged (`cs serve` also warns once at startup).
//! - [`SmtpRelay`]: outbound SMTP relay through `lettre`. Rev 13: delivery is **best effort
//!   and not durable**. [`Notifier::recovery_link`] only puts the link on a bounded in-memory
//!   queue ([`QUEUE_CAPACITY`]) on this node and returns at once, so the `202` of
//!   `recovery/start` never waits for SMTP. A background worker sends with at most
//!   [`MAX_ATTEMPTS`] attempts and exponential backoff capped at 30 s, and logs only the error
//!   class, SMTP status code and attempt number, never the token or the address. A full queue
//!   drops the link and counts it in `cs_notifier_dropped_total`; a node crash before sending
//!   loses the link and the user starts again. Durable delivery is an M4 follow-up (the outbox
//!   carries only `request_id`; the sender mints the token at send time, storing its hash by CAS).
//! - [`DevLogSink`]: `[R7]` writes the link to stderr. It can only be built for the explicit
//!   `--dev` profile and every line it writes starts with `DEV-ONLY SECRET`.

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use cs_common::config::{NotifierConfig, NotifierKind, SmtpConfig, SmtpTls};
use cs_common::error::{Error, ErrorCode};
use cs_common::secret::Secret;
use lettre::message::header::ContentType;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::transport::smtp::extension::ClientId;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use tokio::sync::{Semaphore, mpsc};

/// Delivery of recovery links.
#[async_trait]
pub trait Notifier: Send + Sync {
    /// Send the email recovery link token (an `rt1` token) to the verified address.
    async fn recovery_link(&self, to: &str, token: &Secret<String>) -> Result<(), Error>;
}

/// The link the user opens (rev 13): `https://<deployment domain>/#/recover/<token>`.
pub fn recovery_url(deployment_domain: &str, token: &Secret<String>) -> String {
    format!(
        "https://{deployment_domain}/#/recover/{}",
        token.expose_secret()
    )
}

/// Build the notifier `cs serve` uses. `None` (no `[notifier]`) is [`Discard`]. `dev` is the
/// `--dev` profile; `dev_log` without it is refused (`[R7]`). Must run inside a Tokio runtime
/// (the SMTP worker is spawned).
pub fn from_config(
    cfg: Option<&NotifierConfig>,
    deployment_domain: &str,
    dev: bool,
) -> Result<Arc<dyn Notifier>, Box<Error>> {
    match cfg {
        None => Ok(Arc::new(Discard)),
        Some(n) => match (n.kind, &n.smtp) {
            (NotifierKind::DevLog, _) => Ok(Arc::new(DevLogSink::new(dev, deployment_domain)?)),
            (NotifierKind::Smtp, Some(s)) => Ok(Arc::new(SmtpRelay::start(s, deployment_domain)?)),
            (NotifierKind::Smtp, None) => Err(invalid("notifier.smtp: section required")),
        },
    }
}

/// `check-config`: everything [`from_config`] checks, without spawning anything (sender and
/// TLS parameters are parsed by `lettre`).
pub fn validate_config(
    cfg: Option<&NotifierConfig>,
    deployment_domain: &str,
    dev: bool,
) -> Result<(), Box<Error>> {
    match cfg {
        None => Ok(()),
        Some(n) => match (n.kind, &n.smtp) {
            (NotifierKind::DevLog, _) => DevLogSink::new(dev, deployment_domain).map(|_| ()),
            (NotifierKind::Smtp, Some(s)) => build_transport(s, deployment_domain).map(|_| ()),
            (NotifierKind::Smtp, None) => Err(invalid("notifier.smtp: section required")),
        },
    }
}

fn invalid(detail: &str) -> Box<Error> {
    Box::new(Error::new(ErrorCode::InvalidRequest).with_detail(detail.to_owned()))
}

/// No delivery configured.
#[derive(Debug, Clone, Copy, Default)]
pub struct Discard;

#[async_trait]
impl Notifier for Discard {
    async fn recovery_link(&self, _to: &str, _token: &Secret<String>) -> Result<(), Error> {
        tracing::warn!("no notifier configured: an email recovery link was not delivered");
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------
// SMTP relay
// ---------------------------------------------------------------------------------------------

/// Capacity of the in-memory delivery queue of one node (rev 13).
pub const QUEUE_CAPACITY: usize = 1024;
/// Delivery attempts per link, including the first (rev 13).
pub const MAX_ATTEMPTS: u32 = 5;
/// Concurrent SMTP deliveries per node.
const CONCURRENCY: usize = 4;
/// Timeout of each SMTP command.
const SMTP_TIMEOUT: Duration = Duration::from_secs(30);
const SUBJECT: &str = "Account recovery request";

/// Classified SMTP failure; carries nothing from the message or the server text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MailError {
    /// `permanent`, `transient`, `timeout`, `tls`, `client`, `connection`, `recipient`.
    pub class: &'static str,
    /// SMTP reply code, when the server sent one.
    pub status: Option<u16>,
    /// Not worth retrying.
    pub permanent: bool,
}

/// What actually sends a message (the `lettre` SMTP transport; a fake in unit tests).
#[async_trait]
pub(crate) trait Mailer: Send + Sync + 'static {
    async fn send(&self, msg: Message) -> Result<(), MailError>;
}

#[async_trait]
impl Mailer for AsyncSmtpTransport<Tokio1Executor> {
    async fn send(&self, msg: Message) -> Result<(), MailError> {
        AsyncTransport::send(self, msg)
            .await
            .map(|_| ())
            .map_err(|e| classify(&e))
    }
}

fn classify(e: &lettre::transport::smtp::Error) -> MailError {
    let status = e
        .status()
        .and_then(|c| c.to_string().parse::<u16>().ok());
    let (class, permanent) = if e.is_permanent() {
        ("permanent", true)
    } else if e.is_transient() {
        ("transient", false)
    } else if e.is_timeout() {
        ("timeout", false)
    } else if e.is_tls() {
        ("tls", false)
    } else if e.is_client() {
        ("client", true)
    } else {
        ("connection", false)
    };
    MailError {
        class,
        status,
        permanent,
    }
}

/// Bounded exponential backoff between attempts.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RetryPolicy {
    pub attempts: u32,
    pub base: Duration,
    pub cap: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            attempts: MAX_ATTEMPTS,
            base: Duration::from_secs(1),
            cap: Duration::from_secs(30),
        }
    }
}

impl RetryPolicy {
    /// Wait after failed attempt `n` (1-based): base·2^(n−1), at most `cap`.
    fn delay(&self, n: u32) -> Duration {
        let factor = 1u32.checked_shl(n.saturating_sub(1)).unwrap_or(u32::MAX);
        self.base.saturating_mul(factor).min(self.cap)
    }
}

pub(crate) struct Job {
    to: String,
    token: Secret<String>,
}

struct Shared {
    mailer: Arc<dyn Mailer>,
    from: Mailbox,
    domain: String,
    retry: RetryPolicy,
}

/// SMTP relay notifier (rev 13: bounded in-memory queue, best effort, not durable).
pub struct SmtpRelay {
    queue: mpsc::Sender<Job>,
}

impl std::fmt::Debug for SmtpRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpRelay")
            .field("queued", &(self.queue.max_capacity() - self.queue.capacity()))
            .finish()
    }
}

fn build_transport(
    cfg: &SmtpConfig,
    deployment_domain: &str,
) -> Result<(AsyncSmtpTransport<Tokio1Executor>, Mailbox), Box<Error>> {
    let from: Mailbox = cfg
        .from
        .parse()
        .map_err(|_| invalid("notifier.smtp.from: not a valid mailbox"))?;
    let host = cfg.host.trim_start_matches('[').trim_end_matches(']');
    let tls_params = || {
        TlsParameters::new(host.to_owned())
            .map_err(|_| invalid("notifier.smtp.host: cannot be used as a TLS server name"))
    };
    let tls = match cfg.tls {
        SmtpTls::Tls => Tls::Wrapper(tls_params()?),
        SmtpTls::Starttls => Tls::Required(tls_params()?),
        SmtpTls::None => Tls::None,
    };
    let mut b = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
        .port(cfg.port)
        .tls(tls)
        .timeout(Some(SMTP_TIMEOUT))
        .hello_name(ClientId::Domain(deployment_domain.to_owned()));
    match (&cfg.username, &cfg.password) {
        (Some(u), Some(p)) => {
            b = b.credentials(Credentials::new(
                u.expose_secret().clone(),
                p.expose_secret().clone(),
            ));
        }
        (None, None) => {}
        _ => {
            return Err(invalid(
                "notifier.smtp: username and password must be given together",
            ));
        }
    }
    Ok((b.build(), from))
}

impl SmtpRelay {
    /// Validate the relay configuration and start the delivery worker.
    pub fn start(cfg: &SmtpConfig, deployment_domain: &str) -> Result<Self, Box<Error>> {
        let (transport, from) = build_transport(cfg, deployment_domain)?;
        Ok(Self::spawn(
            Arc::new(transport),
            from,
            deployment_domain,
            RetryPolicy::default(),
            QUEUE_CAPACITY,
        ))
    }

    pub(crate) fn spawn(
        mailer: Arc<dyn Mailer>,
        from: Mailbox,
        deployment_domain: &str,
        retry: RetryPolicy,
        capacity: usize,
    ) -> Self {
        let (tx, rx) = mpsc::channel(capacity);
        let shared = Arc::new(Shared {
            mailer,
            from,
            domain: deployment_domain.to_owned(),
            retry,
        });
        tokio::spawn(worker(rx, shared));
        Self { queue: tx }
    }

    /// Queue without a worker (tests of the full-queue path).
    #[cfg(test)]
    pub(crate) fn unstarted(capacity: usize) -> (Self, mpsc::Receiver<Job>) {
        let (tx, rx) = mpsc::channel(capacity);
        (Self { queue: tx }, rx)
    }

    /// Put the link on the queue; never waits. A full queue drops it (counted, still `Ok`, so
    /// the API answer stays the identical `202`).
    fn enqueue(&self, to: &str, token: &Secret<String>) -> Result<(), Error> {
        let job = Job {
            to: to.to_owned(),
            token: token.clone(),
        };
        match self.queue.try_send(job) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                metrics::counter!("cs_notifier_dropped_total", "reason" => "queue_full")
                    .increment(1);
                tracing::warn!(
                    capacity = self.queue.max_capacity(),
                    "notifier queue full: an email recovery link was dropped"
                );
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                metrics::counter!("cs_notifier_dropped_total", "reason" => "closed").increment(1);
                Err(Error::new(ErrorCode::Unavailable).with_detail("notifier worker stopped"))
            }
        }
    }
}

#[async_trait]
impl Notifier for SmtpRelay {
    async fn recovery_link(&self, to: &str, token: &Secret<String>) -> Result<(), Error> {
        self.enqueue(to, token)
    }
}

async fn worker(mut rx: mpsc::Receiver<Job>, shared: Arc<Shared>) {
    let permits = Arc::new(Semaphore::new(CONCURRENCY));
    while let Some(job) = rx.recv().await {
        let Ok(permit) = permits.clone().acquire_owned().await else {
            return;
        };
        let shared = shared.clone();
        tokio::spawn(async move {
            deliver(&shared, job).await;
            drop(permit);
        });
    }
}

/// Send one link with bounded retries. Logs carry no token and no address.
async fn deliver(shared: &Shared, job: Job) -> u32 {
    let Ok(to) = job.to.parse::<Mailbox>() else {
        metrics::counter!("cs_notifier_failed_total", "class" => "recipient").increment(1);
        tracing::warn!(class = "recipient", "recovery link not sent: invalid recipient address");
        return 0;
    };
    let body = format!(
        "Someone asked to recover your account. If it was you, open this link to continue:\n\n\
         {}\n\n\
         If it was not you, sign in and cancel the request under Security. Your account stays \
         usable and your password is unchanged until a recovery completes.\n",
        recovery_url(&shared.domain, &job.token)
    );
    for attempt in 1..=shared.retry.attempts {
        let msg = Message::builder()
            .from(shared.from.clone())
            .to(to.clone())
            .subject(SUBJECT)
            .header(ContentType::TEXT_PLAIN)
            // lettre picks the transfer encoding (quoted-printable for the long link line).
            .body(body.clone());
        let msg = match msg {
            Ok(m) => m,
            Err(_) => {
                tracing::warn!(class = "message", "recovery link not sent: cannot build the message");
                return attempt;
            }
        };
        match shared.mailer.send(msg).await {
            Ok(()) => {
                metrics::counter!("cs_notifier_sent_total").increment(1);
                tracing::info!(attempt, "recovery link delivered to the SMTP relay");
                return attempt;
            }
            Err(e) => {
                let last = e.permanent || attempt == shared.retry.attempts;
                tracing::warn!(
                    class = e.class,
                    status = e.status,
                    attempt,
                    max_attempts = shared.retry.attempts,
                    final_attempt = last,
                    "recovery link delivery failed"
                );
                if last {
                    metrics::counter!("cs_notifier_failed_total", "class" => e.class)
                        .increment(1);
                    return attempt;
                }
                tokio::time::sleep(shared.retry.delay(attempt)).await;
            }
        }
    }
    shared.retry.attempts
}

// ---------------------------------------------------------------------------------------------
// [R7] development sink
// ---------------------------------------------------------------------------------------------

/// `[R7]` Development sink: writes the link to stderr, each line prefixed `DEV-ONLY SECRET`.
/// Refused outside the `--dev` profile; never the default.
#[derive(Clone)]
pub struct DevLogSink {
    domain: String,
    out: Arc<Mutex<Box<dyn Write + Send>>>,
}

impl std::fmt::Debug for DevLogSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DevLogSink").finish_non_exhaustive()
    }
}

/// Prefix of every line the dev sink writes (`[R7]`).
pub const DEV_PREFIX: &str = "DEV-ONLY SECRET";

impl DevLogSink {
    /// `dev_profile`: whether `cs serve` runs with `--dev`.
    pub fn new(dev_profile: bool, deployment_domain: &str) -> Result<Self, Box<Error>> {
        Self::with_writer(dev_profile, deployment_domain, Box::new(std::io::stderr()))
    }

    pub(crate) fn with_writer(
        dev_profile: bool,
        deployment_domain: &str,
        out: Box<dyn Write + Send>,
    ) -> Result<Self, Box<Error>> {
        if dev_profile {
            Ok(Self {
                domain: deployment_domain.to_owned(),
                out: Arc::new(Mutex::new(out)),
            })
        } else {
            Err(invalid(
                "the dev_log notifier writes bearer secrets and needs the --dev profile",
            ))
        }
    }
}

#[async_trait]
impl Notifier for DevLogSink {
    async fn recovery_link(&self, to: &str, token: &Secret<String>) -> Result<(), Error> {
        // One line, always prefixed: control characters in the address cannot start a new one.
        let to: String = to.chars().map(|c| if c.is_control() { '?' } else { c }).collect();
        let line = format!(
            "{DEV_PREFIX} recovery link for {to}: {}\n",
            recovery_url(&self.domain, token)
        );
        let mut out = self
            .out
            .lock()
            .map_err(|_| Error::new(ErrorCode::Internal).with_detail("dev sink poisoned"))?;
        out.write_all(line.as_bytes())
            .and_then(|()| out.flush())
            .map_err(Error::internal)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

    const TOKEN: &str = "rt1.SECRETTOKENVALUE.zzz";
    const ADDR: &str = "alice.private@example.org";

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl Buf {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buf {
        type Writer = Buf;
        fn make_writer(&'a self) -> Buf {
            self.clone()
        }
    }

    /// Fails with `err` for the first `fail` calls, then succeeds.
    struct Fake {
        calls: AtomicU32,
        fail: u32,
        err: MailError,
        sent: Mutex<Vec<String>>,
    }
    impl Fake {
        fn new(fail: u32, permanent: bool) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicU32::new(0),
                fail,
                err: MailError {
                    class: if permanent { "permanent" } else { "transient" },
                    status: Some(if permanent { 550 } else { 451 }),
                    permanent,
                },
                sent: Mutex::new(Vec::new()),
            })
        }
    }
    #[async_trait]
    impl Mailer for Fake {
        async fn send(&self, msg: Message) -> Result<(), MailError> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if n <= self.fail {
                return Err(self.err);
            }
            self.sent
                .lock()
                .unwrap()
                .push(String::from_utf8_lossy(&msg.formatted()).into_owned());
            Ok(())
        }
    }

    fn fast() -> RetryPolicy {
        RetryPolicy {
            attempts: MAX_ATTEMPTS,
            base: Duration::from_millis(1),
            cap: Duration::from_millis(4),
        }
    }

    fn shared(m: Arc<Fake>) -> Shared {
        Shared {
            mailer: m,
            from: "Cloud System <no-reply@example.com>".parse().unwrap(),
            domain: "cs.example.com".into(),
            retry: fast(),
        }
    }

    fn job() -> Job {
        Job {
            to: ADDR.into(),
            token: Secret::new(TOKEN.to_owned()),
        }
    }

    #[test]
    fn dev_sink_needs_dev_profile() {
        assert!(DevLogSink::new(false, "cs.example.com").is_err());
        assert!(DevLogSink::new(true, "cs.example.com").is_ok());
        assert!(validate_config(
            Some(&NotifierConfig {
                kind: NotifierKind::DevLog,
                smtp: None
            }),
            "cs.example.com",
            false
        )
        .is_err());
    }

    #[tokio::test]
    async fn dev_sink_prefixes_every_line() {
        let buf = Buf::default();
        let sink = DevLogSink::with_writer(true, "cs.example.com", Box::new(buf.clone())).unwrap();
        let t = Secret::new(TOKEN.to_owned());
        sink.recovery_link(ADDR, &t).await.unwrap();
        sink.recovery_link("evil@example.org\nforged line", &t).await.unwrap();
        let text = buf.text();
        assert_eq!(text.lines().count(), 2);
        assert!(text.lines().all(|l| l.starts_with(DEV_PREFIX)), "{text}");
        assert!(text.contains(&format!("https://cs.example.com/#/recover/{TOKEN}")));
    }

    #[test]
    fn backoff_is_exponential_and_capped() {
        let p = RetryPolicy::default();
        let d: Vec<u64> = (1..=8).map(|n| p.delay(n).as_secs()).collect();
        assert_eq!(d, [1, 2, 4, 8, 16, 30, 30, 30]);
    }

    #[tokio::test]
    async fn retries_are_capped_at_five() {
        let m = Fake::new(u32::MAX, false);
        assert_eq!(deliver(&shared(m.clone()), job()).await, MAX_ATTEMPTS);
        assert_eq!(m.calls.load(Ordering::SeqCst), 5);
    }

    #[tokio::test]
    async fn transient_failure_is_retried_then_delivered() {
        let m = Fake::new(2, false);
        assert_eq!(deliver(&shared(m.clone()), job()).await, 3);
        let sent = m.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert!(sent[0].contains(&format!("https://cs.example.com/#/recover/{TOKEN}")));
        assert!(sent[0].contains(&format!("To: {ADDR}")));
    }

    #[tokio::test]
    async fn permanent_failure_is_not_retried() {
        let m = Fake::new(u32::MAX, true);
        assert_eq!(deliver(&shared(m.clone()), job()).await, 1);
        assert_eq!(m.calls.load(Ordering::SeqCst), 1);
    }

    /// Counts `cs_notifier_dropped_total`.
    #[derive(Default)]
    struct Drops(Arc<AtomicU64>);
    struct DropCounter(Arc<AtomicU64>);
    impl metrics::CounterFn for DropCounter {
        fn increment(&self, v: u64) {
            self.0.fetch_add(v, Ordering::SeqCst);
        }
        fn absolute(&self, v: u64) {
            self.0.store(v, Ordering::SeqCst);
        }
    }
    impl metrics::Recorder for Drops {
        fn describe_counter(&self, _: metrics::KeyName, _: Option<metrics::Unit>, _: metrics::SharedString) {}
        fn describe_gauge(&self, _: metrics::KeyName, _: Option<metrics::Unit>, _: metrics::SharedString) {}
        fn describe_histogram(&self, _: metrics::KeyName, _: Option<metrics::Unit>, _: metrics::SharedString) {}
        fn register_counter(&self, key: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Counter {
            if key.name() == "cs_notifier_dropped_total" {
                metrics::Counter::from_arc(Arc::new(DropCounter(self.0.clone())))
            } else {
                metrics::Counter::noop()
            }
        }
        fn register_gauge(&self, _: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Gauge {
            metrics::Gauge::noop()
        }
        fn register_histogram(&self, _: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Histogram {
            metrics::Histogram::noop()
        }
    }

    /// Rev 13: a full queue drops the link, counts it, and still answers `Ok` (the API's
    /// identical `202`); enqueueing never waits.
    #[tokio::test]
    async fn queue_full_drops_counts_and_still_succeeds() {
        let (relay, mut rx) = SmtpRelay::unstarted(1);
        let rec = Drops::default();
        let t = Secret::new(TOKEN.to_owned());
        metrics::with_local_recorder(&rec, || {
            assert!(relay.enqueue(ADDR, &t).is_ok());
            assert!(relay.enqueue(ADDR, &t).is_ok());
            assert!(relay.enqueue(ADDR, &t).is_ok());
        });
        assert_eq!(rec.0.load(Ordering::SeqCst), 2);
        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_err());
    }

    /// Logs of every failure path carry neither the token nor the address.
    #[tokio::test]
    async fn no_token_or_address_in_logs() {
        let buf = Buf::default();
        let sub = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_max_level(tracing::Level::TRACE)
            .json()
            .finish();
        // Global (the only global subscriber of this test binary): a thread-local default races
        // with concurrent tests over the callsite interest cache.
        tracing::subscriber::set_global_default(sub).unwrap();
        deliver(&shared(Fake::new(u32::MAX, false)), job()).await;
        deliver(&shared(Fake::new(u32::MAX, true)), job()).await;
        deliver(&shared(Fake::new(1, false)), job()).await;
        let bad = Job {
            to: format!("not an address {TOKEN}"),
            token: Secret::new(TOKEN.to_owned()),
        };
        deliver(&shared(Fake::new(0, false)), bad).await;
        let (relay, _rx) = SmtpRelay::unstarted(1);
        let t = Secret::new(TOKEN.to_owned());
        relay.enqueue(ADDR, &t).unwrap();
        relay.enqueue(ADDR, &t).unwrap();
        Discard.recovery_link(ADDR, &t).await.unwrap();
        let text = buf.text();
        assert!(text.contains("\"attempt\":5"), "{text}");
        assert!(text.contains("queue full"), "{text}");
        assert!(!text.contains("SECRETTOKENVALUE"), "{text}");
        assert!(!text.contains("alice.private"), "{text}");
    }
}
