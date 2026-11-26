//! M1 adapter and fixtures: the ONLY module of the M1 suite that names cs-identity APIs.
//!
//! Every test drives the identity service through its public HTTP routes
//! (`cs_identity::http::routes` behind the M0 middleware), in process, on a leased pool
//! database. Several "nodes" (independent `AuthService` instances) can share one database,
//! one KMS and Valkey, as API nodes of one deployment do. Fixture-only database access
//! (time travel, inspection) is plain SQL on the contract §1 tables.
//!
//! Log capture (contract §9): a global `tracing` subscriber records every event of every
//! crate at TRACE level as JSON; every request and response passing through [`Node::call`]
//! registers its bearer secrets (tokens, txns, grants, codes, OPAQUE messages, DPoP proofs)
//! and [`Env::finish`] fails the test if any registered secret, or anything shaped like one,
//! appears in the captured log.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cs_common::id::{TenantId, UserId};
use cs_common::secret::Secret;
use cs_common::vector::DomainId;
use cs_db::migrate::{MigrationSet, Migrator, common_migrations};
use cs_db::{DomainPool, RetryPolicy};
use cs_identity::admin::{IdentityAdmin, NewUser, UserKind};
use cs_identity::auth::AuthService;
use cs_identity::ratelimit::{RateLimiter, RateLimits};
use cs_identity::session::SessionPolicy;
use cs_identity_wire::opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, Identifiers, RegistrationResponse,
};
use cs_identity_wire::{CONTEXT, KsfParams, Suite, client_identifier};
use cs_kms::{Kms, LocalSoftwareKms};
use http_body_util::BodyExt as _;
use rand_core_06::RngCore as _;
use serde_json::{Value, json};
use sha2::Digest as _;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tower::ServiceExt as _;

use crate::support::db::TestDb;

/// Same deployment domain as the M0 adapter (`contract::DEPLOYMENT_DOMAIN`), so proofs built
/// here are valid against the `cs` binary started by the shared harness.
pub const DOMAIN: &str = "qa.example";
pub const ORIGIN: &str = "https://qa.example";
pub const ID: DomainId = DomainId::Identity;

pub fn htu(path: &str) -> String {
    format!("{ORIGIN}{path}")
}

pub fn b64(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

pub fn unb64(s: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(s).unwrap()
}

pub fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand_core_06::OsRng.fill_bytes(&mut b);
    b
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

pub fn sha256(b: &[u8]) -> Vec<u8> {
    sha2::Sha256::digest(b).to_vec()
}

pub fn uniq(prefix: &str) -> String {
    format!(
        "{prefix}{}",
        &uuid::Uuid::new_v4().simple().to_string()[..10]
    )
}

// ============================================================================ log capture

static LOG: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static SECRETS: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());
static LOG_INIT: OnceLock<()> = OnceLock::new();

struct LogWriter;
impl std::io::Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        LOG.lock()
            .unwrap_or_else(|p| p.into_inner())
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Install the capturing subscriber (TRACE, every target, JSON). Idempotent.
pub fn init_logs() {
    LOG_INIT.get_or_init(|| {
        let _ = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(|| LogWriter)
            .try_init();
    });
}

/// Register a bearer secret that must never appear in logs.
pub fn secret(kind: &str, value: &str) {
    if value.len() >= 16 {
        SECRETS
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((kind.to_owned(), value.to_owned()));
    }
}

pub fn captured_log() -> String {
    String::from_utf8_lossy(&LOG.lock().unwrap_or_else(|p| p.into_inner())).into_owned()
}

pub fn secrets_registered() -> usize {
    SECRETS.lock().unwrap_or_else(|p| p.into_inner()).len()
}

/// Shapes of M1 bearer secrets: `rt1` tokens (refresh, setup link, grant, txns), compact JWS
/// (access tokens, DPoP proofs), recovery codes, PEM / private JWK members.
pub fn secret_patterns() -> Vec<(&'static str, regex::Regex)> {
    vec![
        (
            "rt1 token",
            regex::Regex::new(r"rt1\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}").unwrap(),
        ),
        (
            "compact JWS",
            regex::Regex::new(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.").unwrap(),
        ),
        (
            "recovery code",
            regex::Regex::new(r"\b[A-Z2-7]{8}-[A-Z2-7]{20}\b").unwrap(),
        ),
        (
            "private key",
            regex::Regex::new(r#"PRIVATE KEY|"d"\s*:\s*"[A-Za-z0-9_-]{20,}"#).unwrap(),
        ),
    ]
}

/// Scan `log` for every registered secret and every secret pattern; returns the findings
/// (kind and a redacted excerpt), never the secret itself.
pub fn scan_text(log: &str, extra: &[(String, String)]) -> Vec<String> {
    let mut found = Vec::new();
    let secrets = SECRETS.lock().unwrap_or_else(|p| p.into_inner()).clone();
    for (kind, v) in secrets.iter().chain(extra.iter()) {
        if log.contains(v.as_str()) {
            found.push(format!("{kind} (len {}) appears in the log", v.len()));
        }
    }
    for (name, re) in secret_patterns() {
        if let Some(m) = re.find(log) {
            let start = log[..m.start()].rfind('\n').map(|i| i + 1).unwrap_or(0);
            let line = &log[start..m.start()];
            found.push(format!(
                "{name}-shaped value in the log after: {:?}",
                &line[line.len().saturating_sub(120)..]
            ));
        }
    }
    found
}

/// Persist the captured log (evidence for the gate report) and scan it.
pub fn scan_logs() -> Vec<String> {
    let log = captured_log();
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/qa-m1-logs");
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::write(
        dir.join(format!("inproc-{}.jsonl", std::process::id())),
        &log,
    );
    scan_text(&log, &[])
}

const SECRET_KEYS: &[&str] = &[
    "access_token",
    "login_txn",
    "credential_request",
    "credential_response",
    "credential_finalization",
    "registration_request",
    "registration_response",
    "registration_upload",
    "registration_txn",
    "grant",
    "token",
    "recovery_txn",
    "auth_txn",
    "assert_txn",
    "reauth_txn",
    "code",
    "codes",
];

fn register_json(v: &Value) {
    if let Some(o) = v.as_object() {
        for (k, x) in o {
            if SECRET_KEYS.contains(&k.as_str()) {
                match x {
                    Value::String(s) => secret(k, s),
                    Value::Array(a) => a
                        .iter()
                        .filter_map(Value::as_str)
                        .for_each(|s| secret(k, s)),
                    _ => {}
                }
            }
        }
    }
}

// ============================================================================ HTTP

#[derive(Debug, Clone)]
pub struct Req {
    method: String,
    path: String,
    body: Option<Vec<u8>>,
    headers: Vec<(String, String)>,
    source: Option<IpAddr>,
}

impl Req {
    pub fn new(method: &str, path: &str) -> Self {
        Self {
            method: method.to_owned(),
            path: path.to_owned(),
            body: None,
            headers: vec![],
            source: None,
        }
    }
    pub fn get(path: &str) -> Self {
        Self::new("GET", path)
    }
    pub fn post(path: &str) -> Self {
        Self::new("POST", path)
    }
    pub fn delete(path: &str) -> Self {
        Self::new("DELETE", path)
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn method(&self) -> &str {
        &self.method
    }
    pub fn json(mut self, v: Value) -> Self {
        self.headers
            .push(("content-type".into(), "application/json".into()));
        self.body = Some(v.to_string().into_bytes());
        self
    }
    pub fn raw_body(mut self, ct: &str, b: &[u8]) -> Self {
        self.headers.push(("content-type".into(), ct.into()));
        self.body = Some(b.to_vec());
        self
    }
    pub fn header(mut self, k: &str, v: &str) -> Self {
        self.headers.push((k.to_owned(), v.to_owned()));
        self
    }
    pub fn bearer(self, at: &str) -> Self {
        self.header("authorization", &format!("Bearer {at}"))
    }
    /// `Authorization: DPoP <at>` plus a fresh proof (with `ath`) for this method and path.
    pub fn dpop(self, at: &str, key: &DKey) -> Self {
        let p = key.proof(&self.method, &htu(&self.path), Some(at));
        self.header("authorization", &format!("DPoP {at}"))
            .header("dpop", &p)
    }
    /// A proof without `ath` (login/finish, refresh).
    pub fn proof(self, key: &DKey) -> Self {
        let p = key.proof(&self.method, &htu(&self.path), None);
        self.header("dpop", &p)
    }
    pub fn cookie(self, rt: &str) -> Self {
        self.header("cookie", &format!("__Secure-cs_rt={rt}"))
    }
    pub fn idem(self, k: &str) -> Self {
        self.header("idempotency-key", k)
    }
    pub fn from(mut self, ip: &str) -> Self {
        self.source = Some(ip.parse().unwrap());
        self
    }
}

#[derive(Debug, Clone)]
pub struct Resp {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Value,
}

impl Resp {
    pub fn code(&self) -> &str {
        self.body["code"].as_str().unwrap_or("")
    }
    pub fn err_codes(&self) -> Vec<String> {
        self.body["errors"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|e| e["code"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn set_cookie(&self) -> Option<String> {
        self.headers
            .get(header::SET_COOKIE)
            .map(|v| v.to_str().unwrap().to_owned())
    }
    pub fn rt(&self) -> Option<String> {
        self.set_cookie().and_then(|c| {
            c.strip_prefix("__Secure-cs_rt=")
                .map(|r| r.split(';').next().unwrap_or("").to_owned())
                .filter(|r| !r.is_empty())
        })
    }
    /// Body with per-request members removed, for indistinguishability comparisons.
    pub fn shape(&self) -> Value {
        let mut v = self.body.clone();
        if let Some(o) = v.as_object_mut() {
            for k in ["request_id", "instance", "trace_id"] {
                o.remove(k);
            }
        }
        v
    }
    #[track_caller]
    pub fn expect(&self, status: u16) -> &Self {
        assert_eq!(
            self.status, status,
            "unexpected status; body: {}",
            self.body
        );
        self
    }
    #[track_caller]
    pub fn expect_unauth(&self) -> &Self {
        assert_eq!(
            self.status, 401,
            "expected 401 unauthenticated; body: {}",
            self.body
        );
        assert_eq!(self.code(), "unauthenticated", "{}", self.body);
        self
    }
}

pub struct Node {
    pub auth: Arc<AuthService>,
    app: axum::Router,
}

/// Something that answers M1 HTTP requests: an in-process node or a running `cs` binary.
#[allow(async_fn_in_trait)]
pub trait Caller {
    async fn call(&self, r: Req) -> Resp;
}

impl Caller for Node {
    async fn call(&self, r: Req) -> Resp {
        Node::call(self, r).await
    }
}

/// A running `cs serve` reached over HTTP.
pub struct Remote {
    pub base: String,
    pub client: reqwest::Client,
}

impl Caller for Remote {
    async fn call(&self, r: Req) -> Resp {
        register_req(&r);
        let m = reqwest::Method::from_bytes(r.method.as_bytes()).unwrap();
        let mut b = self.client.request(m, format!("{}{}", self.base, r.path));
        for (k, v) in &r.headers {
            b = b.header(k.as_str(), v.as_str());
        }
        if let Some(body) = r.body {
            b = b.body(body);
        }
        let res = b.send().await.unwrap();
        let status = res.status().as_u16();
        let mut headers = HeaderMap::new();
        for (k, v) in res.headers() {
            if let (Ok(k), Ok(v)) = (
                axum::http::HeaderName::from_bytes(k.as_str().as_bytes()),
                axum::http::HeaderValue::from_bytes(v.as_bytes()),
            ) {
                headers.append(k, v);
            }
        }
        let bytes = res.bytes().await.unwrap();
        finish_resp(status, headers, &bytes)
    }
}

fn register_req(r: &Req) {
    for (k, v) in &r.headers {
        match k.as_str() {
            "authorization" => {
                if let Some((_, t)) = v.split_once(' ') {
                    secret("access token (Authorization)", t)
                }
            }
            "dpop" => secret("DPoP proof", v),
            "cookie" => {
                if let Some((_, t)) = v.split_once('=') {
                    secret("refresh token (cookie)", t)
                }
            }
            _ => {}
        }
    }
    if let Some(b) = &r.body
        && let Ok(v) = serde_json::from_slice::<Value>(b)
    {
        register_json(&v);
    }
}

fn finish_resp(status: u16, headers: HeaderMap, bytes: &[u8]) -> Resp {
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(bytes).into()))
    };
    register_json(&body);
    let resp = Resp {
        status,
        headers,
        body,
    };
    if let Some(rt) = resp.rt() {
        secret("refresh token (Set-Cookie)", &rt);
    }
    resp
}

impl Node {
    pub async fn call(&self, r: Req) -> Resp {
        // Register the request's secrets before anything can log them.
        register_req(&r);
        let mut b = Request::builder().method(r.method.as_str()).uri(&r.path);
        for (k, v) in &r.headers {
            b = b.header(k.as_str(), v.as_str());
        }
        let mut req = b
            .body(r.body.map(Body::from).unwrap_or_else(Body::empty))
            .unwrap();
        let ip = r.source.unwrap_or_else(|| "198.51.100.7".parse().unwrap());
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(ip, 40000)));
        let res = self.app.clone().oneshot(req).await.unwrap();
        let (status, headers) = (res.status().as_u16(), res.headers().clone());
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        finish_resp(status, headers, &bytes)
    }
}

// ============================================================================ environment

/// Recovery links handed to the Notifier (contract §4): captured, never logged.
#[derive(Debug, Default)]
pub struct Outbox {
    pub links: Mutex<Vec<(String, String)>>,
}

#[derive(Debug)]
struct CapturingNotifier(Arc<Outbox>, u64);

#[async_trait::async_trait]
impl cs_identity::notify::Notifier for CapturingNotifier {
    async fn recovery_link(
        &self,
        to: &str,
        token: &Secret<String>,
    ) -> Result<(), cs_common::error::Error> {
        secret("recovery link", token.expose_secret());
        if self.1 > 0 {
            // A slow SMTP relay (rev 13: response timing must never depend on delivery).
            tokio::time::sleep(Duration::from_millis(self.1)).await;
        }
        self.0
            .links
            .lock()
            .unwrap()
            .push((to.to_owned(), token.expose_secret().clone()));
        Ok(())
    }
}

/// Valkey configuration of one node.
#[derive(Debug, Clone)]
pub enum Valkey {
    /// No Valkey: DPoP replay on the `dpop_jti` table only.
    None,
    /// The dev Valkey (`CS_TEST_VALKEY_URL`, default `redis://localhost:6379`).
    Real,
    /// Configured but unreachable (closed port).
    Down,
}

pub fn valkey_url() -> String {
    std::env::var("CS_TEST_VALKEY_URL").unwrap_or_else(|_| "redis://localhost:6379".into())
}

pub const VALKEY_DOWN: &str = "redis://127.0.0.1:1";

#[derive(Debug, Clone)]
pub struct Opts {
    pub policy: SessionPolicy,
    /// One entry per node.
    pub nodes: Vec<Valkey>,
    /// Rate limits; `None` = generous local limits (rate limiting tested separately).
    pub limits: Option<(RateLimits, Valkey)>,
    /// Delay of every recovery-link delivery (simulated slow SMTP relay).
    pub notify_delay_ms: u64,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            policy: SessionPolicy::default(),
            nodes: vec![Valkey::Real],
            limits: None,
            notify_delay_ms: 0,
        }
    }
}

pub fn generous() -> RateLimits {
    RateLimits {
        source: 1000,
        account: 100,
        tenant: 100_000,
        node_count: 1,
    }
}

pub struct Env {
    pub db: Option<TestDb>,
    pub pool: DomainPool,
    pub kms: Arc<dyn Kms>,
    pub dir: tempfile::TempDir,
    pub admin: IdentityAdmin,
    pub nodes: Vec<Node>,
    pub outbox: Arc<Outbox>,
}

fn migration_set() -> MigrationSet {
    common_migrations()
        .unwrap()
        .merge(cs_identity::migrations().unwrap())
        .unwrap()
}

pub fn pool_for(url: &str) -> DomainPool {
    let cfg = cs_common::config::DomainConfig {
        url: Secret::new(url.to_owned()),
        pool: cs_common::config::PoolConfig {
            max_connections: 12,
            idle_timeout_ms: 1000,
            ..cs_common::config::PoolConfig::default()
        },
    };
    DomainPool::connect_lazy(ID, &cfg, RetryPolicy::default()).unwrap()
}

impl Env {
    /// `None` = skip (no database configured and not required).
    pub async fn new(o: Opts) -> Option<Env> {
        init_logs();
        let admin_url = crate::support::db::admin_url().await?;
        let db = TestDb::create(&admin_url, "m1").await;
        let pool = pool_for(&db.url);
        {
            let _g = crate::support::db::ddl_guard().await;
            let set = migration_set();
            let mut last = String::new();
            let mut ok = false;
            for attempt in 0..5u64 {
                match Migrator::run(&pool, &set).await {
                    Ok(_) => {
                        ok = true;
                        break;
                    }
                    Err(e) => {
                        last = e.to_string();
                        tokio::time::sleep(Duration::from_millis(500 * (attempt + 1))).await;
                    }
                }
            }
            assert!(ok, "identity migrations failed: {last}");
        }
        let dir = tempfile::tempdir().unwrap();
        let kms: Arc<dyn Kms> =
            Arc::new(LocalSoftwareKms::init(&dir.path().join("root.key"), None).unwrap());
        // The root key is key material: it must never be logged.
        let root = std::fs::read(dir.path().join("root.key")).unwrap();
        let root_txt = String::from_utf8_lossy(&root).trim().to_owned();
        secret("KMS root key", &root_txt);
        secret("KMS root key (hex)", &hex::encode(&root));
        let outbox = Arc::new(Outbox::default());
        let mut nodes = Vec::new();
        for v in &o.nodes {
            nodes.push(Self::node_with(&pool, &kms, &o, v, &outbox));
        }
        let admin = IdentityAdmin::new(pool.clone()).unwrap();
        Some(Env {
            db: Some(db),
            pool,
            kms,
            dir,
            admin,
            nodes,
            outbox,
        })
    }

    fn node_with(
        pool: &DomainPool,
        kms: &Arc<dyn Kms>,
        o: &Opts,
        v: &Valkey,
        outbox: &Arc<Outbox>,
    ) -> Node {
        let limiter = match &o.limits {
            None => RateLimiter::local_only(generous()),
            Some((l, Valkey::None)) => RateLimiter::local_only(*l),
            Some((l, Valkey::Real)) => RateLimiter::new(*l, Some(&valkey_url())).unwrap(),
            Some((l, Valkey::Down)) => RateLimiter::new(*l, Some(VALKEY_DOWN)).unwrap(),
        };
        let auth = AuthService::new(pool.clone(), kms.clone(), DOMAIN, o.policy)
            .with_rate_limiter(limiter)
            .with_notifier(Arc::new(CapturingNotifier(
                outbox.clone(),
                o.notify_delay_ms,
            )));
        // M1 contract rev 14: Valkey is no longer on the DPoP replay path (dpop_jti only), so the
        // node's Valkey state matters only for rate limiting (above). Kept as a parameter so the
        // cross-node replay test still runs nodes with Valkey up and down.
        let _ = v;
        Self::node_from(Arc::new(auth))
    }

    pub fn node_from(auth: Arc<AuthService>) -> Node {
        let state = cs_api::ApiState::new(DOMAIN, vec![], Duration::from_secs(2));
        let app = cs_api::with_middleware(
            cs_api::public_routes().merge(cs_identity::http::routes(auth.clone())),
            state,
            1 << 20,
        );
        Node { auth, app }
    }

    pub async fn default() -> Option<Env> {
        Self::new(Opts::default()).await
    }

    pub async fn call(&self, r: Req) -> Resp {
        self.nodes[0].call(r).await
    }

    /// Fixture SQL on the identity database (time travel, state set-up).
    pub async fn exec(&self, sql: &str) {
        self.db.as_ref().unwrap().exec(sql).await;
    }

    pub async fn i64(&self, sql: &str) -> i64 {
        self.db.as_ref().unwrap().scalar_i64(sql).await
    }

    /// Scan the captured log, release the database. Fails the test on a secret in the log.
    pub async fn finish(mut self) {
        for n in &self.nodes {
            let _ = n;
        }
        self.pool.close().await;
        if let Some(db) = self.db.take() {
            db.drop_now().await;
        }
        let found = scan_logs();
        assert!(
            found.is_empty(),
            "contract §9: secrets in the captured log:\n{}",
            found.join("\n")
        );
    }

    // ----------------------------------------------------------------- identities

    pub async fn tenant(&self) -> TenantId {
        self.admin
            .create_tenant(&uniq("qa-t-"))
            .await
            .unwrap()
            .tenant_id
    }

    /// Invited user and a setup link (the registration grant).
    pub async fn invite(&self, t: TenantId, login: &str) -> (UserId, String) {
        let u = self
            .admin
            .create_user(
                t,
                NewUser {
                    login: login.to_owned(),
                    kind: UserKind::Member,
                    display_name: None,
                },
            )
            .await
            .unwrap();
        let link = self.admin.issue_setup_link(t, u.user_id).await.unwrap();
        let tok = link.token.expose_secret().clone();
        secret("setup link", &tok);
        (u.user_id, tok)
    }

    /// Registered active user.
    pub async fn user(&self, t: TenantId, login: &str, pw: &str) -> User {
        let (id, grant) = self.invite(t, login).await;
        let r = self.register(&self.nodes[0], &grant, login, pw).await;
        r.expect(204);
        User {
            tenant: t,
            id,
            login: login.to_owned(),
            pw: pw.to_owned(),
        }
    }

    /// OPAQUE registration under a grant (setup link or recovery grant); returns finish.
    pub async fn register(&self, n: &impl Caller, grant: &str, login: &str, pw: &str) -> Resp {
        let tenant = cs_identity::token::parse(grant)
            .map(|p| p.tenant_id.as_uuid().to_string())
            .unwrap_or_default();
        let (start, c) = Self::reg_start(n, json!({"grant": grant, "login": login}), pw).await;
        if start.status != 200 {
            return start;
        }
        Self::reg_finish(n, &start, c, &tenant, &login.to_lowercase(), pw, None).await
    }

    pub async fn reg_start(
        n: &impl Caller,
        mut body: Value,
        pw: &str,
    ) -> (Resp, ClientRegistration<Suite>) {
        let c =
            ClientRegistration::<Suite>::start(&mut rand_core_06::OsRng, pw.as_bytes()).unwrap();
        let msg = b64(&c.message.serialize());
        secret("OPAQUE registration_request", &msg);
        body["registration_request"] = json!(msg);
        let r = n
            .call(Req::post("/api/v2/auth/opaque/register/start").json(body))
            .await;
        (r, c.state)
    }

    pub async fn reg_start_session(
        n: &impl Caller,
        s: &Session,
        purpose: &str,
        pw: &str,
    ) -> (Resp, ClientRegistration<Suite>) {
        let c =
            ClientRegistration::<Suite>::start(&mut rand_core_06::OsRng, pw.as_bytes()).unwrap();
        let msg = b64(&c.message.serialize());
        let r = n
            .call(
                s.req(
                    Req::post("/api/v2/auth/opaque/register/start")
                        .json(json!({"purpose": purpose, "registration_request": msg})),
                ),
            )
            .await;
        (r, c.state)
    }

    pub async fn reg_finish(
        n: &impl Caller,
        start: &Resp,
        c: ClientRegistration<Suite>,
        tenant: &str,
        login: &str,
        pw: &str,
        session: Option<&Session>,
    ) -> Resp {
        let ksf = ksf_of(&start.body["ksf_params"]);
        let resp = RegistrationResponse::<Suite>::deserialize(&unb64(
            start.body["registration_response"].as_str().unwrap(),
        ))
        .unwrap();
        let cid = client_identifier(tenant, login);
        let argon = ksf.argon2().unwrap();
        let fin = c
            .finish(
                &mut rand_core_06::OsRng,
                pw.as_bytes(),
                resp,
                ClientRegistrationFinishParameters::new(
                    Identifiers {
                        client: Some(cid.as_bytes()),
                        server: None,
                    },
                    Some(&argon),
                ),
            )
            .unwrap();
        let upload = b64(&fin.message.serialize());
        secret("OPAQUE registration_upload", &upload);
        let req = Req::post("/api/v2/auth/opaque/register/finish").json(json!({
            "registration_txn": start.body["registration_txn"],
            "registration_upload": upload
        }));
        match session {
            Some(s) => n.call(s.req(req)).await,
            None => n.call(req).await,
        }
    }

    pub async fn login_start(
        n: &impl Caller,
        tenant: &str,
        login: &str,
        pw: &str,
    ) -> (Resp, ClientLogin<Suite>) {
        Self::login_start_from(n, tenant, login, pw, None).await
    }

    pub async fn login_start_from(
        n: &impl Caller,
        tenant: &str,
        login: &str,
        pw: &str,
        src: Option<&str>,
    ) -> (Resp, ClientLogin<Suite>) {
        let c = ClientLogin::<Suite>::start(&mut rand_core_06::OsRng, pw.as_bytes()).unwrap();
        let msg = b64(&c.message.serialize());
        let mut req = Req::post("/api/v2/auth/opaque/login/start")
            .json(json!({"tenant": tenant, "login": login, "credential_request": msg}));
        if let Some(s) = src {
            req = req.from(s);
        }
        (n.call(req).await, c.state)
    }

    /// Client side of login/finish: the finalization message, or a same-length garbage
    /// message when the password is wrong (so the server path still runs).
    pub fn finalization(
        start: &Resp,
        c: ClientLogin<Suite>,
        tenant: &str,
        login: &str,
        pw: &str,
    ) -> String {
        let ksf = ksf_of(&start.body["ksf_params"]);
        let argon = ksf.argon2().unwrap();
        let resp = CredentialResponse::<Suite>::deserialize(&unb64(
            start.body["credential_response"].as_str().unwrap(),
        ))
        .unwrap();
        let cid = client_identifier(tenant, &login.to_lowercase());
        let fin = match c.finish(
            &mut rand_core_06::OsRng,
            pw.as_bytes(),
            resp,
            ClientLoginFinishParameters::new(
                Some(CONTEXT),
                Identifiers {
                    client: Some(cid.as_bytes()),
                    server: None,
                },
                Some(&argon),
            ),
        ) {
            Ok(f) => f.message.serialize().to_vec(),
            Err(_) => vec![0u8; 64],
        };
        let s = b64(&fin);
        secret("OPAQUE credential_finalization", &s);
        s
    }

    /// Full password login on node `n`: (login/start, login/finish).
    pub async fn login_raw(
        n: &impl Caller,
        tenant: &str,
        login: &str,
        pw: &str,
        key: Option<&DKey>,
    ) -> (Resp, Resp) {
        let (st, c) = Self::login_start(n, tenant, login, pw).await;
        if st.status != 200 {
            return (st.clone(), st);
        }
        let fin = Self::finalization(&st, c, tenant, login, pw);
        let mut req = Req::post("/api/v2/auth/opaque/login/finish")
            .json(json!({"login_txn": st.body["login_txn"], "credential_finalization": fin}));
        if let Some(k) = key {
            req = req.proof(k);
        }
        let f = n.call(req).await;
        (st, f)
    }

    /// Successful password login (no MFA).
    pub async fn login(&self, u: &User) -> Session {
        self.login_on(0, u, None).await
    }

    pub async fn login_dpop(&self, u: &User) -> Session {
        self.login_on(0, u, Some(DKey::es256())).await
    }

    pub async fn login_on(&self, node: usize, u: &User, key: Option<DKey>) -> Session {
        let (_, f) = Self::login_raw(
            &self.nodes[node],
            &u.tenant.as_uuid().to_string(),
            &u.login,
            &u.pw,
            key.as_ref(),
        )
        .await;
        f.expect(200);
        assert_eq!(f.body["state"], "authenticated", "{}", f.body);
        Session::from_auth(&f, key)
    }

    /// Set the session's last strong authentication `secs` seconds into the past.
    pub async fn age_strong_auth(&self, s: &Session, secs: i64) {
        self.exec(&format!(
            "UPDATE sessions SET last_strong_auth_at = now() - interval '{secs} seconds' \
             WHERE session_id = '{}'",
            s.sid
        ))
        .await;
    }
}

pub fn ksf_of(v: &Value) -> KsfParams {
    assert_eq!(v["algorithm"], "argon2id", "ksf_params: {v}");
    let k = KsfParams {
        m_kib: v["m_kib"].as_u64().unwrap() as u32,
        t: v["t"].as_u64().unwrap() as u32,
        p: v["p"].as_u64().unwrap() as u32,
    };
    // rev 7: the client refuses parameters outside the bounds before running Argon2id.
    assert!(k.is_valid(), "ksf_params outside the rev 7 bounds: {v}");
    k
}

#[derive(Debug, Clone)]
pub struct User {
    pub tenant: TenantId,
    pub id: UserId,
    pub login: String,
    pub pw: String,
}

impl User {
    pub fn t(&self) -> String {
        self.tenant.as_uuid().to_string()
    }
}

#[derive(Debug, Clone)]
pub struct Session {
    pub at: String,
    pub rt: String,
    pub sid: String,
    pub key: Option<DKey>,
    pub claims: Value,
}

pub fn claims_of(at: &str) -> Value {
    let p = at.split('.').nth(1).unwrap();
    serde_json::from_slice(&unb64(p)).unwrap()
}

impl Session {
    pub fn from_auth(f: &Resp, key: Option<DKey>) -> Session {
        let at = f.body["access_token"].as_str().unwrap().to_owned();
        Session {
            claims: claims_of(&at),
            rt: f.rt().unwrap_or_default(),
            sid: f.body["session_id"].as_str().unwrap_or_default().to_owned(),
            at,
            key,
        }
    }
    /// Authenticate `r` with this session (DPoP when bound, Bearer otherwise).
    pub fn req(&self, r: Req) -> Req {
        match &self.key {
            Some(k) => r.dpop(&self.at, k),
            None => r.bearer(&self.at),
        }
    }
    /// Refresh request for the current refresh token.
    pub fn refresh_req(&self, idem: &str) -> Req {
        let r = Req::post("/api/v2/auth/token/refresh")
            .cookie(&self.rt)
            .idem(idem);
        match &self.key {
            Some(k) => r.proof(k),
            None => r,
        }
    }
}

// ============================================================================ DPoP keys

#[derive(Clone)]
pub enum DKey {
    Es(p256::ecdsa::SigningKey),
    Ed(ed25519_dalek::SigningKey),
}

impl std::fmt::Debug for DKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DKey(..)")
    }
}

impl DKey {
    pub fn es256() -> Self {
        loop {
            if let Ok(k) = p256::ecdsa::SigningKey::from_slice(&rand_bytes::<32>()) {
                let d = DKey::Es(k);
                secret("DPoP private key", &d.private_b64());
                return d;
            }
        }
    }
    pub fn ed25519() -> Self {
        let d = DKey::Ed(ed25519_dalek::SigningKey::from_bytes(&rand_bytes::<32>()));
        secret("DPoP private key", &d.private_b64());
        d
    }
    pub fn private_b64(&self) -> String {
        match self {
            DKey::Es(k) => b64(&k.to_bytes()),
            DKey::Ed(k) => b64(&k.to_bytes()),
        }
    }
    pub fn alg(&self) -> &'static str {
        match self {
            DKey::Es(_) => "ES256",
            DKey::Ed(_) => "EdDSA",
        }
    }
    pub fn jwk(&self) -> Value {
        match self {
            DKey::Es(k) => {
                let p = k.verifying_key().to_encoded_point(false);
                json!({"kty": "EC", "crv": "P-256", "x": b64(p.x().unwrap()), "y": b64(p.y().unwrap())})
            }
            DKey::Ed(k) => {
                json!({"kty": "OKP", "crv": "Ed25519", "x": b64(k.verifying_key().as_bytes())})
            }
        }
    }
    /// RFC 7638 thumbprint, base64url.
    pub fn jkt(&self) -> String {
        let j = self.jwk();
        let canon = match self {
            DKey::Es(_) => format!(
                r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
                j["x"].as_str().unwrap(),
                j["y"].as_str().unwrap()
            ),
            DKey::Ed(_) => format!(
                r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#,
                j["x"].as_str().unwrap()
            ),
        };
        b64(&sha256(canon.as_bytes()))
    }
    pub fn header(&self) -> Value {
        json!({"typ": "dpop+jwt", "alg": self.alg(), "jwk": self.jwk()})
    }
    pub fn claims(&self, htm: &str, htu: &str, at: Option<&str>) -> Value {
        let mut c = json!({"jti": b64(&rand_bytes::<16>()), "htm": htm, "htu": htu, "iat": now()});
        if let Some(at) = at {
            c["ath"] = json!(b64(&sha256(at.as_bytes())));
        }
        c
    }
    pub fn sign_raw(&self, header: &Value, claims: &Value) -> String {
        let input = format!(
            "{}.{}",
            b64(header.to_string().as_bytes()),
            b64(claims.to_string().as_bytes())
        );
        let sig = match self {
            DKey::Es(k) => {
                use p256::ecdsa::signature::Signer as _;
                let s: p256::ecdsa::Signature = k.sign(input.as_bytes());
                s.to_bytes().to_vec()
            }
            DKey::Ed(k) => {
                use ed25519_dalek::Signer as _;
                k.sign(input.as_bytes()).to_bytes().to_vec()
            }
        };
        let p = format!("{input}.{}", b64(&sig));
        secret("DPoP proof", &p);
        p
    }
    pub fn proof(&self, htm: &str, htu: &str, at: Option<&str>) -> String {
        self.sign_raw(&self.header(), &self.claims(htm, htu, at))
    }
}

// ============================================================================ WebAuthn

/// Software authenticator (P-256, `none` attestation), written from WebAuthn L3.
#[derive(Debug, Clone)]
pub struct Authenticator {
    key: p256::ecdsa::SigningKey,
    pub cred_id: Vec<u8>,
    user_handle: Vec<u8>,
    counter: u32,
}

fn cbor(v: &ciborium::Value) -> Vec<u8> {
    let mut out = vec![];
    ciborium::into_writer(v, &mut out).unwrap();
    out
}

impl Default for Authenticator {
    fn default() -> Self {
        Self::new()
    }
}

impl Authenticator {
    pub fn new() -> Self {
        let key = loop {
            if let Ok(k) = p256::ecdsa::SigningKey::from_slice(&rand_bytes::<32>()) {
                break k;
            }
        };
        Self {
            key,
            cred_id: rand_bytes::<16>().to_vec(),
            user_handle: vec![],
            counter: 0,
        }
    }

    fn client_data(kind: &str, challenge: &Value) -> Vec<u8> {
        json!({"type": kind, "challenge": challenge, "origin": ORIGIN, "crossOrigin": false})
            .to_string()
            .into_bytes()
    }

    pub fn create(&mut self, pk: &Value) -> Value {
        self.user_handle = unb64(pk["user"]["id"].as_str().unwrap());
        let p = self.key.verifying_key().to_encoded_point(false);
        use ciborium::Value as C;
        let cose = cbor(&C::Map(vec![
            (C::Integer(1.into()), C::Integer(2.into())),
            (C::Integer(3.into()), C::Integer((-7).into())),
            (C::Integer((-1).into()), C::Integer(1.into())),
            (C::Integer((-2).into()), C::Bytes(p.x().unwrap().to_vec())),
            (C::Integer((-3).into()), C::Bytes(p.y().unwrap().to_vec())),
        ]));
        let mut ad = sha256(DOMAIN.as_bytes());
        ad.push(0x45);
        ad.extend_from_slice(&self.counter.to_be_bytes());
        ad.extend_from_slice(&[0u8; 16]);
        ad.extend_from_slice(&(self.cred_id.len() as u16).to_be_bytes());
        ad.extend_from_slice(&self.cred_id);
        ad.extend_from_slice(&cose);
        let att = cbor(&C::Map(vec![
            (C::Text("fmt".into()), C::Text("none".into())),
            (C::Text("attStmt".into()), C::Map(vec![])),
            (C::Text("authData".into()), C::Bytes(ad)),
        ]));
        let cd = Self::client_data("webauthn.create", &pk["challenge"]);
        json!({
            "id": b64(&self.cred_id), "rawId": b64(&self.cred_id), "type": "public-key",
            "response": {"attestationObject": b64(&att), "clientDataJSON": b64(&cd),
                         "transports": ["internal"]},
            "clientExtensionResults": {"credProps": {"rk": true}}
        })
    }

    pub fn get(&mut self, pk: &Value) -> Value {
        self.counter += 1;
        let mut ad = sha256(DOMAIN.as_bytes());
        ad.push(0x05);
        ad.extend_from_slice(&self.counter.to_be_bytes());
        let cd = Self::client_data("webauthn.get", &pk["challenge"]);
        let mut msg = ad.clone();
        msg.extend_from_slice(&sha256(&cd));
        use p256::ecdsa::signature::Signer as _;
        let sig: p256::ecdsa::Signature = self.key.sign(&msg);
        json!({
            "id": b64(&self.cred_id), "rawId": b64(&self.cred_id), "type": "public-key",
            "response": {"authenticatorData": b64(&ad), "clientDataJSON": b64(&cd),
                         "signature": b64(sig.to_der().as_bytes()),
                         "userHandle": b64(&self.user_handle)},
            "clientExtensionResults": {}
        })
    }
}

impl Env {
    /// Register a passkey for session `s` (needs step-up); returns its wire id.
    pub async fn add_passkey(&self, s: &Session, a: &mut Authenticator) -> String {
        let st = self
            .call(s.req(Req::post("/api/v2/auth/webauthn/register/start").json(json!({}))))
            .await;
        st.expect(200);
        let cred = a.create(&st.body["public_key"]);
        let f = self
            .call(s.req(Req::post("/api/v2/auth/webauthn/register/finish").json(json!({
                "registration_txn": st.body["registration_txn"], "credential": cred, "label": "QA key"
            }))))
            .await;
        f.expect(200);
        f.body["id"].as_str().unwrap().to_owned()
    }

    /// New recovery-code set for session `s` (needs step-up).
    pub async fn recovery_codes(&self, s: &Session) -> Vec<String> {
        let r = self
            .call(s.req(Req::post("/api/v2/me/recovery-codes").json(json!({}))))
            .await;
        r.expect(200);
        r.body["codes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap().to_owned())
            .collect()
    }
}

// ============================================================================ access tokens

/// Compact JWS with arbitrary header and claims, signed by the deployment's real access-token
/// key through the KMS (a forger without the key cannot do this; it isolates claim checks
/// from signature checks).
pub async fn sign_with_kms(env: &Env, header: &Value, claims: &Value) -> String {
    let kid = env.nodes[0]
        .auth
        .access_tokens()
        .current_key()
        .await
        .unwrap();
    let input = format!(
        "{}.{}",
        b64(header.to_string().as_bytes()),
        b64(claims.to_string().as_bytes())
    );
    let sig = env.kms.sign(&kid, input.as_bytes()).await.unwrap();
    let t = format!("{input}.{}", b64(&sig.to_bytes()));
    secret("forged access token", &t);
    t
}

pub async fn current_kid(env: &Env) -> String {
    env.nodes[0]
        .auth
        .access_tokens()
        .current_key()
        .await
        .unwrap()
        .to_string()
}

/// HMAC-SHA256 (RFC 2104) for the alg-confusion test.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut k = if key.len() > 64 {
        sha256(key)
    } else {
        key.to_vec()
    };
    k.resize(64, 0);
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let inner = sha256(&[ipad, msg.to_vec()].concat());
    sha256(&[opad, inner].concat())
}
