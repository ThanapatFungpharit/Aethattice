//! Engineer DB tests for M1 contract rev 15/16: Idempotency-Key replay on identity writes
//! (spec D.3, App. C rule C4) — byte-identical replays (body, status, Set-Cookie), sealed
//! secret-bearing results (no plaintext bearer in the row), `idempotency_mismatch`, expiry
//! of sealed results and the tombstone sweep (P2), deterministic re-signing and a `kid` that
//! can no longer sign (P1), pre-authentication principals without enumeration (P3), logout
//! replay after revocation (P4), and one effect for concurrent same-key requests.
//!
//! Skipped without `CS_TEST_DATABASE_URL` (failed with `CS_REQUIRE_DB=1`).

#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

mod common;

use std::sync::atomic::{AtomicBool, Ordering};

/// A KMS that refuses to sign with version 1 of any key once `deny_v1_sign` is set (a `kid`
/// that can no longer sign, rev 16 P1).
struct Switch {
    inner: LocalSoftwareKms,
    deny_v1_sign: Arc<AtomicBool>,
}

#[async_trait]
impl Kms for Switch {
    async fn generate_key(
        &self,
        name: &str,
        purpose: cs_kms::KeyPurpose,
    ) -> Result<cs_crypto::sig::KeyId, cs_kms::KmsError> {
        self.inner.generate_key(name, purpose).await
    }
    async fn wrap(
        &self,
        kek_id: &cs_crypto::sig::KeyId,
        plaintext_key: &[u8],
    ) -> Result<cs_kms::WrappedKey, cs_kms::KmsError> {
        self.inner.wrap(kek_id, plaintext_key).await
    }
    async fn unwrap(
        &self,
        wrapped: &cs_kms::WrappedKey,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, cs_kms::KmsError> {
        self.inner.unwrap(wrapped).await
    }
    async fn sign(
        &self,
        key_id: &cs_crypto::sig::KeyId,
        bytes: &[u8],
    ) -> Result<ed25519_dalek::Signature, cs_kms::KmsError> {
        if self.deny_v1_sign.load(Ordering::SeqCst) && key_id.to_string().ends_with("@v1") {
            return Err(cs_kms::KmsError::WrongPurpose {
                key: key_id.to_string(),
                operation: "sign",
            });
        }
        self.inner.sign(key_id, bytes).await
    }
    async fn public_key(
        &self,
        key_id: &cs_crypto::sig::KeyId,
    ) -> Result<ed25519_dalek::VerifyingKey, cs_kms::KmsError> {
        self.inner.public_key(key_id).await
    }
    async fn rotate(&self, name: &str) -> Result<cs_crypto::sig::KeyId, cs_kms::KmsError> {
        self.inner.rotate(name).await
    }
    async fn current(&self, name: &str) -> Result<cs_crypto::sig::KeyId, cs_kms::KmsError> {
        self.inner.current(name).await
    }
}

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cs_api::ApiState;
use cs_common::id::TenantId;
use cs_common::secret::Secret;
use cs_common::vector::DomainId;
use cs_db::DomainPool;
use cs_db::migrate::{MigrationSet, Migrator, common_migrations};
use cs_db::testing::TestDomains;
use cs_identity::admin::{IdentityAdmin, NewUser, UserKind};
use cs_identity::auth::AuthService;
use cs_identity::notify::Notifier;
use cs_identity::ratelimit::{RateLimiter, RateLimits};
use cs_identity::session::SessionPolicy;
use cs_identity_wire::{CONTEXT, KsfParams, Suite, client_identifier};
use cs_kms::{Kms, LocalSoftwareKms};
use http_body_util::BodyExt;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, Identifiers, RegistrationResponse,
};
use serde_json::{Value, json};
use sha2::Digest as _;
use sqlx::Row;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tower::ServiceExt;

const ID: DomainId = DomainId::Identity;
const DOMAIN: &str = "cs.example.test";
const ORIGIN: &str = "https://cs.example.test";
const LOGIN: &str = "alice@acme.test";

fn set() -> MigrationSet {
    common_migrations()
        .unwrap()
        .merge(cs_identity::migrations().unwrap())
        .unwrap()
}

fn generous() -> RateLimits {
    RateLimits {
        source: 1000,
        account: 100,
        tenant: 100_000,
        node_count: 1,
    }
}

/// Captures email recovery links (contract §4 Notifier).
#[derive(Default)]
struct Capture(Mutex<Vec<(String, String)>>);

#[async_trait]
impl Notifier for Capture {
    async fn recovery_link(
        &self,
        to: &str,
        token: &Secret<String>,
    ) -> Result<(), cs_common::error::Error> {
        self.0
            .lock()
            .unwrap()
            .push((to.to_owned(), token.expose_secret().clone()));
        Ok(())
    }
}

struct Env {
    t: TestDomains,
    _dir: tempfile::TempDir,
    kms: Arc<dyn Kms>,
    admin: IdentityAdmin,
    app: axum::Router,
    mail: Arc<Capture>,
    deny: Arc<AtomicBool>,
}

impl Env {
    fn pool(&self) -> &DomainPool {
        self.t.pool(&ID)
    }

    /// A new service on the same database (other policy / limits / keys).
    fn with(mut self, policy: SessionPolicy, limits: RateLimiter) -> Self {
        let auth = Arc::new(
            AuthService::new(self.pool().clone(), self.kms.clone(), DOMAIN, policy)
                .with_rate_limiter(limits)
                .with_notifier(self.mail.clone()),
        );
        self.app = app(auth);
        self
    }

    async fn call(&self, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, Value) {
        let r = self.app.clone().oneshot(req).await.unwrap();
        let (status, headers) = (r.status(), r.headers().clone());
        let b = r.into_body().collect().await.unwrap().to_bytes();
        let v = if b.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&b).unwrap()
        };
        (status, headers, v)
    }

    async fn post(&self, path: &str, body: Value) -> (StatusCode, axum::http::HeaderMap, Value) {
        self.req("POST", path, None, Some(body), &[]).await
    }

    /// A request with an optional Bearer token and extra headers.
    async fn req(
        &self,
        method: &str,
        path: &str,
        at: Option<&str>,
        body: Option<Value>,
        extra: &[(&str, &str)],
    ) -> (StatusCode, axum::http::HeaderMap, Value) {
        let mut b = Request::builder().method(method).uri(path);
        if let Some(at) = at {
            b = b.header(header::AUTHORIZATION, format!("Bearer {at}"));
        }
        for (k, v) in extra {
            b = b.header(*k, *v);
        }
        let body = match body {
            Some(v) => {
                b = b.header(header::CONTENT_TYPE, "application/json");
                Body::from(v.to_string())
            }
            None => Body::empty(),
        };
        self.call(b.body(body).unwrap()).await
    }

    async fn refresh(&self, rt: &str) -> (StatusCode, axum::http::HeaderMap, Value) {
        self.req(
            "POST",
            "/api/v2/auth/token/refresh",
            None,
            None,
            &[
                ("cookie", &format!("__Secure-cs_rt={rt}")),
                ("idempotency-key", &b64(&rand16())),
            ],
        )
        .await
    }
}

fn app(auth: Arc<AuthService>) -> axum::Router {
    let state = ApiState::new(DOMAIN, vec![], Duration::from_secs(2));
    cs_api::with_middleware(
        cs_api::public_routes().merge(cs_identity::http::routes(auth)),
        state,
        1 << 20,
    )
}

async fn env() -> Option<Env> {
    let t = TestDomains::create(&[ID]).await?;
    Migrator::run(t.pool(&ID), &set()).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let deny = Arc::new(AtomicBool::new(false));
    let kms: Arc<dyn Kms> = Arc::new(Switch {
        inner: LocalSoftwareKms::init(&dir.path().join("root.key"), None).unwrap(),
        deny_v1_sign: deny.clone(),
    });
    let admin = IdentityAdmin::new(t.pool(&ID).clone()).unwrap();
    let mail = Arc::new(Capture::default());
    let e = Env {
        t,
        _dir: dir,
        kms,
        admin,
        app: axum::Router::new(),
        mail,
        deny,
    };
    Some(e.with(
        SessionPolicy::default(),
        RateLimiter::local_only(generous()),
    ))
}

fn b64(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

fn unb64(v: &Value) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(v.as_str().unwrap()).unwrap()
}

fn rand16() -> [u8; 16] {
    cs_crypto::rand::bytes::<16>().unwrap()
}

fn claims_of(at: &str) -> Value {
    let p = at.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p).unwrap()).unwrap()
}

fn rt_of(h: &axum::http::HeaderMap) -> String {
    h.get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .strip_prefix("__Secure-cs_rt=")
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

fn ksf() -> argon2::Argon2<'static> {
    KsfParams::DEFAULT.argon2().unwrap()
}

/// Client-side OPAQUE registration through `register/{start,finish}` with a grant.
async fn register_with(
    e: &Env,
    tenant: TenantId,
    grant: &str,
    pw: &str,
    idem: Option<&str>,
) -> (StatusCode, StatusCode, Value) {
    let mut rng = rand_core_06::OsRng;
    let c = ClientRegistration::<Suite>::start(&mut rng, pw.as_bytes()).unwrap();
    let (s, _, v) = e
        .post(
            "/api/v2/auth/opaque/register/start",
            json!({"grant": grant, "login": LOGIN, "registration_request": b64(&c.message.serialize())}),
        )
        .await;
    if s != StatusCode::OK {
        return (s, StatusCode::OK, v);
    }
    let resp =
        RegistrationResponse::<Suite>::deserialize(&unb64(&v["registration_response"])).unwrap();
    let cid = client_identifier(&tenant.as_uuid().to_string(), LOGIN);
    let k = ksf();
    let fin = c
        .state
        .finish(
            &mut rng,
            pw.as_bytes(),
            resp,
            ClientRegistrationFinishParameters::new(
                Identifiers {
                    client: Some(cid.as_bytes()),
                    server: None,
                },
                Some(&k),
            ),
        )
        .unwrap();
    let body = json!({"registration_txn": v["registration_txn"], "registration_upload": b64(&fin.message.serialize())});
    let mut extra = vec![];
    if let Some(k) = idem {
        extra.push(("idempotency-key", k));
    }
    let (s2, _, v2) = e
        .req(
            "POST",
            "/api/v2/auth/opaque/register/finish",
            None,
            Some(body.clone()),
            &extra,
        )
        .await;
    if let Some(k) = idem {
        // A retry with the same key replays the outcome.
        let (s3, _, _) = e
            .req(
                "POST",
                "/api/v2/auth/opaque/register/finish",
                None,
                Some(body),
                &[("idempotency-key", k)],
            )
            .await;
        assert_eq!(s3, s2, "idempotent replay");
    }
    (StatusCode::OK, s2, v2)
}

/// Active alice with password `pw`.
async fn alice(e: &Env, pw: &str) -> TenantId {
    let t = e.admin.create_tenant("acme").await.unwrap().tenant_id;
    let u = e
        .admin
        .create_user(
            t,
            NewUser {
                login: LOGIN.to_owned(),
                kind: UserKind::Member,
                display_name: None,
            },
        )
        .await
        .unwrap();
    let link = e.admin.issue_setup_link(t, u.user_id).await.unwrap();
    let (_, f, _) = register_with(e, t, link.token.expose_secret(), pw, None).await;
    assert_eq!(f, StatusCode::NO_CONTENT);
    t
}

/// Password login: (status, headers, body) of login/finish.
async fn login(
    e: &Env,
    tenant: &str,
    login: &str,
    pw: &str,
) -> (StatusCode, axum::http::HeaderMap, Value) {
    let c = ClientLogin::<Suite>::start(&mut rand_core_06::OsRng, pw.as_bytes()).unwrap();
    let (s, h, v) = e
        .post(
            "/api/v2/auth/opaque/login/start",
            json!({"tenant": tenant, "login": login, "credential_request": b64(&c.message.serialize())}),
        )
        .await;
    if s != StatusCode::OK {
        return (s, h, v);
    }
    let cid = client_identifier(tenant, login);
    let k = ksf();
    let resp = CredentialResponse::<Suite>::deserialize(&unb64(&v["credential_response"])).unwrap();
    let fin = match c.state.finish(
        &mut rand_core_06::OsRng,
        pw.as_bytes(),
        resp,
        ClientLoginFinishParameters::new(
            Some(CONTEXT),
            Identifiers {
                client: Some(cid.as_bytes()),
                server: None,
            },
            Some(&k),
        ),
    ) {
        Ok(f) => f.message.serialize().to_vec(),
        Err(_) => vec![0u8; 64],
    };
    e.req(
        "POST",
        "/api/v2/auth/opaque/login/finish",
        None,
        Some(json!({"login_txn": v["login_txn"], "credential_finalization": b64(&fin)})),
        &[("user-agent", "TestAgent/1.0")],
    )
    .await
}

async fn exec(p: &DomainPool, sql: &'static str) {
    p.transaction(move |tx| {
        Box::pin(async move {
            sqlx::query(sql).execute(tx.conn()).await?;
            Ok(())
        })
    })
    .await
    .unwrap();
}

async fn scalar_i64(p: &DomainPool, sql: &'static str) -> i64 {
    p.read_snapshot(move |tx| {
        Box::pin(async move {
            Ok(sqlx::query(sql)
                .fetch_one(tx.conn())
                .await?
                .get::<i64, _>(0))
        })
    })
    .await
    .unwrap()
}

fn code_of(v: &Value) -> Option<&str> {
    v["errors"][0]["code"].as_str()
}

/// A problem body without the per-request members (for shape comparisons).
fn shape(v: &Value) -> Value {
    let mut v = v.clone();
    if let Some(o) = v.as_object_mut() {
        o.remove("instance");
        o.remove("trace_id");
        o.remove("request_id");
    }
    v
}

// ---------------------------------------------------------------------------------------------
// Software authenticator
// ---------------------------------------------------------------------------------------------

struct Authenticator {
    key: p256::ecdsa::SigningKey,
    cred_id: Vec<u8>,
    user_handle: Vec<u8>,
    counter: u32,
}

fn cbor(v: &ciborium::Value) -> Vec<u8> {
    let mut out = vec![];
    ciborium::into_writer(v, &mut out).unwrap();
    out
}

fn sha256(b: &[u8]) -> Vec<u8> {
    sha2::Sha256::digest(b).to_vec()
}

impl Authenticator {
    fn new() -> Self {
        let key = loop {
            if let Ok(k) =
                p256::ecdsa::SigningKey::from_slice(&cs_crypto::rand::bytes::<32>().unwrap())
            {
                break k;
            }
        };
        Self {
            key,
            cred_id: rand16().to_vec(),
            user_handle: vec![],
            counter: 0,
        }
    }

    fn client_data(kind: &str, challenge: &Value, origin: &str) -> Vec<u8> {
        json!({"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": false})
            .to_string()
            .into_bytes()
    }

    /// `navigator.credentials.create()` answer for `public_key` options.
    fn create(&mut self, pk: &Value, origin: &str, rp_id: &str) -> Value {
        self.user_handle = unb64(&pk["user"]["id"]);
        let p = self.key.verifying_key().to_encoded_point(false);
        use ciborium::Value as C;
        let cose = cbor(&C::Map(vec![
            (C::Integer(1.into()), C::Integer(2.into())),
            (C::Integer(3.into()), C::Integer((-7).into())),
            (C::Integer((-1).into()), C::Integer(1.into())),
            (C::Integer((-2).into()), C::Bytes(p.x().unwrap().to_vec())),
            (C::Integer((-3).into()), C::Bytes(p.y().unwrap().to_vec())),
        ]));
        let mut ad = sha256(rp_id.as_bytes());
        ad.push(0x45); // UP | UV | AT
        ad.extend_from_slice(&self.counter.to_be_bytes());
        ad.extend_from_slice(&[0u8; 16]);
        ad.extend_from_slice(&u16::try_from(self.cred_id.len()).unwrap().to_be_bytes());
        ad.extend_from_slice(&self.cred_id);
        ad.extend_from_slice(&cose);
        let att = cbor(&C::Map(vec![
            (C::Text("fmt".into()), C::Text("none".into())),
            (C::Text("attStmt".into()), C::Map(vec![])),
            (C::Text("authData".into()), C::Bytes(ad)),
        ]));
        let cd = Self::client_data("webauthn.create", &pk["challenge"], origin);
        json!({
            "id": b64(&self.cred_id), "rawId": b64(&self.cred_id), "type": "public-key",
            "response": {"attestationObject": b64(&att), "clientDataJSON": b64(&cd),
                         "transports": ["internal"]},
            "clientExtensionResults": {"credProps": {"rk": true}, "prf": {"enabled": true}}
        })
    }

    /// `navigator.credentials.get()` answer with an explicit counter.
    fn get_with(&self, pk: &Value, origin: &str, rp_id: &str, counter: u32) -> Value {
        let mut ad = sha256(rp_id.as_bytes());
        ad.push(0x05); // UP | UV
        ad.extend_from_slice(&counter.to_be_bytes());
        let cd = Self::client_data("webauthn.get", &pk["challenge"], origin);
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

    fn get(&mut self, pk: &Value) -> Value {
        self.counter += 1;
        self.get_with(pk, ORIGIN, DOMAIN, self.counter)
    }
}

/// Register a passkey for the session of `at`; returns the register/finish body.
async fn add_passkey(e: &Env, at: &str, a: &mut Authenticator) -> Value {
    let (s, _, v) = e
        .req(
            "POST",
            "/api/v2/auth/webauthn/register/start",
            Some(at),
            Some(json!({})),
            &[],
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        v["public_key"]["authenticatorSelection"]["residentKey"],
        "preferred"
    );
    let cred = a.create(&v["public_key"], ORIGIN, DOMAIN);
    let (s, _, p) = e
        .req(
            "POST",
            "/api/v2/auth/webauthn/register/finish",
            Some(at),
            Some(json!({"registration_txn": v["registration_txn"], "credential": cred, "label": "Laptop"})),
            &[],
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{p}");
    p
}

/// Run `webauthn/assert` for an MFA `auth_txn` with a credential built by `f`.
async fn mfa_assert(
    e: &Env,
    auth_txn: &Value,
    f: impl FnOnce(&Value) -> Value,
) -> (StatusCode, axum::http::HeaderMap, Value) {
    let (s, _, v) = e
        .post(
            "/api/v2/auth/webauthn/assert/start",
            json!({"auth_txn": auth_txn}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let cred = f(&v["public_key"]);
    e.post(
        "/api/v2/auth/webauthn/assert/finish",
        json!({"assert_txn": v["assert_txn"], "credential": cred}),
    )
    .await
}

// ---------------------------------------------------------------------------------------------
// Idempotency helpers
// ---------------------------------------------------------------------------------------------

/// A request returning the raw body bytes (byte-identical replay checks).
async fn raw(
    e: &Env,
    method: &str,
    path: &str,
    auth: Option<&str>,
    body: Option<&Value>,
    extra: &[(&str, &str)],
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let mut b = Request::builder().method(method).uri(path);
    if let Some(a) = auth {
        let v = if a.contains(' ') {
            a.to_owned()
        } else {
            format!("Bearer {a}")
        };
        b = b.header(header::AUTHORIZATION, v);
    }
    for (k, v) in extra {
        b = b.header(*k, *v);
    }
    let body = match body {
        Some(v) => {
            b = b.header(header::CONTENT_TYPE, "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    let r = e.app.clone().oneshot(b.body(body).unwrap()).await.unwrap();
    let (s, h) = (r.status(), r.headers().clone());
    (
        s,
        h,
        r.into_body().collect().await.unwrap().to_bytes().to_vec(),
    )
}

fn key(k: &str) -> [(&str, &str); 1] {
    [("idempotency-key", k)]
}

fn json_of(b: &[u8]) -> Value {
    serde_json::from_slice(b).unwrap()
}

fn cookie(h: &axum::http::HeaderMap) -> Option<String> {
    h.get(header::SET_COOKIE)
        .map(|v| v.to_str().unwrap().to_owned())
}

/// Every stored response (CBOR) of the identity domain.
async fn stored(p: &DomainPool) -> Vec<Vec<u8>> {
    p.read_snapshot(|tx| {
        Box::pin(async move {
            Ok(sqlx::query_scalar::<_, Vec<u8>>(
                "SELECT response FROM idempotency_records WHERE response IS NOT NULL",
            )
            .fetch_all(tx.conn())
            .await?)
        })
    })
    .await
    .unwrap()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// No stored row contains any of `secrets` in plaintext.
async fn assert_sealed(p: &DomainPool, secrets: &[&str]) {
    let rows = stored(p).await;
    assert!(!rows.is_empty());
    for r in &rows {
        for s in secrets {
            assert!(
                !contains(r, s.as_bytes()),
                "plaintext bearer in a stored row"
            );
        }
    }
}

/// A user `login` in tenant `t` with password `pw`.
async fn user(e: &Env, t: TenantId, login: &str, pw: &str) {
    let u = e
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
    let link = e.admin.issue_setup_link(t, u.user_id).await.unwrap();
    let mut rng = rand_core_06::OsRng;
    let c = ClientRegistration::<Suite>::start(&mut rng, pw.as_bytes()).unwrap();
    let (s, _, v) = e
        .post(
            "/api/v2/auth/opaque/register/start",
            json!({"grant": link.token.expose_secret(), "login": login, "registration_request": b64(&c.message.serialize())}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let resp =
        RegistrationResponse::<Suite>::deserialize(&unb64(&v["registration_response"])).unwrap();
    let cid = client_identifier(&t.as_uuid().to_string(), login);
    let k = ksf();
    let fin = c
        .state
        .finish(
            &mut rng,
            pw.as_bytes(),
            resp,
            ClientRegistrationFinishParameters::new(
                Identifiers {
                    client: Some(cid.as_bytes()),
                    server: None,
                },
                Some(&k),
            ),
        )
        .unwrap();
    let (s, _, v) = e
        .post(
            "/api/v2/auth/opaque/register/finish",
            json!({"registration_txn": v["registration_txn"], "registration_upload": b64(&fin.message.serialize())}),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{v}");
}

/// `login/start` then the `login/finish` body (without sending it).
async fn login_finish_body(e: &Env, tenant: &str, login: &str, pw: &str) -> Value {
    let c = ClientLogin::<Suite>::start(&mut rand_core_06::OsRng, pw.as_bytes()).unwrap();
    let (s, _, v) = e
        .post(
            "/api/v2/auth/opaque/login/start",
            json!({"tenant": tenant, "login": login, "credential_request": b64(&c.message.serialize())}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let cid = client_identifier(tenant, login);
    let k = ksf();
    let resp = CredentialResponse::<Suite>::deserialize(&unb64(&v["credential_response"])).unwrap();
    let fin = c
        .state
        .finish(
            &mut rand_core_06::OsRng,
            pw.as_bytes(),
            resp,
            ClientLoginFinishParameters::new(
                Some(CONTEXT),
                Identifiers {
                    client: Some(cid.as_bytes()),
                    server: None,
                },
                Some(&k),
            ),
        )
        .unwrap();
    json!({"login_txn": v["login_txn"], "credential_finalization": b64(&fin.message.serialize())})
}

const LOGIN_FINISH: &str = "/api/v2/auth/opaque/login/finish";

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

/// opaque register/finish (204), webauthn/register/{start,finish}: same key + same body →
/// byte-identical replay and one effect; same key + other body → 422 `idempotency_mismatch`;
/// no key → unchanged behaviour (a second finish of the consumed txn fails).
#[tokio::test]
async fn replay_register_finish_and_webauthn_register() {
    let Some(e) = env().await else { return };
    let t = e.admin.create_tenant("acme").await.unwrap().tenant_id;
    let u = e
        .admin
        .create_user(
            t,
            NewUser {
                login: LOGIN.to_owned(),
                kind: UserKind::Member,
                display_name: None,
            },
        )
        .await
        .unwrap();
    let link = e.admin.issue_setup_link(t, u.user_id).await.unwrap();
    // register_with replays register/finish with the same key and asserts the same status.
    let (_, f, _) = register_with(&e, t, link.token.expose_secret(), "pw", Some("reg-1")).await;
    assert_eq!(f, StatusCode::NO_CONTENT);
    assert_eq!(
        scalar_i64(e.pool(), "SELECT count(*) FROM idempotency_records").await,
        1
    );
    let ts = t.as_uuid().to_string();
    let (_, _, v) = login(&e, &ts, LOGIN, "pw").await;
    let at = v["access_token"].as_str().unwrap().to_owned();

    let p = "/api/v2/auth/webauthn/register/start";
    let (s1, _, b1) = raw(&e, "POST", p, Some(&at), Some(&json!({})), &key("wa-s")).await;
    let (s2, _, b2) = raw(&e, "POST", p, Some(&at), Some(&json!({})), &key("wa-s")).await;
    assert_eq!((s1, s2), (StatusCode::OK, StatusCode::OK));
    assert_eq!(b1, b2, "register/start replay is byte-identical");
    let start = json_of(&b1);
    assert_sealed(e.pool(), &[start["registration_txn"].as_str().unwrap()]).await;

    let mut a = Authenticator::new();
    let cred = a.create(&start["public_key"], ORIGIN, DOMAIN);
    let body = json!({"registration_txn": start["registration_txn"], "credential": cred, "label": "Laptop"});
    let p = "/api/v2/auth/webauthn/register/finish";
    let (s1, h1, b1) = raw(&e, "POST", p, Some(&at), Some(&body), &key("wa-f")).await;
    let (s2, h2, b2) = raw(&e, "POST", p, Some(&at), Some(&body), &key("wa-f")).await;
    assert_eq!(
        (s1, s2),
        (StatusCode::OK, StatusCode::OK),
        "{}",
        json_of(&b1)
    );
    assert_eq!(b1, b2, "register/finish replay is byte-identical");
    assert_eq!(cookie(&h1), cookie(&h2));
    assert_eq!(
        scalar_i64(e.pool(), "SELECT count(*) FROM webauthn_credentials").await,
        1,
        "one effect"
    );
    // Same key, other body → 422 idempotency_mismatch.
    let mut other = body.clone();
    other["label"] = json!("Other");
    let (s, _, b) = raw(&e, "POST", p, Some(&at), Some(&other), &key("wa-f")).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json_of(&b)["code"], "idempotency_mismatch");
    // Without a key: unchanged behaviour (the txn is consumed).
    let (s, _, _) = raw(&e, "POST", p, Some(&at), Some(&body), &[]).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    e.t.cleanup().await;
}

/// login/start and login/finish (sealed §2.4, P1): the replay returns the same status, body
/// (access token included) and Set-Cookie; the row holds no plaintext token, refresh token or
/// txn; one session is created. After the access token's lifetime the replay is 401 and the
/// sweeper tombstones the payload in bounded batches (P2).
#[tokio::test]
async fn login_replay_sealed_expiry_and_tombstone() {
    let Some(e) = env().await else { return };
    let policy = SessionPolicy {
        access_ttl_secs: 3,
        ..SessionPolicy::default()
    };
    let e = e.with(policy, RateLimiter::local_only(generous()));
    let t = alice(&e, "pw").await;
    let ts = t.as_uuid().to_string();

    // login/start replay (sealed: it carries the login txn).
    let c = ClientLogin::<Suite>::start(&mut rand_core_06::OsRng, b"pw").unwrap();
    let sb =
        json!({"tenant": ts, "login": LOGIN, "credential_request": b64(&c.message.serialize())});
    let p = "/api/v2/auth/opaque/login/start";
    let (s1, _, b1) = raw(&e, "POST", p, None, Some(&sb), &key("ls")).await;
    let (s2, _, b2) = raw(&e, "POST", p, None, Some(&sb), &key("ls")).await;
    assert_eq!((s1, s2), (StatusCode::OK, StatusCode::OK));
    assert_eq!(b1, b2);
    assert_sealed(e.pool(), &[json_of(&b1)["login_txn"].as_str().unwrap()]).await;

    let fb = login_finish_body(&e, &ts, LOGIN, "pw").await;
    let (s1, h1, b1) = raw(&e, "POST", LOGIN_FINISH, None, Some(&fb), &key("lf")).await;
    let (s2, h2, b2) = raw(&e, "POST", LOGIN_FINISH, None, Some(&fb), &key("lf")).await;
    assert_eq!(
        (s1, s2),
        (StatusCode::OK, StatusCode::OK),
        "{}",
        json_of(&b1)
    );
    assert_eq!(
        b1, b2,
        "login/finish replay is byte-identical (deterministic re-sign)"
    );
    assert!(cookie(&h1).is_some());
    assert_eq!(cookie(&h1), cookie(&h2), "same Set-Cookie");
    let v = json_of(&b1);
    let at = v["access_token"].as_str().unwrap().to_owned();
    let rt = rt_of(&h1);
    assert_sealed(e.pool(), &[&at, &rt, fb["login_txn"].as_str().unwrap()]).await;
    // One session (plus the one alice's registration did not create).
    assert_eq!(
        scalar_i64(e.pool(), "SELECT count(*) FROM sessions").await,
        1
    );
    assert_eq!(
        scalar_i64(
            e.pool(),
            "SELECT count(*) FROM idempotency_records WHERE secret_expires_at IS NOT NULL"
        )
        .await,
        2,
        "login/start and login/finish are sealed with a deadline"
    );
    // The replayed token works.
    let (s, _, _) = e.req("GET", "/api/v2/me", Some(&at), None, &[]).await;
    assert_eq!(s, StatusCode::OK);

    // Two more sealed rows (login/start), then wait past every deadline (3 s token, 60 s txn
    // is longer: use the token's).
    for k in ["x1", "x2"] {
        let c = ClientLogin::<Suite>::start(&mut rand_core_06::OsRng, b"pw").unwrap();
        let sb = json!({"tenant": ts, "login": LOGIN, "credential_request": b64(&c.message.serialize())});
        let (s, _, _) = raw(&e, "POST", p, None, Some(&sb), &key(k)).await;
        assert_eq!(s, StatusCode::OK);
    }
    tokio::time::sleep(Duration::from_secs(4)).await;
    let (s, h, b) = raw(&e, "POST", LOGIN_FINISH, None, Some(&fb), &key("lf")).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "expired sealed result");
    assert_eq!(json_of(&b)["code"], "unauthenticated");
    assert!(cookie(&h).is_none());
    // Sweep: the login/finish row is due; force the start rows due as well, then sweep in
    // batches of 1, at most 2 batches per run.
    exec(
        e.pool(),
        "UPDATE idempotency_records SET secret_expires_at = now() - interval '1 second' \
         WHERE secret_expires_at IS NOT NULL",
    )
    .await;
    let before = stored(e.pool()).await;
    assert_eq!(
        cs_identity::idem::sweep_expired_secrets(e.pool(), 1, 2).await,
        2
    );
    assert_eq!(
        scalar_i64(
            e.pool(),
            "SELECT count(*) FROM idempotency_records WHERE secret_expires_at IS NOT NULL"
        )
        .await,
        2,
        "bounded: two rows per run"
    );
    assert_eq!(
        cs_identity::idem::sweep_expired_secrets(e.pool(), 1, 10).await,
        2
    );
    let after = stored(e.pool()).await;
    let tomb = after.iter().min_by_key(|r| r.len()).unwrap().clone();
    for r in &after {
        assert_eq!(r, &tomb, "every sealed payload is a tombstone");
        for b in &before {
            if b != &tomb {
                assert!(!contains(r, &b[b.len() - 32..]), "no ciphertext remains");
            }
        }
    }
    let (s, _, b) = raw(&e, "POST", LOGIN_FINISH, None, Some(&fb), &key("lf")).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "tombstone → 401");
    assert_eq!(json_of(&b)["code"], "unauthenticated");
    e.t.cleanup().await;
}

/// P1: a replay whose stored `kid` can no longer sign is 401; fresh sign-ins use the new key.
#[tokio::test]
async fn replay_with_unusable_kid_is_unauthenticated() {
    let Some(e) = env().await else { return };
    let t = alice(&e, "pw").await;
    let ts = t.as_uuid().to_string();
    let fb = login_finish_body(&e, &ts, LOGIN, "pw").await;
    let (s, _, b) = raw(&e, "POST", LOGIN_FINISH, None, Some(&fb), &key("k1")).await;
    assert_eq!(s, StatusCode::OK);
    let kid = {
        let at = json_of(&b)["access_token"].as_str().unwrap().to_owned();
        let h = at.split('.').next().unwrap().to_owned();
        json_of(&URL_SAFE_NO_PAD.decode(h).unwrap())["kid"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    assert!(kid.ends_with("@v1"), "{kid}");
    e.kms.rotate(kid.split('@').next().unwrap()).await.unwrap();
    e.deny.store(true, Ordering::SeqCst);
    let (s, _, b2) = raw(&e, "POST", LOGIN_FINISH, None, Some(&fb), &key("k1")).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(json_of(&b2)["code"], "unauthenticated");
    // A fresh sign-in signs with v2.
    let (s, _, v) = login(&e, &ts, LOGIN, "pw").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    e.t.cleanup().await;
}

/// POST /me/recovery-codes (sealed, 24 h) and recovery/start with a code (grant, sealed,
/// 15 min): byte-identical replays, no plaintext code or grant in any row, one effect for
/// concurrent same-key requests.
#[tokio::test]
async fn recovery_codes_and_grant_replay_concurrent_one_effect() {
    let Some(e) = env().await else { return };
    let t = alice(&e, "pw").await;
    let ts = t.as_uuid().to_string();
    let (_, _, v) = login(&e, &ts, LOGIN, "pw").await;
    let at = v["access_token"].as_str().unwrap().to_owned();
    let p = "/api/v2/me/recovery-codes";
    // Four concurrent requests with one key: one set generated, all answers identical.
    let kc = key("codes");
    let futs = (0..4).map(|_| raw(&e, "POST", p, Some(&at), None, &kc));
    let rs = futures::future::join_all(futs).await;
    for (s, _, b) in &rs {
        assert_eq!(*s, StatusCode::OK, "{}", String::from_utf8_lossy(b));
        assert_eq!(b, &rs[0].2, "same codes for every same-key request");
    }
    assert_eq!(
        scalar_i64(
            e.pool(),
            "SELECT count(DISTINCT set_version) FROM recovery_code_entries"
        )
        .await,
        1
    );
    assert_eq!(
        scalar_i64(
            e.pool(),
            "SELECT max(set_version)::bigint FROM recovery_code_entries"
        )
        .await,
        1,
        "one effect"
    );
    let codes = json_of(&rs[0].2);
    let code = codes["codes"][0].as_str().unwrap().to_owned();
    let all: Vec<String> = codes["codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_owned())
        .collect();
    let refs: Vec<&str> = all.iter().map(String::as_str).collect();
    assert_sealed(e.pool(), &refs).await;

    let body = json!({"tenant": ts, "login": LOGIN, "method": "recovery_code", "code": code});
    let p = "/api/v2/auth/recovery/start";
    let (s1, _, b1) = raw(&e, "POST", p, None, Some(&body), &key("rs")).await;
    let (s2, _, b2) = raw(&e, "POST", p, None, Some(&body), &key("rs")).await;
    assert_eq!(
        (s1, s2),
        (StatusCode::OK, StatusCode::OK),
        "{}",
        json_of(&b1)
    );
    assert_eq!(b1, b2, "grant replay is byte-identical");
    let g = json_of(&b1);
    assert_eq!(g["state"], "granted");
    assert_eq!(
        scalar_i64(e.pool(), "SELECT count(*) FROM recovery_requests").await,
        1,
        "one grant"
    );
    assert_sealed(e.pool(), &[g["grant"].as_str().unwrap(), &code]).await;
    // Same key, other body → 422.
    let mut other = body.clone();
    other["code"] = json!(all[1]);
    let (s, _, b) = raw(&e, "POST", p, None, Some(&other), &key("rs")).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json_of(&b)["code"], "idempotency_mismatch");
    e.t.cleanup().await;
}

/// P3: the same key and body for an unknown account gives the same shape as for a known one,
/// on the first answer and on the replay (login/start, recovery/start device approval and
/// email).
#[tokio::test]
async fn pre_auth_replays_do_not_enumerate() {
    let Some(e) = env().await else { return };
    let t = alice(&e, "pw").await;
    let ts = t.as_uuid().to_string();
    let keys_of = |v: &Value| -> Vec<String> {
        let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
        k.sort();
        k
    };
    for login in [LOGIN, "nobody@acme.test"] {
        let c = ClientLogin::<Suite>::start(&mut rand_core_06::OsRng, b"pw").unwrap();
        let sb = json!({"tenant": ts, "login": login, "credential_request": b64(&c.message.serialize())});
        let k = format!("ls-{login}");
        let p = "/api/v2/auth/opaque/login/start";
        let (s1, _, b1) = raw(&e, "POST", p, None, Some(&sb), &key(&k)).await;
        let (s2, _, b2) = raw(&e, "POST", p, None, Some(&sb), &key(&k)).await;
        assert_eq!((s1, s2), (StatusCode::OK, StatusCode::OK));
        assert_eq!(b1, b2);
        assert_eq!(
            keys_of(&json_of(&b1)),
            ["credential_response", "ksf_params", "login_txn"]
        );
        for (method, status) in [
            ("device_approval", StatusCode::ACCEPTED),
            ("email", StatusCode::ACCEPTED),
        ] {
            let body = json!({"tenant": ts, "login": login, "method": method});
            let k = format!("rs-{method}-{login}");
            let p = "/api/v2/auth/recovery/start";
            let (s1, _, b1) = raw(&e, "POST", p, None, Some(&body), &key(&k)).await;
            let (s2, _, b2) = raw(&e, "POST", p, None, Some(&body), &key(&k)).await;
            assert_eq!((s1, s2), (status, status), "{method} {login}");
            assert_eq!(b1, b2, "{method} {login}");
            let v = json_of(&b1);
            assert_eq!(v["state"], "pending");
            if method == "device_approval" {
                assert_eq!(keys_of(&v), ["recovery_txn", "state"]);
                assert_sealed(e.pool(), &[v["recovery_txn"].as_str().unwrap()]).await;
            } else {
                assert_eq!(keys_of(&v), ["state"]);
            }
        }
    }
    // Known and unknown both left exactly one record per request.
    assert_eq!(
        scalar_i64(e.pool(), "SELECT count(*) FROM idempotency_records").await,
        6
    );
    e.t.cleanup().await;
}

/// P4: a logout retried with its key after the session is revoked replays 204 + cookie
/// clear; another digest, an unknown key, an expired access token or a DPoP mismatch are
/// 401. DELETE /me/sessions/{own sid} replays the same way; another sid does not.
#[tokio::test]
async fn logout_and_session_delete_replay_after_revocation() {
    let Some(e) = env().await else { return };
    let policy = SessionPolicy {
        access_ttl_secs: 4,
        ..SessionPolicy::default()
    };
    let e = e.with(policy, RateLimiter::local_only(generous()));
    let t = alice(&e, "pw").await;
    let ts = t.as_uuid().to_string();
    let (_, _, v) = login(&e, &ts, LOGIN, "pw").await;
    let at = v["access_token"].as_str().unwrap().to_owned();
    let p = "/api/v2/auth/logout";
    let (s1, h1, b1) = raw(&e, "POST", p, Some(&at), None, &key("lo")).await;
    assert_eq!(s1, StatusCode::NO_CONTENT);
    let clear = cookie(&h1).unwrap();
    assert!(clear.contains("Max-Age=0"));
    let (s2, h2, b2) = raw(&e, "POST", p, Some(&at), None, &key("lo")).await;
    assert_eq!(s2, StatusCode::NO_CONTENT, "replay after revocation");
    assert_eq!(cookie(&h2).as_deref(), Some(clear.as_str()));
    assert_eq!(b1, b2);
    // No record for this key → 401; no key → 401 (rev 14).
    let (s, _, _) = raw(&e, "POST", p, Some(&at), None, &key("other")).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _, _) = raw(&e, "POST", p, Some(&at), None, &[]).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // Same key, other digest (another route) → 401, not 422.
    let sid = claims_of(&at)["sid"].as_str().unwrap().to_owned();
    let dp = format!("/api/v2/me/sessions/{sid}");
    let (s, _, b) = raw(&e, "DELETE", &dp, Some(&at), None, &key("lo")).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(json_of(&b)["code"], "unauthenticated");

    // DELETE /me/sessions/{own sid}: replayable; DELETE of another sid after revocation: not.
    let (_, _, v) = login(&e, &ts, LOGIN, "pw").await;
    let at2 = v["access_token"].as_str().unwrap().to_owned();
    let (_, _, v) = login(&e, &ts, LOGIN, "pw").await;
    let other_sid = claims_of(v["access_token"].as_str().unwrap())["sid"]
        .as_str()
        .unwrap()
        .to_owned();
    let sid2 = claims_of(&at2)["sid"].as_str().unwrap().to_owned();
    let own = format!("/api/v2/me/sessions/{sid2}");
    let (s1, h1, _) = raw(&e, "DELETE", &own, Some(&at2), None, &key("del")).await;
    assert_eq!(s1, StatusCode::NO_CONTENT);
    let (s2, h2, _) = raw(&e, "DELETE", &own, Some(&at2), None, &key("del")).await;
    assert_eq!(s2, StatusCode::NO_CONTENT, "own session replay");
    assert_eq!(cookie(&h1), cookie(&h2));
    assert!(cookie(&h2).unwrap().contains("Max-Age=0"));
    let oth = format!("/api/v2/me/sessions/{other_sid}");
    let (s, _, _) = raw(&e, "DELETE", &oth, Some(&at2), None, &key("del-o")).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "another sid is not replayable");

    // Expired access token → 401 even with the right key.
    tokio::time::sleep(Duration::from_secs(5)).await;
    let (s, _, _) = raw(&e, "POST", p, Some(&at), None, &key("lo")).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "expired JWT");
    e.t.cleanup().await;
}

/// P4 with a DPoP-bound session: the replay needs a proof of the bound key.
#[tokio::test]
async fn logout_replay_requires_dpop_binding() {
    let Some(e) = env().await else { return };
    let t = alice(&e, "pw").await;
    let ts = t.as_uuid().to_string();
    let k = ed25519_dalek::SigningKey::from_bytes(&cs_crypto::rand::bytes::<32>().unwrap());
    let fb = login_finish_body(&e, &ts, LOGIN, "pw").await;
    let proof = dpop(&k, "POST", LOGIN_FINISH, None);
    let (s, _, b) = raw(
        &e,
        "POST",
        LOGIN_FINISH,
        None,
        Some(&fb),
        &[("dpop", &proof)],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{}", json_of(&b));
    let at = json_of(&b)["access_token"].as_str().unwrap().to_owned();
    let p = "/api/v2/auth/logout";
    let auth = format!("DPoP {at}");
    let pr = dpop(&k, "POST", p, Some(&at));
    let (s, _, _) = raw(
        &e,
        "POST",
        p,
        Some(&auth),
        None,
        &[("idempotency-key", "lo"), ("dpop", &pr)],
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    // Bearer for a bound token, or a proof of another key → 401.
    let (s, _, _) = raw(&e, "POST", p, Some(&at), None, &key("lo")).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let k2 = ed25519_dalek::SigningKey::from_bytes(&cs_crypto::rand::bytes::<32>().unwrap());
    let pr = dpop(&k2, "POST", p, Some(&at));
    let (s, _, _) = raw(
        &e,
        "POST",
        p,
        Some(&auth),
        None,
        &[("idempotency-key", "lo"), ("dpop", &pr)],
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "DPoP mismatch");
    // The right proof replays.
    let pr = dpop(&k, "POST", p, Some(&at));
    let (s, h, _) = raw(
        &e,
        "POST",
        p,
        Some(&auth),
        None,
        &[("idempotency-key", "lo"), ("dpop", &pr)],
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(cookie(&h).unwrap().contains("Max-Age=0"));
    e.t.cleanup().await;
}

/// An Ed25519 DPoP proof (RFC 9449) for `path`.
fn dpop(k: &ed25519_dalek::SigningKey, htm: &str, path: &str, at: Option<&str>) -> String {
    use ed25519_dalek::Signer as _;
    let h = json!({"typ": "dpop+jwt", "alg": "EdDSA",
                   "jwk": {"kty": "OKP", "crv": "Ed25519", "x": b64(k.verifying_key().as_bytes())}});
    let mut c = json!({"jti": b64(&rand16()), "htm": htm, "htu": format!("https://{DOMAIN}{path}"),
                       "iat": cs_identity::auth::unix_now()});
    if let Some(at) = at {
        c["ath"] = json!(cs_identity::dpop::ath(at));
    }
    let input = format!(
        "{}.{}",
        b64(h.to_string().as_bytes()),
        b64(c.to_string().as_bytes())
    );
    format!("{input}.{}", b64(&k.sign(input.as_bytes()).to_bytes()))
}
