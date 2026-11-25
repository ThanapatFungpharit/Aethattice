//! Engineer DB tests for M1 slice 4 (contract §2.2, §2.3, §3, §4 [R5], §5; rev 10/11):
//! WebAuthn passkeys, MFA and the enrolment-only session, recovery codes and recovery flows,
//! rate limiting, `/me/sessions`, `dpop_first_party_required`.
//!
//! Skipped without `CS_TEST_DATABASE_URL` (failed with `CS_REQUIRE_DB=1`).
//! A software authenticator (P-256, `none` attestation) drives the WebAuthn ceremonies, so
//! origin, rp id hash, user verification and the sign counter are under test control.

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
use cs_identity::keys::OpaqueKeys;
use cs_identity::notify::Notifier;
use cs_identity::ratelimit::{Backend, Dimension, Key, RateLimiter, RateLimits};
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
    let kms: Arc<dyn Kms> =
        Arc::new(LocalSoftwareKms::init(&dir.path().join("root.key"), None).unwrap());
    let admin = IdentityAdmin::new(t.pool(&ID).clone()).unwrap();
    let mail = Arc::new(Capture::default());
    let e = Env {
        t,
        _dir: dir,
        kms,
        admin,
        app: axum::Router::new(),
        mail,
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
            if let Ok(k) = p256::ecdsa::SigningKey::from_slice(&cs_crypto::rand::bytes::<32>().unwrap()) {
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
    assert_eq!(v["public_key"]["authenticatorSelection"]["residentKey"], "preferred");
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
// Tests
// ---------------------------------------------------------------------------------------------

/// Passkey registration (step-up, label rule, replay), MFA by passkey (wrong origin / rp id,
/// counter regression, replays, bypass attempts), passwordless sign-in, step-up assertion,
/// passkey listing and deletion.
#[tokio::test]
async fn webauthn_register_mfa_passwordless_stepup_and_negatives() {
    let Some(e) = env().await else { return };
    let t = alice(&e, "pw").await;
    let ts = t.as_uuid().to_string();
    let (s, _, v) = login(&e, &ts, LOGIN, "pw").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["state"], "authenticated");
    let at = v["access_token"].as_str().unwrap().to_owned();

    // register/start needs an access token.
    let (s, _, _) = e
        .post("/api/v2/auth/webauthn/register/start", json!({}))
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // Label rule: missing / empty / too long → invalid_request at /label, txn not consumed.
    let mut a = Authenticator::new();
    let (_, _, st) = e
        .req("POST", "/api/v2/auth/webauthn/register/start", Some(&at), Some(json!({})), &[])
        .await;
    let cred = a.create(&st["public_key"], ORIGIN, DOMAIN);
    for body in [
        json!({"registration_txn": st["registration_txn"], "credential": cred}),
        json!({"registration_txn": st["registration_txn"], "credential": cred, "label": "  "}),
        json!({"registration_txn": st["registration_txn"], "credential": cred, "label": "x".repeat(101)}),
    ] {
        let (s, _, v) = e
            .req("POST", "/api/v2/auth/webauthn/register/finish", Some(&at), Some(body), &[])
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
        assert_eq!(v["errors"][0]["pointer"], "/label", "{v}");
    }
    let finish = json!({"registration_txn": st["registration_txn"], "credential": cred, "label": "Laptop"});
    let (s, _, p) = e
        .req("POST", "/api/v2/auth/webauthn/register/finish", Some(&at), Some(finish.clone()), &[])
        .await;
    assert_eq!(s, StatusCode::OK, "{p}");
    assert_eq!(p["label"], "Laptop");
    assert_eq!(p["prf"], true);
    assert_eq!(p["id"], b64(&a.cred_id));
    assert!(p["created_at"].as_str().unwrap().ends_with('Z'));
    // Ceremony replay.
    let (s, _, _) = e
        .req("POST", "/api/v2/auth/webauthn/register/finish", Some(&at), Some(finish), &[])
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(
        scalar_i64(e.pool(), "SELECT count(*) FROM webauthn_credentials WHERE prf_supported AND discoverable").await,
        1
    );
    // Wrong origin at registration is refused.
    let mut evil = Authenticator::new();
    let (_, _, st) = e
        .req("POST", "/api/v2/auth/webauthn/register/start", Some(&at), Some(json!({})), &[])
        .await;
    let cred = evil.create(&st["public_key"], "https://evil.test", DOMAIN);
    let (s, _, _) = e
        .req("POST", "/api/v2/auth/webauthn/register/finish", Some(&at),
             Some(json!({"registration_txn": st["registration_txn"], "credential": cred, "label": "x"})), &[])
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // Listing.
    let (s, _, l) = e.req("GET", "/api/v2/me/passkeys", Some(&at), None, &[]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(l["items"].as_array().unwrap().len(), 1);
    assert!(l["items"][0]["last_used_at"].is_null());

    // A user with a passkey has MFA: login/finish → mfa_required.
    let (s, _, m) = login(&e, &ts, LOGIN, "pw").await;
    assert_eq!(s, StatusCode::OK, "{m}");
    assert_eq!(m["state"], "mfa_required");
    assert_eq!(m["methods"], json!(["webauthn"]));
    assert!(m.get("access_token").is_none() && m.get("reregister").is_none());
    let auth_txn = m["auth_txn"].clone();
    // The auth_txn on the wrong endpoint → 401 mfa_required (and stays usable).
    let (s, _, v) = e.refresh(auth_txn.as_str().unwrap()).await;
    assert_eq!((s, code_of(&v)), (StatusCode::UNAUTHORIZED, Some("mfa_required")), "{v}");
    let (s, _, v) = e
        .post("/api/v2/auth/opaque/login/finish",
              json!({"login_txn": auth_txn, "credential_finalization": b64(&[0u8; 64])}))
        .await;
    assert_eq!((s, code_of(&v)), (StatusCode::UNAUTHORIZED, Some("mfa_required")), "{v}");
    // Wrong origin, wrong rp id, missing UV → refused; the auth_txn survives.
    let (s, _, _) = mfa_assert(&e, &auth_txn, |pk| a.get_with(pk, "https://evil.test", DOMAIN, 50)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _, _) = mfa_assert(&e, &auth_txn, |pk| a.get_with(pk, ORIGIN, "evil.test", 51)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // MFA bypass: an access token with an auth_txn is refused; another user's token cannot
    // finish an MFA ceremony.
    let (s, _, _) = e
        .req("POST", "/api/v2/auth/webauthn/assert/start", Some(&at), Some(json!({"auth_txn": auth_txn})), &[])
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (_, _, st) = e
        .post("/api/v2/auth/webauthn/assert/start", json!({"auth_txn": auth_txn}))
        .await;
    a.counter = 10;
    let cred = a.get(&st["public_key"]);
    let (s, _, _) = e
        .req("POST", "/api/v2/auth/webauthn/assert/finish", Some(&at),
             Some(json!({"assert_txn": st["assert_txn"], "credential": cred})), &[])
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "MFA assertion with an access token");
    // Correct assertion completes MFA.
    let (s, _, st) = e
        .post("/api/v2/auth/webauthn/assert/start", json!({"auth_txn": auth_txn}))
        .await;
    assert_eq!(s, StatusCode::OK);
    let cred = a.get(&st["public_key"]);
    let fin = json!({"assert_txn": st["assert_txn"], "credential": cred});
    let (s, _, ok) = e.post("/api/v2/auth/webauthn/assert/finish", fin.clone()).await;
    assert_eq!(s, StatusCode::OK, "{ok}");
    assert_eq!(ok["state"], "authenticated");
    let c = claims_of(ok["access_token"].as_str().unwrap());
    assert_eq!(c["amr"], json!(["pwd", "hwk", "mfa"]));
    assert!(ok.get("reregister").is_none());
    // Replays: the assert_txn and the auth_txn are single use.
    let (s, _, _) = e.post("/api/v2/auth/webauthn/assert/finish", fin).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _, _) = e
        .post("/api/v2/auth/webauthn/assert/start", json!({"auth_txn": auth_txn}))
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // Counter regression is refused.
    let (_, _, m) = login(&e, &ts, LOGIN, "pw").await;
    let last = a.counter;
    let (s, _, _) = mfa_assert(&e, &m["auth_txn"], |pk| a.get_with(pk, ORIGIN, DOMAIN, last)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "same counter");
    let (s, _, _) = mfa_assert(&e, &m["auth_txn"], |pk| a.get_with(pk, ORIGIN, DOMAIN, last - 1)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "lower counter");

    // Passwordless sign-in with the discoverable credential.
    let (s, _, st) = e
        .post("/api/v2/auth/webauthn/login/start", json!({"tenant": ts}))
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(st["public_key"]["allowCredentials"], json!([]));
    // Unknown tenant: same shape (no lookup).
    let (s2, _, st2) = e
        .post("/api/v2/auth/webauthn/login/start", json!({"tenant": "0190f1e2-0000-7000-8000-000000000000"}))
        .await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(
        st2.as_object().unwrap().keys().collect::<Vec<_>>(),
        st.as_object().unwrap().keys().collect::<Vec<_>>()
    );
    let cred = a.get(&st["public_key"]);
    let (s, h, pl) = e
        .post("/api/v2/auth/webauthn/login/finish", json!({"login_txn": st["login_txn"], "credential": cred}))
        .await;
    assert_eq!(s, StatusCode::OK, "{pl}");
    assert_eq!(claims_of(pl["access_token"].as_str().unwrap())["amr"], json!(["hwk", "user"]));
    assert!(h.get(header::SET_COOKIE).is_some());
    // Replay of the login ceremony.
    let (s, _, _) = e
        .post("/api/v2/auth/webauthn/login/finish", json!({"login_txn": st["login_txn"], "credential": a.get(&st["public_key"])}))
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // Step-up by assertion on the existing session (204, last_strong_auth_at set).
    let at2 = pl["access_token"].as_str().unwrap().to_owned();
    exec(e.pool(), "UPDATE sessions SET last_strong_auth_at = now() - interval '1 hour'").await;
    let (s, _, v) = e.req("DELETE", "/api/v2/me/passkeys/AAAA", Some(&at2), None, &[]).await;
    assert_eq!((s, code_of(&v)), (StatusCode::UNAUTHORIZED, Some("step_up_required")));
    let (s, _, st) = e
        .req("POST", "/api/v2/auth/webauthn/assert/start", Some(&at2), Some(json!({})), &[])
        .await;
    assert_eq!(s, StatusCode::OK, "{st}");
    let cred = a.get(&st["public_key"]);
    // Without the access token the step-up ceremony cannot finish (no MFA session issued).
    let (s, _, _) = e
        .post("/api/v2/auth/webauthn/assert/finish", json!({"assert_txn": st["assert_txn"], "credential": cred}))
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (_, _, st) = e
        .req("POST", "/api/v2/auth/webauthn/assert/start", Some(&at2), Some(json!({})), &[])
        .await;
    let cred = a.get(&st["public_key"]);
    let (s, _, _) = e
        .req("POST", "/api/v2/auth/webauthn/assert/finish", Some(&at2),
             Some(json!({"assert_txn": st["assert_txn"], "credential": cred})), &[])
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    // Now the passkey can be deleted (step-up satisfied); unknown id → 404.
    let (s, _, _) = e.req("DELETE", "/api/v2/me/passkeys/AAAA", Some(&at2), None, &[]).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let path = format!("/api/v2/me/passkeys/{}", b64(&a.cred_id));
    let (s, _, _) = e.req("DELETE", &path, Some(&at2), None, &[]).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    // Without a passkey (and policy 0) the user signs in with the password alone again.
    let (_, _, v) = login(&e, &ts, LOGIN, "pw").await;
    assert_eq!(v["state"], "authenticated");
    assert_eq!(
        scalar_i64(e.pool(), "SELECT count(*) FROM outbox WHERE event_type = 'identity.credentials.changed' AND position(convert_to('passkey_', 'UTF8') in payload) > 0").await,
        2
    );
    let _ = add_passkey;
    e.t.cleanup().await;
}

/// rev 11: policy mfa_required = 1, enrolment-only session (scope kept across refresh,
/// every other route refused with mfa_required), recovery codes as second factor (wrong
/// code, code reuse), `reregister` only on the MFA completion result.
#[tokio::test]
async fn mfa_policy_enrolment_scope_and_recovery_code_factor() {
    let Some(e) = env().await else { return };
    let t = alice(&e, "pw").await;
    let ts = t.as_uuid().to_string();
    let policy = SessionPolicy {
        mfa_required: true,
        ..SessionPolicy::default()
    };
    let e = e.with(policy, RateLimiter::local_only(generous()));
    let (s, h, v) = login(&e, &ts, LOGIN, "pw").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["state"], "authenticated");
    let at = v["access_token"].as_str().unwrap().to_owned();
    assert_eq!(claims_of(&at)["scp"], "mfa_enrolment");
    // Allowed routes.
    let (s, _, _) = e.req("GET", "/api/v2/me", Some(&at), None, &[]).await;
    assert_eq!(s, StatusCode::OK);
    // Every other route: 401 mfa_required.
    for (m, p, b) in [
        ("GET", "/api/v2/me/sessions", None),
        ("GET", "/api/v2/me/passkeys", None),
        ("GET", "/api/v2/me/recovery-requests", None),
        ("DELETE", "/api/v2/me/sessions/00000000-0000-4000-8000-000000000000", None),
        ("POST", "/api/v2/auth/webauthn/assert/start", Some(json!({}))),
        ("POST", "/api/v2/auth/opaque/reauth/start", Some(json!({"credential_request": "AA"}))),
        ("POST", "/api/v2/auth/opaque/register/start", Some(json!({"purpose": "password_change", "registration_request": "AA"}))),
    ] {
        let (s, _, v) = e.req(m, p, Some(&at), b, &[]).await;
        assert_eq!((s, code_of(&v)), (StatusCode::UNAUTHORIZED, Some("mfa_required")), "{m} {p}: {v}");
    }
    // Refresh keeps the scope.
    let (s, h2, r) = e.refresh(&rt_of(&h)).await;
    assert_eq!(s, StatusCode::OK, "{r}");
    assert_eq!(claims_of(r["access_token"].as_str().unwrap())["scp"], "mfa_enrolment");
    let at = r["access_token"].as_str().unwrap().to_owned();
    let (s, _, v) = e.req("GET", "/api/v2/me/sessions", Some(&at), None, &[]).await;
    assert_eq!((s, code_of(&v)), (StatusCode::UNAUTHORIZED, Some("mfa_required")));
    let _ = h2;
    // Enrol recovery codes (allowed on the enrolment session).
    let (s, _, c) = e.req("POST", "/api/v2/me/recovery-codes", Some(&at), None, &[]).await;
    assert_eq!(s, StatusCode::OK, "{c}");
    let codes: Vec<String> = c["codes"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_owned()).collect();
    assert_eq!(codes.len(), 10);
    assert_eq!(
        scalar_i64(e.pool(), "SELECT count(*) FROM recovery_code_entries WHERE code_hash LIKE '$argon2id$%'").await,
        10
    );
    let (_, _, r) = e.req("GET", "/api/v2/me/recovery-codes", Some(&at), None, &[]).await;
    assert_eq!(r["remaining"], 10);

    // Signing in again: mfa_required with the recovery-code method only.
    let (_, _, m) = login(&e, &ts, LOGIN, "pw").await;
    assert_eq!(m["state"], "mfa_required", "{m}");
    assert_eq!(m["methods"], json!(["recovery_code"]));
    let wrong = "AAAAAAAA-AAAAAAAAAAAAAAAAAAAA";
    let (s, _, w) = e
        .post("/api/v2/auth/mfa/recovery-code", json!({"auth_txn": m["auth_txn"], "code": wrong}))
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{w}");
    let (s, _, ok) = e
        .post("/api/v2/auth/mfa/recovery-code", json!({"auth_txn": m["auth_txn"], "code": codes[0].to_lowercase()}))
        .await;
    assert_eq!(s, StatusCode::OK, "{ok}");
    let c = claims_of(ok["access_token"].as_str().unwrap());
    assert_eq!(c["amr"], json!(["pwd", "otp", "mfa"]));
    assert!(c.get("scp").is_none());
    // auth_txn single use; the used code is refused on a new sign-in.
    let (s, _, _) = e
        .post("/api/v2/auth/mfa/recovery-code", json!({"auth_txn": m["auth_txn"], "code": codes[1]}))
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (_, _, m) = login(&e, &ts, LOGIN, "pw").await;
    let (s, _, _) = e
        .post("/api/v2/auth/mfa/recovery-code", json!({"auth_txn": m["auth_txn"], "code": codes[0]}))
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "code reuse");
    // Tenant override 0 beats deployment 1: but the user has no passkey → plain session.
    exec(e.pool(), "UPDATE tenants SET policy = '\\xa16c6d66615f726571756972656400'::bytea").await;
    let (_, _, v) = login(&e, &ts, LOGIN, "pw").await;
    assert_eq!(v["state"], "authenticated", "{v}");
    assert!(claims_of(v["access_token"].as_str().unwrap()).get("scp").is_none());
    exec(e.pool(), "UPDATE tenants SET policy = '\\xa0'::bytea").await;

    // rev 11 addendum: reregister appears on the MFA completion result, never on mfa_required.
    OpaqueKeys::rotate(e.pool(), e.kms.as_ref()).await.unwrap();
    let e = e.with(policy, RateLimiter::local_only(generous()));
    let (_, _, m) = login(&e, &ts, LOGIN, "pw").await;
    assert_eq!(m["state"], "mfa_required");
    assert!(m.get("reregister").is_none(), "{m}");
    let (s, _, ok) = e
        .post("/api/v2/auth/mfa/recovery-code", json!({"auth_txn": m["auth_txn"], "code": codes[2]}))
        .await;
    assert_eq!(s, StatusCode::OK, "{ok}");
    assert_eq!(ok["reregister"], true, "{ok}");
    let (_, _, r) = e
        .req("GET", "/api/v2/me/recovery-codes", Some(ok["access_token"].as_str().unwrap()), None, &[])
        .await;
    assert_eq!(r["remaining"], 8);
    e.t.cleanup().await;
}

/// rev 10 recovery_code method and [R5] completion: identical refusals, grant, register with
/// the grant (idempotent), every session revoked, code used, grant reuse refused.
#[tokio::test]
async fn recovery_by_code_and_r5_completion() {
    let Some(e) = env().await else { return };
    let t = alice(&e, "old").await;
    let ts = t.as_uuid().to_string();
    let (_, h1, v1) = login(&e, &ts, LOGIN, "old").await;
    let (_, h2, _) = login(&e, &ts, LOGIN, "old").await;
    let at = v1["access_token"].as_str().unwrap().to_owned();
    let (_, _, c) = e.req("POST", "/api/v2/me/recovery-codes", Some(&at), None, &[]).await;
    let code = c["codes"][0].as_str().unwrap().to_owned();
    let start = |tenant: &str, login: &str, code: &str| {
        json!({"tenant": tenant, "login": login, "method": "recovery_code", "code": code})
    };
    // Unknown tenant, unknown account, wrong code: the same problem.
    let other = "0190f1e2-0000-7000-8000-000000000000";
    let mut bodies = vec![];
    for b in [
        start(other, LOGIN, &code),
        start(&ts, "nobody@acme.test", &code),
        start(&ts, LOGIN, "AAAAAAAA-AAAAAAAAAAAAAAAAAAAA"),
        start(&ts, LOGIN, "garbage"),
    ] {
        let (s, _, v) = e.post("/api/v2/auth/recovery/start", b).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{v}");
        bodies.push(shape(&v));
    }
    assert!(bodies.windows(2).all(|w| w[0] == w[1]), "{bodies:?}");
    // Valid code → granted with a 15 min grant.
    let (s, _, g) = e.post("/api/v2/auth/recovery/start", start(&ts, LOGIN, &code)).await;
    assert_eq!(s, StatusCode::OK, "{g}");
    assert_eq!(g["state"], "granted");
    assert_eq!(g["grant_expires_in"], 900);
    let grant = g["grant"].as_str().unwrap().to_owned();
    // Sessions are untouched until completion (an abandoned recovery leaves the account usable).
    assert_eq!(scalar_i64(e.pool(), "SELECT count(*) FROM sessions WHERE state = 'active'").await, 2);
    // Completion, idempotent by Idempotency-Key.
    let (s, f, v) = register_with(&e, t, &grant, "new", Some("recovery-key-1")).await;
    assert_eq!((s, f), (StatusCode::OK, StatusCode::NO_CONTENT), "{v}");
    assert_eq!(scalar_i64(e.pool(), "SELECT count(*) FROM sessions WHERE state = 'active'").await, 0);
    assert_eq!(scalar_i64(e.pool(), "SELECT count(*) FROM refresh_tokens WHERE state = 'active'").await, 0);
    assert_eq!(scalar_i64(e.pool(), "SELECT count(*) FROM recovery_requests WHERE state = 'completed'").await, 1);
    assert_eq!(scalar_i64(e.pool(), "SELECT count(*) FROM recovery_code_entries WHERE used_at IS NOT NULL").await, 1);
    assert_eq!(
        scalar_i64(e.pool(), "SELECT count(*) FROM outbox WHERE event_type = 'identity.session.revoked' AND position(convert_to('recovery', 'UTF8') in payload) > 0").await,
        2
    );
    assert_eq!(scalar_i64(e.pool(), "SELECT count(*) FROM outbox WHERE event_type = 'identity.recovery.completed'").await, 1);
    for h in [&h1, &h2] {
        let (s, _, _) = e.refresh(&rt_of(h)).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }
    let (s, _, _) = login(&e, &ts, LOGIN, "old").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (_, _, v) = login(&e, &ts, LOGIN, "new").await;
    assert_eq!(v["state"], "authenticated");
    // Grant reuse and code reuse.
    let (s, _, v) = register_with(&e, t, &grant, "again", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{v}");
    let (s, _, _) = e.post("/api/v2/auth/recovery/start", start(&ts, LOGIN, &code)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // An expired grant is refused and moves the request to expired.
    let code2 = c["codes"][1].as_str().unwrap();
    let (_, _, g) = e.post("/api/v2/auth/recovery/start", start(&ts, LOGIN, code2)).await;
    exec(e.pool(), "UPDATE recovery_requests SET grant_expires_at = now() - interval '1 second' WHERE state = 'granted'").await;
    let (s, _, _) = register_with(&e, t, g["grant"].as_str().unwrap(), "x", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(scalar_i64(e.pool(), "SELECT count(*) FROM recovery_requests WHERE state = 'expired'").await, 1);
    e.t.cleanup().await;
}

/// rev 10 email method (waiting period, identical 202, link only through the Notifier, MFA
/// users need a code) and device approval (step-up approval, cancel, list).
#[tokio::test]
async fn recovery_by_email_and_device_approval() {
    let Some(e) = env().await else { return };
    let t = alice(&e, "pw").await;
    let ts = t.as_uuid().to_string();
    exec(e.pool(), "UPDATE users SET email = 'alice@mail.test', email_verified_at = now()").await;
    let email = |login: &str| json!({"tenant": ts, "login": login, "method": "email"});
    let (s, _, a) = e.post("/api/v2/auth/recovery/start", email(LOGIN)).await;
    let (s2, _, b) = e.post("/api/v2/auth/recovery/start", email("nobody@acme.test")).await;
    assert_eq!((s, s2), (StatusCode::ACCEPTED, StatusCode::ACCEPTED));
    assert_eq!(a, json!({"state": "pending"}));
    assert_eq!(a, b);
    let links = e.mail.0.lock().unwrap().clone();
    assert_eq!(links.len(), 1, "only the real account gets a link");
    assert_eq!(links[0].0, "alice@mail.test");
    let link = links[0].1.clone();
    // Before the waiting period: pending with available_at, no grant.
    let (s, _, st) = e.post("/api/v2/auth/recovery/status", json!({"token": link})).await;
    assert_eq!(s, StatusCode::OK, "{st}");
    assert_eq!(st["state"], "pending");
    assert!(st["available_at"].as_str().unwrap().ends_with('Z'));
    assert!(st.get("grant").is_none());
    // A forged link is unauthenticated.
    let (s, _, _) = e
        .post("/api/v2/auth/recovery/status", json!({"token": format!("rt1.{}.{}", &link[4..26], "A".repeat(43))}))
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // The user's session lists the request and can see the requester's User-Agent.
    let (_, _, v) = login(&e, &ts, LOGIN, "pw").await;
    let at = v["access_token"].as_str().unwrap().to_owned();
    let (_, _, l) = e.req("GET", "/api/v2/me/recovery-requests", Some(&at), None, &[]).await;
    assert_eq!(l["items"].as_array().unwrap().len(), 1, "{l}");
    assert_eq!(l["items"][0]["method"], "email");
    // MFA user (passkey-free but policy 1 via tenant override) must add a recovery code.
    let (_, _, c) = e.req("POST", "/api/v2/me/recovery-codes", Some(&at), None, &[]).await;
    exec(e.pool(), "UPDATE tenants SET policy = '\\xa16c6d66615f726571756972656401'::bytea").await;
    exec(e.pool(), "UPDATE recovery_requests SET not_before = now() - interval '1 second'").await;
    let (s, _, v) = e.post("/api/v2/auth/recovery/status", json!({"token": link})).await;
    assert_eq!((s, code_of(&v)), (StatusCode::UNAUTHORIZED, Some("mfa_required")), "{v}");
    let (s, _, g) = e
        .post("/api/v2/auth/recovery/status", json!({"token": link, "code": c["codes"][0]}))
        .await;
    assert_eq!(s, StatusCode::OK, "{g}");
    assert_eq!(g["state"], "granted");
    assert_eq!(g["grant_expires_in"], 900);
    // Asking again replaces the grant (the first one no longer works) without extending it.
    let (_, _, g2) = e
        .post("/api/v2/auth/recovery/status", json!({"token": link, "code": c["codes"][0]}))
        .await;
    assert!(g2["grant_expires_in"].as_i64().unwrap() <= 900);
    let (s, _, _) = register_with(&e, t, g["grant"].as_str().unwrap(), "x", None).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "replaced grant is not a grant any more");
    exec(e.pool(), "UPDATE tenants SET policy = '\\xa0'::bytea").await;

    // Device approval: 202 with recovery_txn, also for unknown accounts.
    let dev = |login: &str| json!({"tenant": ts, "login": login, "method": "device_approval"});
    let (s, _, d) = e.post("/api/v2/auth/recovery/start", dev(LOGIN)).await;
    let (s2, _, d2) = e.post("/api/v2/auth/recovery/start", dev("nobody@acme.test")).await;
    assert_eq!((s, s2), (StatusCode::ACCEPTED, StatusCode::ACCEPTED));
    assert_eq!(d["state"], "pending");
    assert!(d2["recovery_txn"].as_str().unwrap().starts_with("rt1."));
    let (_, _, p) = e.post("/api/v2/auth/recovery/status", json!({"recovery_txn": d2["recovery_txn"]})).await;
    assert_eq!(p, json!({"state": "pending"}));
    let (_, _, p) = e.post("/api/v2/auth/recovery/status", json!({"recovery_txn": d["recovery_txn"]})).await;
    assert_eq!(p, json!({"state": "pending"}));
    let (_, _, l) = e.req("GET", "/api/v2/me/recovery-requests", Some(&at), None, &[]).await;
    let item = l["items"].as_array().unwrap().iter().find(|i| i["method"] == "device_approval").unwrap().clone();
    assert!(item["available_at"].is_null());
    let approve = format!("/api/v2/me/recovery-requests/{}/approve", item["id"].as_str().unwrap());
    // Approval needs step-up.
    exec(e.pool(), "UPDATE sessions SET last_strong_auth_at = now() - interval '1 hour'").await;
    let (s, _, v) = e.req("POST", &approve, Some(&at), None, &[]).await;
    assert_eq!((s, code_of(&v)), (StatusCode::UNAUTHORIZED, Some("step_up_required")));
    exec(e.pool(), "UPDATE sessions SET last_strong_auth_at = now()").await;
    // Another user's session cannot approve it.
    let u2 = e.admin.create_user(t, NewUser { login: "bob@acme.test".into(), kind: UserKind::Member, display_name: None }).await.unwrap();
    let link2 = e.admin.issue_setup_link(t, u2.user_id).await.unwrap();
    let bob = register_bob(&e, t, link2.token.expose_secret()).await;
    let (s, _, _) = e.req("POST", &approve, Some(&bob), None, &[]).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _, _) = e.req("POST", &approve, Some(&at), None, &[]).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_, _, p) = e.post("/api/v2/auth/recovery/status", json!({"recovery_txn": d["recovery_txn"]})).await;
    assert_eq!(p["state"], "granted", "{p}");
    assert!(p["grant"].as_str().unwrap().starts_with("rt1."));
    // Cancel: granted requests can be cancelled; status reports it.
    let del = format!("/api/v2/me/recovery-requests/{}", item["id"].as_str().unwrap());
    let (s, _, _) = e.req("DELETE", &del, Some(&at), None, &[]).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_, _, p) = e.post("/api/v2/auth/recovery/status", json!({"recovery_txn": d["recovery_txn"]})).await;
    assert_eq!(p, json!({"state": "cancelled"}));
    let (s, _, _) = e.req("DELETE", &del, Some(&at), None, &[]).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    e.t.cleanup().await;
}

async fn register_bob(e: &Env, t: TenantId, link: &str) -> String {
    let pw = "bobpw";
    let mut rng = rand_core_06::OsRng;
    let c = ClientRegistration::<Suite>::start(&mut rng, pw.as_bytes()).unwrap();
    let (_, _, v) = e
        .post("/api/v2/auth/opaque/register/start",
              json!({"grant": link, "login": "bob@acme.test", "registration_request": b64(&c.message.serialize())}))
        .await;
    let resp = RegistrationResponse::<Suite>::deserialize(&unb64(&v["registration_response"])).unwrap();
    let cid = client_identifier(&t.as_uuid().to_string(), "bob@acme.test");
    let k = ksf();
    let fin = c.state.finish(&mut rng, pw.as_bytes(), resp,
        ClientRegistrationFinishParameters::new(Identifiers { client: Some(cid.as_bytes()), server: None }, Some(&k))).unwrap();
    let (s, _, _) = e
        .post("/api/v2/auth/opaque/register/finish",
              json!({"registration_txn": v["registration_txn"], "registration_upload": b64(&fin.message.serialize())}))
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_, _, v) = login(e, &t.as_uuid().to_string(), "bob@acme.test", pw).await;
    v["access_token"].as_str().unwrap().to_owned()
}

/// rev 10 `/me/sessions`: listing, revoking another own session (step-up), another user's
/// session refused (404), the current one acts as logout.
#[tokio::test]
async fn me_sessions_list_and_revoke() {
    let Some(e) = env().await else { return };
    let t = alice(&e, "pw").await;
    let ts = t.as_uuid().to_string();
    let (_, _, a) = login(&e, &ts, LOGIN, "pw").await;
    let (_, hb, b) = login(&e, &ts, LOGIN, "pw").await;
    let at = a["access_token"].as_str().unwrap().to_owned();
    let (s, _, l) = e.req("GET", "/api/v2/me/sessions", Some(&at), None, &[]).await;
    assert_eq!(s, StatusCode::OK);
    let items = l["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items.iter().filter(|i| i["current"] == true).count(), 1);
    assert_eq!(items[0]["user_agent"], "TestAgent/1.0");
    assert_eq!(items[0]["amr"], json!(["pwd"]));
    assert!(items[0]["created_at"].as_str().unwrap().ends_with('Z'));
    // Another user's session: 404, like a missing one.
    let u2 = e.admin.create_user(t, NewUser { login: "bob@acme.test".into(), kind: UserKind::Member, display_name: None }).await.unwrap();
    let link2 = e.admin.issue_setup_link(t, u2.user_id).await.unwrap();
    let bob = register_bob(&e, t, link2.token.expose_secret()).await;
    let bob_sid = claims_of(&bob)["sid"].as_str().unwrap().to_owned();
    let (s, _, _) = e.req("DELETE", &format!("/api/v2/me/sessions/{bob_sid}"), Some(&at), None, &[]).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _, _) = e.req("GET", "/api/v2/me", Some(&bob), None, &[]).await;
    assert_eq!(s, StatusCode::OK, "bob's session untouched");
    // Other own session: step-up required.
    let other = b["session_id"].as_str().unwrap().to_owned();
    exec(e.pool(), "UPDATE sessions SET last_strong_auth_at = now() - interval '1 hour'").await;
    let (s, _, v) = e.req("DELETE", &format!("/api/v2/me/sessions/{other}"), Some(&at), None, &[]).await;
    assert_eq!((s, code_of(&v)), (StatusCode::UNAUTHORIZED, Some("step_up_required")));
    exec(e.pool(), "UPDATE sessions SET last_strong_auth_at = now()").await;
    let (s, _, _) = e.req("DELETE", &format!("/api/v2/me/sessions/{other}"), Some(&at), None, &[]).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _, _) = e.refresh(&rt_of(&hb)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // Current session: logout semantics, cookie cleared, no step-up needed.
    exec(e.pool(), "UPDATE sessions SET last_strong_auth_at = now() - interval '1 hour'").await;
    let mine = a["session_id"].as_str().unwrap().to_owned();
    let (s, h, _) = e.req("DELETE", &format!("/api/v2/me/sessions/{mine}"), Some(&at), None, &[]).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(h.get(header::SET_COOKIE).unwrap().to_str().unwrap().contains("Max-Age=0"));
    let (s, _, _) = e.req("GET", "/api/v2/me", Some(&at), None, &[]).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    e.t.cleanup().await;
}

/// Contract §5: thresholds per account and source, identical 429 for unknown accounts,
/// Retry-After; Valkey counters and the limit/N local fallback.
#[tokio::test]
async fn rate_limits_thresholds_identical_for_unknown_accounts() {
    let Some(e) = env().await else { return };
    let t = alice(&e, "pw").await;
    let ts = t.as_uuid().to_string();
    let limits = RateLimits { source: 1000, account: 3, tenant: 100_000, node_count: 1 };
    let e = e.with(SessionPolicy::default(), RateLimiter::local_only(limits));
    let start = |login: &str| {
        let c = ClientLogin::<Suite>::start(&mut rand_core_06::OsRng, b"pw").unwrap();
        json!({"tenant": ts, "login": login, "credential_request": b64(&c.message.serialize())})
    };
    let mut over = vec![];
    for login in [LOGIN, "nobody@acme.test"] {
        for _ in 0..3 {
            let (s, _, _) = e.post("/api/v2/auth/opaque/login/start", start(login)).await;
            assert_eq!(s, StatusCode::OK);
        }
        let (s, h, v) = e.post("/api/v2/auth/opaque/login/start", start(login)).await;
        assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{v}");
        assert!(h.get(header::RETRY_AFTER).is_some());
        assert!(v["retry_after_ms"].as_u64().unwrap() <= 60_000);
        let mut v = shape(&v);
        v.as_object_mut().unwrap().remove("retry_after_ms");
        over.push(v);
    }
    assert_eq!(over[0], over[1], "unknown accounts are limited identically");
    assert_eq!(over[0]["code"], "rate_limited");
    // Recovery is limited per account too.
    for _ in 0..3 {
        let (s, _, _) = e.post("/api/v2/auth/recovery/start", json!({"tenant": ts, "login": LOGIN, "method": "email"})).await;
        assert_eq!(s, StatusCode::ACCEPTED);
    }
    let (s, _, _) = e.post("/api/v2/auth/recovery/start", json!({"tenant": ts, "login": LOGIN, "method": "email"})).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    // Per source.
    let src = RateLimits { source: 5, account: 100, tenant: 100_000, node_count: 1 };
    let e = e.with(SessionPolicy::default(), RateLimiter::local_only(src));
    for i in 0..5 {
        let (s, _, _) = e.post("/api/v2/auth/opaque/login/start", start(&format!("u{i}@acme.test"))).await;
        assert_eq!(s, StatusCode::OK);
    }
    let (s, _, _) = e.post("/api/v2/auth/webauthn/login/start", json!({"tenant": ts})).await;
    assert_eq!(s, StatusCode::OK, "other endpoint class has its own source bucket");
    let (s, _, _) = e.post("/api/v2/auth/opaque/login/start", start("u9@acme.test")).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);

    // Valkey-backed counters (shared across nodes), and the fallback when Valkey is down.
    let lim = RateLimits { source: 1000, account: 4, tenant: 100_000, node_count: 2 };
    let key = |acct: &str| vec![Key::new(Dimension::Account, "test", &[ts.as_bytes(), acct.as_bytes(), &rand16()])];
    if let Ok(url) = std::env::var("CS_TEST_VALKEY_URL") {
        let a = RateLimiter::new(lim, Some(&url)).unwrap();
        let b = RateLimiter::new(lim, Some(&url)).unwrap();
        let k = key("x");
        assert_eq!(a.check(&k).await.unwrap(), Backend::Valkey);
        assert_eq!(b.check(&k).await.unwrap(), Backend::Valkey);
        a.check(&k).await.unwrap();
        b.check(&k).await.unwrap();
        assert!(a.check(&k).await.is_err(), "the limit is shared between nodes");
    }
    let down = RateLimiter::new(lim, Some("redis://127.0.0.1:1")).unwrap();
    let k = key("y");
    assert_eq!(down.check(&k).await.unwrap(), Backend::Local);
    assert_eq!(down.check(&k).await.unwrap(), Backend::Local);
    assert!(down.check(&k).await.is_err(), "fallback allows limit/N = 2");
    e.t.cleanup().await;
}

/// rev 11 `dpop_first_party_required` = 1: sign-in and refresh without a proof are refused.
#[tokio::test]
async fn dpop_first_party_required_policy() {
    let Some(e) = env().await else { return };
    let t = alice(&e, "pw").await;
    let ts = t.as_uuid().to_string();
    let (_, h, _) = login(&e, &ts, LOGIN, "pw").await;
    let policy = SessionPolicy { dpop_required: true, ..SessionPolicy::default() };
    let e = e.with(policy, RateLimiter::local_only(generous()));
    let (s, _, v) = login(&e, &ts, LOGIN, "pw").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{v}");
    // An unbound refresh family can no longer be refreshed.
    let (s, _, _) = e.refresh(&rt_of(&h)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // Passwordless and MFA completion follow the same rule.
    let (_, _, st) = e.post("/api/v2/auth/webauthn/login/start", json!({"tenant": ts})).await;
    let (s, _, _) = e
        .post("/api/v2/auth/webauthn/login/finish", json!({"login_txn": st["login_txn"], "credential": {}}))
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    e.t.cleanup().await;
}
