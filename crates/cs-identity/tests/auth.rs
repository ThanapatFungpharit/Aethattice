//! OPAQUE registration/login, sessions, access tokens, refresh and logout (M1 contract rev 6
//! §2.1, §2.4, §3), DPoP (rev 8), step-up and re-registration (rev 9) against a real identity
//! domain, through the HTTP routes.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cs_api::ApiState;
use cs_common::id::TenantId;
use cs_common::vector::DomainId;
use cs_db::DomainPool;
use cs_db::migrate::{MigrationSet, Migrator, common_migrations};
use cs_db::testing::TestDomains;
use cs_identity::admin::{IdentityAdmin, NewUser, UserKind};
use cs_identity::auth::{AuthService, REGISTRATION_GRANT_REQUIRED};
use cs_identity::jws::AccessTokens;
use cs_identity::keys::OpaqueKeys;
use cs_identity::session::SessionPolicy;
use cs_identity_wire::{CONTEXT, KsfParams, Suite, client_identifier};
use cs_kms::{Kms, LocalSoftwareKms};
use http_body_util::BodyExt;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, Identifiers, RegistrationResponse,
};
use serde_json::{Value, json};
use sqlx::Row;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

const ID: DomainId = DomainId::Identity;
const DOMAIN: &str = "cs.example.test";

fn set() -> MigrationSet {
    common_migrations()
        .unwrap()
        .merge(cs_identity::migrations().unwrap())
        .unwrap()
}

struct Env {
    t: TestDomains,
    _dir: tempfile::TempDir,
    kms: Arc<dyn Kms>,
    auth: Arc<AuthService>,
    admin: IdentityAdmin,
    app: axum::Router,
}

impl Env {
    fn pool(&self) -> &DomainPool {
        self.t.pool(&ID)
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
        self.call(
            Request::post(path)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }

    async fn refresh(
        &self,
        rt: &str,
        key: Option<&str>,
    ) -> (StatusCode, axum::http::HeaderMap, Value) {
        let mut b = Request::post("/api/v2/auth/token/refresh")
            .header(header::COOKIE, format!("__Secure-cs_rt={rt}"));
        if let Some(k) = key {
            b = b.header("Idempotency-Key", k);
        }
        self.call(b.body(Body::empty()).unwrap()).await
    }

    async fn cleanup(self) {
        self.t.cleanup().await;
    }
}

async fn env() -> Option<Env> {
    let t = TestDomains::create(&[ID]).await?;
    Migrator::run(t.pool(&ID), &set()).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let kms: Arc<dyn Kms> =
        Arc::new(LocalSoftwareKms::init(&dir.path().join("root.key"), None).unwrap());
    let auth = Arc::new(
        AuthService::new(
            t.pool(&ID).clone(),
            kms.clone(),
            DOMAIN,
            SessionPolicy::default(),
        )
        .with_rate_limiter(generous_limits()),
    );
    let state = ApiState::new(DOMAIN, vec![], Duration::from_secs(2));
    let app = cs_api::with_middleware(
        cs_api::public_routes().merge(cs_identity::http::routes(auth.clone())),
        state,
        1 << 20,
    );
    let admin = IdentityAdmin::new(t.pool(&ID).clone()).unwrap();
    Some(Env {
        t,
        _dir: dir,
        kms,
        auth,
        admin,
        app,
    })
}

/// Rate limits at the top of their ranges: these tests run many sign-ins from one source
/// (rate limiting itself is tested in tests/mfa_recovery.rs).
fn generous_limits() -> cs_identity::ratelimit::RateLimiter {
    cs_identity::ratelimit::RateLimiter::local_only(cs_identity::ratelimit::RateLimits {
        source: 1000,
        account: 100,
        tenant: 100_000,
        node_count: 1,
    })
}

fn b64(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

fn unb64(v: &Value) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(v.as_str().unwrap()).unwrap()
}

/// Invited member user with a fresh setup link: (tenant, login, link).
async fn invited(e: &Env, tenant: TenantId, login: &str) -> String {
    let u = e
        .admin
        .create_user(
            tenant,
            NewUser {
                login: login.to_owned(),
                kind: UserKind::Member,
                display_name: None,
            },
        )
        .await
        .unwrap();
    e.admin
        .issue_setup_link(tenant, u.user_id)
        .await
        .unwrap()
        .token
        .expose_secret()
        .clone()
}

fn ksf() -> argon2::Argon2<'static> {
    KsfParams::DEFAULT.argon2().unwrap()
}

/// Full client-side registration through HTTP. Returns the register/finish status.
async fn register(e: &Env, tenant: TenantId, grant: &str, login: &str, pw: &str) -> StatusCode {
    let mut rng = rand_core_06::OsRng;
    let c = ClientRegistration::<Suite>::start(&mut rng, pw.as_bytes()).unwrap();
    let (s, _, v) = e
        .post(
            "/api/v2/auth/opaque/register/start",
            json!({"grant": grant, "login": login, "registration_request": b64(&c.message.serialize())}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        v["ksf_params"],
        json!({"algorithm": "argon2id", "m_kib": 65536, "t": 3, "p": 1})
    );
    let resp =
        RegistrationResponse::<Suite>::deserialize(&unb64(&v["registration_response"])).unwrap();
    let cid = client_identifier(&tenant.as_uuid().to_string(), &login.to_lowercase());
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
    let (s, _, _) = e
        .post(
            "/api/v2/auth/opaque/register/finish",
            json!({"registration_txn": v["registration_txn"], "registration_upload": b64(&fin.message.serialize())}),
        )
        .await;
    s
}

/// login/start response for (tenant text, login) with a fresh credential request.
async fn login_start(
    e: &Env,
    tenant: &str,
    login: &str,
    pw: &str,
) -> (StatusCode, Value, ClientLogin<Suite>) {
    let c = ClientLogin::<Suite>::start(&mut rand_core_06::OsRng, pw.as_bytes()).unwrap();
    let (s, _, v) = e
        .post(
            "/api/v2/auth/opaque/login/start",
            json!({"tenant": tenant, "login": login, "credential_request": b64(&c.message.serialize())}),
        )
        .await;
    (s, v, c.state)
}

/// Full login; Ok((auth result, refresh token)) or Err(status, body).
async fn login(
    e: &Env,
    tenant: TenantId,
    login: &str,
    pw: &str,
) -> Result<(Value, String, String), (StatusCode, Value)> {
    login_with(e, tenant, login, pw, None).await
}

/// Full login with an optional DPoP proof on login/finish.
async fn login_with(
    e: &Env,
    tenant: TenantId,
    login: &str,
    pw: &str,
    dpop: Option<&PKey>,
) -> Result<(Value, String, String), (StatusCode, Value)> {
    let (s, v, st) = login_start(e, &tenant.as_uuid().to_string(), login, pw).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let cid = client_identifier(&tenant.as_uuid().to_string(), login);
    let k = ksf();
    let resp = CredentialResponse::<Suite>::deserialize(&unb64(&v["credential_response"])).unwrap();
    let fin = match st.finish(
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
        // Wrong password: the client cannot open the envelope. Send garbage of the right
        // length so the server path is still exercised.
        Err(_) => vec![0u8; 64],
    };
    let path = "/api/v2/auth/opaque/login/finish";
    let mut b = Request::post(path).header(header::CONTENT_TYPE, "application/json");
    if let Some(k) = dpop {
        b = b.header("DPoP", k.proof("POST", &htu(path), None));
    }
    let (s, h, v) = e
        .call(
            b.body(Body::from(
                json!({"login_txn": v["login_txn"], "credential_finalization": b64(&fin)})
                    .to_string(),
            ))
            .unwrap(),
        )
        .await;
    if s != StatusCode::OK {
        return Err((s, v));
    }
    let cookie = h
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let rt = cookie
        .strip_prefix("__Secure-cs_rt=")
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    Ok((v, rt, cookie))
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

#[tokio::test]
async fn register_login_tokens_and_grant_rules() {
    let Some(e) = env().await else { return };
    let ten = e.admin.create_tenant("Acme").await.unwrap().tenant_id;
    let grant = invited(&e, ten, "Admin@Acme.test").await;

    // Grant errors: malformed and unknown grants are permission_denied + registration_grant_required.
    for g in [
        "nope",
        "rt1.AAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ] {
        let c = ClientRegistration::<Suite>::start(&mut rand_core_06::OsRng, b"pw").unwrap();
        let (s, _, v) = e
            .post(
                "/api/v2/auth/opaque/register/start",
                json!({"grant": g, "login": "admin@acme.test", "registration_request": b64(&c.message.serialize())}),
            )
            .await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
        assert_eq!(v["errors"][0]["code"], REGISTRATION_GRANT_REQUIRED);
    }
    // Login mismatch with the grant's user.
    let c = ClientRegistration::<Suite>::start(&mut rand_core_06::OsRng, b"pw").unwrap();
    let (s, _, _) = e
        .post(
            "/api/v2/auth/opaque/register/start",
            json!({"grant": grant, "login": "other@acme.test", "registration_request": b64(&c.message.serialize())}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Register (login is normalized) and the grant is consumed: a second use is refused.
    assert_eq!(
        register(&e, ten, &grant, "Admin@Acme.test", "correct horse").await,
        StatusCode::NO_CONTENT
    );
    let c = ClientRegistration::<Suite>::start(&mut rand_core_06::OsRng, b"pw").unwrap();
    let (s, _, v) = e
        .post(
            "/api/v2/auth/opaque/register/start",
            json!({"grant": grant, "login": "admin@acme.test", "registration_request": b64(&c.message.serialize())}),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(v["errors"][0]["code"], REGISTRATION_GRANT_REQUIRED);
    assert_eq!(
        scalar_i64(
            e.pool(),
            "SELECT count(*) FROM users WHERE status = 'active'"
        )
        .await,
        1
    );
    assert_eq!(
        scalar_i64(
            e.pool(),
            "SELECT count(*) FROM setup_links WHERE state = 'used'"
        )
        .await,
        1
    );
    assert_eq!(
        scalar_i64(
            e.pool(),
            "SELECT count(*) FROM outbox WHERE event_type = 'identity.credentials.changed'"
        )
        .await,
        1
    );
    let kv: String = e
        .pool()
        .read_snapshot(|tx| {
            Box::pin(async move {
                Ok(
                    sqlx::query_scalar("SELECT server_key_version FROM opaque_registrations")
                        .fetch_one(tx.conn())
                        .await?,
                )
            })
        })
        .await
        .unwrap();
    assert_eq!(kv, "opaque-server/v1");

    // Wrong password: unauthenticated, same detail as an unknown account.
    let (s1, v1) = login(&e, ten, "admin@acme.test", "wrong")
        .await
        .unwrap_err();
    let (s2, v2) = login(&e, ten, "ghost@acme.test", "whatever")
        .await
        .unwrap_err();
    assert_eq!(
        (s1, s2),
        (StatusCode::UNAUTHORIZED, StatusCode::UNAUTHORIZED)
    );
    assert_eq!(v1["detail"], v2["detail"]);
    assert_eq!(v1["code"], "unauthenticated");

    // Correct password: authentication result + refresh cookie.
    let (v, rt, cookie) = login(&e, ten, "admin@acme.test", "correct horse")
        .await
        .unwrap();
    assert_eq!(v["state"], "authenticated");
    assert_eq!(v["expires_in"], 600);
    for attr in [
        "Path=/api/v2/auth/token",
        "Secure",
        "HttpOnly",
        "SameSite=Strict",
    ] {
        assert!(cookie.contains(attr), "{cookie}");
    }
    assert!(cs_identity::token::parse(&rt).is_ok(), "rt1 format");
    let c = e
        .auth
        .access_tokens()
        .verify(
            v["access_token"].as_str().unwrap(),
            cs_identity::auth::unix_now(),
        )
        .await
        .unwrap();
    assert_eq!(c.iss, format!("https://{DOMAIN}"));
    assert_eq!(c.aud, format!("https://{DOMAIN}/api/v2"));
    assert_eq!(c.tid, ten.as_uuid().to_string());
    assert_eq!(c.sid, v["session_id"].as_str().unwrap());
    assert_eq!(
        (c.sgen, c.amr.clone(), c.exp - c.iat),
        (1, vec!["pwd".to_owned()], 600)
    );
    assert!(c.cnf.is_none());
    // Header: EdDSA, at+jwt, versioned kid.
    let h: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(
                v["access_token"]
                    .as_str()
                    .unwrap()
                    .split('.')
                    .next()
                    .unwrap(),
            )
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        h,
        json!({"alg": "EdDSA", "typ": "at+jwt", "kid": "identity-access-token@v1"})
    );
    // Only SHA-256 of the refresh token is stored.
    let random = rt.rsplit('.').next().unwrap().to_owned();
    let dump: Vec<String> = e
        .pool()
        .read_snapshot(|tx| {
            Box::pin(async move {
                Ok(
                    sqlx::query_scalar("SELECT encode(token_hash, 'base64') FROM refresh_tokens")
                        .fetch_all(tx.conn())
                        .await?,
                )
            })
        })
        .await
        .unwrap();
    assert!(dump.iter().all(|d| !d.contains(&random)));

    // JWKS publishes the signing key.
    let (s, _, j) = e
        .call(
            Request::get("/api/v2/auth/jwks")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(j["keys"][0]["kid"], "identity-access-token@v1");
    assert_eq!(j["keys"][0]["kty"], "OKP");
    e.cleanup().await;
}

#[tokio::test]
async fn unknown_account_and_tenant_are_indistinguishable() {
    let Some(e) = env().await else { return };
    let ten = e.admin.create_tenant("Acme").await.unwrap().tenant_id;
    let g = invited(&e, ten, "alice@acme.test").await;
    assert_eq!(
        register(&e, ten, &g, "alice@acme.test", "pw-a").await,
        StatusCode::NO_CONTENT
    );
    let g = invited(&e, ten, "bob@acme.test").await;
    assert_eq!(
        register(&e, ten, &g, "bob@acme.test", "pw-b").await,
        StatusCode::NO_CONTENT
    );
    let disabled = TenantId::generate().unwrap();
    let t = ten.as_uuid().to_string();
    let unknown_tenant = disabled.as_uuid().to_string();

    // Same status, same body shape and sizes for known, unknown login and unknown tenant.
    let (s_k, v_k, _) = login_start(&e, &t, "alice@acme.test", "x").await;
    let (s_u, v_u, _) = login_start(&e, &t, "nobody@acme.test", "x").await;
    let (s_t, v_t, _) = login_start(&e, &unknown_tenant, "alice@acme.test", "x").await;
    assert_eq!(
        (s_k, s_u, s_t),
        (StatusCode::OK, StatusCode::OK, StatusCode::OK)
    );
    let shape = |v: &Value| {
        let mut k: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
        k.sort();
        (
            k,
            v["login_txn"].as_str().unwrap().len(),
            v["credential_response"].as_str().unwrap().len(),
            v["ksf_params"]
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
        )
    };
    assert_eq!(shape(&v_k), shape(&v_u));
    assert_eq!(shape(&v_k), shape(&v_t));

    // Give bob a different stored parameter set: the tenant distribution is now 50/50.
    exec(
        e.pool(),
        "UPDATE opaque_registrations SET ksf_m_kib = 131072 WHERE user_id = \
         (SELECT user_id FROM users WHERE login = 'bob@acme.test')",
    )
    .await;
    let mut seen = std::collections::BTreeSet::new();
    for i in 0..24 {
        let login = format!("ghost{i}@acme.test");
        let (_, a, _) = login_start(&e, &t, &login, "x").await;
        let (_, b, _) = login_start(&e, &t, &login, "y").await;
        // Deterministic per unknown login (keyed PRF).
        assert_eq!(a["ksf_params"], b["ksf_params"], "{login}");
        seen.insert(a["ksf_params"]["m_kib"].as_i64().unwrap());
    }
    // Drawn from the tenant's real distribution, both sets appear.
    assert_eq!(seen, [65536i64, 131072].into_iter().collect());
    // rev 7: a stored set outside the KSF bounds is never offered.
    exec(
        e.pool(),
        "UPDATE opaque_registrations SET ksf_m_kib = 524288 WHERE user_id = \
         (SELECT user_id FROM users WHERE login = 'bob@acme.test')",
    )
    .await;
    for i in 0..8 {
        let (_, v, _) = login_start(&e, &t, &format!("ghost{i}@acme.test"), "x").await;
        assert_eq!(v["ksf_params"]["m_kib"], 65536);
    }
    let (_, v, _) = login_start(&e, &t, "bob@acme.test", "x").await;
    assert!(v["ksf_params"]["m_kib"].as_i64().unwrap() <= 262_144);
    // The unknown tenant uses the deployment default distribution.
    for i in 0..8 {
        let (_, v, _) = login_start(&e, &unknown_tenant, &format!("u{i}@x.test"), "x").await;
        assert_eq!(v["ksf_params"]["m_kib"], 65536);
    }
    // Disabled user: unauthenticated even with the right password (dummy path).
    exec(
        e.pool(),
        "UPDATE users SET status = 'disabled' WHERE login = 'alice@acme.test'",
    )
    .await;
    let (s, v) = login(&e, ten, "alice@acme.test", "pw-a").await.unwrap_err();
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(v["detail"], "Authentication failed.");
    e.cleanup().await;
}

#[tokio::test]
async fn txns_are_single_use_bound_and_expire() {
    let Some(e) = env().await else { return };
    let ten = e.admin.create_tenant("Acme").await.unwrap().tenant_id;
    let g = invited(&e, ten, "alice@acme.test").await;
    assert_eq!(
        register(&e, ten, &g, "alice@acme.test", "pw").await,
        StatusCode::NO_CONTENT
    );
    let t = ten.as_uuid().to_string();

    // Build a valid finalization, use it twice: the replay is refused.
    let finish = |v: &Value, st: ClientLogin<Suite>| {
        let cid = client_identifier(&t, "alice@acme.test");
        let k = ksf();
        let resp =
            CredentialResponse::<Suite>::deserialize(&unb64(&v["credential_response"])).unwrap();
        let f = st
            .finish(
                &mut rand_core_06::OsRng,
                b"pw",
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
        json!({"login_txn": v["login_txn"], "credential_finalization": b64(&f.message.serialize())})
    };
    let (_, v, st) = login_start(&e, &t, "alice@acme.test", "pw").await;
    let body = finish(&v, st);
    let (s, _, _) = e
        .post("/api/v2/auth/opaque/login/finish", body.clone())
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = e.post("/api/v2/auth/opaque/login/finish", body).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "replayed txn");

    // Expired txn.
    let (_, v, st) = login_start(&e, &t, "alice@acme.test", "pw").await;
    let body = finish(&v, st);
    exec(
        e.pool(),
        "UPDATE auth_txns SET expires_at = now() - interval '1 second'",
    )
    .await;
    let (s, _, _) = e.post("/api/v2/auth/opaque/login/finish", body).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "expired txn");

    // Wrong kind: a login txn presented to register/finish is refused (and vice versa the
    // sealed state cannot be opened under another kind's associated data).
    let (_, v, _) = login_start(&e, &t, "alice@acme.test", "pw").await;
    let (s, _, r) = e
        .post(
            "/api/v2/auth/opaque/register/finish",
            json!({"registration_txn": v["login_txn"], "registration_upload": b64(&[0u8; 192])}),
        )
        .await;
    assert!(
        s == StatusCode::FORBIDDEN || s == StatusCode::BAD_REQUEST,
        "{s} {r}"
    );
    exec(e.pool(), "UPDATE auth_txns SET kind = 'registration', user_id = (SELECT user_id FROM users LIMIT 1), grant_hash = sha256('x'::bytea)").await;
    let keys = OpaqueKeys::load_or_init(e.pool(), e.kms.as_ref())
        .await
        .unwrap();
    let row: (Vec<u8>, Vec<u8>, Vec<u8>) = e
        .pool()
        .read_snapshot(|tx| {
            Box::pin(async move {
                Ok(sqlx::query_as(
                    "SELECT tenant_id::text::bytea, txn_hash, sealed_state FROM auth_txns",
                )
                .fetch_one(tx.conn())
                .await?)
            })
        })
        .await
        .unwrap();
    let k = keys.current();
    let ad = |tenant: &[u8], kind: &str| {
        let mut a = tenant.to_vec();
        a.extend_from_slice(&row.1);
        a.extend_from_slice(kind.as_bytes());
        a
    };
    let tb = ten.as_bytes().to_vec();
    assert!(
        k.open(&row.2, &ad(&tb, "login")).is_some(),
        "opens with its own binding"
    );
    assert!(
        k.open(&row.2, &ad(&tb, "registration")).is_none(),
        "other kind"
    );
    let other = TenantId::generate().unwrap();
    assert!(
        k.open(&row.2, &ad(other.as_bytes(), "login")).is_none(),
        "other tenant"
    );
    let _ = row.0;
    e.cleanup().await;
}

#[tokio::test]
async fn refresh_rotation_lost_response_reuse_and_logout() {
    let Some(e) = env().await else { return };
    let ten = e.admin.create_tenant("Acme").await.unwrap().tenant_id;
    let g = invited(&e, ten, "alice@acme.test").await;
    assert_eq!(
        register(&e, ten, &g, "alice@acme.test", "pw").await,
        StatusCode::NO_CONTENT
    );

    let (_, rt0, _) = login(&e, ten, "alice@acme.test", "pw").await.unwrap();
    // Idempotency-Key is required.
    let (s, _, _) = e.refresh(&rt0, None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    // Rotation.
    let (s, h, v) = e.refresh(&rt0, Some("k1")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["state"], "authenticated");
    let rt1 = rt_of(&h);
    assert_ne!(rt0, rt1);
    // Lost response: same token + same key within 30 s → new successor, old successor revoked.
    let (s, h, _) = e.refresh(&rt0, Some("k1")).await;
    assert_eq!(s, StatusCode::OK);
    let rt1b = rt_of(&h);
    assert_ne!(rt1, rt1b);
    let (s, _, _) = e.refresh(&rt1, Some("k2")).await;
    assert_eq!(
        s,
        StatusCode::UNAUTHORIZED,
        "the unreceived successor was revoked"
    );
    // The new successor works.
    let (s, h, v) = e.refresh(&rt1b, Some("k3")).await;
    assert_eq!(s, StatusCode::OK);
    let rt2 = rt_of(&h);
    let sid = v["session_id"].as_str().unwrap().to_owned();
    // Reuse with a different key → session revoked, every token of the family dead.
    let (s, _, _) = e.refresh(&rt1b, Some("other")).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _, _) = e.refresh(&rt2, Some("k4")).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "session revoked on reuse");
    assert_eq!(
        scalar_i64(e.pool(), "SELECT generation FROM sessions").await,
        2,
        "generation bumped"
    );
    assert_eq!(
        scalar_i64(
            e.pool(),
            "SELECT count(*) FROM outbox WHERE event_type = 'identity.session.revoked'"
        )
        .await,
        1
    );
    assert_eq!(
        scalar_i64(
            e.pool(),
            "SELECT count(*) FROM refresh_tokens WHERE state <> 'revoked'"
        )
        .await,
        0
    );
    let _ = sid;

    // Lost-response window: same key after 30 s is reuse.
    let (_, rt0, _) = login(&e, ten, "alice@acme.test", "pw").await.unwrap();
    let (s, _, _) = e.refresh(&rt0, Some("w1")).await;
    assert_eq!(s, StatusCode::OK);
    exec(
        e.pool(),
        "UPDATE refresh_tokens SET rotated_at = now() - interval '31 seconds' WHERE state = 'rotated'",
    )
    .await;
    let (s, _, _) = e.refresh(&rt0, Some("w1")).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(
        scalar_i64(
            e.pool(),
            "SELECT count(*) FROM sessions WHERE state = 'active'"
        )
        .await,
        0
    );

    // Concurrent refreshes with different keys: exactly one wins, the losers are reuse.
    let (_, rt0, _) = login(&e, ten, "alice@acme.test", "pw").await.unwrap();
    let rs = futures::future::join_all((0..4).map(|i| {
        let e = &e;
        let rt0 = rt0.clone();
        async move { e.refresh(&rt0, Some(&format!("c{i}"))).await.0 }
    }))
    .await;
    assert!(
        rs.iter().filter(|s| **s == StatusCode::OK).count() <= 1,
        "{rs:?}"
    );
    assert_eq!(
        scalar_i64(
            e.pool(),
            "SELECT count(*) FROM sessions WHERE state = 'active'"
        )
        .await,
        0,
        "{rs:?}"
    );

    // Logout [R10]: revokes the session and its family, clears the cookie.
    let (v, rt, _) = login(&e, ten, "alice@acme.test", "pw").await.unwrap();
    let at = v["access_token"].as_str().unwrap().to_owned();
    let (s, _, _) = e
        .call(
            Request::post("/api/v2/auth/logout")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "logout needs the access token");
    let (s, h, _) = e
        .call(
            Request::post("/api/v2/auth/logout")
                .header(header::AUTHORIZATION, format!("Bearer {at}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let c = h.get(header::SET_COOKIE).unwrap().to_str().unwrap();
    assert!(
        c.starts_with("__Secure-cs_rt=; Path=/api/v2/auth/token; Max-Age=0"),
        "{c}"
    );
    let (s, _, _) = e.refresh(&rt, Some("after-logout")).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    e.cleanup().await;
}

#[tokio::test]
async fn access_token_verification_rejects_tampering() {
    let Some(e) = env().await else { return };
    let tokens = AccessTokens::new(e.kms.clone(), DOMAIN);
    let now = cs_identity::auth::unix_now();
    let claims = cs_identity::jws::AccessClaims {
        iss: String::new(),
        aud: String::new(),
        sub: "s".into(),
        tid: "t".into(),
        sid: "x".into(),
        sgen: 1,
        amr: vec!["pwd".into()],
        auth_time: now,
        iat: now,
        exp: now + 600,
        jti: "j".into(),
        cnf: None,
        scp: None,
    };
    let tok = tokens.sign(claims.clone()).await.unwrap();
    assert!(tokens.verify(&tok, now).await.is_ok());
    let parts: Vec<&str> = tok.split('.').collect();
    let enc = |v: Value| URL_SAFE_NO_PAD.encode(v.to_string());
    let bad = [
        // payload changed
        format!("{}.{}.{}", parts[0], enc(json!({"sub": "evil"})), parts[2]),
        // signature changed (first character: its 6 bits are all significant; the last
        // character of an unpadded 64-byte signature carries only 4, so changing it could
        // decode to the same bytes)
        format!(
            "{}.{}.{}{}",
            parts[0],
            parts[1],
            if parts[2].starts_with('A') { "B" } else { "A" },
            &parts[2][1..]
        ),
        // alg none / HS256 / jwk header / unknown kid
        format!(
            "{}.{}.",
            enc(json!({"alg":"none","typ":"at+jwt","kid":"identity-access-token@v1"})),
            parts[1]
        ),
        format!(
            "{}.{}.{}",
            enc(json!({"alg":"HS256","typ":"at+jwt","kid":"identity-access-token@v1"})),
            parts[1],
            parts[2]
        ),
        format!(
            "{}.{}.{}",
            enc(json!({"alg":"EdDSA","typ":"at+jwt","kid":"identity-access-token@v1","jwk":{}})),
            parts[1],
            parts[2]
        ),
        format!(
            "{}.{}.{}",
            enc(json!({"alg":"EdDSA","typ":"at+jwt","kid":"identity-access-token@v9"})),
            parts[1],
            parts[2]
        ),
        format!(
            "{}.{}.{}",
            enc(json!({"alg":"EdDSA","typ":"at+jwt","kid":"other/v1"})),
            parts[1],
            parts[2]
        ),
        "garbage".to_owned(),
    ];
    for b in &bad {
        let err = tokens.verify(b, now).await.unwrap_err();
        assert_eq!(err.status(), 401, "{b}");
    }
    // exp with 0 s leeway; iat at most 60 s in the future.
    assert!(tokens.verify(&tok, now + 600).await.is_err());
    assert!(tokens.verify(&tok, now + 599).await.is_ok());
    let future = tokens
        .sign(cs_identity::jws::AccessClaims {
            iat: now + 61,
            exp: now + 700,
            ..claims.clone()
        })
        .await
        .unwrap();
    assert!(tokens.verify(&future, now).await.is_err());
    // Another deployment's audience is refused.
    let other = AccessTokens::new(e.kms.clone(), "other.example.test");
    assert!(other.verify(&tok, now).await.is_err());
    e.cleanup().await;
}

#[tokio::test]
async fn server_keys_created_once_across_concurrent_initializers() {
    let Some(e) = env().await else { return };
    let (a, b) = tokio::join!(
        OpaqueKeys::load_or_init(e.pool(), e.kms.as_ref()),
        OpaqueKeys::load_or_init(e.pool(), e.kms.as_ref()),
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_eq!(a.versions(), vec![1]);
    assert_eq!(
        a.current().setup.serialize(),
        b.current().setup.serialize(),
        "both nodes use the stored row"
    );
    assert_eq!(
        scalar_i64(e.pool(), "SELECT count(*) FROM opaque_server_keys").await,
        1
    );
    // Nothing secret in plaintext: the row holds a wrapped data key and ciphertext only.
    let ct: Vec<u8> = e
        .pool()
        .read_snapshot(|tx| {
            Box::pin(async move {
                Ok(
                    sqlx::query_scalar("SELECT ciphertext FROM opaque_server_keys")
                        .fetch_one(tx.conn())
                        .await?,
                )
            })
        })
        .await
        .unwrap();
    let setup = a.current().setup.serialize();
    assert!(!ct.windows(32).any(|w| w == &setup[..32]));
    // Rotation adds version 2; version 1 stays loaded.
    let r = OpaqueKeys::rotate(e.pool(), e.kms.as_ref()).await.unwrap();
    assert_eq!(r.versions(), vec![1, 2]);
    assert_eq!(r.current().version, 2);
    assert_eq!(r.get(1).unwrap().setup.serialize(), setup);
    e.cleanup().await;
}

async fn reauth_call(e: &Env, at: &str, tenant: &str, pw: &str) -> StatusCode {
    let c = ClientLogin::<Suite>::start(&mut rand_core_06::OsRng, pw.as_bytes()).unwrap();
    let (s, _, v) = e
        .call(
            Request::post("/api/v2/auth/opaque/reauth/start")
                .header(header::AUTHORIZATION, format!("Bearer {at}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"credential_request": b64(&c.message.serialize())}).to_string(),
                ))
                .unwrap(),
        )
        .await;
    if s != StatusCode::OK {
        return s;
    }
    let cid = client_identifier(tenant, "alice@acme.test");
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
    e.call(
        Request::post("/api/v2/auth/opaque/reauth/finish")
            .header(header::AUTHORIZATION, format!("Bearer {at}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({"reauth_txn": v["reauth_txn"], "credential_finalization": b64(&fin)})
                    .to_string(),
            ))
            .unwrap(),
    )
    .await
    .0
}

#[tokio::test]
async fn reauth_steps_up_the_existing_session_and_me() {
    let Some(e) = env().await else { return };
    let ten = e.admin.create_tenant("Acme").await.unwrap().tenant_id;
    let g = invited(&e, ten, "alice@acme.test").await;
    assert_eq!(
        register(&e, ten, &g, "alice@acme.test", "pw").await,
        StatusCode::NO_CONTENT
    );
    let (v, _, _) = login(&e, ten, "alice@acme.test", "pw").await.unwrap();
    let at = v["access_token"].as_str().unwrap().to_owned();
    let sid = v["session_id"].as_str().unwrap().to_owned();
    let t = ten.as_uuid().to_string();
    let me = |tok: Option<&str>| {
        let mut r = Request::get("/api/v2/me");
        if let Some(tok) = tok {
            r = r.header(header::AUTHORIZATION, format!("Bearer {tok}"));
        }
        r.body(Body::empty()).unwrap()
    };

    let (s, _, m) = e.call(me(Some(&at))).await;
    assert_eq!(s, StatusCode::OK, "{m}");
    assert_eq!(m["login"], "alice@acme.test");
    assert_eq!(m["tenant_id"], t);
    assert_eq!(m["sid"], sid);
    assert_eq!(m["state"], "active");
    assert_eq!(m["amr"], json!(["pwd"]));
    assert_eq!(e.call(me(None)).await.0, StatusCode::UNAUTHORIZED);

    exec(
        e.pool(),
        "UPDATE sessions SET last_strong_auth_at = now() - interval '1 hour'",
    )
    .await;
    assert_eq!(
        reauth_call(&e, &at, &t, "wrong").await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        scalar_i64(
            e.pool(),
            "SELECT (last_strong_auth_at < now() - interval '30 minutes')::int::bigint FROM sessions"
        )
        .await,
        1,
        "a failed reauth leaves the session unchanged"
    );
    assert_eq!(reauth_call(&e, &at, &t, "pw").await, StatusCode::NO_CONTENT);
    assert_eq!(
        scalar_i64(
            e.pool(),
            "SELECT (last_strong_auth_at > now() - interval '1 minute')::int::bigint FROM sessions"
        )
        .await,
        1
    );
    // No new session or refresh token.
    assert_eq!(
        scalar_i64(e.pool(), "SELECT count(*) FROM sessions").await,
        1
    );
    assert_eq!(
        scalar_i64(e.pool(), "SELECT count(*) FROM refresh_tokens").await,
        1
    );
    // A revoked session (generation bumped): the old access token gets neither /me nor reauth.
    exec(
        e.pool(),
        "UPDATE sessions SET state = 'revoked', generation = generation + 1",
    )
    .await;
    assert_eq!(e.call(me(Some(&at))).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        reauth_call(&e, &at, &t, "pw").await,
        StatusCode::UNAUTHORIZED
    );
    e.cleanup().await;
}

/// Expired `auth_txns` are reclaimed in bounded batches (App. E, §21.3): at most
/// `batch_rows` per transaction and `max_batches` transactions per run; live rows are kept.
#[tokio::test]
async fn expired_txn_sweep_is_bounded_and_keeps_live_rows() {
    let Some(e) = env().await else { return };
    exec(
        e.pool(),
        "INSERT INTO auth_txns (tenant_id, txn_hash, kind, login, source, key_version, sealed_state, expires_at) \
         SELECT gen_random_uuid(), sha256(('expired-' || i)::bytea), 'login', 'u', 's', 1, '\\x01'::bytea, \
         now() - interval '1 minute' FROM generate_series(1, 25) AS i",
    )
    .await;
    // 20 rows carry their bucket (current nodes); 5 have none (rows of an N-1 node).
    exec(
        e.pool(),
        "UPDATE auth_txns SET expiry_bucket = get_byte(txn_hash, 0) % 16 \
         WHERE txn_hash IN (SELECT sha256(('expired-' || i)::bytea) FROM generate_series(1, 20) AS i)",
    )
    .await;
    exec(
        e.pool(),
        "INSERT INTO auth_txns (tenant_id, txn_hash, kind, login, source, key_version, sealed_state, expires_at) \
         SELECT gen_random_uuid(), sha256(('live-' || i)::bytea), 'login', 'u', 's', 1, '\\x01'::bytea, \
         now() + interval '1 minute' FROM generate_series(1, 3) AS i",
    )
    .await;
    let pool = e.pool().clone();
    let count = |sql: &'static str| {
        let pool = pool.clone();
        async move {
            pool.transaction(move |tx| {
                Box::pin(async move {
                    Ok(sqlx::query_scalar::<_, i64>(sql)
                        .fetch_one(tx.conn())
                        .await?)
                })
            })
            .await
            .unwrap()
        }
    };
    let expired = "SELECT count(*) FROM auth_txns WHERE expires_at < now()";
    let live = "SELECT count(*) FROM auth_txns WHERE expires_at >= now()";
    let sweep = cs_identity::auth::sweep_expired_txns;

    // The run cap holds: 2 batches of 10 delete 20 of the 25 expired rows.
    assert_eq!(sweep(e.pool(), 10, 2).await, 20);
    assert_eq!(count(expired).await, 5);
    // The next run stops early on a short batch and never touches live rows.
    assert_eq!(sweep(e.pool(), 10, 5).await, 5);
    assert_eq!(count(expired).await, 0);
    assert_eq!(count(live).await, 3);
    // Nothing left: a run is a no-op.
    assert_eq!(sweep(e.pool(), 10, 5).await, 0);
    // The bucketed read uses the hash-sharded expiry index (App. E). While the expand-phase
    // range index `auth_txns_expiry_idx` still exists the planner may prefer it; the follow-up
    // contract migration drops it, which is simulated here.
    exec(e.pool(), "DROP INDEX auth_txns_expiry_idx").await;
    let plan: Vec<String> = {
        let pool = e.pool().clone();
        pool.transaction(move |tx| {
            Box::pin(async move {
                Ok(sqlx::query_scalar::<_, String>(
                    "EXPLAIN SELECT tenant_id, txn_hash FROM auth_txns \
                     WHERE expiry_bucket = 3 AND expires_at < now() LIMIT 500",
                )
                .fetch_all(tx.conn())
                .await?)
            })
        })
        .await
        .unwrap()
    };
    assert!(
        plan.iter()
            .any(|l| l.contains("auth_txns_expiry_bucket_idx")),
        "{plan:?}"
    );
    assert_eq!(cs_identity::auth::expiry_bucket(&[0x1f, 0]), 15);
    e.cleanup().await;
}

// ---------------------------------------------------------------------------------------------
// DPoP (M1 contract rev 8 §3, [R6], [R12])
// ---------------------------------------------------------------------------------------------

/// A client DPoP key.
enum PKey {
    Es(p256::ecdsa::SigningKey),
    Ed(ed25519_dalek::SigningKey),
}

fn rand32() -> [u8; 32] {
    use rand_core_06::RngCore as _;
    let mut b = [0u8; 32];
    rand_core_06::OsRng.fill_bytes(&mut b);
    b
}

fn now() -> i64 {
    cs_identity::auth::unix_now()
}

fn htu(path: &str) -> String {
    format!("https://{DOMAIN}{path}")
}

impl PKey {
    fn es256() -> Self {
        loop {
            if let Ok(k) = p256::ecdsa::SigningKey::from_slice(&rand32()) {
                return PKey::Es(k);
            }
        }
    }

    fn ed25519() -> Self {
        PKey::Ed(ed25519_dalek::SigningKey::from_bytes(&rand32()))
    }

    fn alg(&self) -> &'static str {
        match self {
            PKey::Es(_) => "ES256",
            PKey::Ed(_) => "EdDSA",
        }
    }

    fn jwk(&self) -> Value {
        match self {
            PKey::Es(k) => {
                let p = k.verifying_key().to_encoded_point(false);
                json!({"kty": "EC", "crv": "P-256",
                       "x": b64(p.x().unwrap()), "y": b64(p.y().unwrap())})
            }
            PKey::Ed(k) => json!({"kty": "OKP", "crv": "Ed25519",
                                  "x": b64(k.verifying_key().as_bytes())}),
        }
    }

    /// RFC 7638 thumbprint, base64url.
    fn jkt(&self) -> String {
        use sha2::Digest as _;
        let j = self.jwk();
        let canon = match self {
            PKey::Es(_) => format!(
                r#"{{"crv":"P-256","kty":"EC","x":{},"y":{}}}"#,
                j["x"], j["y"]
            ),
            PKey::Ed(_) => format!(r#"{{"crv":"Ed25519","kty":"OKP","x":{}}}"#, j["x"]),
        };
        b64(&sha2::Sha256::digest(canon.as_bytes()))
    }

    fn sign_raw(&self, header: &Value, claims: &Value) -> String {
        let input = format!(
            "{}.{}",
            b64(header.to_string().as_bytes()),
            b64(claims.to_string().as_bytes())
        );
        let sig = match self {
            PKey::Es(k) => {
                use p256::ecdsa::signature::Signer as _;
                let s: p256::ecdsa::Signature = k.sign(input.as_bytes());
                s.to_bytes().to_vec()
            }
            PKey::Ed(k) => {
                use ed25519_dalek::Signer as _;
                k.sign(input.as_bytes()).to_bytes().to_vec()
            }
        };
        format!("{input}.{}", b64(&sig))
    }

    fn header(&self) -> Value {
        json!({"typ": "dpop+jwt", "alg": self.alg(), "jwk": self.jwk()})
    }

    fn claims(&self, htm: &str, htu: &str, at: Option<&str>) -> Value {
        let mut c = json!({"jti": b64(&rand32()), "htm": htm, "htu": htu, "iat": now()});
        if let Some(at) = at {
            c["ath"] = json!(cs_identity::dpop::ath(at));
        }
        c
    }

    fn proof(&self, htm: &str, htu: &str, at: Option<&str>) -> String {
        self.sign_raw(&self.header(), &self.claims(htm, htu, at))
    }
}

/// Call `path` with an access token (`scheme` Bearer or DPoP) and an optional proof.
async fn with_at(
    e: &Env,
    method: &str,
    path: &str,
    scheme: &str,
    at: &str,
    proof: Option<String>,
    body: Option<Value>,
) -> (StatusCode, axum::http::HeaderMap, Value) {
    let mut b = Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("{scheme} {at}"));
    if let Some(p) = proof {
        b = b.header("DPoP", p);
    }
    let body = match body {
        Some(v) => {
            b = b.header(header::CONTENT_TYPE, "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    e.call(b.body(body).unwrap()).await
}

async fn me_dpop(e: &Env, at: &str, proof: String) -> StatusCode {
    with_at(e, "GET", "/api/v2/me", "DPoP", at, Some(proof), None)
        .await
        .0
}

fn claims_of(at: &str) -> Value {
    let p = at.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p).unwrap()).unwrap()
}

async fn refresh_dpop(
    e: &Env,
    rt: &str,
    proof: Option<String>,
) -> (StatusCode, axum::http::HeaderMap, Value) {
    let mut b = Request::post("/api/v2/auth/token/refresh")
        .header(header::COOKIE, format!("__Secure-cs_rt={rt}"))
        .header("Idempotency-Key", b64(&rand32()));
    if let Some(p) = proof {
        b = b.header("DPoP", p);
    }
    e.call(b.body(Body::empty()).unwrap()).await
}

/// Active user alice@acme.test with password `pw`.
async fn alice(e: &Env, pw: &str) -> TenantId {
    let t = e.admin.create_tenant("acme").await.unwrap().tenant_id;
    let link = invited(e, t, "alice@acme.test").await;
    assert_eq!(
        register(e, t, &link, "alice@acme.test", pw).await,
        StatusCode::NO_CONTENT
    );
    t
}

/// A valid proof binds the session, its access tokens and refresh family; bound tokens need
/// `DPoP` + a fresh proof with matching htm, htu, iat, ath and key; every negative is 401.
#[tokio::test]
async fn dpop_bound_access_token_proof_checks() {
    let Some(e) = env().await else { return };
    let t = alice(&e, "pw").await;
    let key = PKey::es256();
    let (v, _, _) = login_with(&e, t, "alice@acme.test", "pw", Some(&key))
        .await
        .unwrap();
    let at = v["access_token"].as_str().unwrap().to_owned();
    assert_eq!(claims_of(&at)["cnf"]["jkt"], json!(key.jkt()));
    assert_eq!(
        scalar_i64(
            e.pool(),
            "SELECT count(*) FROM sessions WHERE device_key_jkt IS NOT NULL"
        )
        .await,
        1
    );
    assert_eq!(
        scalar_i64(
            e.pool(),
            "SELECT count(*) FROM refresh_tokens WHERE key_jkt IS NOT NULL"
        )
        .await,
        1
    );
    let me = "/api/v2/me";
    let good = || key.proof("GET", &htu(me), Some(&at));
    // Valid; htu query and fragment are ignored.
    assert_eq!(me_dpop(&e, &at, good()).await, StatusCode::OK);
    let mut c = key.claims("GET", &format!("{}?x=1#f", htu(me)), Some(&at));
    assert_eq!(
        me_dpop(&e, &at, key.sign_raw(&key.header(), &c)).await,
        StatusCode::OK
    );
    // Replay of the same proof (the shared dpop_jti table, rev 14).
    let p = good();
    assert_eq!(me_dpop(&e, &at, p.clone()).await, StatusCode::OK);
    assert_eq!(me_dpop(&e, &at, p).await, StatusCode::UNAUTHORIZED);
    // Bearer with a cnf-bound token is refused, with or without a proof.
    assert_eq!(
        with_at(&e, "GET", me, "Bearer", &at, None, None).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        with_at(&e, "GET", me, "Bearer", &at, Some(good()), None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    // DPoP scheme without a proof.
    assert_eq!(
        with_at(&e, "GET", me, "DPoP", &at, None, None).await.0,
        StatusCode::UNAUTHORIZED
    );
    let bad: Vec<(&str, String)> = vec![
        ("wrong htm", key.proof("POST", &htu(me), Some(&at))),
        (
            "wrong htu path",
            key.proof("GET", &htu("/api/v2/other"), Some(&at)),
        ),
        (
            "wrong htu origin",
            key.proof("GET", &format!("https://evil.test{me}"), Some(&at)),
        ),
        ("wrong ath", key.proof("GET", &htu(me), Some("other-token"))),
        ("missing ath", key.proof("GET", &htu(me), None)),
        ("other key", PKey::es256().proof("GET", &htu(me), Some(&at))),
        (
            "other key (EdDSA)",
            PKey::ed25519().proof("GET", &htu(me), Some(&at)),
        ),
        ("stale iat", {
            c = key.claims("GET", &htu(me), Some(&at));
            c["iat"] = json!(now() - 120);
            key.sign_raw(&key.header(), &c)
        }),
        ("future iat", {
            c = key.claims("GET", &htu(me), Some(&at));
            c["iat"] = json!(now() + 120);
            key.sign_raw(&key.header(), &c)
        }),
        ("typ jwt", {
            let mut h = key.header();
            h["typ"] = json!("jwt");
            key.sign_raw(&h, &key.claims("GET", &htu(me), Some(&at)))
        }),
        ("alg RS256", {
            let mut h = key.header();
            h["alg"] = json!("RS256");
            key.sign_raw(&h, &key.claims("GET", &htu(me), Some(&at)))
        }),
        ("alg none", {
            let mut h = key.header();
            h["alg"] = json!("none");
            let p = key.sign_raw(&h, &key.claims("GET", &htu(me), Some(&at)));
            format!("{}.", p.rsplit_once('.').unwrap().0)
        }),
        ("alg EdDSA with an EC key", {
            let mut h = key.header();
            h["alg"] = json!("EdDSA");
            key.sign_raw(&h, &key.claims("GET", &htu(me), Some(&at)))
        }),
        ("private jwk member", {
            let mut h = key.header();
            h["jwk"]["d"] = json!(b64(&rand32()));
            key.sign_raw(&h, &key.claims("GET", &htu(me), Some(&at)))
        }),
        ("bad signature", {
            let p = good();
            let (head, sig) = p.rsplit_once('.').unwrap();
            let first = if sig.starts_with('A') { "B" } else { "A" };
            format!("{head}.{first}{}", &sig[1..])
        }),
        ("garbage", "garbage".to_owned()),
    ];
    for (what, p) in bad {
        assert_eq!(
            me_dpop(&e, &at, p).await,
            StatusCode::UNAUTHORIZED,
            "{what}"
        );
    }
    // Two DPoP headers are refused.
    let r = e
        .call(
            Request::get(me)
                .header(header::AUTHORIZATION, format!("DPoP {at}"))
                .header("DPoP", good())
                .header("DPoP", good())
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(r.0, StatusCode::UNAUTHORIZED);
    // No DPoP-Nonce in M1.
    assert!(r.1.get("dpop-nonce").is_none());
    // An unbound token is refused with the DPoP scheme and accepted as Bearer.
    let (v2, _, _) = login(&e, t, "alice@acme.test", "pw").await.unwrap();
    let at2 = v2["access_token"].as_str().unwrap();
    assert!(claims_of(at2).get("cnf").is_none());
    assert_eq!(
        me_dpop(&e, at2, key.proof("GET", &htu(me), Some(at2))).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        with_at(&e, "GET", me, "Bearer", at2, None, None).await.0,
        StatusCode::OK
    );
    // EdDSA proofs are accepted too.
    let ed = PKey::ed25519();
    let (v3, _, _) = login_with(&e, t, "alice@acme.test", "pw", Some(&ed))
        .await
        .unwrap();
    let at3 = v3["access_token"].as_str().unwrap();
    assert_eq!(claims_of(at3)["cnf"]["jkt"], json!(ed.jkt()));
    assert_eq!(
        me_dpop(&e, at3, ed.proof("GET", &htu(me), Some(at3))).await,
        StatusCode::OK
    );
    // A broken proof at login/finish is refused (never silently unbound).
    let mut h = key.header();
    h["typ"] = json!("jwt");
    let (s, v, st) = login_start(&e, &t.as_uuid().to_string(), "alice@acme.test", "pw").await;
    assert_eq!(s, StatusCode::OK);
    let cid = client_identifier(&t.as_uuid().to_string(), "alice@acme.test");
    let k = ksf();
    let resp = CredentialResponse::<Suite>::deserialize(&unb64(&v["credential_response"])).unwrap();
    let fin = st
        .finish(
            &mut rand_core_06::OsRng,
            b"pw",
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
    let path = "/api/v2/auth/opaque/login/finish";
    let (s, _, _) = e
        .call(
            Request::post(path)
                .header(header::CONTENT_TYPE, "application/json")
                .header(
                    "DPoP",
                    key.sign_raw(&h, &key.claims("POST", &htu(path), None)),
                )
                .body(Body::from(
                    json!({"login_txn": v["login_txn"],
                           "credential_finalization": b64(&fin.message.serialize())})
                    .to_string(),
                ))
                .unwrap(),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    e.cleanup().await;
}

/// A bound refresh family needs a proof of the same key; a missing proof or another key is
/// treated like theft (session revoked, family revoked, identity.session.revoked). An unbound
/// session stays unbound.
#[tokio::test]
async fn dpop_bound_refresh_requires_the_same_key() {
    let Some(e) = env().await else { return };
    let t = alice(&e, "pw").await;
    let rpath = "/api/v2/auth/token/refresh";
    let key = PKey::es256();
    let (_, rt, _) = login_with(&e, t, "alice@acme.test", "pw", Some(&key))
        .await
        .unwrap();
    // Same key: rotates, the new access token and refresh token stay bound.
    let (s, h, v) = refresh_dpop(&e, &rt, Some(key.proof("POST", &htu(rpath), None))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        claims_of(v["access_token"].as_str().unwrap())["cnf"]["jkt"],
        json!(key.jkt())
    );
    let rt2 = rt_of(&h);
    assert_eq!(
        scalar_i64(
            e.pool(),
            "SELECT count(*) FROM refresh_tokens WHERE key_jkt IS NULL"
        )
        .await,
        0
    );
    // A proof from another key: refused and the session is revoked.
    let (s, _, _) = refresh_dpop(
        &e,
        &rt2,
        Some(PKey::es256().proof("POST", &htu(rpath), None)),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(
        scalar_i64(
            e.pool(),
            "SELECT count(*) FROM sessions WHERE state = 'revoked' AND generation = 2"
        )
        .await,
        1
    );
    assert_eq!(
        scalar_i64(
            e.pool(),
            "SELECT count(*) FROM refresh_tokens WHERE state <> 'revoked'"
        )
        .await,
        0
    );
    assert_eq!(
        scalar_i64(
            e.pool(),
            "SELECT count(*) FROM outbox WHERE event_type = 'identity.session.revoked' \
             AND position(convert_to('dpop_key_mismatch', 'UTF8') in payload) > 0"
        )
        .await,
        1
    );
    // The right key can no longer refresh the revoked family.
    let (s, _, _) = refresh_dpop(&e, &rt2, Some(key.proof("POST", &htu(rpath), None))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // A bound token without any proof: same treatment.
    let (_, rt, _) = login_with(&e, t, "alice@acme.test", "pw", Some(&key))
        .await
        .unwrap();
    let (s, _, _) = refresh_dpop(&e, &rt, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(
        scalar_i64(
            e.pool(),
            "SELECT count(*) FROM sessions WHERE state = 'revoked'"
        )
        .await,
        2
    );
    // A bound token with a broken proof (wrong htu) of its own key: same treatment.
    let (_, rt, _) = login_with(&e, t, "alice@acme.test", "pw", Some(&key))
        .await
        .unwrap();
    let (s, _, _) = refresh_dpop(&e, &rt, Some(key.proof("POST", &htu("/x"), None))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(
        scalar_i64(
            e.pool(),
            "SELECT count(*) FROM sessions WHERE state = 'revoked'"
        )
        .await,
        3
    );

    // Unbound session: a valid proof at refresh does not bind it; a broken proof is refused
    // without revoking.
    let (_, rt, _) = login(&e, t, "alice@acme.test", "pw").await.unwrap();
    let (s, h, v) = refresh_dpop(&e, &rt, Some(key.proof("POST", &htu(rpath), None))).await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        claims_of(v["access_token"].as_str().unwrap())
            .get("cnf")
            .is_none()
    );
    let rt = rt_of(&h);
    let (s, _, _) = refresh_dpop(&e, &rt, Some(key.proof("GET", &htu(rpath), None))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(
        scalar_i64(
            e.pool(),
            "SELECT count(*) FROM sessions WHERE state = 'active'"
        )
        .await,
        1
    );
    let (s, _, _) = refresh_dpop(&e, &rt, None).await;
    assert_eq!(s, StatusCode::OK);
    e.cleanup().await;
}

fn dead_pool() -> DomainPool {
    let cfg = cs_common::config::DomainConfig {
        url: cs_common::Secret::new("postgres://yugabyte@127.0.0.1:1/cs_identity".to_owned()),
        pool: cs_common::config::PoolConfig {
            acquire_timeout_ms: 300,
            ..Default::default()
        },
    };
    DomainPool::connect_lazy(
        ID,
        &cfg,
        cs_db::RetryPolicy {
            max_attempts: 2,
            max_elapsed: Duration::from_millis(500),
            base_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(50),
        },
    )
    .unwrap()
}

/// `[R6]` rev 14: `dpop_jti` is the only replay record, shared by every node; table
/// unreachable → 503 (fail closed).
#[tokio::test]
async fn dpop_replay_store_dpop_jti_only_and_fail_closed() {
    let tenant = TenantId::generate().unwrap();
    dpop_fallback_part(tenant).await;
}

/// Replay store on `dpop_jti`: shared across nodes, purged by the sweep, fail-closed.
async fn dpop_fallback_part(tenant: TenantId) {
    use cs_identity::dpop::{ReplayStore, ReplayVerdict, verify_proof};
    let Some(e) = env().await else { return };
    let key = PKey::es256();
    let path = "/api/v2/me";
    let proof = || {
        verify_proof(
            &key.proof("GET", &htu(path), None),
            "GET",
            &htu(path),
            None,
            now(),
        )
        .unwrap()
    };
    let store = ReplayStore::new(e.pool().clone());
    let p = proof();
    assert_eq!(store.check(tenant, &p).await.unwrap(), ReplayVerdict::Fresh);
    assert_eq!(
        store.check(tenant, &p).await.unwrap(),
        ReplayVerdict::Replayed
    );
    // Shared across nodes: another node's store sees the same record.
    let other = ReplayStore::new(e.pool().clone());
    assert_eq!(
        other.check(tenant, &p).await.unwrap(),
        ReplayVerdict::Replayed
    );
    // Same jti under another tenant is a different entry.
    let t2 = TenantId::generate().unwrap();
    assert_eq!(other.check(t2, &p).await.unwrap(), ReplayVerdict::Fresh);
    exec(
        e.pool(),
        "DELETE FROM dpop_jti WHERE tenant_id <> (SELECT min(tenant_id) FROM dpop_jti)",
    )
    .await;
    // Rows carry their expiry bucket and are purged by the bounded sweep once expired.
    assert_eq!(
        scalar_i64(
            e.pool(),
            "SELECT count(*) FROM dpop_jti WHERE expiry_bucket IS NOT NULL \
             AND expires_at > now() + interval '100 seconds'"
        )
        .await,
        1
    );
    exec(
        e.pool(),
        "UPDATE dpop_jti SET expires_at = now() - interval '1 second'",
    )
    .await;
    assert_eq!(
        cs_identity::dpop::sweep_expired_jti(e.pool(), 500, 20).await,
        1
    );
    // Table unreachable → 503 unavailable (fail closed).
    let dead = ReplayStore::new(dead_pool());
    let err = dead.check(tenant, &proof()).await.unwrap_err();
    assert_eq!(err.status(), 503);
    // Through HTTP: a DPoP-bound request fails closed with 503.
    let auth = Arc::new(
        AuthService::new(
            e.pool().clone(),
            e.kms.clone(),
            DOMAIN,
            SessionPolicy::default(),
        )
        .with_replay_store(ReplayStore::new(e.pool().clone())),
    );
    let e2 = env_with(e, auth);
    let t = alice(&e2, "pw").await;
    let (v, _, _) = login_with(&e2, t, "alice@acme.test", "pw", Some(&key))
        .await
        .unwrap();
    let at = v["access_token"].as_str().unwrap().to_owned();
    let pr = key.proof("GET", &htu(path), Some(&at));
    assert_eq!(me_dpop(&e2, &at, pr.clone()).await, StatusCode::OK);
    assert_eq!(me_dpop(&e2, &at, pr).await, StatusCode::UNAUTHORIZED);
    let down = Arc::new(
        AuthService::new(
            e2.pool().clone(),
            e2.kms.clone(),
            DOMAIN,
            SessionPolicy::default(),
        )
        .with_replay_store(ReplayStore::new(dead_pool())),
    );
    let e3 = env_with(e2, down);
    let (s, h, v) = with_at(
        &e3,
        "GET",
        path,
        "DPoP",
        &at,
        Some(key.proof("GET", &htu(path), Some(&at))),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{v}");
    assert_eq!(v["code"], json!("unavailable"));
    assert!(h.get("dpop-nonce").is_none());
    e3.cleanup().await;
}

/// The same database and KMS behind another AuthService (another node, or other settings).
fn env_with(e: Env, auth: Arc<AuthService>) -> Env {
    let state = ApiState::new(DOMAIN, vec![], Duration::from_secs(2));
    let app = cs_api::with_middleware(
        cs_api::public_routes().merge(cs_identity::http::routes(auth.clone())),
        state,
        1 << 20,
    );
    Env { auth, app, ..e }
}

// ---------------------------------------------------------------------------------------------
// Step-up (§2.3 [R2]) and re-registration by a step-up session (rev 9)
// ---------------------------------------------------------------------------------------------

/// Re-register through `register/{start,finish}` with the session's access token. Returns the
/// (start, finish) statuses and the failing body.
#[allow(clippy::too_many_arguments)]
async fn reregister(
    e: &Env,
    tenant: TenantId,
    at: &str,
    key: Option<&PKey>,
    purpose: &str,
    pw: &str,
    extra: Value,
) -> (StatusCode, StatusCode, Value) {
    let mut rng = rand_core_06::OsRng;
    let c = ClientRegistration::<Suite>::start(&mut rng, pw.as_bytes()).unwrap();
    let mut body = json!({"purpose": purpose, "registration_request": b64(&c.message.serialize())});
    for (k, v) in extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    let (scheme, sp, fp) = match key {
        Some(k) => (
            "DPoP",
            Some(k.proof("POST", &htu("/api/v2/auth/opaque/register/start"), Some(at))),
            Some(k.proof(
                "POST",
                &htu("/api/v2/auth/opaque/register/finish"),
                Some(at),
            )),
        ),
        None => ("Bearer", None, None),
    };
    let (s, _, v) = with_at(
        e,
        "POST",
        "/api/v2/auth/opaque/register/start",
        scheme,
        at,
        sp,
        Some(body),
    )
    .await;
    if s != StatusCode::OK {
        return (s, s, v);
    }
    let resp =
        RegistrationResponse::<Suite>::deserialize(&unb64(&v["registration_response"])).unwrap();
    let cid = client_identifier(&tenant.as_uuid().to_string(), "alice@acme.test");
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
    let (f, _, fv) = with_at(
        e,
        "POST",
        "/api/v2/auth/opaque/register/finish",
        scheme,
        at,
        fp,
        Some(json!({"registration_txn": v["registration_txn"],
                    "registration_upload": b64(&fin.message.serialize())})),
    )
    .await;
    (s, f, fv)
}

/// Step-up guard: outside the window → 401 with errors[] step_up_required; a body `login`
/// is refused; password change keeps the current session, revokes every other one, and the
/// old password stops working.
#[tokio::test]
async fn step_up_password_change_revokes_other_sessions() {
    let Some(e) = env().await else { return };
    let t = alice(&e, "old-pw").await;
    // Session A (DPoP-bound) and session B (unbound).
    let key = PKey::es256();
    let (a, rt_a, _) = login_with(&e, t, "alice@acme.test", "old-pw", Some(&key))
        .await
        .unwrap();
    let at_a = a["access_token"].as_str().unwrap().to_owned();
    let (b, rt_b, _) = login(&e, t, "alice@acme.test", "old-pw").await.unwrap();
    let at_b = b["access_token"].as_str().unwrap().to_owned();
    let sid_a = a["session_id"].as_str().unwrap().to_owned();
    // A login inside the step-up window does not ask for re-registration.
    assert!(a.get("reregister").is_none(), "{a}");

    // Outside the window (policy default 5 min): step_up_required.
    exec(
        e.pool(),
        "UPDATE sessions SET last_strong_auth_at = now() - interval '6 minutes'",
    )
    .await;
    let (s, _, v) = reregister(&e, t, &at_b, None, "password_change", "new-pw", json!({})).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{v}");
    assert_eq!(v["errors"][0]["code"], json!("step_up_required"));
    assert_eq!(v["errors"][0]["pointer"], json!(""));
    // The reusable guard agrees.
    let claims = e.auth.access_tokens().verify(&at_b, now()).await.unwrap();
    let err = e.auth.require_step_up(&claims).await.unwrap_err();
    assert_eq!(err.status(), 401);
    assert_eq!(
        err.detail(),
        Some("Recent strong authentication is required.")
    );
    // A password reauth brings session B back into the window.
    assert_eq!(
        reauth_call(&e, &at_b, &t.as_uuid().to_string(), "old-pw").await,
        StatusCode::NO_CONTENT
    );
    e.auth.require_step_up(&claims).await.unwrap();
    exec(e.pool(), "UPDATE sessions SET last_strong_auth_at = now()").await;

    // A body login, an unknown purpose, a grant with a purpose: refused.
    let (s, _, v) = reregister(
        &e,
        t,
        &at_a,
        Some(&key),
        "password_change",
        "new-pw",
        json!({"login": "alice@acme.test"}),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(v["errors"][0]["pointer"], json!("/login"));
    let (s, _, _) = reregister(&e, t, &at_a, Some(&key), "other", "new-pw", json!({})).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    // Without an access token.
    let (s, _, _) = e
        .post(
            "/api/v2/auth/opaque/register/start",
            json!({"purpose": "password_change", "registration_request": b64(&[0u8; 32])}),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // Password change from the DPoP-bound session A.
    let (s, f, v) = reregister(
        &e,
        t,
        &at_a,
        Some(&key),
        "password_change",
        "new-pw",
        json!({}),
    )
    .await;
    assert_eq!((s, f), (StatusCode::OK, StatusCode::NO_CONTENT), "{v}");
    // A is kept, B is revoked (generation bumped, family revoked, event).
    assert_eq!(
        scalar_i64(
            e.pool(),
            "SELECT count(*) FROM sessions WHERE state = 'active'"
        )
        .await,
        1
    );
    let active: String = {
        let p = e.pool().clone();
        p.read_snapshot(|tx| {
            Box::pin(async move {
                Ok(sqlx::query_scalar::<_, uuid::Uuid>(
                    "SELECT session_id FROM sessions WHERE state = 'active'",
                )
                .fetch_one(tx.conn())
                .await?
                .to_string())
            })
        })
        .await
        .unwrap()
    };
    assert_eq!(active, sid_a);
    assert_eq!(
        scalar_i64(
            e.pool(),
            "SELECT count(*) FROM outbox WHERE event_type = 'identity.session.revoked' \
             AND position(convert_to('credentials_changed', 'UTF8') in payload) > 0"
        )
        .await,
        1
    );
    assert_eq!(
        scalar_i64(
            e.pool(),
            "SELECT count(*) FROM outbox WHERE event_type = 'identity.credentials.changed' \
             AND position(convert_to('password_change', 'UTF8') in payload) > 0"
        )
        .await,
        1
    );
    assert_eq!(
        with_at(&e, "GET", "/api/v2/me", "Bearer", &at_b, None, None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        refresh_dpop(&e, &rt_b, None).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (s, _, _) = refresh_dpop(
        &e,
        &rt_a,
        Some(key.proof("POST", &htu("/api/v2/auth/token/refresh"), None)),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    // The old password fails, the new one works; the user stays active.
    assert!(login(&e, t, "alice@acme.test", "old-pw").await.is_err());
    login(&e, t, "alice@acme.test", "new-pw").await.unwrap();
    assert_eq!(
        scalar_i64(
            e.pool(),
            "SELECT count(*) FROM users WHERE status = 'active'"
        )
        .await,
        1
    );
    // A registration txn cannot be finished by another session (bound to sid and generation).
    e.cleanup().await;
}

/// `reregister: true` after a login whose registration uses an older server key version;
/// `ksf_upgrade` with the same password moves it to the current version and clears the flag.
#[tokio::test]
async fn reregister_signal_and_ksf_upgrade() {
    let Some(e) = env().await else { return };
    let t = alice(&e, "pw").await;
    let (v, _, _) = login(&e, t, "alice@acme.test", "pw").await.unwrap();
    assert!(v.get("reregister").is_none(), "{v}");
    let (_, _, other) = login(&e, t, "alice@acme.test", "pw").await.unwrap();
    let _ = other;
    // Rotate the OPAQUE server keys; a node loading them now has version 2 as current.
    OpaqueKeys::rotate(e.pool(), e.kms.as_ref()).await.unwrap();
    let auth = Arc::new(AuthService::new(
        e.pool().clone(),
        e.kms.clone(),
        DOMAIN,
        SessionPolicy::default(),
    ));
    let e = env_with(e, auth);
    let (v, _, _) = login(&e, t, "alice@acme.test", "pw").await.unwrap();
    assert_eq!(v["reregister"], json!(true), "{v}");
    let at = v["access_token"].as_str().unwrap();
    let (s, f, b) = reregister(&e, t, at, None, "ksf_upgrade", "pw", json!({})).await;
    assert_eq!((s, f), (StatusCode::OK, StatusCode::NO_CONTENT), "{b}");
    assert_eq!(
        scalar_i64(
            e.pool(),
            "SELECT count(*) FROM opaque_registrations WHERE server_key_version LIKE '%2'"
        )
        .await,
        1
    );
    // ksf_upgrade also revokes the other sessions (rev 9: purpose never weakens revocation).
    assert_eq!(
        scalar_i64(
            e.pool(),
            "SELECT count(*) FROM sessions WHERE state = 'active'"
        )
        .await,
        1
    );
    assert_eq!(
        scalar_i64(
            e.pool(),
            "SELECT count(*) FROM outbox WHERE event_type = 'identity.credentials.changed' \
             AND position(convert_to('ksf_upgrade', 'UTF8') in payload) > 0"
        )
        .await,
        1
    );
    let (v, _, _) = login(&e, t, "alice@acme.test", "pw").await.unwrap();
    assert!(v.get("reregister").is_none(), "{v}");
    // A re-registration txn is bound to its session: another session cannot finish it.
    let (v2, _, _) = login(&e, t, "alice@acme.test", "pw").await.unwrap();
    let at1 = v["access_token"].as_str().unwrap();
    let at2 = v2["access_token"].as_str().unwrap();
    let mut rng = rand_core_06::OsRng;
    let c = ClientRegistration::<Suite>::start(&mut rng, b"pw").unwrap();
    let (s, _, sv) = with_at(
        &e,
        "POST",
        "/api/v2/auth/opaque/register/start",
        "Bearer",
        at1,
        None,
        Some(
            json!({"purpose": "ksf_upgrade", "registration_request": b64(&c.message.serialize())}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let resp =
        RegistrationResponse::<Suite>::deserialize(&unb64(&sv["registration_response"])).unwrap();
    let cid = client_identifier(&t.as_uuid().to_string(), "alice@acme.test");
    let k = ksf();
    let fin = c
        .state
        .finish(
            &mut rng,
            b"pw",
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
    let body = json!({"registration_txn": sv["registration_txn"],
                      "registration_upload": b64(&fin.message.serialize())});
    let (s, _, _) = with_at(
        &e,
        "POST",
        "/api/v2/auth/opaque/register/finish",
        "Bearer",
        at2,
        None,
        Some(body.clone()),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // ... nor can the setup-link path (no Authorization header).
    let (s, _, _) = e.post("/api/v2/auth/opaque/register/finish", body).await;
    assert_ne!(s, StatusCode::NO_CONTENT);
    e.cleanup().await;
}
