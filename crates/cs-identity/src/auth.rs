//! Authentication service: OPAQUE registration and login (contract rev 6 §2.1, spec §5.2),
//! sessions, refresh and logout (contract §3).
//!
//! OPAQUE (`opaque-ke` 4.0.1, suite [`cs_identity_wire::Suite`], context `cs-opaque/v1`, client
//! identifier `<tenant UUID>/<normalized login>`, server identifier = server public key):
//! - `login_start` runs the same work for every request: the same three reads, opaque-ke's
//!   `ServerLogin::start` (with `None` as password file for an unknown, disabled or unregistered
//!   account, which is opaque-ke's dummy-record path) and the same txn insert. KSF parameters
//!   for a non-loginable account come from the `[R3]` keyed PRF over `tenant ‖ login` choosing
//!   from the tenant's current distribution of stored parameter sets (weighted by count), or
//!   from the deployment default distribution for an unknown tenant or a tenant with no
//!   registration. The response shape and status never depend on account existence.
//! - Txn records (`auth_txns`) are 60 s, single use (consumed by `DELETE … RETURNING` in the
//!   finishing transaction), bound to tenant, login, kind and source; their state is sealed with
//!   associated data `tenant ‖ txn_hash ‖ kind`.
//! - Registration needs a grant: in M1 slice 2 the first-administrator setup link. `register/
//!   finish` stores the registration, marks the link used and activates the user in one
//!   identity transaction, writing `identity.credentials.changed` and `identity.user.updated`.
//!   Sessions are issued only by `login/finish`.

use crate::admin::{AdminError as AuthError, AdminResult as AuthResult};
use crate::jws::{AccessClaims, AccessTokens};
use crate::keys::{OpaqueKeys, ServerKeyVersion};
use crate::login::normalize_login;
use crate::session::{self, NewTokens, RefreshOutcome, SessionPolicy};
use crate::token::{self, TokenHash};
use cs_common::error::{Error, ErrorCode, FieldError};
use cs_common::id::{SessionId, TenantId, UserId};
use cs_common::secret::Secret;
use cs_db::outbox::{NewEvent, Outbox};
use cs_db::{DbError, DomainPool, DomainTx};
use cs_identity_wire::{CONTEXT, KsfParams, Suite, client_identifier};
use cs_kms::Kms;
use opaque_ke::{
    CredentialFinalization, CredentialRequest, Identifiers, RegistrationRequest,
    RegistrationUpload, ServerLogin, ServerLoginParameters, ServerRegistration,
};
use serde::Serialize;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use tokio::sync::OnceCell;
use uuid::Uuid;

/// Txn lifetime (contract §2.1).
pub const TXN_TTL_SECS: i64 = 60;
/// `errors[].code` for `register/*` without a valid grant (contract §6.1).
pub const REGISTRATION_GRANT_REQUIRED: &str = "registration_grant_required";
/// Interval between lazy sweeps of expired txn rows on one node.
const SWEEP_INTERVAL_SECS: i64 = 60;
/// Rows deleted per sweep transaction (App. E / §21.3: bounded, short transactions).
pub const SWEEP_BATCH_ROWS: i64 = 500;
/// Maximum sweep transactions per sweep run; the remainder waits for the next interval.
pub const SWEEP_MAX_BATCHES: u32 = 20;

/// Result of `login/start`.
#[derive(Debug)]
pub struct LoginStart {
    pub login_txn: Secret<String>,
    pub credential_response: Vec<u8>,
    pub ksf_params: KsfParams,
}

/// Result of `register/start`.
#[derive(Debug)]
pub struct RegisterStart {
    pub registration_txn: Secret<String>,
    pub registration_response: Vec<u8>,
    pub ksf_params: KsfParams,
}

/// A successful authentication or refresh (contract §2.4), plus the refresh token for the
/// cookie.
#[derive(Debug)]
pub struct Authenticated {
    pub access_token: Secret<String>,
    pub expires_in: i64,
    pub session_id: SessionId,
    pub refresh_token: Secret<String>,
    pub refresh_max_age: i64,
}

#[derive(Serialize)]
struct CredentialsChanged {
    tenant_id: TenantId,
    user_id: UserId,
    method: &'static str,
    reason: &'static str,
}

#[derive(Serialize)]
struct UserUpdated {
    tenant_id: TenantId,
    user_id: UserId,
    status: &'static str,
}

fn unauthenticated() -> AuthError {
    // One detail for wrong password, unknown account, disabled user and bad txn (§6).
    Error::new(ErrorCode::Unauthenticated)
        .with_detail("Authentication failed.")
        .into()
}

fn grant_required() -> AuthError {
    let detail = "A valid registration grant is required.".to_owned();
    Error::new(ErrorCode::PermissionDenied)
        .with_detail(detail.clone())
        .with_field_error(FieldError {
            pointer: "/grant".to_owned(),
            code: REGISTRATION_GRANT_REQUIRED.to_owned(),
            detail,
        })
        .into()
}

fn invalid(pointer: &str, detail: &str) -> AuthError {
    Error::new(ErrorCode::InvalidRequest)
        .with_detail(detail.to_owned())
        .with_field_error(FieldError {
            pointer: pointer.to_owned(),
            code: ErrorCode::InvalidRequest.as_str().to_owned(),
            detail: detail.to_owned(),
        })
        .into()
}

/// Associated data of sealed txn state.
fn txn_ad(tenant: &TenantId, hash: &TokenHash, kind: &str) -> Vec<u8> {
    let mut ad = tenant.as_bytes().to_vec();
    ad.extend_from_slice(hash.as_bytes());
    ad.extend_from_slice(kind.as_bytes());
    ad
}

/// Parse the canonical tenant UUID text (rev 5: never a name or slug).
fn parse_tenant(s: &str) -> AuthResult<TenantId> {
    let bad = || {
        invalid(
            "/tenant",
            "tenant must be a tenant ID (canonical UUID text)",
        )
    };
    let u = Uuid::parse_str(s).map_err(|_| bad())?;
    if u.hyphenated().to_string() != s {
        return Err(bad());
    }
    TenantId::from_uuid(u).map_err(|_| bad())
}

/// `[R3]` choice from a weighted distribution, keyed by the PRF over `tenant ‖ login`.
/// `dist` must be sorted; an empty distribution means the deployment default.
pub fn choose_params(
    k: &ServerKeyVersion,
    tenant: &TenantId,
    login: &str,
    dist: &[(KsfParams, i64)],
) -> KsfParams {
    let total: i64 = dist.iter().map(|(_, n)| (*n).max(0)).sum();
    if total <= 0 {
        return KsfParams::DEFAULT;
    }
    let mut input = tenant.as_bytes().to_vec();
    input.extend_from_slice(login.as_bytes());
    let h = k.prf(&input);
    let mut b = [0u8; 8];
    b.copy_from_slice(&h[..8]);
    // Modulo bias is at most total / 2^64 (total ≤ number of registrations).
    let mut pick = (u64::from_be_bytes(b) % total.unsigned_abs()) as i64;
    for (p, n) in dist {
        let n = (*n).max(0);
        if pick < n {
            return *p;
        }
        pick -= n;
    }
    KsfParams::DEFAULT
}

/// Source binding for txns: IPv4 /32 or IPv6 /64 (`[R12]`).
pub fn source_of(addr: Option<std::net::IpAddr>) -> String {
    match addr {
        Some(std::net::IpAddr::V4(a)) => a.to_string(),
        Some(std::net::IpAddr::V6(a)) => match a.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = a.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
        None => "unknown".to_owned(),
    }
}

fn to_i32(v: u32) -> i32 {
    i32::try_from(v).unwrap_or(i32::MAX)
}

fn ksf_from_row(m: i32, t: i32, p: i32) -> KsfParams {
    KsfParams {
        m_kib: u32::try_from(m).unwrap_or(0),
        t: u32::try_from(t).unwrap_or(0),
        p: u32::try_from(p).unwrap_or(0),
    }
}

fn ksf_bytes(k: &KsfParams) -> Vec<u8> {
    let mut v = k.m_kib.to_be_bytes().to_vec();
    v.extend_from_slice(&k.t.to_be_bytes());
    v.extend_from_slice(&k.p.to_be_bytes());
    v
}

fn ksf_parse(b: &[u8]) -> Option<KsfParams> {
    if b.len() != 12 {
        return None;
    }
    let u = |i: usize| b[i..i + 4].try_into().ok().map(u32::from_be_bytes);
    Some(KsfParams {
        m_kib: u(0)?,
        t: u(4)?,
        p: u(8)?,
    })
}

struct TxnInsert<'a> {
    tenant: TenantId,
    hash: TokenHash,
    kind: &'static str,
    login: &'a str,
    source: &'a str,
    user: Option<UserId>,
    session: Option<SessionId>,
    grant: Option<TokenHash>,
    key_version: i32,
    sealed: Vec<u8>,
}

async fn insert_txn(pool: &DomainPool, t: TxnInsert<'_>) -> AuthResult<()> {
    let (login, source) = (t.login.to_owned(), t.source.to_owned());
    let (tenant, hash, kind, user, session, grant, kv, sealed) = (
        t.tenant,
        t.hash,
        t.kind,
        t.user,
        t.session,
        t.grant,
        t.key_version,
        t.sealed,
    );
    pool.transaction(move |tx| {
        let (login, source, sealed) = (login.clone(), source.clone(), sealed.clone());
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO auth_txns (tenant_id, txn_hash, kind, login, source, user_id, \
                   grant_hash, key_version, sealed_state, expires_at, session_id) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now() + make_interval(secs => $10::float8), $11)",
            )
            .bind(tenant.as_uuid())
            .bind(hash.as_bytes().as_slice())
            .bind(kind)
            .bind(login)
            .bind(source)
            .bind(user.map(UserId::into_uuid))
            .bind(grant.as_ref().map(|g| g.as_bytes().to_vec()))
            .bind(kv)
            .bind(sealed)
            .bind(TXN_TTL_SECS as f64)
            .bind(session.map(SessionId::into_uuid))
            .execute(tx.conn())
            .await?;
            Ok(())
        })
    })
    .await
    .map_err(AuthError::from)
}

/// A consumed txn row.
struct Txn {
    login: String,
    source: String,
    user: Option<Uuid>,
    session: Option<Uuid>,
    grant: Option<Vec<u8>>,
    key_version: i32,
    sealed: Vec<u8>,
}

/// Consume (delete) a live txn of `kind`; `None` if missing, expired or of another kind.
async fn take_txn(
    tx: &mut DomainTx,
    tenant: TenantId,
    hash: &TokenHash,
    kind: &str,
) -> Result<Option<Txn>, DbError> {
    type R = (
        String,
        String,
        Option<Uuid>,
        Option<Uuid>,
        Option<Vec<u8>>,
        i32,
        Vec<u8>,
        bool,
    );
    let r: Option<R> = sqlx::query_as(
        "DELETE FROM auth_txns WHERE tenant_id = $1 AND txn_hash = $2 AND kind = $3 \
         RETURNING login, source, user_id, session_id, grant_hash, key_version, sealed_state, \
           expires_at > now()",
    )
    .bind(tenant.as_uuid())
    .bind(hash.as_bytes().as_slice())
    .bind(kind)
    .fetch_optional(tx.conn())
    .await?;
    Ok(r.and_then(
        |(login, source, user, session, grant, key_version, sealed, live)| {
            live.then_some(Txn {
                login,
                source,
                user,
                session,
                grant,
                key_version,
                sealed,
            })
        },
    ))
}

/// The authentication service.
pub struct AuthService {
    pool: DomainPool,
    kms: Arc<dyn Kms>,
    keys: OnceCell<Arc<OpaqueKeys>>,
    tokens: AccessTokens,
    policy: SessionPolicy,
    last_sweep: AtomicI64,
}

impl std::fmt::Debug for AuthService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthService")
            .field("tokens", &self.tokens)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

enum LoginOutcome {
    Ok(Box<NewTokens>),
    Failed,
}

impl AuthService {
    /// `pool` must be the identity domain's pool.
    pub fn new(
        pool: DomainPool,
        kms: Arc<dyn Kms>,
        deployment_domain: &str,
        policy: SessionPolicy,
    ) -> Self {
        Self {
            pool,
            tokens: AccessTokens::new(kms.clone(), deployment_domain),
            kms,
            keys: OnceCell::new(),
            policy,
            last_sweep: AtomicI64::new(0),
        }
    }

    pub fn access_tokens(&self) -> &AccessTokens {
        &self.tokens
    }

    /// OPAQUE server keys, loaded (or created) on first use.
    pub async fn keys(&self) -> AuthResult<Arc<OpaqueKeys>> {
        self.keys
            .get_or_try_init(|| async {
                OpaqueKeys::load_or_init(&self.pool, self.kms.as_ref())
                    .await
                    .map(Arc::new)
            })
            .await
            .cloned()
    }

    /// Start a sweep of expired txn rows, at most once per interval per node (lazy
    /// reclamation). It runs in the background, so a request never waits for it.
    fn sweep(&self) {
        let now = unix_now();
        let last = self.last_sweep.load(Ordering::Relaxed);
        if now - last < SWEEP_INTERVAL_SECS
            || self
                .last_sweep
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            return;
        }
        let pool = self.pool.clone();
        tokio::spawn(async move {
            let deleted = sweep_expired_txns(&pool, SWEEP_BATCH_ROWS, SWEEP_MAX_BATCHES).await;
            tracing::debug!(deleted, "auth txn sweep finished");
        });
    }

    // ----- login -----

    /// `login/start` (contract §2.1).
    pub async fn login_start(
        &self,
        tenant: &str,
        login: &str,
        credential_request: &[u8],
        source: &str,
    ) -> AuthResult<LoginStart> {
        let tenant = parse_tenant(tenant)?;
        let login = normalize_login(login).map_err(|e| invalid("/login", &e.to_string()))?;
        let request = CredentialRequest::<Suite>::deserialize(credential_request)
            .map_err(|_| invalid("/credential_request", "malformed credential_request"))?;
        let keys = self.keys().await?;
        self.sweep();

        type Reg = (Uuid, String, Vec<u8>, i32, i32, i32, String);
        type DistRow = (i32, i32, i32, i64);
        let login_q = login.clone();
        let (reg, dist): (Option<Reg>, Vec<DistRow>) = self
            .pool
            .read_snapshot(move |tx| {
                let login = login_q.clone();
                Box::pin(async move {
                    // The same three statements run for every request.
                    let tenant_active: Option<String> = sqlx::query_scalar(
                        "SELECT state FROM tenants WHERE tenant_id = $1",
                    )
                    .bind(tenant.as_uuid())
                    .fetch_optional(tx.conn())
                    .await?;
                    let reg: Option<Reg> = sqlx::query_as(
                        "SELECT u.user_id, u.status, r.password_file, r.ksf_m_kib, r.ksf_t, r.ksf_p, \
                           r.server_key_version \
                         FROM users u JOIN opaque_registrations r \
                           ON r.tenant_id = u.tenant_id AND r.user_id = u.user_id \
                         WHERE u.tenant_id = $1 AND u.login = $2",
                    )
                    .bind(tenant.as_uuid())
                    .bind(&login)
                    .fetch_optional(tx.conn())
                    .await?;
                    let dist: Vec<(i32, i32, i32, i64)> = sqlx::query_as(
                        "SELECT ksf_m_kib, ksf_t, ksf_p, count(*) FROM opaque_registrations \
                         WHERE tenant_id = $1 GROUP BY ksf_m_kib, ksf_t, ksf_p \
                         ORDER BY ksf_m_kib, ksf_t, ksf_p",
                    )
                    .bind(tenant.as_uuid())
                    .fetch_all(tx.conn())
                    .await?;
                    let active = tenant_active.as_deref() == Some("active");
                    Ok((reg.filter(|r| active && r.1 == "active"), dist))
                })
            })
            .await?;

        let cred_id = client_identifier(&tenant.as_uuid().to_string(), &login);
        // A loginable account: active tenant, active user, registration whose key version is
        // loaded and whose password file parses. Anything else takes the dummy path.
        let known = reg.and_then(|(uid, _, file, m, t, p, kv)| {
            let k = keys.by_label(&kv)?;
            let file = ServerRegistration::<Suite>::deserialize(&file).ok()?;
            let user = UserId::from_uuid(uid).ok()?;
            // Never offer parameters outside the rev 7 bounds (none are ever stored).
            let ksf = Some(ksf_from_row(m, t, p)).filter(KsfParams::is_valid)?;
            Some((user, file, ksf, k))
        });
        let (user, file, ksf, k) = match known {
            Some((u, f, ksf, k)) => (Some(u), Some(f), ksf, k),
            None => {
                let k = keys.current();
                let mut d: Vec<(KsfParams, i64)> = dist
                    .iter()
                    .map(|(m, t, p, n)| (ksf_from_row(*m, *t, *p), *n))
                    .filter(|(k, _)| k.is_valid())
                    .collect();
                d.sort();
                let ksf = choose_params(&k, &tenant, &login, &d);
                (None, None, ksf, k)
            }
        };
        let params = ServerLoginParameters {
            context: Some(CONTEXT),
            identifiers: Identifiers {
                client: Some(cred_id.as_bytes()),
                server: None,
            },
        };
        let start = ServerLogin::start(
            &mut rand_core_06::OsRng,
            &k.setup,
            file,
            request,
            cred_id.as_bytes(),
            params,
        )
        .map_err(|_| unauthenticated())?;
        let txn = token::generate(tenant).map_err(Error::internal)?;
        let state = zeroize::Zeroizing::new(start.state.serialize().to_vec());
        let sealed = k.seal(&state, &txn_ad(&tenant, &txn.hash, "login"))?;
        insert_txn(
            &self.pool,
            TxnInsert {
                tenant,
                hash: txn.hash,
                kind: "login",
                login: &login,
                source,
                user,
                session: None,
                grant: None,
                key_version: k.version,
                sealed,
            },
        )
        .await?;
        Ok(LoginStart {
            login_txn: txn.token,
            credential_response: start.message.serialize().to_vec(),
            ksf_params: ksf,
        })
    }

    /// `login/finish` (contract §2.1): on success, a session (contract §2.4).
    pub async fn login_finish(
        &self,
        login_txn: &str,
        credential_finalization: &[u8],
        source: &str,
    ) -> AuthResult<Authenticated> {
        let parsed = token::parse(login_txn).map_err(|_| unauthenticated())?;
        let fin = CredentialFinalization::<Suite>::deserialize(credential_finalization).map_err(
            |_| {
                invalid(
                    "/credential_finalization",
                    "malformed credential_finalization",
                )
            },
        )?;
        let keys = self.keys().await?;
        let (tenant, hash) = (parsed.tenant_id, parsed.hash);
        let policy = self.policy;
        let source = source.to_owned();
        let out = self
            .pool
            .transaction(move |tx| {
                let (keys, fin, source) = (keys.clone(), fin.clone(), source.clone());
                Box::pin(async move {
                    let Some(t) = take_txn(tx, tenant, &hash, "login").await? else {
                        return Ok(LoginOutcome::Failed);
                    };
                    if t.source != source {
                        return Ok(LoginOutcome::Failed);
                    }
                    let Some(k) = keys.get(t.key_version) else {
                        return Ok(LoginOutcome::Failed);
                    };
                    let Some(state) = k.open(&t.sealed, &txn_ad(&tenant, &hash, "login")) else {
                        return Ok(LoginOutcome::Failed);
                    };
                    let Ok(server_login) = ServerLogin::<Suite>::deserialize(&state) else {
                        return Ok(LoginOutcome::Failed);
                    };
                    let cred_id = client_identifier(&tenant.as_uuid().to_string(), &t.login);
                    let params = ServerLoginParameters {
                        context: Some(CONTEXT),
                        identifiers: Identifiers {
                            client: Some(cred_id.as_bytes()),
                            server: None,
                        },
                    };
                    let verified = server_login.finish(fin, params).is_ok();
                    let Some(uid) = t.user.filter(|_| verified) else {
                        return Ok(LoginOutcome::Failed);
                    };
                    // Re-check, under lock, that the account is still loginable.
                    let ok: Option<bool> = sqlx::query_scalar(
                        "SELECT u.status = 'active' AND t.state = 'active' FROM users u \
                         JOIN tenants t ON t.tenant_id = u.tenant_id \
                         WHERE u.tenant_id = $1 AND u.user_id = $2 FOR SHARE OF u",
                    )
                    .bind(tenant.as_uuid())
                    .bind(uid)
                    .fetch_optional(tx.conn())
                    .await?;
                    if ok != Some(true) {
                        return Ok(LoginOutcome::Failed);
                    }
                    let user =
                        UserId::from_uuid(uid).map_err(|e| DbError::Invalid(e.to_string()))?;
                    let nt = session::create_in_tx(tx, tenant, user, &["pwd"], policy).await?;
                    Ok(LoginOutcome::Ok(Box::new(nt)))
                })
            })
            .await?;
        match out {
            LoginOutcome::Ok(nt) => self.finish_tokens(*nt).await,
            LoginOutcome::Failed => Err(unauthenticated()),
        }
    }

    async fn finish_tokens(&self, nt: NewTokens) -> AuthResult<Authenticated> {
        let expires_in = nt.claims.exp - nt.claims.iat;
        let at = self.tokens.sign(nt.claims).await?;
        Ok(Authenticated {
            access_token: Secret::new(at),
            expires_in,
            session_id: nt.session_id,
            refresh_token: nt.refresh.token,
            refresh_max_age: nt.refresh_max_age,
        })
    }

    // ----- registration -----

    /// `register/start {grant, login, registration_request}` (contract rev 5 §2.1).
    pub async fn register_start(
        &self,
        grant: &str,
        login: &str,
        registration_request: &[u8],
        source: &str,
    ) -> AuthResult<RegisterStart> {
        let g = token::parse(grant).map_err(|_| grant_required())?;
        let login = normalize_login(login).map_err(|e| invalid("/login", &e.to_string()))?;
        let request = RegistrationRequest::<Suite>::deserialize(registration_request)
            .map_err(|_| invalid("/registration_request", "malformed registration_request"))?;
        let keys = self.keys().await?;
        self.sweep();
        let (tenant, ghash) = (g.tenant_id, g.hash);
        let user: Option<(Uuid, String)> = self
            .pool
            .read_snapshot(move |tx| {
                Box::pin(async move {
                    Ok(sqlx::query_as(
                        "SELECT u.user_id, u.login FROM setup_links l \
                         JOIN users u ON u.tenant_id = l.tenant_id AND u.user_id = l.user_id \
                         JOIN tenants t ON t.tenant_id = l.tenant_id \
                         WHERE l.tenant_id = $1 AND l.token_hash = $2 AND l.state = 'active' \
                           AND l.expires_at > now() AND u.status = 'invited' AND t.state = 'active'",
                    )
                    .bind(tenant.as_uuid())
                    .bind(ghash.as_bytes().as_slice())
                    .fetch_optional(tx.conn())
                    .await?)
                })
            })
            .await?;
        let (uid, user_login) = user.ok_or_else(grant_required)?;
        if user_login != login {
            return Err(invalid(
                "/login",
                "login does not match the registration grant",
            ));
        }
        let user = UserId::from_uuid(uid).map_err(Error::internal)?;
        let k = keys.current();
        let cred_id = client_identifier(&tenant.as_uuid().to_string(), &login);
        let resp = ServerRegistration::<Suite>::start(&k.setup, request, cred_id.as_bytes())
            .map_err(|_| invalid("/registration_request", "invalid registration_request"))?;
        let ksf = KsfParams::DEFAULT;
        let txn = token::generate(tenant).map_err(Error::internal)?;
        let sealed = k.seal(
            &ksf_bytes(&ksf),
            &txn_ad(&tenant, &txn.hash, "registration"),
        )?;
        insert_txn(
            &self.pool,
            TxnInsert {
                tenant,
                hash: txn.hash,
                kind: "registration",
                login: &login,
                source,
                user: Some(user),
                session: None,
                grant: Some(ghash),
                key_version: k.version,
                sealed,
            },
        )
        .await?;
        Ok(RegisterStart {
            registration_txn: txn.token,
            registration_response: resp.message.serialize().to_vec(),
            ksf_params: ksf,
        })
    }

    /// `register/finish {registration_txn, registration_upload}` → 204, consuming the grant.
    pub async fn register_finish(
        &self,
        registration_txn: &str,
        registration_upload: &[u8],
        source: &str,
    ) -> AuthResult<()> {
        let parsed = token::parse(registration_txn).map_err(|_| grant_required())?;
        let upload = RegistrationUpload::<Suite>::deserialize(registration_upload)
            .map_err(|_| invalid("/registration_upload", "malformed registration_upload"))?;
        let file = ServerRegistration::<Suite>::finish(upload)
            .serialize()
            .to_vec();
        let keys = self.keys().await?;
        let (tenant, hash) = (parsed.tenant_id, parsed.hash);
        let source = source.to_owned();
        self.pool
            .transaction(move |tx| {
                let (keys, file, source) = (keys.clone(), file.clone(), source.clone());
                Box::pin(async move {
                    let fail = || DbError::app(grant_required());
                    let t = take_txn(tx, tenant, &hash, "registration")
                        .await?
                        .ok_or_else(fail)?;
                    if t.source != source {
                        return Err(fail());
                    }
                    let k = keys.get(t.key_version).ok_or_else(fail)?;
                    let st = k
                        .open(&t.sealed, &txn_ad(&tenant, &hash, "registration"))
                        .ok_or_else(fail)?;
                    let ksf = ksf_parse(&st).ok_or_else(fail)?;
                    if !ksf.is_valid() {
                        return Err(DbError::app(invalid(
                            "/ksf_params",
                            "KSF parameters outside the allowed bounds",
                        )));
                    }
                    let (uid, grant) = (t.user.ok_or_else(fail)?, t.grant.ok_or_else(fail)?);
                    // Consume the grant (CAS on state).
                    let used = sqlx::query(
                        "UPDATE setup_links SET state = 'used', used_at = now(), version = version + 1 \
                         WHERE tenant_id = $1 AND token_hash = $2 AND user_id = $3 \
                           AND state = 'active' AND expires_at > now()",
                    )
                    .bind(tenant.as_uuid())
                    .bind(&grant)
                    .bind(uid)
                    .execute(tx.conn())
                    .await?
                    .rows_affected();
                    if used != 1 {
                        return Err(fail());
                    }
                    let activated = sqlx::query(
                        "UPDATE users SET status = 'active', version = version + 1, updated_at = now() \
                         WHERE tenant_id = $1 AND user_id = $2 AND status = 'invited'",
                    )
                    .bind(tenant.as_uuid())
                    .bind(uid)
                    .execute(tx.conn())
                    .await?
                    .rows_affected();
                    if activated != 1 {
                        return Err(fail());
                    }
                    sqlx::query(
                        "INSERT INTO opaque_registrations (tenant_id, user_id, password_file, \
                           ksf_m_kib, ksf_t, ksf_p, server_key_version, version) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, 1) \
                         ON CONFLICT (tenant_id, user_id) DO UPDATE SET \
                           password_file = EXCLUDED.password_file, ksf_m_kib = EXCLUDED.ksf_m_kib, \
                           ksf_t = EXCLUDED.ksf_t, ksf_p = EXCLUDED.ksf_p, \
                           server_key_version = EXCLUDED.server_key_version, \
                           version = opaque_registrations.version + 1, updated_at = now()",
                    )
                    .bind(tenant.as_uuid())
                    .bind(uid)
                    .bind(&file)
                    .bind(to_i32(ksf.m_kib))
                    .bind(to_i32(ksf.t))
                    .bind(to_i32(ksf.p))
                    .bind(k.label())
                    .execute(tx.conn())
                    .await?;
                    let user =
                        UserId::from_uuid(uid).map_err(|e| DbError::Invalid(e.to_string()))?;
                    Outbox::append(
                        tx,
                        NewEvent {
                            tenant_id: Some(tenant),
                            event_type: "identity.credentials.changed",
                            event_version: 1,
                            partition_key: uid,
                            payload: &CredentialsChanged {
                                tenant_id: tenant,
                                user_id: user,
                                method: "opaque",
                                reason: "setup_link",
                            },
                        },
                    )
                    .await?;
                    Outbox::append(
                        tx,
                        NewEvent {
                            tenant_id: Some(tenant),
                            event_type: "identity.user.updated",
                            event_version: 1,
                            partition_key: uid,
                            payload: &UserUpdated {
                                tenant_id: tenant,
                                user_id: user,
                                status: "active",
                            },
                        },
                    )
                    .await?;
                    Ok(())
                })
            })
            .await
            .map_err(AuthError::from)
    }

    // ----- tokens -----

    /// `POST /api/v2/auth/token/refresh` (contract §3 `[R1]`).
    pub async fn refresh(
        &self,
        refresh_token: &str,
        idempotency_key: &str,
    ) -> AuthResult<Authenticated> {
        let parsed = token::parse(refresh_token).map_err(|_| unauthenticated())?;
        let (tenant, hash) = (parsed.tenant_id, parsed.hash);
        let key = idempotency_key.to_owned();
        let policy = self.policy;
        let out = self
            .pool
            .transaction(move |tx| {
                let key = key.clone();
                Box::pin(
                    async move { session::refresh_in_tx(tx, tenant, hash, &key, policy).await },
                )
            })
            .await?;
        match out {
            RefreshOutcome::Issued(nt) => self.finish_tokens(*nt).await,
            RefreshOutcome::Reuse => {
                tracing::warn!(tenant = %tenant.as_uuid(), "refresh token reuse: session revoked");
                Err(unauthenticated())
            }
            RefreshOutcome::Invalid => Err(unauthenticated()),
        }
    }

    /// Verify a bearer access token (no DPoP proof: a `cnf`-bound token is refused).
    pub async fn verify_bearer(&self, access_token: &str) -> AuthResult<AccessClaims> {
        let c = self.tokens.verify(access_token, unix_now()).await?;
        if c.cnf.is_some() {
            return Err(unauthenticated());
        }
        Ok(c)
    }

    /// `POST /api/v2/auth/logout` (contract §3 `[R10]`): revoke the session named by `sid`
    /// (generation bump) and its whole refresh family in one identity transaction.
    pub async fn logout(&self, claims: &AccessClaims) -> AuthResult<()> {
        let uuid = |s: &str| Uuid::parse_str(s).map_err(|_| unauthenticated());
        let tenant = TenantId::from_uuid(uuid(&claims.tid)?).map_err(|_| unauthenticated())?;
        let session = SessionId::from_uuid(uuid(&claims.sid)?).map_err(|_| unauthenticated())?;
        self.pool
            .transaction(move |tx| {
                Box::pin(async move {
                    session::revoke_session(tx, tenant, session, "logout").await?;
                    Ok(())
                })
            })
            .await
            .map_err(AuthError::from)
    }

    /// Tenant, user and session named by verified access-token claims.
    fn subject(claims: &AccessClaims) -> AuthResult<(TenantId, UserId, SessionId)> {
        let uuid = |s: &str| Uuid::parse_str(s).map_err(|_| unauthenticated());
        Ok((
            TenantId::from_uuid(uuid(&claims.tid)?).map_err(|_| unauthenticated())?,
            UserId::from_uuid(uuid(&claims.sub)?).map_err(|_| unauthenticated())?,
            SessionId::from_uuid(uuid(&claims.sid)?).map_err(|_| unauthenticated())?,
        ))
    }

    /// `opaque/reauth/start {credential_request}` (contract rev 7): password step-up on the
    /// session named by the access token. Needs an active session whose generation equals
    /// `sgen`, an active user and a registration.
    pub async fn reauth_start(
        &self,
        claims: &AccessClaims,
        credential_request: &[u8],
        source: &str,
    ) -> AuthResult<LoginStart> {
        let (tenant, user, session) = Self::subject(claims)?;
        let request = CredentialRequest::<Suite>::deserialize(credential_request)
            .map_err(|_| invalid("/credential_request", "malformed credential_request"))?;
        let keys = self.keys().await?;
        let sgen = claims.sgen;
        type Reg = (String, Vec<u8>, i32, i32, i32, String);
        let reg: Option<Reg> = self
            .pool
            .read_snapshot(move |tx| {
                Box::pin(async move {
                    Ok(sqlx::query_as(
                        "SELECT u.login, r.password_file, r.ksf_m_kib, r.ksf_t, r.ksf_p, \
                           r.server_key_version \
                         FROM sessions s \
                         JOIN users u ON u.tenant_id = s.tenant_id AND u.user_id = s.user_id \
                         JOIN opaque_registrations r ON r.tenant_id = u.tenant_id AND r.user_id = u.user_id \
                         JOIN tenants t ON t.tenant_id = s.tenant_id \
                         WHERE s.tenant_id = $1 AND s.session_id = $2 AND s.user_id = $3 \
                           AND s.state = 'active' AND s.generation = $4 \
                           AND now() < s.idle_expires_at AND now() < s.absolute_expires_at \
                           AND u.status = 'active' AND t.state = 'active'",
                    )
                    .bind(tenant.as_uuid())
                    .bind(session.as_uuid())
                    .bind(user.as_uuid())
                    .bind(sgen)
                    .fetch_optional(tx.conn())
                    .await?)
                })
            })
            .await?;
        let (login, file, m, t, p, kv) = reg.ok_or_else(unauthenticated)?;
        let k = keys.by_label(&kv).ok_or_else(unauthenticated)?;
        let file =
            ServerRegistration::<Suite>::deserialize(&file).map_err(|_| unauthenticated())?;
        let ksf = Some(ksf_from_row(m, t, p))
            .filter(KsfParams::is_valid)
            .ok_or_else(unauthenticated)?;
        let cred_id = client_identifier(&tenant.as_uuid().to_string(), &login);
        let params = ServerLoginParameters {
            context: Some(CONTEXT),
            identifiers: Identifiers {
                client: Some(cred_id.as_bytes()),
                server: None,
            },
        };
        let start = ServerLogin::start(
            &mut rand_core_06::OsRng,
            &k.setup,
            Some(file),
            request,
            cred_id.as_bytes(),
            params,
        )
        .map_err(|_| unauthenticated())?;
        let txn = token::generate(tenant).map_err(Error::internal)?;
        let state = zeroize::Zeroizing::new(start.state.serialize().to_vec());
        let sealed = k.seal(&state, &txn_ad(&tenant, &txn.hash, "reauth"))?;
        insert_txn(
            &self.pool,
            TxnInsert {
                tenant,
                hash: txn.hash,
                kind: "reauth",
                login: &login,
                source,
                user: Some(user),
                session: Some(session),
                grant: None,
                key_version: k.version,
                sealed,
            },
        )
        .await?;
        Ok(LoginStart {
            login_txn: txn.token,
            credential_response: start.message.serialize().to_vec(),
            ksf_params: ksf,
        })
    }

    /// `opaque/reauth/finish {reauth_txn, credential_finalization}` → 204 (contract rev 7):
    /// sets `last_strong_auth_at` on the existing session; issues no token.
    pub async fn reauth_finish(
        &self,
        claims: &AccessClaims,
        reauth_txn: &str,
        credential_finalization: &[u8],
        source: &str,
    ) -> AuthResult<()> {
        let (tenant, user, session) = Self::subject(claims)?;
        let parsed = token::parse(reauth_txn).map_err(|_| unauthenticated())?;
        if parsed.tenant_id != tenant {
            return Err(unauthenticated());
        }
        let fin = CredentialFinalization::<Suite>::deserialize(credential_finalization).map_err(
            |_| {
                invalid(
                    "/credential_finalization",
                    "malformed credential_finalization",
                )
            },
        )?;
        let keys = self.keys().await?;
        let hash = parsed.hash;
        let (source, sgen) = (source.to_owned(), claims.sgen);
        let ok = self
            .pool
            .transaction(move |tx| {
                let (keys, fin, source) = (keys.clone(), fin.clone(), source.clone());
                Box::pin(async move {
                    let Some(t) = take_txn(tx, tenant, &hash, "reauth").await? else {
                        return Ok(false);
                    };
                    if t.source != source
                        || t.session != Some(session.into_uuid())
                        || t.user != Some(user.into_uuid())
                    {
                        return Ok(false);
                    }
                    let Some(k) = keys.get(t.key_version) else {
                        return Ok(false);
                    };
                    let Some(state) = k.open(&t.sealed, &txn_ad(&tenant, &hash, "reauth")) else {
                        return Ok(false);
                    };
                    let Ok(server_login) = ServerLogin::<Suite>::deserialize(&state) else {
                        return Ok(false);
                    };
                    let cred_id = client_identifier(&tenant.as_uuid().to_string(), &t.login);
                    let params = ServerLoginParameters {
                        context: Some(CONTEXT),
                        identifiers: Identifiers {
                            client: Some(cred_id.as_bytes()),
                            server: None,
                        },
                    };
                    if server_login.finish(fin, params).is_err() {
                        return Ok(false);
                    }
                    let n = sqlx::query(
                        "UPDATE sessions SET last_strong_auth_at = now(), \
                           amr = CASE WHEN 'pwd' = ANY(amr) THEN amr ELSE array_append(amr, 'pwd') END, \
                           version = version + 1, updated_at = now() \
                         WHERE tenant_id = $1 AND session_id = $2 AND state = 'active' \
                           AND generation = $3 AND now() < idle_expires_at AND now() < absolute_expires_at",
                    )
                    .bind(tenant.as_uuid())
                    .bind(session.as_uuid())
                    .bind(sgen)
                    .execute(tx.conn())
                    .await?
                    .rows_affected();
                    Ok(n == 1)
                })
            })
            .await?;
        if ok { Ok(()) } else { Err(unauthenticated()) }
    }

    /// `GET /api/v2/me` (contract rev 7). The session must be active at the token's `sgen`.
    pub async fn me(&self, claims: &AccessClaims) -> AuthResult<Me> {
        let (tenant, user, session) = Self::subject(claims)?;
        let sgen = claims.sgen;
        type R = (String, Option<String>, String, Vec<String>, i64);
        let r: Option<R> = self
            .pool
            .read_snapshot(move |tx| {
                Box::pin(async move {
                    Ok(sqlx::query_as(
                        "SELECT u.login, u.display_name, u.status, s.amr, \
                           extract(epoch FROM s.auth_time)::bigint \
                         FROM sessions s JOIN users u \
                           ON u.tenant_id = s.tenant_id AND u.user_id = s.user_id \
                         WHERE s.tenant_id = $1 AND s.session_id = $2 AND s.user_id = $3 \
                           AND s.state = 'active' AND s.generation = $4",
                    )
                    .bind(tenant.as_uuid())
                    .bind(session.as_uuid())
                    .bind(user.as_uuid())
                    .bind(sgen)
                    .fetch_optional(tx.conn())
                    .await?)
                })
            })
            .await?;
        let (login, display_name, state, amr, auth_time) = r.ok_or_else(unauthenticated)?;
        Ok(Me {
            user_id: user.as_uuid().to_string(),
            tenant_id: tenant.as_uuid().to_string(),
            login,
            display_name,
            state,
            amr,
            auth_time,
            sid: session.as_uuid().to_string(),
        })
    }
}

/// `GET /api/v2/me` body (contract rev 7). `auth_time` is Unix seconds, as in the token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Me {
    pub user_id: String,
    pub tenant_id: String,
    pub login: String,
    pub display_name: Option<String>,
    pub state: String,
    pub amr: Vec<String>,
    pub auth_time: i64,
    pub sid: String,
}

/// Unix time in seconds.
/// Delete expired `auth_txns` rows in bounded batches: at most `batch_rows` rows per
/// transaction and at most `max_batches` transactions. Each batch is a short, single-domain
/// transaction retried on 40001/40P01 like any other; a failed batch stops the run (the next
/// interval resumes it), since expired rows are already unusable and only cost space.
/// Returns the number of rows deleted.
pub async fn sweep_expired_txns(pool: &DomainPool, batch_rows: i64, max_batches: u32) -> u64 {
    let mut total = 0u64;
    for _ in 0..max_batches {
        let r = pool
            .transaction(move |tx| {
                Box::pin(async move {
                    let n = sqlx::query(
                        "DELETE FROM auth_txns WHERE (tenant_id, txn_hash) IN \
                         (SELECT tenant_id, txn_hash FROM auth_txns WHERE expires_at < now() LIMIT $1)",
                    )
                    .bind(batch_rows)
                    .execute(tx.conn())
                    .await?
                    .rows_affected();
                    Ok(n)
                })
            })
            .await;
        match r {
            Ok(n) => {
                total += n;
                if n < u64::try_from(batch_rows).unwrap_or(0) {
                    break;
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "auth txn sweep batch failed");
                break;
            }
        }
    }
    total
}

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}
