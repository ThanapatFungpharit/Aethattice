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
use crate::dpop::{self, ReplayStore, VerifiedProof};
use crate::jws::{AccessClaims, AccessTokens};
use crate::keys::{OpaqueKeys, ServerKeyVersion};
use crate::login::normalize_login;
use crate::notify::Notifier;
use crate::ratelimit::{RateLimiter, RateLimits};
use crate::session::{self, NewTokens, PresentedProof, RefreshOutcome, SessionPolicy};
use crate::token::{self, TokenHash};
use cs_common::error::{Code, Error, ErrorCode, FieldError};
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
    /// (rev 9) `login/finish` only: the registration uses KSF parameters below the current
    /// defaults or an older server key version; the client re-registers (`ksf_upgrade`).
    pub reregister: bool,
}

/// Request context for DPoP (contract rev 8): method, path and the `DPoP` header.
#[derive(Debug, Clone, Copy)]
pub struct RequestCtx<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub dpop: Option<&'a str>,
}

/// `errors[].code` for an operation that needs recent strong authentication (§2.3 `[R2]`).
pub const STEP_UP_REQUIRED: &str = "step_up_required";

/// Re-registration purposes (rev 9).
pub const PURPOSES: &[&str] = &["password_change", "ksf_upgrade"];

pub(crate) fn step_up_required() -> AuthError {
    let detail = "Recent strong authentication is required.".to_owned();
    Error::new(ErrorCode::Unauthenticated)
        .with_detail(detail.clone())
        .with_field_error(FieldError {
            pointer: String::new(),
            code: STEP_UP_REQUIRED.to_owned(),
            detail,
        })
        .into()
}

/// Binding of a re-registration txn to the session and its generation (stored in the txn's
/// `grant_hash`, which a setup link can never match).
fn reregistration_binding(session: SessionId, generation: i64) -> TokenHash {
    TokenHash::of(&format!(
        "cs-reregistration/v1:{}:{generation}",
        session.as_uuid()
    ))
}

/// Sealed state of a re-registration txn: KSF params ‖ purpose index ‖ generation.
fn rereg_bytes(ksf: &KsfParams, purpose: u8, generation: i64) -> Vec<u8> {
    let mut v = ksf_bytes(ksf);
    v.push(purpose);
    v.extend_from_slice(&generation.to_be_bytes());
    v
}

fn rereg_parse(b: &[u8]) -> Option<(KsfParams, &'static str, i64)> {
    if b.len() != 21 {
        return None;
    }
    let ksf = ksf_parse(&b[..12])?;
    let purpose = PURPOSES.get(usize::from(b[12]))?;
    let generation = i64::from_be_bytes(b[13..21].try_into().ok()?);
    Some((ksf, purpose, generation))
}

/// Whether stored KSF parameters are below the current defaults (rev 9 `reregister`).
pub(crate) fn ksf_below_default(k: &KsfParams) -> bool {
    let d = KsfParams::DEFAULT;
    k.m_kib < d.m_kib || k.t < d.t || k.p < d.p
}

#[derive(Serialize)]
pub(crate) struct CredentialsChanged {
    pub(crate) tenant_id: TenantId,
    pub(crate) user_id: UserId,
    pub(crate) method: &'static str,
    pub(crate) reason: &'static str,
}

#[derive(Serialize)]
struct UserUpdated {
    tenant_id: TenantId,
    user_id: UserId,
    status: &'static str,
}

pub(crate) fn unauthenticated() -> AuthError {
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

pub(crate) fn invalid(pointer: &str, detail: &str) -> AuthError {
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
pub(crate) fn parse_tenant(s: &str) -> AuthResult<TenantId> {
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

pub(crate) fn to_i32(v: u32) -> i32 {
    i32::try_from(v).unwrap_or(i32::MAX)
}

pub(crate) fn ksf_from_row(m: i32, t: i32, p: i32) -> KsfParams {
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
                   grant_hash, key_version, sealed_state, expires_at, session_id, expiry_bucket) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now() + make_interval(secs => $10::float8), $11, $12)",
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
            .bind(expiry_bucket(hash.as_bytes()))
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

/// `errors[].code` for a sign-in that needs a second factor (contract §6.1, rev 11).
pub const MFA_REQUIRED: &str = "mfa_required";

/// 401 with `errors[] = [{pointer: "", code: "mfa_required"}]` (rev 11: enrolment-only
/// session outside its routes, or an `auth_txn` presented to the wrong endpoint).
pub(crate) fn mfa_required_error() -> AuthError {
    let detail = "A second factor is required.".to_owned();
    Error::new(ErrorCode::Unauthenticated)
        .with_detail(detail.clone())
        .with_field_error(FieldError {
            pointer: String::new(),
            code: MFA_REQUIRED.to_owned(),
            detail,
        })
        .into()
}

/// Routes an enrolment-only session may call (rev 11): `webauthn/register/*`,
/// `me/recovery-codes` (POST, GET), `GET /me` and logout.
pub fn enrolment_allowed(method: &str, path: &str) -> bool {
    matches!(
        (method, path),
        ("POST", "/api/v2/auth/webauthn/register/start")
            | ("POST", "/api/v2/auth/webauthn/register/finish")
            | ("POST" | "GET", "/api/v2/me/recovery-codes")
            | ("GET", "/api/v2/me")
            | ("POST", "/api/v2/auth/logout")
    )
}

/// Refuse a sign-in without a DPoP proof when `dpop_first_party_required` = 1 (rev 11).
pub(crate) fn dpop_proof_required() -> AuthError {
    Error::new(ErrorCode::Unauthenticated)
        .with_detail("A DPoP proof is required.")
        .into()
}

/// The authentication service.
pub struct AuthService {
    pub(crate) pool: DomainPool,
    kms: Arc<dyn Kms>,
    keys: OnceCell<Arc<OpaqueKeys>>,
    pub(crate) tokens: AccessTokens,
    pub(crate) policy: SessionPolicy,
    last_sweep: AtomicI64,
    pub(crate) replay: ReplayStore,
    /// WebAuthn relying party (rp id = deployment domain, origin `https://<domain>`).
    pub(crate) webauthn: Option<Arc<webauthn_rs::Webauthn>>,
    /// Rate limits of the authentication endpoints (contract §5).
    pub(crate) limiter: Arc<RateLimiter>,
    /// Out-of-band delivery of recovery links (contract §4).
    pub(crate) notifier: Arc<dyn Notifier>,
    /// Dummy Argon2id hash for unknown recovery-code IDs (same timing path, rev 11).
    pub(crate) dummy_code_hash: OnceCell<String>,
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
    Ok(Box<NewTokens>, bool),
    Mfa(Secret<String>, Vec<&'static str>),
    Failed,
}

/// Result of a password sign-in (contract §2.4, §2.3 rev 11).
#[derive(Debug)]
pub enum LoginResult {
    Authenticated(Authenticated),
    MfaRequired(crate::mfa::MfaChallenge),
}

impl LoginResult {
    /// The session, or `None` for `mfa_required`.
    pub fn authenticated(self) -> Option<Authenticated> {
        match self {
            LoginResult::Authenticated(a) => Some(a),
            LoginResult::MfaRequired(_) => None,
        }
    }
}

impl AuthService {
    /// `pool` must be the identity domain's pool.
    pub fn new(
        pool: DomainPool,
        kms: Arc<dyn Kms>,
        deployment_domain: &str,
        policy: SessionPolicy,
    ) -> Self {
        let pool_for_replay = pool.clone();
        Self {
            pool,
            tokens: AccessTokens::new(kms.clone(), deployment_domain),
            kms,
            keys: OnceCell::new(),
            policy,
            last_sweep: AtomicI64::new(0),
            replay: ReplayStore::table_only(pool_for_replay),
            webauthn: crate::webauthn::relying_party(deployment_domain),
            limiter: Arc::new(RateLimiter::local_only(RateLimits::default())),
            notifier: Arc::new(crate::notify::Discard),
            dummy_code_hash: OnceCell::new(),
        }
    }

    /// Replace the rate limiter (`cs serve`: policy limits, `[cluster] node_count`, Valkey).
    pub fn with_rate_limiter(mut self, limiter: RateLimiter) -> Self {
        self.limiter = Arc::new(limiter);
        self
    }

    /// Replace the recovery-link notifier (contract §4).
    pub fn with_notifier(mut self, notifier: Arc<dyn Notifier>) -> Self {
        self.notifier = notifier;
        self
    }

    /// Use Valkey (`[valkey] url`) as the primary DPoP replay store `[R6]`; without it the
    /// `dpop_jti` table is used alone.
    pub fn with_valkey(mut self, url: &str) -> AuthResult<Self> {
        self.replay = ReplayStore::new(self.pool.clone(), Some(url))?;
        Ok(self)
    }

    /// Replace the replay store (tests: unreachable stores).
    pub fn with_replay_store(mut self, replay: ReplayStore) -> Self {
        self.replay = replay;
        self
    }

    /// `https://<deployment domain>` + `path`: the expected DPoP `htu` (rev 8).
    fn expected_htu(&self, path: &str) -> String {
        format!("{}{path}", self.tokens.issuer())
    }

    /// Verify an optional DPoP proof on a request without an access token (login/finish,
    /// refresh): form, signature, claims, then the shared replay check.
    pub(crate) async fn proof_without_token(
        &self,
        tenant: TenantId,
        ctx: &RequestCtx<'_>,
    ) -> AuthResult<Option<VerifiedProof>> {
        let Some(proof) = ctx.dpop else {
            return Ok(None);
        };
        let v = dpop::verify_proof(
            proof,
            ctx.method,
            &self.expected_htu(ctx.path),
            None,
            unix_now(),
        )?;
        self.replay.require_fresh(tenant, &v).await?;
        Ok(Some(v))
    }

    /// Authenticate a request by its access token (contract rev 8): a `cnf`-bound token must
    /// come as `Authorization: DPoP <token>` with a fresh proof of the bound key carrying
    /// `ath`; an unbound token comes as `Bearer`. Anything else is `unauthenticated`.
    pub async fn authorize(
        &self,
        authorization: Option<&str>,
        ctx: &RequestCtx<'_>,
    ) -> AuthResult<AccessClaims> {
        let claims = self.authorize_token(authorization, ctx).await?;
        // rev 11: an enrolment-only session may call only the enrolment routes.
        if claims.scp.as_deref() == Some(session::SCOPE_MFA_ENROLMENT)
            && !enrolment_allowed(ctx.method, ctx.path)
        {
            return Err(mfa_required_error());
        }
        Ok(claims)
    }

    async fn authorize_token(
        &self,
        authorization: Option<&str>,
        ctx: &RequestCtx<'_>,
    ) -> AuthResult<AccessClaims> {
        let (scheme, token) = authorization
            .and_then(|v| v.split_once(' '))
            .map(|(s, t)| (s, t.trim()))
            .ok_or_else(|| {
                AuthError::from(
                    Error::new(ErrorCode::Unauthenticated).with_detail("Access token required."),
                )
            })?;
        let claims = self.tokens.verify(token, unix_now()).await?;
        if scheme.eq_ignore_ascii_case("bearer") {
            return if claims.cnf.is_some() {
                Err(unauthenticated())
            } else {
                Ok(claims)
            };
        }
        if !scheme.eq_ignore_ascii_case("dpop") {
            return Err(unauthenticated());
        }
        let cnf = claims.cnf.as_ref().ok_or_else(unauthenticated)?;
        let proof = ctx.dpop.ok_or_else(unauthenticated)?;
        let v = dpop::verify_proof(
            proof,
            ctx.method,
            &self.expected_htu(ctx.path),
            Some(token),
            unix_now(),
        )?;
        if v.jkt_b64() != cnf.jkt {
            return Err(unauthenticated());
        }
        let (tenant, _, _) = Self::subject(&claims)?;
        self.replay.require_fresh(tenant, &v).await?;
        Ok(claims)
    }

    /// Step-up guard (contract §2.3 `[R2]`, spec §5.5): the session of `claims` must be
    /// active at the token's generation and have `last_strong_auth_at` within the step-up
    /// window (policy `step_up_window_secs`). Otherwise `unauthenticated`, with
    /// `errors[] = [{pointer: "", code: "step_up_required"}]` when only the window failed.
    pub async fn require_step_up(&self, claims: &AccessClaims) -> AuthResult<()> {
        let (tenant, user, session) = Self::subject(claims)?;
        let (sgen, window) = (claims.sgen, self.policy.step_up_secs);
        let fresh: Option<bool> = self
            .pool
            .read_snapshot(move |tx| {
                Box::pin(async move {
                    Ok(sqlx::query_scalar(
                        "SELECT COALESCE(last_strong_auth_at >= now() - make_interval(secs => $5::float8), false) \
                         FROM sessions WHERE tenant_id = $1 AND session_id = $2 AND user_id = $3 \
                           AND state = 'active' AND generation = $4 \
                           AND now() < idle_expires_at AND now() < absolute_expires_at",
                    )
                    .bind(tenant.as_uuid())
                    .bind(session.as_uuid())
                    .bind(user.as_uuid())
                    .bind(sgen)
                    .bind(window as f64)
                    .fetch_optional(tx.conn())
                    .await?)
                })
            })
            .await?;
        match fresh {
            Some(true) => Ok(()),
            Some(false) => Err(step_up_required()),
            None => Err(unauthenticated()),
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
    pub(crate) fn sweep(&self) {
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
            let jti =
                crate::dpop::sweep_expired_jti(&pool, SWEEP_BATCH_ROWS, SWEEP_MAX_BATCHES).await;
            let ceremonies =
                crate::ceremony::sweep_expired(&pool, SWEEP_BATCH_ROWS, SWEEP_MAX_BATCHES).await;
            tracing::debug!(deleted, jti, ceremonies, "expiry sweep finished");
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
        let tenant_text = tenant;
        let tenant = parse_tenant(tenant)?;
        let login = normalize_login(login).map_err(|e| invalid("/login", &e.to_string()))?;
        // Contract §5: per source, tenant and account, whether or not they exist.
        self.limit("login", source, Some(tenant_text), Some(&login))
            .await?;
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
        user_agent: Option<&str>,
        ctx: &RequestCtx<'_>,
    ) -> AuthResult<LoginResult> {
        let parsed = token::parse(login_txn).map_err(|_| unauthenticated())?;
        // rev 8: a valid proof binds the new session; an invalid one is refused.
        let jkt = self
            .proof_without_token(parsed.tenant_id, ctx)
            .await?
            .map(|p| p.jkt);
        // rev 11: `dpop_first_party_required` = 1 refuses a sign-in without a proof.
        if self.policy.dpop_required && jkt.is_none() {
            return Err(dpop_proof_required());
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
        let (tenant, hash) = (parsed.tenant_id, parsed.hash);
        let policy = self.policy;
        let source = source.to_owned();
        let ua = user_agent.map(str::to_owned);
        let out = self
            .pool
            .transaction(move |tx| {
                let (keys, fin, source, ua) =
                    (keys.clone(), fin.clone(), source.clone(), ua.clone());
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
                    // rev 9: signal a transparent re-registration when the stored KSF
                    // parameters or the server key version are not current.
                    let reg: Option<(i32, i32, i32)> = sqlx::query_as(
                        "SELECT ksf_m_kib, ksf_t, ksf_p FROM opaque_registrations \
                         WHERE tenant_id = $1 AND user_id = $2",
                    )
                    .bind(tenant.as_uuid())
                    .bind(uid)
                    .fetch_optional(tx.conn())
                    .await?;
                    let reregister = t.key_version != keys.current().version
                        || reg.is_none_or(|(m, t, p)| ksf_below_default(&ksf_from_row(m, t, p)));
                    // rev 11: MFA decision.
                    let f =
                        crate::mfa::factors_in_tx(tx, tenant, user, policy.mfa_required).await?;
                    let scope = match f.decision() {
                        crate::mfa::Decision::Session => None,
                        crate::mfa::Decision::Enrol => Some(session::SCOPE_MFA_ENROLMENT),
                        crate::mfa::Decision::Challenge(methods) => {
                            let state = crate::mfa::mfa_state(reregister);
                            let txn = crate::ceremony::insert_in_tx(
                                tx,
                                &keys,
                                crate::ceremony::New {
                                    tenant,
                                    kind: crate::ceremony::Kind::Mfa,
                                    source: &source,
                                    user: Some(user),
                                    session: None,
                                    state: &state,
                                },
                            )
                            .await?;
                            return Ok(LoginOutcome::Mfa(txn, methods));
                        }
                    };
                    let nt = session::create_session(
                        tx,
                        tenant,
                        user,
                        session::NewSession {
                            amr: vec!["pwd"],
                            jkt,
                            scope,
                            user_agent: ua,
                        },
                        policy,
                    )
                    .await?;
                    Ok(LoginOutcome::Ok(Box::new(nt), reregister))
                })
            })
            .await?;
        match out {
            LoginOutcome::Ok(nt, reregister) => {
                let mut a = self.finish_tokens(*nt).await?;
                a.reregister = reregister;
                Ok(LoginResult::Authenticated(a))
            }
            LoginOutcome::Mfa(auth_txn, methods) => {
                Ok(LoginResult::MfaRequired(crate::mfa::MfaChallenge {
                    auth_txn,
                    methods,
                }))
            }
            LoginOutcome::Failed => Err(self.mfa_or(login_txn, unauthenticated()).await),
        }
    }

    pub(crate) async fn finish_tokens(&self, nt: NewTokens) -> AuthResult<Authenticated> {
        let expires_in = nt.claims.exp - nt.claims.iat;
        let at = self.tokens.sign(nt.claims).await?;
        Ok(Authenticated {
            access_token: Secret::new(at),
            expires_in,
            session_id: nt.session_id,
            refresh_token: nt.refresh.token,
            refresh_max_age: nt.refresh_max_age,
            reregister: false,
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
        // Contract §5: registration is rate limited per source, tenant and account.
        self.limit(
            "register",
            source,
            Some(&g.tenant_id.as_uuid().to_string()),
            Some(&login),
        )
        .await?;
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
        // [R5]: a recovery grant re-registers an active user.
        let (uid, user_login) = match user {
            Some(u) => u,
            None => match self.recovery_grant_user(tenant, ghash).await? {
                Some(u) => u,
                None => return Err(self.mfa_or(grant, grant_required()).await),
            },
        };
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
    ///
    /// - Setup link: stores the registration, marks the link used and activates the user.
    /// - Recovery grant (`[R5]`): one identity transaction replaces the OPAQUE registration,
    ///   revokes every session of the user (generation bump each) and every refresh family,
    ///   invalidates the recovery code used (if any), marks the request `completed` (which uses
    ///   the grant up) and writes `identity.credentials.changed`, `identity.session.revoked` per
    ///   session and `identity.recovery.completed`. A used grant is `unauthenticated`; an
    ///   expired one also moves the request to `expired`.
    /// - `idempotency_key`: a retry with the same key and body replays the stored outcome
    ///   (M0 idempotency records, scope = the registration txn).
    pub async fn register_finish(
        &self,
        registration_txn: &str,
        registration_upload: &[u8],
        source: &str,
        idempotency_key: Option<&cs_common::idempotency::IdempotencyKey>,
    ) -> AuthResult<()> {
        use cs_db::idempotency::{
            Begin, IdempotencyRecords, IdempotencyScope, RequestBody, StoredResponse,
            request_digest,
        };
        let parsed = token::parse(registration_txn).map_err(|_| grant_required())?;
        self.limit(
            "register",
            source,
            Some(&parsed.tenant_id.as_uuid().to_string()),
            None,
        )
        .await?;
        let upload = RegistrationUpload::<Suite>::deserialize(registration_upload)
            .map_err(|_| invalid("/registration_upload", "malformed registration_upload"))?;
        let file = ServerRegistration::<Suite>::finish(upload)
            .serialize()
            .to_vec();
        let keys = self.keys().await?;
        let (tenant, hash) = (parsed.tenant_id, parsed.hash);
        let source = source.to_owned();
        // Idempotency scope: the registration txn (a deterministic v7-shaped principal id
        // derived from its hash, so a retry after the txn was consumed finds the record).
        let idem = match idempotency_key {
            Some(k) => {
                let mut b = [0u8; 16];
                b.copy_from_slice(&hash.as_bytes()[..16]);
                let u = uuid::Builder::from_bytes(b)
                    .with_variant(uuid::Variant::RFC4122)
                    .with_version(uuid::Version::SortRand)
                    .into_uuid();
                let principal =
                    cs_common::id::PrincipalId::from_uuid(u).map_err(Error::internal)?;
                let body = serde_json::json!({
                    "registration_txn": registration_txn,
                    "registration_upload": hash_hex(registration_upload),
                })
                .to_string();
                let digest = request_digest(
                    "POST",
                    "/api/v2/auth/opaque/register/finish",
                    &std::collections::BTreeMap::new(),
                    RequestBody::Json(body.as_bytes()),
                )?;
                Some((
                    IdempotencyScope {
                        tenant_id: tenant,
                        principal_id: principal,
                        key: k.clone(),
                    },
                    digest,
                ))
            }
            None => None,
        };
        let retention = self.policy.idempotency_retention_hours;
        let out = self
            .pool
            .transaction(move |tx| {
                let (keys, file, source, idem) =
                    (keys.clone(), file.clone(), source.clone(), idem.clone());
                Box::pin(async move {
                    if let Some((scope, digest)) = &idem
                        && let Begin::Replay(r) =
                            IdempotencyRecords::begin(tx, scope, digest, retention).await?
                    {
                        return Ok(if r.status == 204 {
                            RegOutcome::Done
                        } else {
                            RegOutcome::Refused
                        });
                    }
                    let out =
                        register_finish_in_tx(tx, &keys, tenant, &hash, &file, &source).await?;
                    if let Some((scope, _)) = &idem {
                        let status = if matches!(out, RegOutcome::Done) {
                            204
                        } else {
                            401
                        };
                        IdempotencyRecords::complete(
                            tx,
                            scope,
                            &StoredResponse {
                                status,
                                body: Vec::new(),
                            },
                        )
                        .await?;
                    }
                    Ok(out)
                })
            })
            .await?;
        match out {
            RegOutcome::Done => Ok(()),
            RegOutcome::Refused => Err(unauthenticated()),
        }
    }

    /// `register/start {purpose, registration_request}` with the session's access token
    /// (contract rev 9): password change or transparent KSF / key-version upgrade. Needs the
    /// step-up window; the txn is bound to the session's `sid`, user and generation.
    pub async fn register_start_session(
        &self,
        claims: &AccessClaims,
        purpose: &str,
        registration_request: &[u8],
        source: &str,
    ) -> AuthResult<RegisterStart> {
        let (tenant, user, session) = Self::subject(claims)?;
        let purpose_idx = PURPOSES
            .iter()
            .position(|p| *p == purpose)
            .and_then(|i| u8::try_from(i).ok())
            .ok_or_else(|| invalid("/purpose", "purpose must be password_change or ksf_upgrade"))?;
        let request = RegistrationRequest::<Suite>::deserialize(registration_request)
            .map_err(|_| invalid("/registration_request", "malformed registration_request"))?;
        self.require_step_up(claims).await?;
        let keys = self.keys().await?;
        self.sweep();
        let sgen = claims.sgen;
        let login: Option<String> = self
            .pool
            .read_snapshot(move |tx| {
                Box::pin(async move {
                    Ok(sqlx::query_scalar(
                        "SELECT u.login FROM users u JOIN tenants t ON t.tenant_id = u.tenant_id \
                         WHERE u.tenant_id = $1 AND u.user_id = $2 AND u.status = 'active' \
                           AND t.state = 'active'",
                    )
                    .bind(tenant.as_uuid())
                    .bind(user.as_uuid())
                    .fetch_optional(tx.conn())
                    .await?)
                })
            })
            .await?;
        let login = login.ok_or_else(unauthenticated)?;
        let k = keys.current();
        let cred_id = client_identifier(&tenant.as_uuid().to_string(), &login);
        let resp = ServerRegistration::<Suite>::start(&k.setup, request, cred_id.as_bytes())
            .map_err(|_| invalid("/registration_request", "invalid registration_request"))?;
        let ksf = KsfParams::DEFAULT;
        let txn = token::generate(tenant).map_err(Error::internal)?;
        let sealed = k.seal(
            &rereg_bytes(&ksf, purpose_idx, sgen),
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
                session: Some(session),
                grant: Some(reregistration_binding(session, sgen)),
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

    /// `register/finish {registration_txn, registration_upload}` with the session's access
    /// token (contract rev 9) → 204. In one identity transaction: replaces the registration
    /// with the current KSF parameters and key version, revokes **every other** session and
    /// refresh family of the user (whatever the purpose), keeps the current session, and
    /// emits `identity.credentials.changed` with reason = purpose.
    pub async fn register_finish_session(
        &self,
        claims: &AccessClaims,
        registration_txn: &str,
        registration_upload: &[u8],
        source: &str,
    ) -> AuthResult<()> {
        let (tenant, user, session) = Self::subject(claims)?;
        let parsed = token::parse(registration_txn).map_err(|_| unauthenticated())?;
        if parsed.tenant_id != tenant {
            return Err(unauthenticated());
        }
        let upload = RegistrationUpload::<Suite>::deserialize(registration_upload)
            .map_err(|_| invalid("/registration_upload", "malformed registration_upload"))?;
        let file = ServerRegistration::<Suite>::finish(upload)
            .serialize()
            .to_vec();
        let keys = self.keys().await?;
        let hash = parsed.hash;
        let (source, sgen, window) = (source.to_owned(), claims.sgen, self.policy.step_up_secs);
        self.pool
            .transaction(move |tx| {
                let (keys, file, source) = (keys.clone(), file.clone(), source.clone());
                Box::pin(async move {
                    let fail = || DbError::app(unauthenticated());
                    let t = take_txn(tx, tenant, &hash, "registration")
                        .await?
                        .ok_or_else(fail)?;
                    let binding = reregistration_binding(session, sgen);
                    if t.source != source
                        || t.session != Some(session.into_uuid())
                        || t.user != Some(user.into_uuid())
                        || t.grant.as_deref() != Some(binding.as_bytes().as_slice())
                    {
                        return Err(fail());
                    }
                    let k = keys.get(t.key_version).ok_or_else(fail)?;
                    let st = k
                        .open(&t.sealed, &txn_ad(&tenant, &hash, "registration"))
                        .ok_or_else(fail)?;
                    let (ksf, purpose, txn_gen) = rereg_parse(&st).ok_or_else(fail)?;
                    if txn_gen != sgen {
                        return Err(fail());
                    }
                    if !ksf.is_valid() {
                        return Err(DbError::app(invalid(
                            "/ksf_params",
                            "KSF parameters outside the allowed bounds",
                        )));
                    }
                    // The session must still be active at this generation and within the
                    // step-up window (checked again under lock).
                    let fresh: Option<bool> = sqlx::query_scalar(
                        "SELECT COALESCE(last_strong_auth_at >= now() - make_interval(secs => $5::float8), false) \
                         FROM sessions WHERE tenant_id = $1 AND session_id = $2 AND user_id = $3 \
                           AND state = 'active' AND generation = $4 \
                           AND now() < idle_expires_at AND now() < absolute_expires_at FOR UPDATE",
                    )
                    .bind(tenant.as_uuid())
                    .bind(session.as_uuid())
                    .bind(user.as_uuid())
                    .bind(sgen)
                    .bind(window as f64)
                    .fetch_optional(tx.conn())
                    .await?;
                    match fresh {
                        Some(true) => {}
                        Some(false) => return Err(DbError::app(step_up_required())),
                        None => return Err(fail()),
                    }
                    let active: Option<bool> = sqlx::query_scalar(
                        "SELECT u.status = 'active' AND t.state = 'active' FROM users u \
                         JOIN tenants t ON t.tenant_id = u.tenant_id \
                         WHERE u.tenant_id = $1 AND u.user_id = $2 FOR SHARE OF u",
                    )
                    .bind(tenant.as_uuid())
                    .bind(user.as_uuid())
                    .fetch_optional(tx.conn())
                    .await?;
                    if active != Some(true) {
                        return Err(fail());
                    }
                    let n = sqlx::query(
                        "UPDATE opaque_registrations SET password_file = $3, ksf_m_kib = $4, \
                           ksf_t = $5, ksf_p = $6, server_key_version = $7, \
                           version = version + 1, updated_at = now() \
                         WHERE tenant_id = $1 AND user_id = $2",
                    )
                    .bind(tenant.as_uuid())
                    .bind(user.as_uuid())
                    .bind(&file)
                    .bind(to_i32(ksf.m_kib))
                    .bind(to_i32(ksf.t))
                    .bind(to_i32(ksf.p))
                    .bind(k.label())
                    .execute(tx.conn())
                    .await?
                    .rows_affected();
                    if n != 1 {
                        return Err(fail());
                    }
                    // rev 9: revoke every other session (and refresh family) of the user.
                    let others: Vec<Uuid> = sqlx::query_scalar(
                        "SELECT session_id FROM sessions WHERE tenant_id = $1 AND user_id = $2 \
                           AND session_id <> $3 AND state = 'active'",
                    )
                    .bind(tenant.as_uuid())
                    .bind(user.as_uuid())
                    .bind(session.as_uuid())
                    .fetch_all(tx.conn())
                    .await?;
                    for o in others {
                        let o = SessionId::from_uuid(o)
                            .map_err(|e| DbError::Invalid(e.to_string()))?;
                        session::revoke_session(tx, tenant, o, "credentials_changed").await?;
                    }
                    Outbox::append(
                        tx,
                        NewEvent {
                            tenant_id: Some(tenant),
                            event_type: "identity.credentials.changed",
                            event_version: 1,
                            partition_key: user.into_uuid(),
                            payload: &CredentialsChanged {
                                tenant_id: tenant,
                                user_id: user,
                                method: "opaque",
                                reason: purpose,
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
        ctx: &RequestCtx<'_>,
    ) -> AuthResult<Authenticated> {
        let parsed = token::parse(refresh_token).map_err(|_| unauthenticated())?;
        let (tenant, hash) = (parsed.tenant_id, parsed.hash);
        let key = idempotency_key.to_owned();
        let policy = self.policy;
        // rev 8: the binding decision is made under the token's row lock; a replay store
        // outage fails closed (503) before anything is touched.
        let proof = match self.proof_without_token(tenant, ctx).await {
            Ok(Some(p)) => PresentedProof::Valid(p.jkt),
            Ok(None) => PresentedProof::None,
            Err(e) if matches!(e.code(), Code::Core(ErrorCode::Unavailable)) => return Err(e),
            Err(_) => PresentedProof::Invalid,
        };
        let out = self
            .pool
            .transaction(move |tx| {
                let key = key.clone();
                Box::pin(async move {
                    session::refresh_in_tx(tx, tenant, hash, &key, policy, proof).await
                })
            })
            .await?;
        match out {
            RefreshOutcome::Issued(nt) => self.finish_tokens(*nt).await,
            RefreshOutcome::Reuse => {
                tracing::warn!(tenant = %tenant.as_uuid(), "refresh token reuse: session revoked");
                Err(unauthenticated())
            }
            RefreshOutcome::KeyMismatch => {
                tracing::warn!(tenant = %tenant.as_uuid(), "DPoP-bound refresh without a proof of its key: session revoked");
                Err(unauthenticated())
            }
            RefreshOutcome::Invalid => Err(self.mfa_or(refresh_token, unauthenticated()).await),
        }
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
    pub(crate) fn subject(claims: &AccessClaims) -> AuthResult<(TenantId, UserId, SessionId)> {
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

/// Number of `auth_txns.expiry_bucket` values (migration 0102).
pub const EXPIRY_BUCKETS: i16 = 16;

/// Expiry bucket of a txn: first byte of its (random) hash, mod [`EXPIRY_BUCKETS`].
pub fn expiry_bucket(txn_hash: &[u8]) -> i16 {
    txn_hash
        .first()
        .map_or(0, |b| i16::from(*b) % EXPIRY_BUCKETS)
}

/// Delete expired `auth_txns` rows in bounded batches: at most `batch_rows` rows per
/// transaction and at most `max_batches` transactions. Each batch is a short, single-domain
/// transaction retried on 40001/40P01 like any other; a failed batch stops the run (the next
/// interval resumes it), since expired rows are already unusable and only cost space.
/// Returns the number of rows deleted.
pub async fn sweep_expired_txns(pool: &DomainPool, batch_rows: i64, max_batches: u32) -> u64 {
    sweep_bucketed(
        pool,
        "auth_txns",
        "tenant_id, txn_hash",
        batch_rows,
        max_batches,
    )
    .await
}

/// Bounded expiry sweep over a table with the hash-bucketed expiry index of migration 0102
/// (App. E). Each batch walks the buckets one by one (`expiry_bucket = $b`, so every read is a
/// point lookup on the hash column plus a range on `expires_at`, which the planner always
/// serves from the bucketed index), then the NULL bucket written by N-1 nodes, all within one
/// row budget of `batch_rows`. `table` and `key` are compile-time constants of this crate.
pub(crate) async fn sweep_bucketed(
    pool: &DomainPool,
    table: &'static str,
    key: &'static str,
    batch_rows: i64,
    max_batches: u32,
) -> u64 {
    let mut total = 0u64;
    for _ in 0..max_batches {
        let r = pool
            .transaction(move |tx| {
                Box::pin(async move {
                    let mut left = batch_rows;
                    let buckets = (0..EXPIRY_BUCKETS).map(Some).chain(std::iter::once(None));
                    for b in buckets {
                        if left <= 0 {
                            break;
                        }
                        let cond = if b.is_some() {
                            "expiry_bucket = $2"
                        } else {
                            "expiry_bucket IS NULL"
                        };
                        let q = format!(
                            "DELETE FROM {table} WHERE ({key}) IN (SELECT {key} FROM {table} \
                             WHERE {cond} AND expires_at < now() LIMIT $1)"
                        );
                        let mut q = sqlx::query(sqlx::AssertSqlSafe(q)).bind(left);
                        if let Some(b) = b {
                            q = q.bind(b);
                        }
                        let n = q.execute(tx.conn()).await?.rows_affected();
                        left -= i64::try_from(n).unwrap_or(left);
                    }
                    Ok(u64::try_from(batch_rows - left).unwrap_or(0))
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
                tracing::warn!(error = %e, table, "expiry sweep batch failed");
                break;
            }
        }
    }
    total
}

/// Unix time in seconds.
pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Outcome of `register/finish`.
#[derive(Debug, Clone, Copy)]
enum RegOutcome {
    Done,
    /// A used or expired recovery grant (`unauthenticated`); the state change commits.
    Refused,
}

/// BLAKE3 hex of a request part (idempotency digest input).
fn hash_hex(b: &[u8]) -> String {
    blake3::hash(b).to_hex().to_string()
}

#[derive(Serialize)]
struct RecoveryCompleted {
    tenant_id: TenantId,
    user_id: UserId,
    request_id: Uuid,
    sessions_revoked: usize,
}

async fn upsert_registration(
    tx: &mut DomainTx,
    tenant: TenantId,
    uid: Uuid,
    file: &[u8],
    ksf: &KsfParams,
    key_label: &str,
) -> Result<(), DbError> {
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
    .bind(file)
    .bind(to_i32(ksf.m_kib))
    .bind(to_i32(ksf.t))
    .bind(to_i32(ksf.p))
    .bind(key_label)
    .execute(tx.conn())
    .await?;
    Ok(())
}

/// The body of `register/finish` inside its transaction (see [`AuthService::register_finish`]).
async fn register_finish_in_tx(
    tx: &mut DomainTx,
    keys: &OpaqueKeys,
    tenant: TenantId,
    hash: &TokenHash,
    file: &[u8],
    source: &str,
) -> Result<RegOutcome, DbError> {
    let fail = || DbError::app(grant_required());
    let t = take_txn(tx, tenant, hash, "registration")
        .await?
        .ok_or_else(fail)?;
    if t.source != source {
        return Err(fail());
    }
    let k = keys.get(t.key_version).ok_or_else(fail)?;
    let st = k
        .open(&t.sealed, &txn_ad(&tenant, hash, "registration"))
        .ok_or_else(fail)?;
    let ksf = ksf_parse(&st).ok_or_else(fail)?;
    if !ksf.is_valid() {
        return Err(DbError::app(invalid(
            "/ksf_params",
            "KSF parameters outside the allowed bounds",
        )));
    }
    let (uid, grant) = (t.user.ok_or_else(fail)?, t.grant.ok_or_else(fail)?);
    let user = UserId::from_uuid(uid).map_err(|e| DbError::Invalid(e.to_string()))?;
    // Setup link: consume it (CAS on state).
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
    if used == 1 {
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
        upsert_registration(tx, tenant, uid, file, &ksf, &k.label()).await?;
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
        return Ok(RegOutcome::Done);
    }
    // [R5] recovery grant: lock the request.
    let req: Option<(Uuid, String, bool, Option<String>)> = sqlx::query_as(
        "SELECT request_id, state, grant_expires_at > now(), code_id FROM recovery_requests \
         WHERE tenant_id = $1 AND grant_hash = $2 AND user_id = $3 FOR UPDATE",
    )
    .bind(tenant.as_uuid())
    .bind(&grant)
    .bind(uid)
    .fetch_optional(tx.conn())
    .await?;
    let Some((rid, state, live, code_id)) = req else {
        return Err(fail());
    };
    if state != "granted" {
        return Ok(RegOutcome::Refused);
    }
    if !live {
        sqlx::query(
            "UPDATE recovery_requests SET state = 'expired', version = version + 1, \
               updated_at = now() WHERE tenant_id = $1 AND request_id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(rid)
        .execute(tx.conn())
        .await?;
        return Ok(RegOutcome::Refused);
    }
    if !crate::webauthn::loginable_in_tx(tx, tenant, user).await? {
        return Err(DbError::app(unauthenticated()));
    }
    // The recovery code used must still be unused (it may have been spent meanwhile).
    if let Some(c) = &code_id
        && !crate::recovery::use_code_in_tx(tx, tenant, user, c).await?
    {
        return Err(DbError::app(unauthenticated()));
    }
    sqlx::query(
        "UPDATE recovery_requests SET state = 'completed', version = version + 1, \
           updated_at = now() WHERE tenant_id = $1 AND request_id = $2",
    )
    .bind(tenant.as_uuid())
    .bind(rid)
    .execute(tx.conn())
    .await?;
    upsert_registration(tx, tenant, uid, file, &ksf, &k.label()).await?;
    // Every session and refresh family of the user: there is no state in which the new
    // password exists and an old session is still valid.
    let sessions: Vec<Uuid> = sqlx::query_scalar(
        "SELECT session_id FROM sessions WHERE tenant_id = $1 AND user_id = $2 AND state = 'active'",
    )
    .bind(tenant.as_uuid())
    .bind(uid)
    .fetch_all(tx.conn())
    .await?;
    let n = sessions.len();
    for s in sessions {
        let s = SessionId::from_uuid(s).map_err(|e| DbError::Invalid(e.to_string()))?;
        session::revoke_session(tx, tenant, s, "recovery").await?;
    }
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
                reason: "recovery",
            },
        },
    )
    .await?;
    Outbox::append(
        tx,
        NewEvent {
            tenant_id: Some(tenant),
            event_type: "identity.recovery.completed",
            event_version: 1,
            partition_key: uid,
            payload: &RecoveryCompleted {
                tenant_id: tenant,
                user_id: user,
                request_id: rid,
                sessions_revoked: n,
            },
        },
    )
    .await?;
    Ok(RegOutcome::Done)
}
