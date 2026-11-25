//! Account recovery (contract §4 `[R5]`, rev 10/11; spec §5.6). Recovery restores sign-in and
//! never touches vault keys.
//!
//! - **Recovery codes** (rev 11): sets of 10, wire format `<code_id>-<secret>` (8 + 20 base32
//!   characters, 100-bit secret), shown once, stored as Argon2id PHC strings in
//!   `recovery_code_entries`. Lookup is by `code_id`; exactly one Argon2id verification runs,
//!   against a dummy hash when the ID is unknown, so timing does not reveal the account.
//!   Generating a set (step-up) replaces the previous one.
//! - **Methods** (`POST /api/v2/auth/recovery/start`):
//!   - `recovery_code`: no waiting period; a valid unused code returns a grant at once.
//!     Unknown tenant or account, wrong code and used code give the same `unauthenticated`.
//!   - `email`: always `202 {state: "pending"}`; for an active user with a verified address a
//!     request is created with `not_before = now + recovery_waiting_period_secs` and the
//!     [`crate::notify::Notifier`] sends an `rt1` link after commit (never in the API).
//!   - `device_approval`: always `202 {state: "pending", recovery_txn}`; a signed-in session of
//!     the user approves it (step-up), which counts as the second factor and skips the wait.
//!   - `admin` assisted: `cs admin recovery start` creates an email-method request.
//! - **Status** (`POST /api/v2/auth/recovery/status`): with the link `token` (email; users
//!   with MFA also send a recovery `code`) or the `recovery_txn` (device approval). Once the
//!   conditions hold the request moves `pending → granted` and the response carries a grant:
//!   an `rt1` token, single use, 15 min, bound to the user, stored as SHA-256. Asking again
//!   while granted replaces the grant hash but keeps the original expiry, so a lost response
//!   can be recovered without extending the grant. An expired grant moves the request to
//!   `expired`.
//! - **Completion** (`register/{start,finish}` with the grant; see
//!   [`crate::auth::AuthService::register_finish`]): one identity transaction replaces the
//!   OPAQUE registration, revokes every session and refresh family of the user, invalidates the
//!   recovery code used, marks the request `completed` and writes the outbox events.
//! - Pending, approved, cancelled and completed recoveries write outbox events
//!   (`identity.recovery.*`) so that every device is notified (delivery is M4).

use crate::admin::AdminResult as AuthResult;
use crate::auth::{AuthService, invalid, mfa_required_error, parse_tenant, unauthenticated};
use crate::jws::AccessClaims;
use crate::login::normalize_login;
use crate::ratelimit::{Dimension, Key};
use crate::token::{self, TokenHash};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use cs_common::error::{Error, ErrorCode};
use cs_common::id::{TenantId, UserId};
use cs_common::secret::Secret;
use cs_db::outbox::{NewEvent, Outbox};
use cs_db::{DbError, DomainTx};
use serde::Serialize;
use uuid::Uuid;

/// Codes per set (rev 11).
pub const CODES_PER_SET: usize = 10;
/// Recovery grant lifetime (contract §8: fixed 15 min).
pub const GRANT_TTL_SECS: i64 = 900;
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const CODE_ID_LEN: usize = 8;
const SECRET_LEN: usize = 20;
/// Bounded listings.
const MAX_LISTED: i64 = 50;
/// RFC 3339 UTC rendering in SQL (rev 10 addendum).
pub(crate) const RFC3339: &str = "YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"";

fn random_b32(n: usize) -> AuthResult<String> {
    let mut b = vec![0u8; n];
    cs_crypto::rand::fill(&mut b).map_err(Error::internal)?;
    // 256 is a multiple of 32: `byte & 31` is uniform.
    Ok(b.iter()
        .map(|x| char::from(ALPHABET[usize::from(x & 31)]))
        .collect())
}

/// Normalize a presented code: `(code_id, normalized code)`, or `None` if malformed.
pub fn parse_code(code: &str) -> Option<(String, String)> {
    let c = code.trim().to_ascii_uppercase();
    let (id, secret) = c.split_once('-')?;
    let ok = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| ALPHABET.contains(&b));
    (ok(id, CODE_ID_LEN) && ok(secret, SECRET_LEN)).then(|| (id.to_owned(), c.clone()))
}

/// Server-side Argon2id for recovery codes. The codes carry 100 random bits, so the cost only
/// has to make an offline search of a leaked hash pointless: m = 19 MiB, t = 2, p = 1.
fn hasher() -> AuthResult<Argon2<'static>> {
    let p = Params::new(19_456, 2, 1, None).map_err(Error::internal)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, p))
}

fn hash_code(code: &str) -> AuthResult<String> {
    let salt = cs_crypto::rand::bytes::<16>().map_err(Error::internal)?;
    let salt = SaltString::encode_b64(&salt).map_err(Error::internal)?;
    Ok(hasher()?
        .hash_password(code.as_bytes(), &salt)
        .map_err(Error::internal)?
        .to_string())
}

fn verify_code(code: &str, phc: &str) -> bool {
    let Ok(h) = PasswordHash::new(phc) else {
        return false;
    };
    hasher().is_ok_and(|a| a.verify_password(code.as_bytes(), &h).is_ok())
}

/// A new code: `(code_id, full code)`.
fn new_code() -> AuthResult<(String, String)> {
    let id = random_b32(CODE_ID_LEN)?;
    let secret = random_b32(SECRET_LEN)?;
    Ok((id.clone(), format!("{id}-{secret}")))
}

/// Mark `code_id` used (CAS on `used_at IS NULL`); `false` when it was already used or gone.
pub(crate) async fn use_code_in_tx(
    tx: &mut DomainTx,
    tenant: TenantId,
    user: UserId,
    code_id: &str,
) -> Result<bool, DbError> {
    Ok(sqlx::query(
        "UPDATE recovery_code_entries SET used_at = now() \
         WHERE tenant_id = $1 AND user_id = $2 AND code_id = $3 AND used_at IS NULL",
    )
    .bind(tenant.as_uuid())
    .bind(user.as_uuid())
    .bind(code_id)
    .execute(tx.conn())
    .await?
    .rows_affected()
        == 1)
}

#[derive(Serialize)]
struct RecoveryEvent {
    tenant_id: TenantId,
    user_id: UserId,
    request_id: Uuid,
    method: &'static str,
}

async fn recovery_event(
    tx: &mut DomainTx,
    tenant: TenantId,
    user: UserId,
    request_id: Uuid,
    event_type: &'static str,
    method: &'static str,
) -> Result<(), DbError> {
    Outbox::append(
        tx,
        NewEvent {
            tenant_id: Some(tenant),
            event_type,
            event_version: 1,
            partition_key: user.into_uuid(),
            payload: &RecoveryEvent {
                tenant_id: tenant,
                user_id: user,
                request_id,
                method,
            },
        },
    )
    .await
    .map(|_| ())
}

fn method_static(m: &str) -> &'static str {
    match m {
        "recovery_code" => "recovery_code",
        "email" => "email",
        "device_approval" => "device_approval",
        "admin" => "admin",
        _ => "passkey_approval",
    }
}

/// Result of `recovery/start`.
#[derive(Debug)]
pub enum RecoveryStart {
    /// `recovery_code`: `{state: "granted", grant, grant_expires_in}`.
    Granted {
        grant: Secret<String>,
        grant_expires_in: i64,
    },
    /// `email` (`recovery_txn` = `None`) or `device_approval`: `202 {state: "pending", …}`.
    Pending {
        recovery_txn: Option<Secret<String>>,
    },
}

/// What `recovery/status` was called with.
#[derive(Debug, Clone, Copy)]
pub enum StatusBy<'a> {
    /// The email link token, plus a recovery code for users with MFA.
    Link {
        token: &'a str,
        code: Option<&'a str>,
    },
    /// The device-approval `recovery_txn`.
    Txn(&'a str),
}

/// Result of `recovery/status`.
#[derive(Debug, Default)]
pub struct RecoveryStatus {
    pub state: &'static str,
    pub available_at: Option<String>,
    pub grant: Option<Secret<String>>,
    pub grant_expires_in: Option<i64>,
}

impl RecoveryStatus {
    fn only(state: &'static str) -> Self {
        Self {
            state,
            ..Self::default()
        }
    }
}

/// One entry of `GET /api/v2/me/recovery-requests`.
#[derive(Debug, Serialize)]
pub struct RecoveryRequestItem {
    pub id: Uuid,
    pub method: String,
    pub state: String,
    pub created_at: String,
    pub available_at: Option<String>,
    pub requester_user_agent: Option<String>,
}

fn state_static(s: &str) -> &'static str {
    match s {
        "pending" => "pending",
        "granted" => "granted",
        "completed" => "completed",
        "cancelled" => "cancelled",
        _ => "expired",
    }
}

fn not_found() -> crate::admin::AdminError {
    Error::new(ErrorCode::NotFound)
        .with_detail("No such recovery request.")
        .into()
}

/// A request found by link or txn hash (status phase 1).
struct Found {
    request_id: Uuid,
    user: UserId,
    state: String,
    due: bool,
    approved: bool,
    available_at: String,
    has_mfa: bool,
}

/// A user to recover, by tenant and login.
#[derive(Debug, Clone)]
struct Account {
    user: UserId,
    email_verified: Option<String>,
}

enum Grant {
    Issued(i64),
    State(&'static str),
}

impl AuthService {
    /// Count an attempt (contract §5): always per source; per tenant when `tenant` is given;
    /// per account (tenant + normalized login) when `login` is given too. The keys never
    /// depend on whether the tenant or account exists.
    pub(crate) async fn limit(
        &self,
        class: &'static str,
        source: &str,
        tenant: Option<&str>,
        login: Option<&str>,
    ) -> AuthResult<()> {
        let mut keys = vec![Key::new(Dimension::Source, class, &[source.as_bytes()])];
        if let Some(t) = tenant {
            keys.push(Key::new(Dimension::Tenant, class, &[t.as_bytes()]));
            if let Some(l) = login {
                keys.push(Key::new(
                    Dimension::Account,
                    class,
                    &[t.as_bytes(), l.as_bytes()],
                ));
            }
        }
        self.limiter.check(&keys).await.map(|_| ())
    }

    async fn dummy_hash(&self) -> AuthResult<String> {
        Ok(self
            .dummy_code_hash
            .get_or_try_init(|| async {
                let (_, c) = new_code()?;
                tokio::task::spawn_blocking(move || hash_code(&c))
                    .await
                    .map_err(|e| crate::admin::AdminError::from(Error::internal(e)))?
            })
            .await?
            .clone())
    }

    /// Verify a recovery code of `user` (or of nobody: dummy path). Exactly one Argon2id
    /// verification runs whatever the input. Returns the `code_id` of a valid unused code.
    pub(crate) async fn verify_recovery_code(
        &self,
        tenant: TenantId,
        user: Option<UserId>,
        code: &str,
    ) -> AuthResult<Option<String>> {
        let parsed = parse_code(code);
        let stored: Option<String> = match (&parsed, user) {
            (Some((id, _)), Some(u)) => {
                let id = id.clone();
                self.pool
                    .read_snapshot(move |tx| {
                        let id = id.clone();
                        Box::pin(async move {
                            Ok(sqlx::query_scalar(
                                "SELECT code_hash FROM recovery_code_entries \
                                 WHERE tenant_id = $1 AND user_id = $2 AND code_id = $3 \
                                   AND used_at IS NULL",
                            )
                            .bind(tenant.as_uuid())
                            .bind(u.as_uuid())
                            .bind(id)
                            .fetch_optional(tx.conn())
                            .await?)
                        })
                    })
                    .await?
            }
            _ => None,
        };
        let real = stored.is_some() && parsed.is_some();
        let phc = match stored {
            Some(h) => h,
            None => self.dummy_hash().await?,
        };
        let input = parsed
            .as_ref()
            .map_or_else(|| code.to_owned(), |(_, c)| c.clone());
        let ok = tokio::task::spawn_blocking(move || verify_code(&input, &phc))
            .await
            .map_err(Error::internal)?;
        Ok(if ok && real {
            parsed.map(|(id, _)| id)
        } else {
            None
        })
    }

    /// `POST /api/v2/me/recovery-codes` (step-up; allowed on an enrolment-only session): a
    /// new set of 10 codes replacing the previous set. The codes are returned once.
    pub async fn recovery_codes_generate(
        &self,
        claims: &AccessClaims,
    ) -> AuthResult<Vec<Secret<String>>> {
        self.require_step_up(claims).await?;
        let (tenant, user, _) = Self::subject(claims)?;
        let codes: Vec<(String, String)> = (0..CODES_PER_SET)
            .map(|_| new_code())
            .collect::<Result<_, _>>()?;
        let plain: Vec<String> = codes.iter().map(|(_, c)| c.clone()).collect();
        let hashed: Vec<(String, String)> = tokio::task::spawn_blocking(move || {
            codes
                .into_iter()
                .map(|(id, c)| hash_code(&c).map(|h| (id, h)))
                .collect::<Result<Vec<_>, _>>()
        })
        .await
        .map_err(Error::internal)??;
        self.pool
            .transaction(move |tx| {
                let hashed = hashed.clone();
                Box::pin(async move {
                    let v: i64 = sqlx::query_scalar(
                        "SELECT COALESCE(max(set_version), 0) + 1 FROM recovery_code_entries \
                         WHERE tenant_id = $1 AND user_id = $2",
                    )
                    .bind(tenant.as_uuid())
                    .bind(user.as_uuid())
                    .fetch_one(tx.conn())
                    .await?;
                    sqlx::query(
                        "DELETE FROM recovery_code_entries WHERE tenant_id = $1 AND user_id = $2",
                    )
                    .bind(tenant.as_uuid())
                    .bind(user.as_uuid())
                    .execute(tx.conn())
                    .await?;
                    for (id, h) in &hashed {
                        sqlx::query(
                            "INSERT INTO recovery_code_entries (tenant_id, user_id, code_id, \
                               code_hash, set_version) VALUES ($1, $2, $3, $4, $5)",
                        )
                        .bind(tenant.as_uuid())
                        .bind(user.as_uuid())
                        .bind(id)
                        .bind(h)
                        .bind(v)
                        .execute(tx.conn())
                        .await?;
                    }
                    Outbox::append(
                        tx,
                        NewEvent {
                            tenant_id: Some(tenant),
                            event_type: "identity.credentials.changed",
                            event_version: 1,
                            partition_key: user.into_uuid(),
                            payload: &crate::auth::CredentialsChanged {
                                tenant_id: tenant,
                                user_id: user,
                                method: "recovery_code",
                                reason: "recovery_codes_generated",
                            },
                        },
                    )
                    .await?;
                    Ok(())
                })
            })
            .await?;
        Ok(plain.into_iter().map(Secret::new).collect())
    }

    /// `GET /api/v2/me/recovery-codes` → `{remaining}`.
    pub async fn recovery_codes_remaining(&self, claims: &AccessClaims) -> AuthResult<i64> {
        let (tenant, user, _) = Self::subject(claims)?;
        Ok(self
            .pool
            .read_snapshot(move |tx| {
                Box::pin(async move {
                    Ok(sqlx::query_scalar(
                        "SELECT count(*) FROM recovery_code_entries \
                         WHERE tenant_id = $1 AND user_id = $2 AND used_at IS NULL",
                    )
                    .bind(tenant.as_uuid())
                    .bind(user.as_uuid())
                    .fetch_one(tx.conn())
                    .await?)
                })
            })
            .await?)
    }

    async fn account(&self, tenant: TenantId, login: &str) -> AuthResult<Option<Account>> {
        let login = login.to_owned();
        let r: Option<(Uuid, Option<String>)> = self
            .pool
            .read_snapshot(move |tx| {
                let login = login.clone();
                Box::pin(async move {
                    Ok(sqlx::query_as(
                        "SELECT u.user_id, CASE WHEN u.email_verified_at IS NOT NULL THEN u.email END \
                         FROM users u JOIN tenants t ON t.tenant_id = u.tenant_id \
                         WHERE u.tenant_id = $1 AND u.login = $2 AND u.status = 'active' \
                           AND t.state = 'active'",
                    )
                    .bind(tenant.as_uuid())
                    .bind(login)
                    .fetch_optional(tx.conn())
                    .await?)
                })
            })
            .await?;
        Ok(r.and_then(|(u, email)| {
            Some(Account {
                user: UserId::from_uuid(u).ok()?,
                email_verified: email,
            })
        }))
    }

    /// `POST /api/v2/auth/recovery/start {tenant, login, method, code?}` (rev 10).
    pub async fn recovery_start(
        &self,
        tenant: &str,
        login: &str,
        method: &str,
        code: Option<&str>,
        source: &str,
        user_agent: Option<&str>,
    ) -> AuthResult<RecoveryStart> {
        let tenant_id = parse_tenant(tenant)?;
        let login = normalize_login(login).map_err(|e| invalid("/login", &e.to_string()))?;
        let method = match method {
            "recovery_code" | "email" | "device_approval" => method_static(method),
            _ => {
                return Err(invalid(
                    "/method",
                    "method must be recovery_code, email or device_approval",
                ));
            }
        };
        if method == "recovery_code" && code.is_none() {
            return Err(invalid(
                "/code",
                "code is required for method recovery_code",
            ));
        }
        self.limit("recovery", source, Some(tenant), Some(&login))
            .await?;
        self.sweep();
        let account = self.account(tenant_id, &login).await?;
        let ua = user_agent.map(|u| truncate_bytes(u, 256));
        match method {
            "recovery_code" => {
                let code = code.unwrap_or_default();
                let user = account.as_ref().map(|a| a.user);
                let code_id = self
                    .verify_recovery_code(tenant_id, user, code)
                    .await?
                    .ok_or_else(unauthenticated)?;
                let user = user.ok_or_else(unauthenticated)?;
                let grant = token::generate(tenant_id).map_err(Error::internal)?;
                let ghash = grant.hash;
                let request_id = cs_common::id::new_random128().map_err(Error::internal)?;
                let ok = self
                    .pool
                    .transaction(move |tx| {
                        let (code_id, ua) = (code_id.clone(), ua.clone());
                        Box::pin(async move {
                            let unused: Option<bool> = sqlx::query_scalar(
                                "SELECT used_at IS NULL FROM recovery_code_entries \
                                 WHERE tenant_id = $1 AND user_id = $2 AND code_id = $3 FOR SHARE",
                            )
                            .bind(tenant_id.as_uuid())
                            .bind(user.as_uuid())
                            .bind(&code_id)
                            .fetch_optional(tx.conn())
                            .await?;
                            if unused != Some(true) {
                                return Ok(false);
                            }
                            sqlx::query(
                                "INSERT INTO recovery_requests (tenant_id, request_id, user_id, method, \
                                   state, not_before, grant_hash, grant_expires_at, code_id, \
                                   requester_user_agent, version) \
                                 VALUES ($1, $2, $3, 'recovery_code', 'granted', now(), $4, \
                                   now() + make_interval(secs => $5::float8), $6, $7, 1)",
                            )
                            .bind(tenant_id.as_uuid())
                            .bind(request_id)
                            .bind(user.as_uuid())
                            .bind(ghash.as_bytes().as_slice())
                            .bind(GRANT_TTL_SECS as f64)
                            .bind(&code_id)
                            .bind(ua)
                            .execute(tx.conn())
                            .await?;
                            recovery_event(
                                tx,
                                tenant_id,
                                user,
                                request_id,
                                "identity.recovery.granted",
                                "recovery_code",
                            )
                            .await?;
                            Ok(true)
                        })
                    })
                    .await?;
                if !ok {
                    return Err(unauthenticated());
                }
                Ok(RecoveryStart::Granted {
                    grant: grant.token,
                    grant_expires_in: GRANT_TTL_SECS,
                })
            }
            "email" => {
                let Some((user, email)) =
                    account.and_then(|a| a.email_verified.map(|e| (a.user, e)))
                else {
                    return Ok(RecoveryStart::Pending { recovery_txn: None });
                };
                let link = self
                    .create_email_request(tenant_id, user, ua, "email")
                    .await?;
                if let Err(e) = self.notifier.recovery_link(&email, &link).await {
                    tracing::warn!(error = %e.code(), "recovery link delivery failed");
                }
                Ok(RecoveryStart::Pending { recovery_txn: None })
            }
            _ => {
                let txn = token::generate(tenant_id).map_err(Error::internal)?;
                if let Some(a) = account {
                    let (thash, user, request_id) = (
                        txn.hash,
                        a.user,
                        cs_common::id::new_random128().map_err(Error::internal)?,
                    );
                    self.pool
                        .transaction(move |tx| {
                            let ua = ua.clone();
                            Box::pin(async move {
                                sqlx::query(
                                    "INSERT INTO recovery_requests (tenant_id, request_id, user_id, \
                                       method, state, not_before, txn_hash, requester_user_agent, version) \
                                     VALUES ($1, $2, $3, 'device_approval', 'pending', now(), $4, $5, 1)",
                                )
                                .bind(tenant_id.as_uuid())
                                .bind(request_id)
                                .bind(user.as_uuid())
                                .bind(thash.as_bytes().as_slice())
                                .bind(ua)
                                .execute(tx.conn())
                                .await?;
                                recovery_event(
                                    tx,
                                    tenant_id,
                                    user,
                                    request_id,
                                    "identity.recovery.requested",
                                    "device_approval",
                                )
                                .await
                            })
                        })
                        .await?;
                }
                Ok(RecoveryStart::Pending {
                    recovery_txn: Some(txn.token),
                })
            }
        }
    }

    /// Create an email-method request with the waiting period and return its link token
    /// (`recovery/start` method `email`).
    pub async fn create_email_request(
        &self,
        tenant: TenantId,
        user: UserId,
        requester_user_agent: Option<String>,
        actor: &'static str,
    ) -> AuthResult<Secret<String>> {
        create_email_request(
            &self.pool,
            tenant,
            user,
            self.policy.recovery_wait_secs,
            requester_user_agent,
            actor,
        )
        .await
    }

    /// `POST /api/v2/auth/recovery/status` (rev 10 addendum).
    pub async fn recovery_status(
        &self,
        by: StatusBy<'_>,
        source: &str,
    ) -> AuthResult<RecoveryStatus> {
        self.limit("recovery", source, None, None).await?;
        let (tok, by_link, code) = match by {
            StatusBy::Link { token, code } => (token, true, code),
            StatusBy::Txn(t) => (t, false, None),
        };
        let Ok(p) = token::parse(tok) else {
            return if by_link {
                Err(unauthenticated())
            } else {
                Ok(RecoveryStatus::only("pending"))
            };
        };
        let (tenant, hash, default_mfa) = (p.tenant_id, p.hash, self.policy.mfa_required);
        let found: Option<Found> = self
            .pool
            .read_snapshot(move |tx| {
                Box::pin(async move {
                    let col = if by_link { "link_hash" } else { "txn_hash" };
                    let q = format!(
                        "SELECT request_id, user_id, state, not_before <= now(), approved_at IS NOT NULL, \
                           to_char(not_before AT TIME ZONE 'UTC', '{RFC3339}') \
                         FROM recovery_requests WHERE tenant_id = $1 AND {col} = $2"
                    );
                    let r: Option<(Uuid, Uuid, String, bool, bool, String)> =
                        sqlx::query_as(sqlx::AssertSqlSafe(q))
                            .bind(tenant.as_uuid())
                            .bind(hash.as_bytes().as_slice())
                            .fetch_optional(tx.conn())
                            .await?;
                    let Some((request_id, uid, state, due, approved, available_at)) = r else {
                        return Ok(None);
                    };
                    let user =
                        UserId::from_uuid(uid).map_err(|e| DbError::Invalid(e.to_string()))?;
                    let f = crate::mfa::factors_in_tx(tx, tenant, user, default_mfa).await?;
                    Ok(Some(Found {
                        request_id,
                        user,
                        state,
                        due,
                        approved,
                        available_at,
                        has_mfa: f.has_mfa(),
                    }))
                })
            })
            .await?;
        let Some(f) = found else {
            // Device approval: an unknown txn looks like a request nobody approved (it may be
            // the dummy txn of an unknown account). Email: links exist only for real requests.
            return if by_link {
                Err(unauthenticated())
            } else {
                Ok(RecoveryStatus::only("pending"))
            };
        };
        match f.state.as_str() {
            "pending" | "granted" => {}
            s => return Ok(RecoveryStatus::only(state_static(s))),
        }
        let mut code_id: Option<String> = None;
        if f.state == "pending" {
            if by_link {
                if !f.due {
                    return Ok(RecoveryStatus {
                        state: "pending",
                        available_at: Some(f.available_at),
                        ..RecoveryStatus::default()
                    });
                }
                // §4: users with MFA also present a recovery code.
                if f.has_mfa {
                    let c = code.ok_or_else(mfa_required_error)?;
                    code_id = Some(
                        self.verify_recovery_code(tenant, Some(f.user), c)
                            .await?
                            .ok_or_else(unauthenticated)?,
                    );
                }
            } else if !f.approved {
                return Ok(RecoveryStatus::only("pending"));
            }
        }
        let grant = token::generate(tenant).map_err(Error::internal)?;
        let (ghash, rid, user) = (grant.hash, f.request_id, f.user);
        let out = self
            .pool
            .transaction(move |tx| {
                let code_id = code_id.clone();
                Box::pin(async move {
                    grant_in_tx(tx, tenant, rid, user, ghash, code_id, by_link).await
                })
            })
            .await?;
        Ok(match out {
            Grant::Issued(expires_in) => RecoveryStatus {
                state: "granted",
                available_at: by_link.then_some(f.available_at),
                grant: Some(grant.token),
                grant_expires_in: Some(expires_in),
            },
            Grant::State(s) => RecoveryStatus::only(s),
        })
    }

    /// `GET /api/v2/me/recovery-requests` (rev 10 addendum): pending and granted email and
    /// device-approval requests of the caller, newest first, bounded.
    pub async fn recovery_requests(
        &self,
        claims: &AccessClaims,
    ) -> AuthResult<Vec<RecoveryRequestItem>> {
        let (tenant, user, _) = Self::subject(claims)?;
        type R = (Uuid, String, String, String, Option<String>, Option<String>);
        let rows: Vec<R> = self
            .pool
            .read_snapshot(move |tx| {
                Box::pin(async move {
                    let q = format!(
                        "SELECT request_id, method, state, \
                           to_char(created_at AT TIME ZONE 'UTC', '{RFC3339}'), \
                           CASE WHEN method = 'email' THEN to_char(not_before AT TIME ZONE 'UTC', '{RFC3339}') END, \
                           requester_user_agent \
                         FROM recovery_requests WHERE tenant_id = $1 AND user_id = $2 \
                           AND method IN ('email', 'device_approval') AND state IN ('pending', 'granted') \
                         ORDER BY created_at DESC LIMIT {MAX_LISTED}"
                    );
                    Ok(sqlx::query_as(sqlx::AssertSqlSafe(q))
                        .bind(tenant.as_uuid())
                        .bind(user.as_uuid())
                        .fetch_all(tx.conn())
                        .await?)
                })
            })
            .await?;
        Ok(rows
            .into_iter()
            .map(
                |(id, method, state, created_at, available_at, ua)| RecoveryRequestItem {
                    id,
                    method,
                    state,
                    created_at,
                    available_at,
                    requester_user_agent: ua,
                },
            )
            .collect())
    }

    /// `POST /api/v2/me/recovery-requests/{id}/approve` (step-up): approve a pending
    /// device-approval request of the caller. 404 for anything else.
    pub async fn recovery_approve(&self, claims: &AccessClaims, id: Uuid) -> AuthResult<()> {
        self.require_step_up(claims).await?;
        let (tenant, user, _) = Self::subject(claims)?;
        let ok = self
            .pool
            .transaction(move |tx| {
                Box::pin(async move {
                    let n = sqlx::query(
                        "UPDATE recovery_requests SET approved_at = now(), version = version + 1, \
                           updated_at = now() \
                         WHERE tenant_id = $1 AND request_id = $2 AND user_id = $3 \
                           AND method = 'device_approval' AND state = 'pending' AND approved_at IS NULL",
                    )
                    .bind(tenant.as_uuid())
                    .bind(id)
                    .bind(user.as_uuid())
                    .execute(tx.conn())
                    .await?
                    .rows_affected();
                    if n == 1 {
                        recovery_event(
                            tx,
                            tenant,
                            user,
                            id,
                            "identity.recovery.approved",
                            "device_approval",
                        )
                        .await?;
                    }
                    Ok(n == 1)
                })
            })
            .await?;
        if ok { Ok(()) } else { Err(not_found()) }
    }

    /// `DELETE /api/v2/me/recovery-requests/{id}`: any session of the user cancels a pending
    /// or granted request (rev 10). 404 for anything else.
    pub async fn recovery_cancel(&self, claims: &AccessClaims, id: Uuid) -> AuthResult<()> {
        let (tenant, user, _) = Self::subject(claims)?;
        let ok = self
            .pool
            .transaction(move |tx| {
                Box::pin(async move {
                    let m: Option<String> = sqlx::query_scalar(
                        "UPDATE recovery_requests SET state = 'cancelled', version = version + 1, \
                           updated_at = now() \
                         WHERE tenant_id = $1 AND request_id = $2 AND user_id = $3 \
                           AND state IN ('pending', 'granted') RETURNING method",
                    )
                    .bind(tenant.as_uuid())
                    .bind(id)
                    .bind(user.as_uuid())
                    .fetch_optional(tx.conn())
                    .await?;
                    if let Some(m) = &m {
                        recovery_event(
                            tx,
                            tenant,
                            user,
                            id,
                            "identity.recovery.cancelled",
                            method_static(m),
                        )
                        .await?;
                    }
                    Ok(m.is_some())
                })
            })
            .await?;
        if ok { Ok(()) } else { Err(not_found()) }
    }

    /// The user and login a recovery grant may re-register (`register/start`, [R5]).
    /// `Ok(None)`: not a recovery grant. A used, cancelled or expired grant is
    /// `unauthenticated`; an expired one also moves the request to `expired`.
    pub(crate) async fn recovery_grant_user(
        &self,
        tenant: TenantId,
        ghash: TokenHash,
    ) -> AuthResult<Option<(Uuid, String)>> {
        type R = (Uuid, Uuid, String, String, bool);
        let r: Option<R> = self
            .pool
            .read_snapshot(move |tx| {
                Box::pin(async move {
                    Ok(sqlx::query_as(
                        "SELECT r.request_id, u.user_id, u.login, r.state, r.grant_expires_at > now() \
                         FROM recovery_requests r \
                         JOIN users u ON u.tenant_id = r.tenant_id AND u.user_id = r.user_id \
                         JOIN tenants t ON t.tenant_id = r.tenant_id \
                         WHERE r.tenant_id = $1 AND r.grant_hash = $2 AND u.status = 'active' \
                           AND t.state = 'active'",
                    )
                    .bind(tenant.as_uuid())
                    .bind(ghash.as_bytes().as_slice())
                    .fetch_optional(tx.conn())
                    .await?)
                })
            })
            .await?;
        let Some((rid, uid, login, state, live)) = r else {
            return Ok(None);
        };
        if state == "granted" && live {
            return Ok(Some((uid, login)));
        }
        if state == "granted" {
            self.expire_request(tenant, rid).await?;
        }
        Err(unauthenticated())
    }

    pub(crate) async fn expire_request(&self, tenant: TenantId, rid: Uuid) -> AuthResult<()> {
        self.pool
            .transaction(move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "UPDATE recovery_requests SET state = 'expired', version = version + 1, \
                           updated_at = now() \
                         WHERE tenant_id = $1 AND request_id = $2 AND state = 'granted' \
                           AND grant_expires_at <= now()",
                    )
                    .bind(tenant.as_uuid())
                    .bind(rid)
                    .execute(tx.conn())
                    .await?;
                    Ok(())
                })
            })
            .await?;
        Ok(())
    }
}

/// Create an email-method recovery request (`not_before = now + wait_secs`) for an active
/// user and return its link token; `actor` is `email` (self-service) or `admin`
/// (`cs admin recovery start`, rev 10). Outbox `identity.recovery.requested`.
pub async fn create_email_request(
    pool: &cs_db::DomainPool,
    tenant: TenantId,
    user: UserId,
    wait_secs: i64,
    requester_user_agent: Option<String>,
    actor: &'static str,
) -> AuthResult<Secret<String>> {
    let link = token::generate(tenant).map_err(Error::internal)?;
    let lhash = link.hash;
    let request_id = cs_common::id::new_random128().map_err(Error::internal)?;
    let ok = pool
        .transaction(move |tx| {
            let ua = requester_user_agent.clone();
            Box::pin(async move {
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
                    return Ok(false);
                }
                sqlx::query(
                    "INSERT INTO recovery_requests (tenant_id, request_id, user_id, method, \
                       state, not_before, link_hash, requester_user_agent, version) \
                     VALUES ($1, $2, $3, 'email', 'pending', \
                       now() + make_interval(secs => $4::float8), $5, $6, 1)",
                )
                .bind(tenant.as_uuid())
                .bind(request_id)
                .bind(user.as_uuid())
                .bind(wait_secs as f64)
                .bind(lhash.as_bytes().as_slice())
                .bind(ua)
                .execute(tx.conn())
                .await?;
                recovery_event(
                    tx,
                    tenant,
                    user,
                    request_id,
                    "identity.recovery.requested",
                    if actor == "admin" { "admin" } else { "email" },
                )
                .await?;
                Ok(true)
            })
        })
        .await?;
    if !ok {
        return Err(not_found_user());
    }
    Ok(link.token)
}

fn not_found_user() -> crate::admin::AdminError {
    Error::new(ErrorCode::NotFound)
        .with_detail("No such active user.")
        .into()
}

/// `pending → granted` (or a new grant hash for a granted request, keeping its expiry), under
/// the request's row lock.
async fn grant_in_tx(
    tx: &mut DomainTx,
    tenant: TenantId,
    rid: Uuid,
    user: UserId,
    ghash: TokenHash,
    code_id: Option<String>,
    by_link: bool,
) -> Result<Grant, DbError> {
    type R = (String, bool, bool, Option<i64>, String);
    let r: Option<R> = sqlx::query_as(
        "SELECT state, not_before <= now(), approved_at IS NOT NULL, \
           extract(epoch FROM (grant_expires_at - now()))::bigint, method \
         FROM recovery_requests WHERE tenant_id = $1 AND request_id = $2 AND user_id = $3 FOR UPDATE",
    )
    .bind(tenant.as_uuid())
    .bind(rid)
    .bind(user.as_uuid())
    .fetch_optional(tx.conn())
    .await?;
    let Some((state, due, approved, left, method)) = r else {
        return Ok(Grant::State("expired"));
    };
    match state.as_str() {
        "granted" => {
            let left = left.unwrap_or(0);
            if left <= 0 {
                sqlx::query(
                    "UPDATE recovery_requests SET state = 'expired', version = version + 1, \
                       updated_at = now() WHERE tenant_id = $1 AND request_id = $2",
                )
                .bind(tenant.as_uuid())
                .bind(rid)
                .execute(tx.conn())
                .await?;
                return Ok(Grant::State("expired"));
            }
            sqlx::query(
                "UPDATE recovery_requests SET grant_hash = $3, version = version + 1, updated_at = now() \
                 WHERE tenant_id = $1 AND request_id = $2",
            )
            .bind(tenant.as_uuid())
            .bind(rid)
            .bind(ghash.as_bytes().as_slice())
            .execute(tx.conn())
            .await?;
            Ok(Grant::Issued(left))
        }
        "pending" => {
            let ready = if by_link { due } else { approved };
            if !ready {
                return Ok(Grant::State("pending"));
            }
            sqlx::query(
                "UPDATE recovery_requests SET state = 'granted', grant_hash = $3, \
                   grant_expires_at = now() + make_interval(secs => $4::float8), \
                   code_id = COALESCE($5, code_id), version = version + 1, updated_at = now() \
                 WHERE tenant_id = $1 AND request_id = $2",
            )
            .bind(tenant.as_uuid())
            .bind(rid)
            .bind(ghash.as_bytes().as_slice())
            .bind(GRANT_TTL_SECS as f64)
            .bind(code_id)
            .execute(tx.conn())
            .await?;
            recovery_event(
                tx,
                tenant,
                user,
                rid,
                "identity.recovery.granted",
                method_static(&method),
            )
            .await?;
            Ok(Grant::Issued(GRANT_TTL_SECS))
        }
        s => Ok(Grant::State(state_static(s))),
    }
}

/// Truncate to at most `max` bytes on a character boundary.
pub(crate) fn truncate_bytes(s: &str, max: usize) -> String {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_format_and_parse() {
        let (id, c) = new_code().unwrap();
        assert_eq!(id.len(), 8);
        assert_eq!(c.len(), 8 + 1 + 20);
        assert_eq!(parse_code(&c.to_lowercase()), Some((id.clone(), c.clone())));
        assert_eq!(parse_code(&format!("  {c} ")), Some((id, c.clone())));
        assert_eq!(parse_code("ABCDEFGH"), None);
        assert_eq!(parse_code("ABCDEFG1-AAAAAAAAAAAAAAAAAAAA"), None);
        assert_eq!(parse_code("ABCDEFGH-AAAAAAAAAAAAAAAAAAA"), None);
    }

    #[test]
    fn hash_verifies_only_the_same_code() {
        let (_, c) = new_code().unwrap();
        let h = hash_code(&c).unwrap();
        assert!(h.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert!(verify_code(&c, &h));
        let (_, other) = new_code().unwrap();
        assert!(!verify_code(&other, &h));
        assert!(!verify_code(&c, "not a phc string"));
    }

    #[test]
    fn truncation_respects_char_boundaries() {
        assert_eq!(truncate_bytes("abc", 2), "ab");
        assert_eq!(truncate_bytes("aé", 2), "a");
        assert_eq!(truncate_bytes("ok", 256), "ok");
    }
}
