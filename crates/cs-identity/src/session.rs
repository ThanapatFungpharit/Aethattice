//! Sessions and refresh tokens (contract §3; spec §5.5).
//!
//! Every function here runs inside one identity-domain transaction supplied by the caller
//! (App. C rule C1). Nothing here signs or calls the KMS: access tokens are signed by the
//! caller after commit, so no network call happens inside a transaction.
//!
//! Refresh rotation (`[R1]`):
//! - an `active` token is rotated: it becomes `rotated` with `rotated_at`, the presenting
//!   `Idempotency-Key` and the successor's hash; the successor is inserted `active`;
//! - a `rotated` token presented again with the key that rotated it, within 30 s of
//!   `rotated_at`, while its successor is still `active`, is a lost response: that successor is
//!   revoked and a new successor is issued from the same family;
//! - any other presentation of a `rotated` token is reuse: the session is revoked (generation
//!   bump), every token of the family is revoked and `identity.session.revoked` is written;
//! - concurrent presentations serialize on the token row lock (`FOR UPDATE`); the losers see
//!   `rotated` and are reuse unless they carry the winner's key.

use crate::jws::AccessClaims;
use crate::token::{self, IssuedToken, TokenHash};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cs_common::config::{Policy, PolicyKey};
use cs_common::id::{SessionId, TenantId, UserId};
use cs_db::outbox::{NewEvent, Outbox};
use cs_db::{DbError, DomainTx};
use serde::Serialize;
use uuid::Uuid;

/// Lost-response window (contract §8: fixed 30 s).
pub const LOST_RESPONSE_WINDOW_SECS: i64 = 30;

/// Session and access-token lifetimes from validated policy (erratum C13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionPolicy {
    pub access_ttl_secs: i64,
    pub idle_secs: i64,
    pub absolute_secs: i64,
    /// Step-up window (contract §2.3, erratum C13: 5 min, 1–60 min).
    pub step_up_secs: i64,
}

impl SessionPolicy {
    pub fn from_policy(p: &Policy) -> Self {
        Self {
            access_ttl_secs: p.get(PolicyKey::AccessTokenLifetimeSecs),
            idle_secs: p.get(PolicyKey::SessionIdleLifetimeSecs),
            absolute_secs: p.get(PolicyKey::SessionAbsoluteLifetimeSecs),
            step_up_secs: p.get(PolicyKey::StepUpWindowSecs),
        }
    }
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self::from_policy(&Policy::default())
    }
}

/// Tokens to hand out once the transaction has committed. `claims` lacks `iss` / `aud`, which
/// the signer sets.
#[derive(Debug)]
pub struct NewTokens {
    pub session_id: SessionId,
    pub claims: AccessClaims,
    pub refresh: IssuedToken,
    /// Seconds until the session's absolute expiry (refresh cookie `Max-Age`).
    pub refresh_max_age: i64,
}

/// Result of presenting a refresh token.
#[derive(Debug)]
pub enum RefreshOutcome {
    Issued(Box<NewTokens>),
    /// A `rotated` token was reused; the session has been revoked.
    Reuse,
    /// Unknown, revoked or expired token, or an inactive session.
    Invalid,
    /// A DPoP-bound refresh token presented without a valid proof of its key (rev 8): treated
    /// like theft; the session has been revoked.
    KeyMismatch,
}

/// The DPoP proof that came with a refresh request (already checked for form, signature,
/// claims and replay; see [`crate::dpop`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresentedProof {
    None,
    Valid([u8; 32]),
    /// A proof was sent but failed verification or was replayed.
    Invalid,
}

#[derive(Serialize)]
struct SessionRevoked {
    tenant_id: TenantId,
    session_id: SessionId,
    user_id: UserId,
    generation: i64,
    reason: &'static str,
}

fn jti() -> Result<String, DbError> {
    Ok(cs_common::id::new_random128()?.simple().to_string())
}

#[allow(clippy::too_many_arguments)]
fn claims(
    tenant: TenantId,
    user: UserId,
    session: SessionId,
    generation: i64,
    amr: Vec<String>,
    auth_time: i64,
    now: i64,
    policy: SessionPolicy,
    jkt: Option<&[u8]>,
) -> Result<AccessClaims, DbError> {
    Ok(AccessClaims {
        iss: String::new(),
        aud: String::new(),
        sub: user.as_uuid().to_string(),
        tid: tenant.as_uuid().to_string(),
        sid: session.as_uuid().to_string(),
        sgen: generation,
        amr,
        auth_time,
        iat: now,
        exp: now + policy.access_ttl_secs,
        jti: jti()?,
        cnf: jkt.map(|j| crate::jws::Confirmation {
            jkt: URL_SAFE_NO_PAD.encode(j),
        }),
    })
}

async fn insert_refresh(
    tx: &mut DomainTx,
    tenant: TenantId,
    session: SessionId,
    family_generation: i64,
    jkt: Option<&[u8]>,
) -> Result<IssuedToken, DbError> {
    let t = token::generate(tenant)?;
    sqlx::query(
        "INSERT INTO refresh_tokens (tenant_id, token_hash, session_id, family_generation, state, key_jkt) \
         VALUES ($1, $2, $3, $4, 'active', $5)",
    )
    .bind(tenant.as_uuid())
    .bind(t.hash.as_bytes().as_slice())
    .bind(session.as_uuid())
    .bind(family_generation)
    .bind(jkt)
    .execute(tx.conn())
    .await?;
    Ok(t)
}

/// Create a session for an authenticated user, with its first refresh token. `amr` lists the
/// methods used; a password login counts as strong authentication for step-up (§2.3).
/// `jkt` (rev 8): the DPoP key thumbprint when `login/finish` carried a valid proof; the
/// session, its access tokens (`cnf.jkt`) and its whole refresh family are bound to it.
pub async fn create_in_tx(
    tx: &mut DomainTx,
    tenant: TenantId,
    user: UserId,
    amr: &[&str],
    policy: SessionPolicy,
    jkt: Option<[u8; 32]>,
) -> Result<NewTokens, DbError> {
    let jkt = jkt.as_ref().map(<[u8; 32]>::as_slice);
    let session = SessionId::generate()?;
    let amr: Vec<String> = amr.iter().map(|s| (*s).to_owned()).collect();
    let (now, max_age): (i64, i64) = sqlx::query_as(
        "INSERT INTO sessions (tenant_id, session_id, user_id, state, amr, auth_time, \
           last_strong_auth_at, idle_expires_at, absolute_expires_at, generation, version, \
           device_key_jkt) \
         VALUES ($1, $2, $3, 'active', $4, now(), now(), \
           now() + make_interval(secs => $5::float8), now() + make_interval(secs => $6::float8), 1, 1, $7) \
         RETURNING extract(epoch FROM now())::bigint, \
           extract(epoch FROM (absolute_expires_at - now()))::bigint",
    )
    .bind(tenant.as_uuid())
    .bind(session.as_uuid())
    .bind(user.as_uuid())
    .bind(&amr)
    .bind(policy.idle_secs.min(policy.absolute_secs) as f64)
    .bind(policy.absolute_secs as f64)
    .bind(jkt)
    .fetch_one(tx.conn())
    .await?;
    let refresh = insert_refresh(tx, tenant, session, 1, jkt).await?;
    Ok(NewTokens {
        session_id: session,
        claims: claims(tenant, user, session, 1, amr, now, now, policy, jkt)?,
        refresh,
        refresh_max_age: max_age,
    })
}

type TokenRow = (
    String,
    Uuid,
    Option<Vec<u8>>,
    Option<String>,
    bool,
    Option<Vec<u8>>,
);
type SessionRow = (String, Uuid, i64, Vec<String>, i64, bool, i64, i64);

/// Present a refresh token (`[R1]`). `key` is the request's `Idempotency-Key`; `proof` the
/// DPoP proof that came with it (rev 8: a bound family needs a proof of its key).
pub async fn refresh_in_tx(
    tx: &mut DomainTx,
    tenant: TenantId,
    hash: TokenHash,
    key: &str,
    policy: SessionPolicy,
    proof: PresentedProof,
) -> Result<RefreshOutcome, DbError> {
    let row: Option<TokenRow> = sqlx::query_as(
        "SELECT state, session_id, successor_hash, rotation_idempotency_key, \
           (rotated_at IS NOT NULL AND now() - rotated_at <= make_interval(secs => $3::float8)), \
           key_jkt \
         FROM refresh_tokens WHERE tenant_id = $1 AND token_hash = $2 FOR UPDATE",
    )
    .bind(tenant.as_uuid())
    .bind(hash.as_bytes().as_slice())
    .bind(LOST_RESPONSE_WINDOW_SECS as f64)
    .fetch_optional(tx.conn())
    .await?;
    let Some((state, sid, successor, rot_key, in_window, key_jkt)) = row else {
        return Ok(RefreshOutcome::Invalid);
    };
    let session = SessionId::from_uuid(sid).map_err(|e| DbError::Invalid(e.to_string()))?;
    let s: SessionRow = sqlx::query_as(
        "SELECT state, user_id, generation, amr, extract(epoch FROM auth_time)::bigint, \
           (now() < idle_expires_at AND now() < absolute_expires_at), \
           extract(epoch FROM now())::bigint, \
           extract(epoch FROM (absolute_expires_at - now()))::bigint \
         FROM sessions WHERE tenant_id = $1 AND session_id = $2 FOR UPDATE",
    )
    .bind(tenant.as_uuid())
    .bind(sid)
    .fetch_one(tx.conn())
    .await?;
    let (s_state, uid, generation, amr, auth_time, live, now, max_age) = s;
    let user = UserId::from_uuid(uid).map_err(|e| DbError::Invalid(e.to_string()))?;
    if s_state != "active" || state == "revoked" {
        return Ok(RefreshOutcome::Invalid);
    }
    if !live {
        sqlx::query(
            "UPDATE sessions SET state = 'expired', version = version + 1, updated_at = now() \
             WHERE tenant_id = $1 AND session_id = $2",
        )
        .bind(tenant.as_uuid())
        .bind(sid)
        .execute(tx.conn())
        .await?;
        revoke_family(tx, tenant, sid).await?;
        return Ok(RefreshOutcome::Invalid);
    }

    // DPoP binding (rev 8): a bound token without a proof of the same key is treated like
    // theft (session revoked, as for reuse). An unbound session stays unbound; a broken proof
    // on it is refused without revocation.
    match (&key_jkt, proof) {
        (Some(k), PresentedProof::Valid(j)) if k.as_slice() == j.as_slice() => {}
        (Some(_), _) => {
            revoke_session(tx, tenant, session, "dpop_key_mismatch").await?;
            return Ok(RefreshOutcome::KeyMismatch);
        }
        (None, PresentedProof::Invalid) => return Ok(RefreshOutcome::Invalid),
        (None, _) => {}
    }

    let lost_response = state == "rotated"
        && in_window
        && rot_key.as_deref() == Some(key)
        && match &successor {
            Some(sh) => {
                let st: Option<String> = sqlx::query_scalar(
                    "SELECT state FROM refresh_tokens WHERE tenant_id = $1 AND token_hash = $2 FOR UPDATE",
                )
                .bind(tenant.as_uuid())
                .bind(sh.as_slice())
                .fetch_optional(tx.conn())
                .await?;
                st.as_deref() == Some("active")
            }
            None => false,
        };

    if state == "rotated" && !lost_response {
        revoke_session(tx, tenant, session, "refresh_token_reuse").await?;
        return Ok(RefreshOutcome::Reuse);
    }

    if lost_response {
        // The successor never reached the client: revoke it and issue a new one.
        sqlx::query(
            "UPDATE refresh_tokens SET state = 'revoked' WHERE tenant_id = $1 AND token_hash = $2",
        )
        .bind(tenant.as_uuid())
        .bind(successor.as_deref().unwrap_or_default())
        .execute(tx.conn())
        .await?;
    }
    let next = insert_refresh(tx, tenant, session, generation, key_jkt.as_deref()).await?;
    if lost_response {
        sqlx::query(
            "UPDATE refresh_tokens SET successor_hash = $3 WHERE tenant_id = $1 AND token_hash = $2",
        )
        .bind(tenant.as_uuid())
        .bind(hash.as_bytes().as_slice())
        .bind(next.hash.as_bytes().as_slice())
        .execute(tx.conn())
        .await?;
    } else {
        sqlx::query(
            "UPDATE refresh_tokens SET state = 'rotated', rotated_at = now(), \
               rotation_idempotency_key = $3, successor_hash = $4 \
             WHERE tenant_id = $1 AND token_hash = $2 AND state = 'active'",
        )
        .bind(tenant.as_uuid())
        .bind(hash.as_bytes().as_slice())
        .bind(key)
        .bind(next.hash.as_bytes().as_slice())
        .execute(tx.conn())
        .await?;
    }
    sqlx::query(
        "UPDATE sessions SET idle_expires_at = LEAST(now() + make_interval(secs => $3::float8), \
           absolute_expires_at), updated_at = now() \
         WHERE tenant_id = $1 AND session_id = $2",
    )
    .bind(tenant.as_uuid())
    .bind(sid)
    .bind(policy.idle_secs as f64)
    .execute(tx.conn())
    .await?;
    Ok(RefreshOutcome::Issued(Box::new(NewTokens {
        session_id: session,
        claims: claims(
            tenant,
            user,
            session,
            generation,
            amr,
            auth_time,
            now,
            policy,
            key_jkt.as_deref(),
        )?,
        refresh: next,
        refresh_max_age: max_age,
    })))
}

async fn revoke_family(tx: &mut DomainTx, tenant: TenantId, sid: Uuid) -> Result<(), DbError> {
    sqlx::query(
        "UPDATE refresh_tokens SET state = 'revoked' \
         WHERE tenant_id = $1 AND session_id = $2 AND state <> 'revoked'",
    )
    .bind(tenant.as_uuid())
    .bind(sid)
    .execute(tx.conn())
    .await?;
    Ok(())
}

/// Revoke a session: generation bump, every refresh token of its family revoked, outbox
/// `identity.session.revoked`. Returns whether the session was active. Revoking an inactive
/// session still revokes its tokens and writes no event.
pub async fn revoke_session(
    tx: &mut DomainTx,
    tenant: TenantId,
    session: SessionId,
    reason: &'static str,
) -> Result<bool, DbError> {
    let row: Option<(i64, Uuid)> = sqlx::query_as(
        "UPDATE sessions SET state = 'revoked', generation = generation + 1, \
           version = version + 1, updated_at = now() \
         WHERE tenant_id = $1 AND session_id = $2 AND state = 'active' \
         RETURNING generation, user_id",
    )
    .bind(tenant.as_uuid())
    .bind(session.as_uuid())
    .fetch_optional(tx.conn())
    .await?;
    revoke_family(tx, tenant, session.into_uuid()).await?;
    let Some((generation, uid)) = row else {
        return Ok(false);
    };
    let user = UserId::from_uuid(uid).map_err(|e| DbError::Invalid(e.to_string()))?;
    Outbox::append(
        tx,
        NewEvent {
            tenant_id: Some(tenant),
            event_type: "identity.session.revoked",
            event_version: 1,
            partition_key: user.into_uuid(),
            payload: &SessionRevoked {
                tenant_id: tenant,
                session_id: session,
                user_id: user,
                generation,
                reason,
            },
        },
    )
    .await?;
    Ok(true)
}
