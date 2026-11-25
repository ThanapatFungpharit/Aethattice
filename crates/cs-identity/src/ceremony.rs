//! Server-side ceremony state for MFA and WebAuthn (contract §2.2, §2.3, rev 10/11), stored in
//! `auth_ceremonies` exactly like the OPAQUE txns of `auth_txns` (rev 6):
//! - the client-visible id is an `rt1` token; only its SHA-256 is stored, and its tenant
//!   segment selects the partition;
//! - the state is AEAD-sealed under the txn-sealing key of the current server key version,
//!   with associated data `tenant_id ‖ txn_hash ‖ kind`;
//! - a ceremony is consumed by `DELETE … RETURNING` in the finishing transaction, so it is
//!   single use across nodes; a ceremony past `expires_at` is never accepted;
//! - expired rows are swept lazily in bounded batches (hash-bucketed expiry index, App. E).

use crate::auth::{EXPIRY_BUCKETS, expiry_bucket, sweep_bucketed};
use crate::keys::OpaqueKeys;
use crate::token::{self, TokenHash};
use cs_common::id::{SessionId, TenantId, UserId};
use cs_common::secret::Secret;
use cs_db::{DbError, DomainPool, DomainTx};
use uuid::Uuid;
use zeroize::Zeroizing;

/// `auth_txn` after OPAQUE (rev 11: 5 min, single use).
pub const MFA_TTL_SECS: i64 = 300;
/// WebAuthn ceremonies: the WebAuthn default timeout (5 min) covers the user's interaction
/// with the authenticator.
pub const WEBAUTHN_TTL_SECS: i64 = 300;

const _: () = assert!(EXPIRY_BUCKETS == 16);

/// Ceremony kinds (CHECK-constrained in migration 0103).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Mfa,
    WebauthnReg,
    WebauthnLogin,
    WebauthnAssert,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Mfa => "mfa",
            Kind::WebauthnReg => "webauthn_reg",
            Kind::WebauthnLogin => "webauthn_login",
            Kind::WebauthnAssert => "webauthn_assert",
        }
    }

    fn ttl(self) -> i64 {
        match self {
            Kind::Mfa => MFA_TTL_SECS,
            _ => WEBAUTHN_TTL_SECS,
        }
    }
}

fn ad(tenant: &TenantId, hash: &TokenHash, kind: Kind) -> Vec<u8> {
    let mut ad = tenant.as_bytes().to_vec();
    ad.extend_from_slice(hash.as_bytes());
    ad.extend_from_slice(kind.as_str().as_bytes());
    ad
}

/// A ceremony to create.
#[derive(Debug)]
pub struct New<'a> {
    pub tenant: TenantId,
    pub kind: Kind,
    pub source: &'a str,
    pub user: Option<UserId>,
    pub session: Option<SessionId>,
    pub state: &'a [u8],
}

/// Create a ceremony inside the caller's transaction; returns the client-visible id.
/// Sealing is local CPU work (no network call inside the transaction).
pub async fn insert_in_tx(
    tx: &mut DomainTx,
    keys: &OpaqueKeys,
    c: New<'_>,
) -> Result<Secret<String>, DbError> {
    let t = token::generate(c.tenant)?;
    let k = keys.current();
    let sealed = k
        .seal(c.state, &ad(&c.tenant, &t.hash, c.kind))
        .map_err(|e| DbError::app(e.into_inner()))?;
    sqlx::query(
        "INSERT INTO auth_ceremonies (tenant_id, txn_hash, kind, source, user_id, session_id, \
           key_version, sealed_state, expires_at, expiry_bucket) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now() + make_interval(secs => $9::float8), $10)",
    )
    .bind(c.tenant.as_uuid())
    .bind(t.hash.as_bytes().as_slice())
    .bind(c.kind.as_str())
    .bind(c.source)
    .bind(c.user.map(UserId::into_uuid))
    .bind(c.session.map(SessionId::into_uuid))
    .bind(k.version)
    .bind(sealed)
    .bind(c.kind.ttl() as f64)
    .bind(expiry_bucket(t.hash.as_bytes()))
    .execute(tx.conn())
    .await?;
    Ok(t.token)
}

/// Create a ceremony in its own transaction.
#[allow(clippy::too_many_arguments)]
pub async fn insert(
    pool: &DomainPool,
    keys: std::sync::Arc<OpaqueKeys>,
    tenant: TenantId,
    kind: Kind,
    source: &str,
    user: Option<UserId>,
    session: Option<SessionId>,
    state: Zeroizing<Vec<u8>>,
) -> Result<Secret<String>, DbError> {
    let source = source.to_owned();
    pool.transaction(move |tx| {
        let (keys, source, state) = (keys.clone(), source.clone(), state.clone());
        Box::pin(async move {
            insert_in_tx(
                tx,
                &keys,
                New {
                    tenant,
                    kind,
                    source: &source,
                    user,
                    session,
                    state: &state,
                },
            )
            .await
        })
    })
    .await
}

/// A live ceremony with its opened state.
#[derive(Debug)]
pub struct Ceremony {
    pub source: String,
    pub user: Option<Uuid>,
    pub session: Option<Uuid>,
    pub state: Zeroizing<Vec<u8>>,
}

type Row = (String, Option<Uuid>, Option<Uuid>, i32, Vec<u8>, bool);

fn open(
    keys: &OpaqueKeys,
    tenant: &TenantId,
    hash: &TokenHash,
    kind: Kind,
    r: Row,
) -> Option<Ceremony> {
    let (source, user, session, kv, sealed, live) = r;
    if !live {
        return None;
    }
    let k = keys.get(kv)?;
    let state = k.open(&sealed, &ad(tenant, hash, kind))?;
    Some(Ceremony {
        source,
        user,
        session,
        state,
    })
}

/// Consume (delete) a ceremony of `kind`; `None` if missing, expired, of another kind or not
/// openable. The delete commits with the caller's transaction.
pub async fn take(
    tx: &mut DomainTx,
    keys: &OpaqueKeys,
    tenant: TenantId,
    hash: &TokenHash,
    kind: Kind,
) -> Result<Option<Ceremony>, DbError> {
    let r: Option<Row> = sqlx::query_as(
        "DELETE FROM auth_ceremonies WHERE tenant_id = $1 AND txn_hash = $2 AND kind = $3 \
         RETURNING source, user_id, session_id, key_version, sealed_state, expires_at > now()",
    )
    .bind(tenant.as_uuid())
    .bind(hash.as_bytes().as_slice())
    .bind(kind.as_str())
    .fetch_optional(tx.conn())
    .await?;
    Ok(r.and_then(|r| open(keys, &tenant, hash, kind, r)))
}

/// Read a live ceremony without consuming it (`webauthn/assert/start` reads the `auth_txn`).
pub async fn peek(
    tx: &mut DomainTx,
    keys: &OpaqueKeys,
    tenant: TenantId,
    hash: &TokenHash,
    kind: Kind,
) -> Result<Option<Ceremony>, DbError> {
    let r: Option<Row> = sqlx::query_as(
        "SELECT source, user_id, session_id, key_version, sealed_state, expires_at > now() \
         FROM auth_ceremonies WHERE tenant_id = $1 AND txn_hash = $2 AND kind = $3",
    )
    .bind(tenant.as_uuid())
    .bind(hash.as_bytes().as_slice())
    .bind(kind.as_str())
    .fetch_optional(tx.conn())
    .await?;
    Ok(r.and_then(|r| open(keys, &tenant, hash, kind, r)))
}

/// Whether `token` names a live MFA `auth_txn` (rev 11: presenting it to the wrong endpoint
/// answers `mfa_required`).
pub async fn is_live_mfa(pool: &DomainPool, token: &str) -> bool {
    let Ok(p) = token::parse(token) else {
        return false;
    };
    pool.read_snapshot(move |tx| {
        Box::pin(async move {
            let n: Option<bool> = sqlx::query_scalar(
                "SELECT expires_at > now() FROM auth_ceremonies \
                 WHERE tenant_id = $1 AND txn_hash = $2 AND kind = 'mfa'",
            )
            .bind(p.tenant_id.as_uuid())
            .bind(p.hash.as_bytes().as_slice())
            .fetch_optional(tx.conn())
            .await?;
            Ok(n == Some(true))
        })
    })
    .await
    .unwrap_or(false)
}

/// Bounded sweep of expired ceremonies (see [`crate::auth::sweep_expired_txns`]).
pub async fn sweep_expired(pool: &DomainPool, batch_rows: i64, max_batches: u32) -> u64 {
    sweep_bucketed(
        pool,
        "auth_ceremonies",
        "tenant_id, txn_hash",
        batch_rows,
        max_batches,
    )
    .await
}
