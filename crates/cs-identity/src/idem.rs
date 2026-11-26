//! Idempotency-Key replay on identity writes (contract rev 15, implemented per rev 16; spec D.3,
//! App. C rule C4).
//!
//! Every identity write except `token/refresh` (which keeps `[R1]`) records its result in the
//! identity domain's `idempotency_records` through the M0 `cs_db::idempotency` API, in the same
//! transaction as the effect ([`run`]). The stored `response` is a [`StoredResponse`] whose
//! status is the HTTP status and whose body is a CBOR [`Envelope`]:
//!
//! - `Plain`: a response without bearer secrets (body and an optional `Set-Cookie`);
//! - `Failed`: a committed failure (e.g. a consumed ceremony that did not verify); a replay
//!   answers the same error code again;
//! - `Sealed`: a response carrying bearer secrets (§2.4 results, recovery grants, recovery
//!   codes, ceremony txn tokens), XChaCha20-Poly1305-sealed under the idempotency purpose key of
//!   an OPAQUE server key version, associated data `tenant ‖ principal ‖ key ‖ route`
//!   (length-prefixed). Its `not_after` (DB clock) is the secret's own lifetime, capped by the
//!   C13 retention; it is also written to `secret_expires_at` (migration 0104);
//! - `Expired`: the tombstone the sweeper ([`sweep_expired_secrets`]) writes over a sealed
//!   payload past `secret_expires_at`, so no ciphertext outlives the secret.
//!
//! A replay of a sealed result past `not_after`, or of a tombstone, is `unauthenticated` (the
//! client restarts the ceremony). §2.4 results (rev 16 P1) store the claims, the signing `kid`
//! and the refresh token instead of the signed access token: the token is signed after commit
//! (the KMS may be remote), and a replay re-signs the same claims with the same `kid`, which
//! Ed25519 makes byte-identical.

use crate::admin::AdminResult as AuthResult;
use crate::auth::{EXPIRY_BUCKETS, unauthenticated};
use crate::jws::AccessClaims;
use crate::keys::OpaqueKeys;
use crate::session::NewTokens;
use crate::token::TokenHash;
use cs_common::error::{Code, Error, ErrorCode};
use cs_common::id::{PrincipalId, TenantId, UserId};
use cs_common::idempotency::IdempotencyKey;
use cs_common::secret::Secret;
use cs_crypto::sig::KeyId;
use cs_db::idempotency::{
    Begin, IdempotencyRecords, IdempotencyScope, RequestDigest, StoredResponse,
};
use cs_db::{DbError, DomainPool, DomainTx, TxFuture};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Lifetime of a stored recovery-code set (contract rev 15: 24 h).
pub const CODES_TTL_SECS: i64 = 24 * 3600;
/// Sealed rows rewritten per sweep transaction are bounded by the caller's batch size.
const MAX_SEALED_BYTES: usize = cs_db::idempotency::MAX_RESPONSE_BYTES;

/// What the HTTP layer extracted from a write request carrying an `Idempotency-Key`.
#[derive(Debug, Clone)]
pub struct IdemRequest {
    pub key: IdempotencyKey,
    /// `request_digest(method, route template, path params, JCS body)` (M0 §5.3).
    pub digest: RequestDigest,
    /// The route template, bound into the sealing associated data.
    pub route: String,
}

/// A request bound to its scope (tenant and principal), ready to run.
#[derive(Clone)]
pub struct Idem(Arc<Inner>);

struct Inner {
    req: IdemRequest,
    scope: IdempotencyScope,
    keys: Arc<OpaqueKeys>,
    retention_hours: i64,
}

impl std::fmt::Debug for Idem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Idem")
            .field("route", &self.0.req.route)
            .finish_non_exhaustive()
    }
}

/// Deterministic, v7-shaped principal id from 32 bytes of hash output.
fn principal_from(h: &[u8; 32]) -> AuthResult<PrincipalId> {
    let mut b = [0u8; 16];
    b.copy_from_slice(&h[..16]);
    let u = uuid::Builder::from_bytes(b)
        .with_variant(uuid::Variant::RFC4122)
        .with_version(uuid::Version::SortRand)
        .into_uuid();
    Ok(PrincipalId::from_uuid(u).map_err(Error::internal)?)
}

/// Principal of an authenticated write: the user.
pub fn user_principal(user: UserId) -> AuthResult<PrincipalId> {
    Ok(PrincipalId::from_uuid(user.into_uuid()).map_err(Error::internal)?)
}

/// Principal of a write that carries a grant, txn or ceremony token (rev 16 P3): derived from
/// the token's hash, so a retry after the token was consumed finds the record.
pub fn token_principal(hash: &TokenHash) -> AuthResult<PrincipalId> {
    principal_from(hash.as_bytes())
}

/// Principal of a pre-authentication start without a ceremony id yet (rev 16 P3):
/// `H(route ‖ tenant ‖ normalized login)` (`login` empty for `webauthn/login/start`). It does not
/// depend on whether the account exists.
pub fn start_principal(route: &str, tenant: TenantId, login: &str) -> AuthResult<PrincipalId> {
    let mut h = blake3::Hasher::new_derive_key("identity idempotency start principal v1");
    for part in [
        route.as_bytes(),
        tenant.as_uuid().as_bytes(),
        login.as_bytes(),
    ] {
        h.update(&u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
        h.update(part);
    }
    principal_from(h.finalize().as_bytes())
}

impl Idem {
    pub fn new(
        req: IdemRequest,
        tenant: TenantId,
        principal: PrincipalId,
        keys: Arc<OpaqueKeys>,
        retention_hours: i64,
    ) -> Self {
        let scope = IdempotencyScope {
            tenant_id: tenant,
            principal_id: principal,
            key: req.key.clone(),
        };
        Self(Arc::new(Inner {
            req,
            scope,
            keys,
            retention_hours,
        }))
    }

    /// `tenant ‖ principal ‖ key ‖ route`, each length-prefixed.
    fn ad(&self) -> Vec<u8> {
        let s = &self.0.scope;
        let mut ad = b"identity-idempotency-v1".to_vec();
        for part in [
            s.tenant_id.as_uuid().as_bytes().as_slice(),
            s.principal_id.as_uuid().as_bytes().as_slice(),
            s.key.as_str().as_bytes(),
            self.0.req.route.as_bytes(),
        ] {
            ad.extend_from_slice(&u32::try_from(part.len()).unwrap_or(u32::MAX).to_be_bytes());
            ad.extend_from_slice(part);
        }
        ad
    }

    fn bucket(&self) -> i16 {
        let h = blake3::hash(self.0.scope.key.as_str().as_bytes());
        crate::auth::expiry_bucket(h.as_bytes())
    }

    async fn begin(&self, tx: &mut DomainTx) -> Result<Option<Replayed>, DbError> {
        let i = &self.0;
        match IdempotencyRecords::begin(tx, &i.scope, &i.req.digest, i.retention_hours).await? {
            Begin::Started => Ok(None),
            Begin::Replay(stored) => Ok(Some(Replayed {
                stored,
                db_now: db_now(tx).await?,
            })),
        }
    }

    /// Read-only look-up before the request's preconditions are checked (a retry must replay
    /// even when the original consumed its txn or grant). The claim in [`run`] stays
    /// authoritative for concurrent requests.
    pub async fn peek(&self, pool: &DomainPool) -> AuthResult<Option<Replayed>> {
        let s = self.0.scope.clone();
        type R = (Vec<u8>, String, Option<Vec<u8>>, i64);
        let row: Option<R> = pool
            .read_snapshot(move |tx| {
                let s = s.clone();
                Box::pin(async move {
                    Ok(sqlx::query_as(
                        "SELECT request_digest, state, response, \
                           floor(extract(epoch FROM now()))::bigint \
                         FROM idempotency_records \
                         WHERE tenant_id = $1 AND principal_id = $2 AND key = $3 \
                           AND expires_at > now()",
                    )
                    .bind(s.tenant_id.as_uuid())
                    .bind(s.principal_id.as_uuid())
                    .bind(s.key.as_str())
                    .fetch_optional(tx.conn())
                    .await?)
                })
            })
            .await?;
        let Some((digest, state, response, db_now)) = row else {
            return Ok(None);
        };
        if digest.as_slice() != self.0.req.digest.as_slice() {
            return Err(Error::new(ErrorCode::IdempotencyMismatch)
                .with_detail("This Idempotency-Key was already used with a different request.")
                .into());
        }
        match (state.as_str(), response) {
            ("completed", Some(resp)) => {
                let stored: StoredResponse =
                    cs_crypto::cbor::from_canonical(&resp, MAX_SEALED_BYTES)
                        .map_err(|e| Error::internal(DbError::Invalid(e.to_string())))?;
                Ok(Some(Replayed { stored, db_now }))
            }
            // In progress: the claim in `run` decides (waits or answers outcome_unknown).
            _ => Ok(None),
        }
    }

    async fn complete(&self, tx: &mut DomainTx, entry: Entry) -> Result<(), DbError> {
        let (status, env, secret_until) = match entry {
            Entry::Plain {
                status,
                body,
                cookie,
            } => (status, Envelope::Plain { body, cookie }, None),
            Entry::Failed { status, code } => (
                status,
                Envelope::Failed {
                    code: code.as_str().to_owned(),
                },
                None,
            ),
            Entry::Secret {
                status,
                ttl_secs,
                content,
            } => {
                let cap = self.0.retention_hours.saturating_mul(3600);
                let not_after = db_now(tx).await?.saturating_add(ttl_secs.min(cap).max(0));
                let pt = Zeroizing::new(
                    cs_crypto::cbor::to_canonical(&SealedPayload { not_after, content })
                        .map_err(|e| DbError::Invalid(e.to_string()))?,
                );
                let k = self.0.keys.current();
                let ct = k
                    .seal_idempotency(&pt, &self.ad())
                    .map_err(|e| DbError::Invalid(e.to_string()))?;
                (
                    status,
                    Envelope::Sealed {
                        key_version: k.version,
                        ct,
                    },
                    Some(not_after),
                )
            }
        };
        let body =
            cs_crypto::cbor::to_canonical(&env).map_err(|e| DbError::Invalid(e.to_string()))?;
        IdempotencyRecords::complete(tx, &self.0.scope, &StoredResponse { status, body }).await?;
        // Always written: a record re-claimed after expiry must not keep a stale deadline.
        let s = &self.0.scope;
        sqlx::query(
            "UPDATE idempotency_records SET secret_expires_at = to_timestamp($4::float8), \
               secret_expiry_bucket = CASE WHEN $4::float8 IS NULL THEN NULL ELSE $5 END \
             WHERE tenant_id = $1 AND principal_id = $2 AND key = $3",
        )
        .bind(s.tenant_id.as_uuid())
        .bind(s.principal_id.as_uuid())
        .bind(s.key.as_str())
        .bind(secret_until.map(|t| t as f64))
        .bind(self.bucket())
        .execute(tx.conn())
        .await?;
        Ok(())
    }

    /// Decode a replayed record: plain or sealed reply, a re-signable session, or the original
    /// error. An expired (or tombstoned, or unopenable) sealed result is `unauthenticated`.
    pub fn open(&self, r: Replayed) -> AuthResult<Opened> {
        let env: Envelope = cs_crypto::cbor::from_canonical(&r.stored.body, MAX_SEALED_BYTES)
            .map_err(|e| Error::internal(DbError::Invalid(format!("stored replay: {e}"))))?;
        match env {
            Envelope::Plain { body, cookie } => Ok(Opened::Reply(Reply {
                status: r.stored.status,
                body,
                cookie,
            })),
            Envelope::Failed { code } => {
                let code = ErrorCode::from_str(&code).unwrap_or(ErrorCode::Unauthenticated);
                Err(match code {
                    ErrorCode::Unauthenticated => unauthenticated(),
                    c => Error::new(c).into(),
                })
            }
            Envelope::Expired => Err(unauthenticated()),
            Envelope::Sealed { key_version, ct } => {
                let k = self.0.keys.get(key_version).ok_or_else(unauthenticated)?;
                let pt = k
                    .open_idempotency(&ct, &self.ad())
                    .ok_or_else(unauthenticated)?;
                let p: SealedPayload = cs_crypto::cbor::from_canonical(&pt, MAX_SEALED_BYTES)
                    .map_err(|_| unauthenticated())?;
                if r.db_now >= p.not_after {
                    return Err(unauthenticated());
                }
                Ok(match p.content {
                    Content::Reply { body, cookie } => Opened::Reply(Reply {
                        status: r.stored.status,
                        body,
                        cookie,
                    }),
                    Content::Session(s) => Opened::Session(s),
                })
            }
        }
    }
}

async fn db_now(tx: &mut DomainTx) -> Result<i64, DbError> {
    Ok(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM now()))::bigint")
            .fetch_one(tx.conn())
            .await?,
    )
}

/// The wire form of a response: status, JSON body (empty for 204) and `Set-Cookie`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub status: u16,
    pub body: Vec<u8>,
    pub cookie: Option<String>,
}

impl Reply {
    /// A JSON reply. The fresh path and the stored copy use the same bytes.
    pub fn json<T: Serialize>(status: u16, v: &T) -> Result<Self, DbError> {
        Ok(Self {
            status,
            body: serde_json::to_vec(v).map_err(|e| DbError::Invalid(e.to_string()))?,
            cookie: None,
        })
    }

    pub fn empty(status: u16) -> Self {
        Self {
            status,
            body: Vec::new(),
            cookie: None,
        }
    }

    pub fn with_cookie(mut self, cookie: Option<String>) -> Self {
        self.cookie = cookie;
        self
    }
}

/// What to record for a fresh result.
#[derive(Debug, Clone)]
pub enum Entry {
    Plain {
        status: u16,
        body: Vec<u8>,
        cookie: Option<String>,
    },
    /// A failure that committed (the effect consumed something); replays the same code.
    Failed { status: u16, code: ErrorCode },
    /// A result carrying bearer secrets: sealed, kept for `ttl_secs` (capped by C13).
    Secret {
        status: u16,
        ttl_secs: i64,
        content: Content,
    },
}

impl Entry {
    pub fn plain(r: Reply) -> Self {
        Entry::Plain {
            status: r.status,
            body: r.body,
            cookie: r.cookie,
        }
    }

    pub fn secret(r: Reply, ttl_secs: i64) -> Self {
        Entry::Secret {
            status: r.status,
            ttl_secs,
            content: Content::Reply {
                body: r.body,
                cookie: r.cookie,
            },
        }
    }

    pub fn unauthenticated() -> Self {
        Entry::Failed {
            status: 401,
            code: ErrorCode::Unauthenticated,
        }
    }
}

/// A replayed record as read inside the transaction (decoded after commit by [`Idem::open`]).
#[derive(Debug)]
pub struct Replayed {
    stored: StoredResponse,
    db_now: i64,
}

/// A decoded replay.
#[derive(Debug)]
pub enum Opened {
    Reply(Reply),
    /// A §2.4 result to re-sign (rev 16 P1).
    Session(SessionSeal),
}

/// Result of [`run`].
#[derive(Debug)]
pub enum Ran<T> {
    Fresh(T),
    Replay(Replayed),
}

#[derive(Debug, Serialize, Deserialize)]
enum Envelope {
    Plain {
        #[serde(with = "cs_crypto::cbor::bstr")]
        body: Vec<u8>,
        cookie: Option<String>,
    },
    Failed {
        code: String,
    },
    Sealed {
        key_version: i32,
        #[serde(with = "cs_crypto::cbor::bstr")]
        ct: Vec<u8>,
    },
    Expired,
}

#[derive(Serialize, Deserialize)]
struct SealedPayload {
    not_after: i64,
    content: Content,
}

/// Sealed content.
#[derive(Clone, Serialize, Deserialize)]
pub enum Content {
    Reply {
        #[serde(with = "cs_crypto::cbor::bstr")]
        body: Vec<u8>,
        cookie: Option<String>,
    },
    Session(SessionSeal),
}

/// The inputs of a §2.4 result (rev 16 P1). Never logged (`Debug` is redacted).
#[derive(Clone, Serialize, Deserialize)]
pub struct SessionSeal {
    /// JSON of the access-token claims before `iss`/`aud` are set by the signer.
    #[serde(with = "cs_crypto::cbor::bstr")]
    pub claims: Vec<u8>,
    pub kid: String,
    pub refresh_token: String,
    pub refresh_max_age: i64,
    pub expires_in: i64,
    pub session_id: String,
    pub reregister: bool,
}

impl std::fmt::Debug for SessionSeal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionSeal(..)")
    }
}

impl std::fmt::Debug for Content {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Content(..)")
    }
}

/// Run `effect` in one identity transaction together with the idempotency record (when `idem`
/// is set): a duplicate gets the stored record, a new key runs the effect and stores
/// `encode(&result)`. Without `idem` this is a plain transaction.
pub async fn run<T, F, E>(
    pool: &DomainPool,
    idem: Option<Idem>,
    effect: F,
    encode: E,
) -> Result<Ran<T>, DbError>
where
    T: Send + 'static,
    F: for<'c> Fn(&'c mut DomainTx) -> TxFuture<'c, T> + Send + Sync + 'static,
    E: Fn(&T) -> Result<Entry, DbError> + Send + Sync + 'static,
{
    let effect = Arc::new(effect);
    let encode = Arc::new(encode);
    pool.transaction(move |tx| {
        let (idem, effect, encode) = (idem.clone(), effect.clone(), encode.clone());
        Box::pin(async move {
            if let Some(i) = &idem
                && let Some(r) = i.begin(tx).await?
            {
                return Ok(Ran::Replay(r));
            }
            let out = effect(tx).await?;
            if let Some(i) = &idem {
                i.complete(tx, encode(&out)?).await?;
            }
            Ok(Ran::Fresh(out))
        })
    })
    .await
}

/// Tombstone bytes written over expired sealed payloads.
fn tombstone() -> Result<Vec<u8>, DbError> {
    let body = cs_crypto::cbor::to_canonical(&Envelope::Expired)
        .map_err(|e| DbError::Invalid(e.to_string()))?;
    cs_crypto::cbor::to_canonical(&StoredResponse { status: 401, body })
        .map_err(|e| DbError::Invalid(e.to_string()))
}

/// Overwrite sealed payloads past `secret_expires_at` with a tombstone (rev 16 P2), in bounded
/// batches: at most `batch_rows` rows per transaction, at most `max_batches` transactions. Each
/// read is a point lookup on the hash-sharded bucket plus a range on the deadline (migration
/// 0104 index). Returns the number of rows tombstoned.
pub async fn sweep_expired_secrets(pool: &DomainPool, batch_rows: i64, max_batches: u32) -> u64 {
    let Ok(tomb) = tombstone() else { return 0 };
    let mut total = 0u64;
    for _ in 0..max_batches {
        let tomb = tomb.clone();
        let r = pool
            .transaction(move |tx| {
                let tomb = tomb.clone();
                Box::pin(async move {
                    let mut left = batch_rows;
                    for b in 0..EXPIRY_BUCKETS {
                        if left <= 0 {
                            break;
                        }
                        let n = sqlx::query(
                            "UPDATE idempotency_records SET response = $3, \
                               secret_expires_at = NULL, secret_expiry_bucket = NULL \
                             WHERE (tenant_id, principal_id, key) IN ( \
                               SELECT tenant_id, principal_id, key FROM idempotency_records \
                               WHERE secret_expiry_bucket = $2 AND secret_expires_at IS NOT NULL \
                                 AND secret_expires_at <= now() LIMIT $1)",
                        )
                        .bind(left)
                        .bind(b)
                        .bind(&tomb)
                        .execute(tx.conn())
                        .await?
                        .rows_affected();
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
                tracing::warn!(error = %e, "idempotency secret sweep batch failed");
                break;
            }
        }
    }
    total
}

fn plain<T>(o: Opened) -> AuthResult<Out<T>> {
    match o {
        Opened::Reply(r) => Ok(Out::Reply(r)),
        Opened::Session(_) => Err(Error::new(ErrorCode::Internal)
            .with_detail("unexpected stored session result")
            .into()),
    }
}

pub const ROUTE_LOGIN_START: &str = "/api/v2/auth/opaque/login/start";
pub const ROUTE_WEBAUTHN_LOGIN_START: &str = "/api/v2/auth/webauthn/login/start";
pub const ROUTE_RECOVERY_START: &str = "/api/v2/auth/recovery/start";

/// A service result: the typed value (fresh, or a re-signed §2.4 replay) or a stored reply.
#[derive(Debug)]
pub enum Out<T> {
    Value(T),
    Reply(Reply),
}

impl crate::auth::AuthService {
    /// Bind an extracted request to its scope (`None` without an `Idempotency-Key`).
    pub(crate) fn bind_idem(
        &self,
        req: Option<IdemRequest>,
        tenant: TenantId,
        principal: impl FnOnce() -> AuthResult<PrincipalId>,
        keys: &Arc<OpaqueKeys>,
    ) -> AuthResult<Option<Idem>> {
        req.map(|r| {
            Ok(Idem::new(
                r,
                tenant,
                principal()?,
                keys.clone(),
                self.policy.idempotency_retention_hours,
            ))
        })
        .transpose()
    }

    /// [`Self::early_replay`] for a route without a §2.4 result.
    pub(crate) async fn early<T>(&self, idem: Option<&Idem>) -> AuthResult<Option<Out<T>>> {
        let Some(i) = idem else { return Ok(None) };
        match i.peek(&self.pool).await? {
            Some(r) => Ok(Some(plain(i.open(r)?)?)),
            None => Ok(None),
        }
    }

    /// The outcome of [`run`] for a route without a §2.4 result: `value` when fresh.
    pub(crate) fn ran_plain<T, U>(
        &self,
        idem: Option<&Idem>,
        ran: Ran<U>,
        value: impl FnOnce(U) -> T,
    ) -> AuthResult<Out<T>> {
        match ran {
            Ran::Fresh(u) => Ok(Out::Value(value(u))),
            Ran::Replay(r) => {
                let i = idem.ok_or_else(|| Error::new(ErrorCode::Internal))?;
                plain(i.open(r)?)
            }
        }
    }

    /// [`Idem::peek`] then decode: `Some` when the request is a replay.
    pub(crate) async fn early_replay<T>(
        &self,
        idem: Option<&Idem>,
        session: impl FnOnce(crate::auth::Authenticated) -> T,
    ) -> AuthResult<Option<Out<T>>> {
        let Some(i) = idem else { return Ok(None) };
        match i.peek(&self.pool).await? {
            Some(r) => Ok(Some(self.open_replay(Some(i), r, session).await?)),
            None => Ok(None),
        }
    }

    /// The signing key for a §2.4 result, fetched before the effect transaction (rev 16 P1).
    pub(crate) async fn signing_kid(&self) -> AuthResult<KeyId> {
        self.access_tokens().current_key().await
    }

    /// Decode a replay; a §2.4 envelope is re-signed with its stored `kid`.
    pub(crate) async fn open_replay<T>(
        &self,
        idem: Option<&Idem>,
        r: Replayed,
        session: impl FnOnce(crate::auth::Authenticated) -> T,
    ) -> AuthResult<Out<T>> {
        let idem = idem.ok_or_else(|| Error::new(ErrorCode::Internal))?;
        match idem.open(r)? {
            Opened::Reply(r) => Ok(Out::Reply(r)),
            Opened::Session(s) => Ok(Out::Value(session(self.resign(s).await?))),
        }
    }

    async fn resign(&self, s: SessionSeal) -> AuthResult<crate::auth::Authenticated> {
        let claims: AccessClaims =
            serde_json::from_slice(&s.claims).map_err(|_| unauthenticated())?;
        let kid = KeyId::from_str(&s.kid).map_err(|_| unauthenticated())?;
        let token = match self.access_tokens().sign_with(&kid, claims).await {
            Ok(t) => t,
            Err(e) if matches!(e.code(), Code::Core(ErrorCode::Unavailable)) => return Err(e),
            // rev 16 P1: a kid that can no longer sign → unauthenticated.
            Err(_) => return Err(unauthenticated()),
        };
        let session_id = uuid::Uuid::parse_str(&s.session_id)
            .ok()
            .and_then(|u| cs_common::id::SessionId::from_uuid(u).ok())
            .ok_or_else(unauthenticated)?;
        Ok(crate::auth::Authenticated {
            access_token: Secret::new(token),
            expires_in: s.expires_in,
            session_id,
            refresh_token: Secret::new(s.refresh_token),
            refresh_max_age: s.refresh_max_age,
            reregister: s.reregister,
        })
    }

    /// Sign a fresh §2.4 result with the `kid` stored in its envelope.
    pub(crate) async fn finish_tokens_with(
        &self,
        kid: &KeyId,
        nt: NewTokens,
        reregister: bool,
    ) -> AuthResult<crate::auth::Authenticated> {
        let expires_in = nt.claims.exp - nt.claims.iat;
        let at = self.access_tokens().sign_with(kid, nt.claims).await?;
        Ok(crate::auth::Authenticated {
            access_token: Secret::new(at),
            expires_in,
            session_id: nt.session_id,
            refresh_token: nt.refresh.token,
            refresh_max_age: nt.refresh_max_age,
            reregister,
        })
    }
}

/// The sealed §2.4 envelope of a fresh session (rev 16 P1), kept for the access token's
/// lifetime.
pub(crate) fn session_entry(
    nt: &NewTokens,
    kid: &KeyId,
    reregister: bool,
) -> Result<Entry, DbError> {
    let claims = serde_json::to_vec(&nt.claims).map_err(|e| DbError::Invalid(e.to_string()))?;
    Ok(Entry::Secret {
        status: 200,
        ttl_secs: nt.claims.exp - nt.claims.iat,
        content: Content::Session(SessionSeal {
            claims,
            kid: kid.to_string(),
            refresh_token: nt.refresh.token.expose_secret().clone(),
            refresh_max_age: nt.refresh_max_age,
            expires_in: nt.claims.exp - nt.claims.iat,
            session_id: nt.session_id.as_uuid().to_string(),
            reregister,
        }),
    })
}
