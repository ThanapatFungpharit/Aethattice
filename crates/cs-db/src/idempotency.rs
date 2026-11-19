//! Idempotency records (contract §5.3; spec D.3, C4).
//!
//! Semantics of [`IdempotencyRecords::begin`]:
//! 1. new key (or expired record) → `Begin::Started`; the caller performs the effect and calls
//!    [`IdempotencyRecords::complete`] in the SAME transaction (single-domain operations);
//! 2. same key, same digest, completed → `Begin::Replay(stored response)`;
//! 3. same key, different digest → `idempotency_mismatch` (422);
//! 4. same key, still in progress → `conflict` (409, not retryable), or `outcome_unknown`
//!    (504, retryable) when the caller declares that the original's outcome may already be
//!    committed ([`InProgress::MayBeCommitted`]).
//!
//! For single-domain operations the record and the effect share one transaction, so a
//! concurrent duplicate blocks on the row and then observes the committed result (or a
//! 40001 and is retried). An `in_progress` record is only ever visible when a caller commits
//! it separately from the effect.

use crate::error::DbError;
use crate::pool::DomainTx;
use cs_common::error::{Error as CsError, ErrorCode};
use cs_common::id::{PrincipalId, TenantId};
use cs_common::idempotency::IdempotencyKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Maximum stored response size (row limit, App. E). Larger results need a reference to
/// object storage (M3); until then they are refused.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// BLAKE3 digest of the canonical request.
pub type RequestDigest = [u8; 32];

/// BLAKE3 of the deterministic CBOR array `[method, route_template, {path params}, body]`.
/// `method` is upper-cased; `body` is the exact request body bytes.
pub fn request_digest(
    method: &str,
    route_template: &str,
    path_params: &BTreeMap<String, String>,
    body: &[u8],
) -> Result<RequestDigest, DbError> {
    use cs_crypto::cbor::{Value, encode};
    let v = Value::Array(vec![
        Value::Text(method.to_ascii_uppercase()),
        Value::Text(route_template.to_owned()),
        Value::Map(
            path_params
                .iter()
                .map(|(k, v)| (Value::Text(k.clone()), Value::Text(v.clone())))
                .collect(),
        ),
        Value::Bytes(body.to_vec()),
    ]);
    let bytes = encode(&v).map_err(|e| DbError::Invalid(e.to_string()))?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

/// Who owns the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdempotencyScope {
    pub tenant_id: TenantId,
    pub principal_id: PrincipalId,
    pub key: IdempotencyKey,
}

/// A stored response (status + body), CBOR-encoded in the `response` column.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredResponse {
    pub status: u16,
    #[serde(with = "cs_crypto::cbor::bstr")]
    pub body: Vec<u8>,
}

/// What an `in_progress` record means for this operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InProgress {
    /// The original has not reached its commit point: answer `conflict`.
    NotYetCommitted,
    /// The original's effect may already be committed: answer `outcome_unknown`.
    MayBeCommitted,
}

/// Result of [`IdempotencyRecords::begin`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Begin {
    Started,
    Replay(StoredResponse),
}

#[derive(sqlx::FromRow)]
struct Row {
    request_digest: Vec<u8>,
    state: String,
    response: Option<Vec<u8>>,
}

/// Operations on `idempotency_records`.
#[derive(Debug, Clone, Copy, Default)]
pub struct IdempotencyRecords;

impl IdempotencyRecords {
    /// Claim `scope` for a request with `digest`, or report what happened to an earlier one.
    pub async fn begin(
        tx: &mut DomainTx,
        scope: &IdempotencyScope,
        digest: &RequestDigest,
        retention_hours: i64,
        in_progress: InProgress,
    ) -> Result<Begin, DbError> {
        let claimed: Option<bool> = sqlx::query_scalar(
            "INSERT INTO idempotency_records (tenant_id, principal_id, key, request_digest, state, response, expires_at) \
             VALUES ($1, $2, $3, $4, 'in_progress', NULL, now() + make_interval(hours => $5)) \
             ON CONFLICT (tenant_id, principal_id, key) DO UPDATE \
               SET request_digest = EXCLUDED.request_digest, state = 'in_progress', response = NULL, \
                   expires_at = EXCLUDED.expires_at \
               WHERE idempotency_records.expires_at <= now() \
             RETURNING true",
        )
        .bind(scope.tenant_id.as_uuid())
        .bind(scope.principal_id.as_uuid())
        .bind(scope.key.as_str())
        .bind(digest.as_slice())
        .bind(i32::try_from(retention_hours).map_err(|_| DbError::Invalid("retention".into()))?)
        .fetch_optional(tx.conn())
        .await?;
        if claimed.is_some() {
            return Ok(Begin::Started);
        }
        let row: Row = sqlx::query_as(
            "SELECT request_digest, state, response FROM idempotency_records \
             WHERE tenant_id = $1 AND principal_id = $2 AND key = $3",
        )
        .bind(scope.tenant_id.as_uuid())
        .bind(scope.principal_id.as_uuid())
        .bind(scope.key.as_str())
        .fetch_one(tx.conn())
        .await?;
        if row.request_digest.as_slice() != digest.as_slice() {
            return Err(DbError::app(
                CsError::new(ErrorCode::IdempotencyMismatch)
                    .with_detail("This Idempotency-Key was already used with a different request."),
            ));
        }
        match (row.state.as_str(), row.response) {
            ("completed", Some(resp)) => {
                let r: StoredResponse =
                    cs_crypto::cbor::from_canonical(&resp, MAX_RESPONSE_BYTES + 64)
                        .map_err(|e| DbError::Invalid(format!("stored response: {e}")))?;
                Ok(Begin::Replay(r))
            }
            ("in_progress", _) => Err(DbError::app(match in_progress {
                InProgress::NotYetCommitted => CsError::new(ErrorCode::Conflict)
                    .with_detail("A request with this Idempotency-Key is still in progress."),
                InProgress::MayBeCommitted => CsError::new(ErrorCode::OutcomeUnknown).with_detail(
                    "The original request may have committed. Retry with the same Idempotency-Key.",
                ),
            })),
            _ => Err(DbError::Invalid("inconsistent idempotency record".into())),
        }
    }

    /// Store the response of a started request (same transaction as the effect).
    pub async fn complete(
        tx: &mut DomainTx,
        scope: &IdempotencyScope,
        response: &StoredResponse,
    ) -> Result<(), DbError> {
        let bytes =
            cs_crypto::cbor::to_canonical(response).map_err(|e| DbError::Invalid(e.to_string()))?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(DbError::Invalid(format!(
                "response of {} bytes exceeds {MAX_RESPONSE_BYTES}; large results need an object-storage reference (M3)",
                bytes.len()
            )));
        }
        let n = sqlx::query(
            "UPDATE idempotency_records SET state = 'completed', response = $4 \
             WHERE tenant_id = $1 AND principal_id = $2 AND key = $3 AND state = 'in_progress'",
        )
        .bind(scope.tenant_id.as_uuid())
        .bind(scope.principal_id.as_uuid())
        .bind(scope.key.as_str())
        .bind(&bytes)
        .execute(tx.conn())
        .await?
        .rows_affected();
        if n != 1 {
            return Err(DbError::Invalid(
                "idempotency record is not in progress (complete without begin?)".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_covers_every_component() {
        let mut p = BTreeMap::new();
        p.insert("id".to_owned(), "1".to_owned());
        let base = request_digest("post", "/api/v2/things/{id}", &p, b"{}").unwrap();
        assert_eq!(
            base,
            request_digest("POST", "/api/v2/things/{id}", &p, b"{}").unwrap()
        );
        assert_ne!(
            base,
            request_digest("PUT", "/api/v2/things/{id}", &p, b"{}").unwrap()
        );
        assert_ne!(
            base,
            request_digest("POST", "/api/v2/other/{id}", &p, b"{}").unwrap()
        );
        assert_ne!(
            base,
            request_digest("POST", "/api/v2/things/{id}", &p, b"{ }").unwrap()
        );
        let mut p2 = p.clone();
        p2.insert("id".to_owned(), "2".to_owned());
        assert_ne!(
            base,
            request_digest("POST", "/api/v2/things/{id}", &p2, b"{}").unwrap()
        );
    }
}
