//! Idempotency records (contract §5.3 rev 2; spec D.3, App. C rule C4).
//!
//! Semantics of [`IdempotencyRecords::begin`]:
//! 1. new key, or a record past `expires_at` → `Begin::Started`; the caller performs the effect
//!    and calls [`IdempotencyRecords::complete`] in the SAME transaction;
//! 2. same key, same digest, completed → `Begin::Replay(stored response)`;
//! 3. same key, different digest → `idempotency_mismatch` (422);
//! 4. same key, same digest, still `in_progress` → `outcome_unknown` (504, retryable).
//!
//! Because the record and the effect share one transaction, exactly one of N concurrent
//! identical requests executes: the others wait on the record's row lock and then replay the
//! committed result (or, if the original rolled back, one of them executes). An `in_progress`
//! record is only visible when a writer committed it without completing it (an original that
//! crashed mid-flight in a multi-step flow); that case answers `outcome_unknown`.
//! [`IdempotencyRecords::execute`] packages the whole pattern.

use crate::error::DbError;
use crate::pool::{DomainPool, DomainTx, TxFuture};
use cs_common::error::{Error as CsError, ErrorCode};
use cs_common::id::{PrincipalId, TenantId};
use cs_common::idempotency::IdempotencyKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Maximum stored response size (row limit, App. E). Exceeding it is an `internal` error,
/// never truncation; operations with possibly larger results must return a reference.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// BLAKE3 digest of the canonical request.
pub type RequestDigest = [u8; 32];

/// The request body as seen by the digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestBody<'a> {
    /// No body: digested as the empty string.
    Absent,
    /// A JSON body: digested in RFC 8785 (JCS) canonical form.
    Json(&'a [u8]),
    /// Any other media type: digested raw.
    Raw(&'a [u8]),
}

/// `body_digest`: BLAKE3 of the JCS canonical JSON, of the raw bytes, or of "" when absent.
/// Invalid JSON is `invalid_request`.
pub fn body_digest(body: RequestBody<'_>) -> Result<[u8; 32], DbError> {
    Ok(match body {
        RequestBody::Absent => *blake3::hash(b"").as_bytes(),
        RequestBody::Raw(b) => *blake3::hash(b).as_bytes(),
        RequestBody::Json(b) => {
            let v: serde_json::Value = serde_json::from_slice(b).map_err(|_| {
                DbError::app(
                    CsError::new(ErrorCode::InvalidRequest)
                        .with_detail("The request body is not valid JSON."),
                )
            })?;
            let canon = serde_jcs::to_vec(&v).map_err(|e| DbError::Invalid(e.to_string()))?;
            *blake3::hash(&canon).as_bytes()
        }
    })
}

/// BLAKE3 over the deterministic-CBOR array
/// `[method, route_template, {path params, sorted}, body_digest]` (contract §5.3 rev 2).
/// `method` is upper-cased.
pub fn request_digest(
    method: &str,
    route_template: &str,
    path_params: &BTreeMap<String, String>,
    body: RequestBody<'_>,
) -> Result<RequestDigest, DbError> {
    use cs_crypto::cbor::{Value, encode};
    let v = Value::Array(vec![
        Value::Text(method.to_ascii_uppercase()),
        Value::Text(route_template.to_owned()),
        // The deterministic encoder sorts map keys bytewise.
        Value::Map(
            path_params
                .iter()
                .map(|(k, v)| (Value::Text(k.clone()), Value::Text(v.clone())))
                .collect(),
        ),
        Value::Bytes(body_digest(body)?.to_vec()),
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
                let r: StoredResponse = cs_crypto::cbor::from_canonical(&resp, MAX_RESPONSE_BYTES)
                    .map_err(|e| DbError::Invalid(format!("stored response: {e}")))?;
                Ok(Begin::Replay(r))
            }
            ("in_progress", _) => Err(DbError::app(
                CsError::new(ErrorCode::OutcomeUnknown).with_detail(
                    "The original request may have committed. Retry with the same Idempotency-Key.",
                ),
            )),
            _ => Err(DbError::Invalid("inconsistent idempotency record".into())),
        }
    }

    /// Store the response of a started request (same transaction as the effect). A response
    /// larger than [`MAX_RESPONSE_BYTES`] is an internal error (never truncated).
    pub async fn complete(
        tx: &mut DomainTx,
        scope: &IdempotencyScope,
        response: &StoredResponse,
    ) -> Result<(), DbError> {
        let bytes =
            cs_crypto::cbor::to_canonical(response).map_err(|e| DbError::Invalid(e.to_string()))?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(DbError::Invalid(format!(
                "stored response of {} bytes exceeds {MAX_RESPONSE_BYTES}; the operation must return a reference",
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

    /// Run a single-domain idempotent operation: one transaction containing the record and
    /// the effect. `effect` runs only for a new (or expired) key; duplicates get the stored
    /// response. `effect` is re-runnable (40001/40P01 retries).
    pub async fn execute<F>(
        pool: &DomainPool,
        scope: &IdempotencyScope,
        digest: RequestDigest,
        retention_hours: i64,
        effect: F,
    ) -> Result<StoredResponse, DbError>
    where
        F: for<'c> Fn(&'c mut DomainTx) -> TxFuture<'c, StoredResponse> + Send + Sync + 'static,
    {
        let scope = Arc::new(scope.clone());
        let effect = Arc::new(effect);
        pool.transaction(move |tx| {
            let (scope, effect) = (scope.clone(), effect.clone());
            Box::pin(async move {
                match Self::begin(tx, &scope, &digest, retention_hours).await? {
                    Begin::Replay(r) => Ok(r),
                    Begin::Started => {
                        let r = effect(tx).await?;
                        Self::complete(tx, &scope, &r).await?;
                        Ok(r)
                    }
                }
            })
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(
        method: &str,
        route: &str,
        p: &BTreeMap<String, String>,
        b: RequestBody<'_>,
    ) -> RequestDigest {
        request_digest(method, route, p, b).unwrap()
    }

    #[test]
    fn digest_covers_every_component() {
        let mut p = BTreeMap::new();
        p.insert("id".to_owned(), "1".to_owned());
        let r = "/api/v2/things/{id}";
        let base = d("post", r, &p, RequestBody::Json(b"{}"));
        assert_eq!(base, d("POST", r, &p, RequestBody::Json(b"{}")));
        assert_ne!(base, d("PUT", r, &p, RequestBody::Json(b"{}")));
        assert_ne!(
            base,
            d("POST", "/api/v2/other/{id}", &p, RequestBody::Json(b"{}"))
        );
        assert_ne!(base, d("POST", r, &p, RequestBody::Json(b"{\"a\":1}")));
        let mut p2 = p.clone();
        p2.insert("id".to_owned(), "2".to_owned());
        assert_ne!(base, d("POST", r, &p2, RequestBody::Json(b"{}")));
    }

    #[test]
    fn json_bodies_are_canonicalized() {
        let p = BTreeMap::new();
        let a = d(
            "POST",
            "/x",
            &p,
            RequestBody::Json(br#"{"b":2,"a":[1,2.50,"x"]}"#),
        );
        let b = d(
            "POST",
            "/x",
            &p,
            RequestBody::Json(b"{ \"a\" : [1, 2.5, \"x\"],\n \"b\" : 2 }"),
        );
        assert_eq!(
            a, b,
            "whitespace, key order and number spelling must not matter"
        );
        // raw bodies are not canonicalized
        assert_ne!(
            d("POST", "/x", &p, RequestBody::Raw(b"{\"a\":1}")),
            d("POST", "/x", &p, RequestBody::Raw(b"{ \"a\":1}"))
        );
        // absent body == digest of the empty string
        assert_eq!(
            body_digest(RequestBody::Absent).unwrap(),
            *blake3::hash(b"").as_bytes()
        );
        assert_eq!(
            d("DELETE", "/x", &p, RequestBody::Absent),
            d("DELETE", "/x", &p, RequestBody::Raw(b""))
        );
        assert!(matches!(
            body_digest(RequestBody::Json(b"{nope")),
            Err(DbError::App(_))
        ));
    }

    #[test]
    fn jcs_matches_rfc8785_examples() {
        // RFC 8785 §3.2.2 / Appendix B number serialization and §3.2.3 key sorting.
        let input = br#"{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"literals":[null,true,false],"b":"x"}"#;
        let v: serde_json::Value = serde_json::from_slice(input).unwrap();
        let out = String::from_utf8(serde_jcs::to_vec(&v).unwrap()).unwrap();
        assert_eq!(
            out,
            r#"{"b":"x","literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27]}"#
        );
    }
}
