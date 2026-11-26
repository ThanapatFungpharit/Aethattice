//! DPoP (RFC 9449), M1 contract §3 (rev 8 wire details, `[R6]` replay, `[R12]` skew).
//!
//! - Proofs: JWS compact, `typ: dpop+jwt`, `alg` `ES256` (P-256) or `EdDSA` (Ed25519) only;
//!   the `jwk` header carries public members only (a private member is refused). Claims
//!   `jti`, `htm`, `htu`, `iat` (±60 s), and `ath` when an access token is presented.
//! - `htu` is compared, without query and fragment, with `https://<deployment domain>` plus
//!   the request path. No `DPoP-Nonce` in M1.
//! - The key is identified by its RFC 7638 SHA-256 JWK thumbprint (`jkt`).
//! - Replay `[R6]`, rev 14: the only authoritative record is the identity-domain table
//!   `dpop_jti`. Every DPoP-checked request inserts `((tenant_id, jkt), jti)` with
//!   `INSERT … ON CONFLICT DO NOTHING` in one short identity transaction; a conflict is a
//!   replay. Valkey is not on the replay path (a split Valkey/table record let a node
//!   partitioned from Valkey accept a replay: QA F-1). When the identity domain is unavailable
//!   the request fails closed with `unavailable` (503). Never a per-node cache.
//!
//! Nothing here logs a proof, a token or key material.

use crate::admin::{AdminError as AuthError, AdminResult as AuthResult};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cs_common::error::{Error, ErrorCode};
use cs_common::id::TenantId;
use cs_db::DomainPool;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// `[R12]`: proof `iat` within ±60 s.
pub const MAX_PROOF_SKEW_SECS: i64 = 60;
/// `[R6]`: replay entries live 120 s (covers the ±60 s `iat` window).
pub const REPLAY_TTL_SECS: u64 = 120;
/// Largest proof accepted for parsing.
const MAX_PROOF_BYTES: usize = 4096;
/// Largest `jti` accepted (the `dpop_jti.jti` column bound).
const MAX_JTI_BYTES: usize = 255;
/// Private JWK members (RFC 7517/7518): any of them refuses the proof.
const PRIVATE_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// A verified proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProof {
    /// SHA-256 JWK thumbprint.
    pub jkt: [u8; 32],
    pub jti: String,
}

impl VerifiedProof {
    /// base64url thumbprint, as carried in `cnf.jkt`.
    pub fn jkt_b64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.jkt)
    }
}

fn bad_proof() -> AuthError {
    Error::new(ErrorCode::Unauthenticated)
        .with_detail("Invalid DPoP proof.")
        .into()
}

/// base64url(SHA-256(access token)), the `ath` claim.
pub fn ath(access_token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()))
}

fn b64_exact(s: &str, len: usize) -> Option<Vec<u8>> {
    let v = URL_SAFE_NO_PAD.decode(s).ok()?;
    // Canonical encoding only, so the thumbprint input is unambiguous.
    (v.len() == len && URL_SAFE_NO_PAD.encode(&v) == s).then_some(v)
}

fn str_member<'a>(o: &'a serde_json::Map<String, Value>, k: &str) -> Option<&'a str> {
    o.get(k).and_then(Value::as_str)
}

enum Key {
    P256(p256::ecdsa::VerifyingKey),
    Ed25519(ed25519_dalek::VerifyingKey),
}

/// Parse the `jwk` header for `alg`; returns the key and its RFC 7638 thumbprint.
fn parse_jwk(alg: &str, jwk: &Value) -> Option<(Key, [u8; 32])> {
    let o = jwk.as_object()?;
    if PRIVATE_MEMBERS.iter().any(|m| o.contains_key(*m)) {
        return None;
    }
    let kty = str_member(o, "kty")?;
    let crv = str_member(o, "crv")?;
    let x = str_member(o, "x")?;
    match (alg, kty, crv) {
        ("ES256", "EC", "P-256") => {
            let y = str_member(o, "y")?;
            let (xb, yb) = (b64_exact(x, 32)?, b64_exact(y, 32)?);
            let mut sec1 = vec![0x04];
            sec1.extend_from_slice(&xb);
            sec1.extend_from_slice(&yb);
            let k = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).ok()?;
            let tp = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
            Some((Key::P256(k), Sha256::digest(tp.as_bytes()).into()))
        }
        ("EdDSA", "OKP", "Ed25519") => {
            let xb: [u8; 32] = b64_exact(x, 32)?.try_into().ok()?;
            let k = ed25519_dalek::VerifyingKey::from_bytes(&xb).ok()?;
            let tp = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);
            Some((Key::Ed25519(k), Sha256::digest(tp.as_bytes()).into()))
        }
        _ => None,
    }
}

fn verify_sig(key: &Key, signing_input: &[u8], sig: &[u8]) -> bool {
    match key {
        Key::P256(k) => {
            use p256::ecdsa::signature::Verifier as _;
            p256::ecdsa::Signature::from_slice(sig)
                .is_ok_and(|s| k.verify(signing_input, &s).is_ok())
        }
        Key::Ed25519(k) => ed25519_dalek::Signature::from_slice(sig)
            .is_ok_and(|s| k.verify_strict(signing_input, &s).is_ok()),
    }
}

/// Strip query and fragment from an `htu`.
fn htu_base(htu: &str) -> &str {
    let end = htu.find(['?', '#']).unwrap_or(htu.len());
    &htu[..end]
}

/// Verify a proof's form, signature and claims (no replay check: see [`ReplayStore`]).
///
/// `expected_htu` is `https://<deployment domain><path>`; `access_token` is the token the
/// request presents (its `ath` is then required and must match).
pub fn verify_proof(
    proof: &str,
    htm: &str,
    expected_htu: &str,
    access_token: Option<&str>,
    now: i64,
) -> AuthResult<VerifiedProof> {
    if proof.len() > MAX_PROOF_BYTES {
        return Err(bad_proof());
    }
    let mut parts = proof.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(bad_proof());
    };
    let json = |seg: &str| -> AuthResult<serde_json::Map<String, Value>> {
        let raw = URL_SAFE_NO_PAD.decode(seg).map_err(|_| bad_proof())?;
        match serde_json::from_slice(&raw) {
            Ok(Value::Object(o)) => Ok(o),
            _ => Err(bad_proof()),
        }
    };
    let header = json(h)?;
    if str_member(&header, "typ") != Some("dpop+jwt") {
        return Err(bad_proof());
    }
    let alg = str_member(&header, "alg").ok_or_else(bad_proof)?;
    let jwk = header.get("jwk").ok_or_else(bad_proof)?;
    let (key, jkt) = parse_jwk(alg, jwk).ok_or_else(bad_proof)?;
    let sig = URL_SAFE_NO_PAD.decode(s).map_err(|_| bad_proof())?;
    let signing_input = &proof[..h.len() + 1 + p.len()];
    if !verify_sig(&key, signing_input.as_bytes(), &sig) {
        return Err(bad_proof());
    }
    let claims = json(p)?;
    let jti = str_member(&claims, "jti").ok_or_else(bad_proof)?;
    if jti.is_empty() || jti.len() > MAX_JTI_BYTES {
        return Err(bad_proof());
    }
    if str_member(&claims, "htm") != Some(htm) {
        return Err(bad_proof());
    }
    let htu = str_member(&claims, "htu").ok_or_else(bad_proof)?;
    if htu_base(htu) != expected_htu {
        return Err(bad_proof());
    }
    let iat = claims
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or_else(bad_proof)?;
    if (now - iat).abs() > MAX_PROOF_SKEW_SECS {
        return Err(bad_proof());
    }
    match (access_token, str_member(&claims, "ath")) {
        (Some(at), Some(a)) if a == ath(at) => {}
        (None, None) => {}
        _ => return Err(bad_proof()),
    }
    Ok(VerifiedProof {
        jkt,
        jti: jti.to_owned(),
    })
}

/// Outcome of a replay check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayVerdict {
    /// First use, recorded in the shared store.
    Fresh,
    /// Already seen.
    Replayed,
}

/// The shared replay store `[R6]` (rev 14: `dpop_jti` only).
#[derive(Debug, Clone)]
pub struct ReplayStore {
    pool: DomainPool,
}

impl ReplayStore {
    /// `pool` is the identity domain's pool (`dpop_jti`).
    pub fn new(pool: DomainPool) -> Self {
        Self { pool }
    }

    /// Record `(tenant, jkt, jti)` in `dpop_jti`; reports a replay, or fails closed with
    /// `unavailable` when the identity domain does not answer.
    pub async fn check(
        &self,
        tenant: TenantId,
        proof: &VerifiedProof,
    ) -> AuthResult<ReplayVerdict> {
        let (jkt, jti) = (proof.jkt, proof.jti.clone());
        let r = self
            .pool
            .transaction(move |tx| {
                let jti = jti.clone();
                Box::pin(async move {
                    let bucket = expiry_bucket_of(&jti);
                    Ok(sqlx::query(
                        "INSERT INTO dpop_jti (tenant_id, jkt, jti, expires_at, expiry_bucket) \
                         VALUES ($1, $2, $3, now() + make_interval(secs => $4::float8), $5) \
                         ON CONFLICT DO NOTHING",
                    )
                    .bind(tenant.as_uuid())
                    .bind(jkt.as_slice())
                    .bind(jti)
                    .bind(REPLAY_TTL_SECS as f64)
                    .bind(bucket)
                    .execute(tx.conn())
                    .await?
                    .rows_affected())
                })
            })
            .await;
        match r {
            Ok(1) => Ok(ReplayVerdict::Fresh),
            Ok(_) => Ok(ReplayVerdict::Replayed),
            Err(e) => {
                tracing::error!(error = %e, "DPoP replay store unavailable (dpop_jti)");
                Err(Error::new(ErrorCode::Unavailable)
                    .with_detail("DPoP replay protection is temporarily unavailable.")
                    .into())
            }
        }
    }

    /// Verify a replay-free proof: `Ok` only for a fresh proof.
    pub async fn require_fresh(&self, tenant: TenantId, proof: &VerifiedProof) -> AuthResult<()> {
        match self.check(tenant, proof).await? {
            ReplayVerdict::Fresh => Ok(()),
            ReplayVerdict::Replayed => Err(bad_proof()),
        }
    }
}

/// `dpop_jti.expiry_bucket` (migration 0103): first byte of SHA-256(jti) mod 16.
pub fn expiry_bucket_of(jti: &str) -> i16 {
    i16::from(Sha256::digest(jti.as_bytes())[0]) % crate::auth::EXPIRY_BUCKETS
}

/// Purge expired `dpop_jti` rows in bounded batches (same bounds and bucketed index walk as
/// the `auth_txns` sweep). Returns the number of rows deleted.
pub async fn sweep_expired_jti(pool: &DomainPool, batch_rows: i64, max_batches: u32) -> u64 {
    crate::auth::sweep_bucketed(
        pool,
        "dpop_jti",
        "tenant_id, jkt, jti",
        batch_rows,
        max_batches,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn htu_strips_query_and_fragment() {
        assert_eq!(htu_base("https://a.test/x?y=1#z"), "https://a.test/x");
        assert_eq!(htu_base("https://a.test/x#z"), "https://a.test/x");
        assert_eq!(htu_base("https://a.test/x"), "https://a.test/x");
    }

    #[test]
    fn rfc7638_thumbprint_example() {
        // RFC 7638 §3.1 uses RSA; for EC/OKP check the member order and canonical form instead.
        let jwk = serde_json::json!({
            "kty": "OKP", "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        });
        let (_, tp) = parse_jwk("EdDSA", &jwk).unwrap();
        // RFC 8037 §A.3 thumbprint of this key.
        assert_eq!(
            URL_SAFE_NO_PAD.encode(tp),
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
        let mut private = jwk.clone();
        private["d"] = Value::String("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A".into());
        assert!(parse_jwk("EdDSA", &private).is_none());
        assert!(parse_jwk("ES256", &jwk).is_none());
        assert!(parse_jwk("RS256", &jwk).is_none());
    }
}
