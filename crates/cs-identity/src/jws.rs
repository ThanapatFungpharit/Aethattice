//! Access tokens: JWS compact, `alg: EdDSA`, `typ: at+jwt`, `kid` = KMS key ID with version
//! (contract §3; spec §5.5).
//!
//! Verification accepts only EdDSA and only `kid`s of the configured KMS key name that the KMS
//! knows. `alg: none`, HS* and every other algorithm, and `jwk` / `jku` / `x5u` / `x5c` /
//! `crit` headers are rejected. `exp` has 0 s leeway; `iat` may be at most 60 s in the future
//! (`[R12]`). `iss` and `aud` must match exactly (rev 6). Unknown claims are ignored (`[R9]`: `av`
//! is reserved for M2).

use crate::admin::{AdminError as AuthError, AdminResult as AuthResult};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cs_common::error::{Error, ErrorCode};
use cs_crypto::sig::KeyId;
use cs_kms::{KeyPurpose, Kms, KmsError};
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// KMS signing key name for access tokens (versions `identity-access-token@vN`).
pub const SIGNING_KEY_NAME: &str = "identity-access-token";
/// Maximum accepted clock skew for `iat` in the future (`[R12]`).
pub const MAX_IAT_SKEW_SECS: i64 = 60;
/// Largest token accepted for parsing.
const MAX_TOKEN_BYTES: usize = 4096;

/// `cnf` claim (RFC 7800 / RFC 9449).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Confirmation {
    /// base64url SHA-256 JWK thumbprint of the DPoP key.
    pub jkt: String,
}

/// Access-token claims (contract §3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessClaims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub tid: String,
    pub sid: String,
    pub sgen: i64,
    pub amr: Vec<String>,
    pub auth_time: i64,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<Confirmation>,
    /// (rev 11) `"mfa_enrolment"` on an enrolment-only session; absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scp: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Header {
    alg: String,
    typ: String,
    kid: String,
}

/// Issues and verifies access tokens with a KMS-held Ed25519 key.
#[derive(Clone)]
pub struct AccessTokens {
    kms: Arc<dyn Kms>,
    key_name: String,
    iss: String,
    aud: String,
}

impl std::fmt::Debug for AccessTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessTokens")
            .field("key_name", &self.key_name)
            .field("iss", &self.iss)
            .field("aud", &self.aud)
            .finish()
    }
}

fn unauthenticated() -> AuthError {
    Error::new(ErrorCode::Unauthenticated)
        .with_detail("Invalid or expired access token.")
        .into()
}

fn kms_err(e: KmsError) -> AuthError {
    Error::new(ErrorCode::Unavailable)
        .with_detail("key management is unavailable")
        .with_cause(e)
        .into()
}

impl AccessTokens {
    /// `iss = https://<deployment domain>`, `aud = https://<deployment domain>/api/v2` (rev 6).
    pub fn new(kms: Arc<dyn Kms>, deployment_domain: &str) -> Self {
        Self {
            kms,
            key_name: SIGNING_KEY_NAME.to_owned(),
            iss: format!("https://{deployment_domain}"),
            aud: format!("https://{deployment_domain}/api/v2"),
        }
    }

    pub fn issuer(&self) -> &str {
        &self.iss
    }

    pub fn audience(&self) -> &str {
        &self.aud
    }

    /// The current signing key, created (version 1) if the KMS has none yet.
    pub async fn current_key(&self) -> AuthResult<KeyId> {
        match self.kms.current(&self.key_name).await {
            Ok(k) => Ok(k),
            Err(KmsError::UnknownKey(_)) => {
                match self
                    .kms
                    .generate_key(&self.key_name, KeyPurpose::Signing)
                    .await
                {
                    Ok(k) => Ok(k),
                    Err(KmsError::KeyExists(_)) => {
                        self.kms.current(&self.key_name).await.map_err(kms_err)
                    }
                    Err(e) => Err(kms_err(e)),
                }
            }
            Err(e) => Err(kms_err(e)),
        }
    }

    /// Sign `claims` (`iss` / `aud` are overwritten with this issuer's values).
    pub async fn sign(&self, claims: AccessClaims) -> AuthResult<String> {
        let kid = self.current_key().await?;
        self.sign_with(&kid, claims).await
    }

    /// Sign `claims` with the given key version (contract rev 16 P1: a replay re-signs the
    /// stored claims with the stored `kid`; Ed25519 is deterministic, so the token is
    /// byte-identical).
    pub async fn sign_with(&self, kid: &KeyId, claims: AccessClaims) -> AuthResult<String> {
        self.sign_kid(kid, claims).await?.map_err(kms_err)
    }

    /// Re-sign stored claims for a replay (rev 16 P1): a `kid` that can no longer sign
    /// (unknown, not a signing key) is `unauthenticated`; any other KMS failure is
    /// `unavailable`.
    pub async fn resign(&self, kid: &KeyId, claims: AccessClaims) -> AuthResult<String> {
        match self.sign_kid(kid, claims).await? {
            Ok(t) => Ok(t),
            Err(
                KmsError::UnknownKey(_) | KmsError::WrongPurpose { .. } | KmsError::InvalidKeyId,
            ) => Err(unauthenticated()),
            Err(e) => Err(kms_err(e)),
        }
    }

    async fn sign_kid(
        &self,
        kid: &KeyId,
        mut claims: AccessClaims,
    ) -> AuthResult<Result<String, KmsError>> {
        claims.iss = self.iss.clone();
        claims.aud = self.aud.clone();
        let header = Header {
            alg: "EdDSA".to_owned(),
            typ: "at+jwt".to_owned(),
            kid: kid.to_string(),
        };
        let h = serde_json::to_vec(&header).map_err(Error::internal)?;
        let c = serde_json::to_vec(&claims).map_err(Error::internal)?;
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(h),
            URL_SAFE_NO_PAD.encode(c)
        );
        Ok(self
            .kms
            .sign(kid, signing_input.as_bytes())
            .await
            .map(|sig| format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))))
    }

    /// Verify a token at `now` (unix seconds). Every failure is `unauthenticated`, except an
    /// unavailable KMS (`unavailable`).
    pub async fn verify(&self, token: &str, now: i64) -> AuthResult<AccessClaims> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(unauthenticated());
        }
        let mut parts = token.split('.');
        let (Some(h64), Some(c64), Some(s64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(unauthenticated());
        };
        let h = URL_SAFE_NO_PAD.decode(h64).map_err(|_| unauthenticated())?;
        // Reject any header member beyond alg/typ/kid (jwk, jku, x5u, x5c, crit, ...).
        let hv: serde_json::Map<String, serde_json::Value> =
            serde_json::from_slice(&h).map_err(|_| unauthenticated())?;
        if hv
            .keys()
            .any(|k| !matches!(k.as_str(), "alg" | "typ" | "kid"))
        {
            return Err(unauthenticated());
        }
        let header: Header = serde_json::from_slice(&h).map_err(|_| unauthenticated())?;
        if header.alg != "EdDSA" || header.typ != "at+jwt" {
            return Err(unauthenticated());
        }
        let kid: KeyId = header.kid.parse().map_err(|_| unauthenticated())?;
        if kid.name() != self.key_name {
            return Err(unauthenticated());
        }
        let vk = match self.kms.public_key(&kid).await {
            Ok(k) => k,
            Err(KmsError::UnknownKey(_)) | Err(KmsError::WrongPurpose { .. }) => {
                return Err(unauthenticated());
            }
            Err(e) => return Err(kms_err(e)),
        };
        let sig_b = URL_SAFE_NO_PAD.decode(s64).map_err(|_| unauthenticated())?;
        let sig_arr: [u8; 64] = sig_b.as_slice().try_into().map_err(|_| unauthenticated())?;
        let sig = Signature::from_bytes(&sig_arr);
        let signing_input = &token[..h64.len() + 1 + c64.len()];
        vk.verify_strict(signing_input.as_bytes(), &sig)
            .map_err(|_| unauthenticated())?;
        let c = URL_SAFE_NO_PAD.decode(c64).map_err(|_| unauthenticated())?;
        let claims: AccessClaims = serde_json::from_slice(&c).map_err(|_| unauthenticated())?;
        if claims.iss != self.iss
            || claims.aud != self.aud
            || now >= claims.exp
            || claims.iat > now + MAX_IAT_SKEW_SECS
        {
            return Err(unauthenticated());
        }
        Ok(claims)
    }

    /// JWKS document: the current key and the previous version, if any (contract §3).
    pub async fn jwks(&self) -> AuthResult<serde_json::Value> {
        let cur = self.current_key().await?;
        let mut ids = vec![cur.clone()];
        if cur.version() > 1
            && let Ok(prev) = KeyId::new(cur.name(), cur.version() - 1)
        {
            ids.push(prev);
        }
        let mut keys = Vec::new();
        for id in ids {
            let pk = match self.kms.public_key(&id).await {
                Ok(pk) => pk,
                Err(KmsError::UnknownKey(_)) => continue,
                Err(e) => return Err(kms_err(e)),
            };
            keys.push(serde_json::json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode(pk.as_bytes()),
                "kid": id.to_string(),
                "alg": "EdDSA",
                "use": "sig",
            }));
        }
        Ok(serde_json::json!({ "keys": keys }))
    }
}
