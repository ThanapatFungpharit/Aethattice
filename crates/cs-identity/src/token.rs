//! Opaque bearer token format (contract §3 `[R8]`), shared by refresh tokens, setup links and
//! recovery grants: `rt1.<tenant_id base64url>.<256-bit random base64url>` (unpadded).
//!
//! - The server stores only SHA-256 of the **whole** string, so a client that edits the tenant
//!   segment changes the hash and finds nothing.
//! - The tenant segment only selects the partition `(tenant_id, token_hash)` for the lookup;
//!   it is never trusted on its own.
//! - The token string is a bearer secret: it is held in [`Secret`] and never logged.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cs_common::id::TenantId;
use cs_common::secret::Secret;
use cs_crypto::rand::RandError;
use sha2::{Digest, Sha256};
use std::fmt;

/// Format prefix (version 1).
pub const PREFIX: &str = "rt1";
/// Random part: 256 bits.
pub const RANDOM_BYTES: usize = 32;
/// Unpadded base64url length of the tenant segment (16 bytes).
const TENANT_B64_LEN: usize = 22;
/// Unpadded base64url length of the random segment (32 bytes).
const RANDOM_B64_LEN: usize = 43;
/// Total length of a well-formed token.
pub const TOKEN_LEN: usize = PREFIX.len() + 1 + TENANT_B64_LEN + 1 + RANDOM_B64_LEN;

/// SHA-256 of a whole token string.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TokenHash([u8; 32]);

impl TokenHash {
    pub fn of(token: &str) -> Self {
        let mut out = [0u8; 32];
        out.copy_from_slice(&Sha256::digest(token.as_bytes()));
        Self(out)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// A stored hash (e.g. sealed inside ceremony state).
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }
}

impl fmt::Debug for TokenHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A hash of a 256-bit secret does not reveal it, but keep logs terse.
        f.write_str("TokenHash(..)")
    }
}

/// A freshly generated token. The string is shown to its recipient once and never stored.
#[derive(Debug)]
pub struct IssuedToken {
    pub token: Secret<String>,
    pub tenant_id: TenantId,
    pub hash: TokenHash,
}

/// A syntactically valid presented token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedToken {
    /// Partition selector only; not trusted (see module docs).
    pub tenant_id: TenantId,
    pub hash: TokenHash,
}

/// The presented string is not a well-formed `rt1` token. Deliberately carries no detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MalformedToken;

impl fmt::Display for MalformedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("malformed token")
    }
}

impl std::error::Error for MalformedToken {}

/// Generate a new token for `tenant_id`.
pub fn generate(tenant_id: TenantId) -> Result<IssuedToken, RandError> {
    let random: [u8; RANDOM_BYTES] = cs_crypto::rand::bytes()?;
    let token = format!(
        "{PREFIX}.{}.{}",
        URL_SAFE_NO_PAD.encode(tenant_id.as_bytes()),
        URL_SAFE_NO_PAD.encode(random)
    );
    let hash = TokenHash::of(&token);
    Ok(IssuedToken {
        token: Secret::new(token),
        tenant_id,
        hash,
    })
}

/// Parse a presented token strictly: exact prefix, exact segment lengths, canonical unpadded
/// base64url, a UUIDv7 tenant ID.
pub fn parse(token: &str) -> Result<ParsedToken, MalformedToken> {
    if token.len() != TOKEN_LEN {
        return Err(MalformedToken);
    }
    let mut parts = token.split('.');
    let (Some(prefix), Some(tenant), Some(random), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(MalformedToken);
    };
    if prefix != PREFIX || tenant.len() != TENANT_B64_LEN || random.len() != RANDOM_B64_LEN {
        return Err(MalformedToken);
    }
    let tenant_bytes = URL_SAFE_NO_PAD.decode(tenant).map_err(|_| MalformedToken)?;
    let random_bytes = URL_SAFE_NO_PAD.decode(random).map_err(|_| MalformedToken)?;
    // Canonical encoding only: trailing bits of the last character must be zero.
    if URL_SAFE_NO_PAD.encode(&tenant_bytes) != tenant
        || URL_SAFE_NO_PAD.encode(&random_bytes) != random
        || random_bytes.len() != RANDOM_BYTES
    {
        return Err(MalformedToken);
    }
    let tenant_id = TenantId::from_slice(&tenant_bytes).map_err(|_| MalformedToken)?;
    Ok(ParsedToken {
        tenant_id,
        hash: TokenHash::of(token),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn generated_tokens_have_the_rt1_format_and_parse_back() {
        let t = TenantId::generate().unwrap();
        let a = generate(t).unwrap();
        let s = a.token.expose_secret();
        assert_eq!(s.len(), TOKEN_LEN);
        let parts: Vec<&str> = s.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "rt1");
        assert_eq!(URL_SAFE_NO_PAD.decode(parts[1]).unwrap(), t.as_bytes());
        assert_eq!(URL_SAFE_NO_PAD.decode(parts[2]).unwrap().len(), 32);
        let p = parse(s).unwrap();
        assert_eq!(p.tenant_id, t);
        assert_eq!(p.hash, a.hash);
        // stored value is SHA-256 of the whole string
        let mut h = [0u8; 32];
        h.copy_from_slice(&Sha256::digest(s.as_bytes()));
        assert_eq!(a.hash.as_bytes(), &h);
        // 256-bit random part: two tokens never collide
        let b = generate(t).unwrap();
        assert_ne!(a.hash, b.hash);
    }

    #[test]
    fn tenant_segment_change_changes_the_hash() {
        let a = generate(TenantId::generate().unwrap()).unwrap();
        let other = TenantId::generate().unwrap();
        let s = a.token.expose_secret();
        let random = s.rsplit('.').next().unwrap();
        let forged = format!("rt1.{}.{random}", URL_SAFE_NO_PAD.encode(other.as_bytes()));
        let p = parse(&forged).unwrap();
        assert_eq!(p.tenant_id, other);
        assert_ne!(p.hash, a.hash);
    }

    #[test]
    fn malformed_tokens_rejected() {
        let s = generate(TenantId::generate().unwrap()).unwrap();
        let s = s.token.expose_secret().clone();
        let random = s.rsplit('.').next().unwrap().to_owned();
        let nil_tenant = URL_SAFE_NO_PAD.encode([0u8; 16]);
        for bad in [
            String::new(),
            s.replacen("rt1", "rt2", 1),
            s.replacen("rt1.", "rt1..", 1),
            format!("{s}."),
            format!("{s}A"),
            s[..s.len() - 1].to_owned(),
            s.replace('.', ":"),
            format!("rt1.{nil_tenant}.{random}"),
            // padded / non-url-safe alphabets
            s.replacen(&random[..2], "+/", 1),
        ] {
            assert_eq!(parse(&bad), Err(MalformedToken), "{bad:?}");
        }
        // non-canonical trailing bits in the random segment (43 chars carry 256 bits, so the
        // last character's two low bits must be zero)
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut b = s.clone().into_bytes();
        let last = b.len() - 1;
        let idx = ALPHABET.iter().position(|c| *c == b[last]).unwrap();
        assert_eq!(idx % 4, 0);
        b[last] = ALPHABET[idx + 1];
        assert_eq!(parse(&String::from_utf8(b).unwrap()), Err(MalformedToken));
    }

    #[test]
    fn debug_never_prints_the_token() {
        let a = generate(TenantId::generate().unwrap()).unwrap();
        let s = a.token.expose_secret().clone();
        let d = format!("{a:?}");
        assert!(!d.contains(&s));
        assert!(!d.contains(s.rsplit('.').next().unwrap()));
    }
}
