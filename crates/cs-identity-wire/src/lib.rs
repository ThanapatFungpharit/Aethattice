//! OPAQUE wire definitions shared by the server (`cs-identity`) and the browser client
//! (`web/packages/opaque-wasm`), so the two cannot drift apart (M1 contract rev 5 §2.1).
//!
//! - [`Suite`]: the one cipher suite (ristretto255 OPRF, ristretto255 3DH, SHA-512, Argon2id
//!   KSF; RFC 9807) of `opaque-ke` 4.0.1.
//! - [`login`]: login-name normalization, identical on client and server.
//! - [`CONTEXT`], [`client_identifier`], [`KsfParams`]: the rest of the binding wire format.
//!
//! This crate has no `cs-*` dependencies so it compiles to WASM.

pub mod login;

pub use opaque_ke;

/// The OPAQUE cipher suite (contract §2.1): ristretto255 OPRF, ristretto255 3DH with SHA-512,
/// Argon2id key-stretching function.
#[derive(Debug, Clone, Copy)]
pub struct Suite;

impl opaque_ke::CipherSuite for Suite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2_010::Sha512>;
    type Ksf = argon2::Argon2<'static>;
}

/// OPAQUE context string (contract rev 5 §2.1).
pub const CONTEXT: &[u8] = b"cs-opaque/v1";

/// OPAQUE client identifier: UTF-8 `<tenant UUID>/<normalized login>` (contract rev 5 §2.1).
/// `tenant` must be the canonical (lowercase, hyphenated) UUID text; `normalized_login` must
/// already be the output of [`login::normalize_login`].
pub fn client_identifier(tenant: &str, normalized_login: &str) -> String {
    format!("{tenant}/{normalized_login}")
}

/// KSF algorithm name on the wire.
pub const KSF_ALGORITHM: &str = "argon2id";

/// Argon2id parameters of a registration (`ksf_params` on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KsfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KsfParams {
    /// Contract default and minimum: `m = 65536 KiB, t = 3, p = 1`.
    pub const DEFAULT: KsfParams = KsfParams {
        m_kib: 65_536,
        t: 3,
        p: 1,
    };

    /// Whether a registration may use these parameters: none below the defaults (rev 5).
    pub fn meets_minimum(&self) -> bool {
        self.m_kib >= Self::DEFAULT.m_kib && self.t >= Self::DEFAULT.t && self.p >= Self::DEFAULT.p
    }

    /// The Argon2id instance the client runs as the OPAQUE KSF.
    pub fn argon2(&self) -> Result<argon2::Argon2<'static>, argon2::Error> {
        let params = argon2::Params::new(self.m_kib, self.t, self.p, None)?;
        Ok(argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        ))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn wire_constants_match_contract_rev5() {
        assert_eq!(CONTEXT, b"cs-opaque/v1");
        assert_eq!(
            client_identifier("0190c1d2-0000-7000-8000-000000000001", "alice@example.com"),
            "0190c1d2-0000-7000-8000-000000000001/alice@example.com"
        );
        assert_eq!(KSF_ALGORITHM, "argon2id");
        assert_eq!(
            KsfParams::DEFAULT,
            KsfParams {
                m_kib: 65_536,
                t: 3,
                p: 1
            }
        );
    }

    #[test]
    fn ksf_minimum_rejects_any_weaker_component() {
        let k = |m_kib, t, p| KsfParams { m_kib, t, p };
        assert!(KsfParams::DEFAULT.meets_minimum());
        assert!(k(131_072, 4, 2).meets_minimum());
        assert!(!k(65_535, 3, 1).meets_minimum());
        assert!(!k(65_536, 2, 1).meets_minimum());
        assert!(!k(65_536, 3, 0).meets_minimum());
        assert!(KsfParams::DEFAULT.argon2().is_ok());
    }
}
