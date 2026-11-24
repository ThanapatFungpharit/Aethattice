//! Login-name normalization (contract §1: `users.login` is normalized and unique per tenant).
//!
//! Normal form: Unicode NFKC, then lowercase (full Unicode case mapping), then NFKC again (case
//! mapping can produce non-NFKC sequences). The result must be 1–254 bytes and must not contain
//! whitespace or control characters. Leading and trailing whitespace is rejected, not trimmed,
//! so the stored login is exactly what the user types modulo case and compatibility forms.

use unicode_normalization::UnicodeNormalization;

/// Maximum normalized length in bytes (an e-mail address is at most 254 octets).
pub const MAX_LOGIN_BYTES: usize = 254;

/// Why a login name was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginError {
    Empty,
    TooLong,
    /// Contains whitespace or a control character.
    ForbiddenCharacter,
}

impl std::fmt::Display for LoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            LoginError::Empty => "login must not be empty",
            LoginError::TooLong => "login must be at most 254 bytes after normalization",
            LoginError::ForbiddenCharacter => {
                "login must not contain whitespace or control characters"
            }
        })
    }
}

impl std::error::Error for LoginError {}

/// Normalize a login name for storage and lookup.
pub fn normalize_login(raw: &str) -> Result<String, LoginError> {
    let lowered: String = raw.nfkc().collect::<String>().to_lowercase();
    let n: String = lowered.nfkc().collect();
    if n.is_empty() {
        return Err(LoginError::Empty);
    }
    if n.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(LoginError::ForbiddenCharacter);
    }
    if n.len() > MAX_LOGIN_BYTES {
        return Err(LoginError::TooLong);
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn case_and_compatibility_forms_fold_to_one_login() {
        let a = normalize_login("Alice@Example.COM").unwrap();
        assert_eq!(a, "alice@example.com");
        // fullwidth compatibility characters
        assert_eq!(normalize_login("ＡＬＩＣＥ@example.com").unwrap(), a);
        // composed vs decomposed
        assert_eq!(
            normalize_login("Jos\u{e9}").unwrap(),
            normalize_login("Jose\u{301}").unwrap()
        );
        // idempotent
        assert_eq!(normalize_login(&a).unwrap(), a);
    }

    #[test]
    fn invalid_logins_rejected() {
        assert_eq!(normalize_login(""), Err(LoginError::Empty));
        assert_eq!(
            normalize_login(" alice"),
            Err(LoginError::ForbiddenCharacter)
        );
        assert_eq!(
            normalize_login("al ice"),
            Err(LoginError::ForbiddenCharacter)
        );
        assert_eq!(
            normalize_login("alice\u{0}"),
            Err(LoginError::ForbiddenCharacter)
        );
        assert_eq!(
            normalize_login("alice\u{3000}"),
            Err(LoginError::ForbiddenCharacter)
        );
        assert_eq!(normalize_login(&"a".repeat(255)), Err(LoginError::TooLong));
        assert!(normalize_login(&"a".repeat(254)).is_ok());
    }
}
