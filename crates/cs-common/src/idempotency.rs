//! Client `Idempotency-Key` values (spec D.3, contract §5.3): 1..=255 visible ASCII characters.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use thiserror::Error;

/// Header carrying the key.
pub const IDEMPOTENCY_KEY_HEADER: &str = "Idempotency-Key";
/// Maximum key length.
pub const MAX_IDEMPOTENCY_KEY_LEN: usize = 255;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("Idempotency-Key must be 1 to 255 visible ASCII characters")]
pub struct IdempotencyKeyError;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    pub fn parse(s: &str) -> Result<Self, IdempotencyKeyError> {
        if s.is_empty()
            || s.len() > MAX_IDEMPOTENCY_KEY_LEN
            || !s.bytes().all(|b| (0x21..=0x7e).contains(&b))
        {
            return Err(IdempotencyKeyError);
        }
        Ok(Self(s.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IdempotencyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for IdempotencyKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for IdempotencyKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules() {
        assert!(IdempotencyKey::parse("a").is_ok());
        assert!(IdempotencyKey::parse(&"x".repeat(255)).is_ok());
        assert!(IdempotencyKey::parse("!~").is_ok());
        for bad in [
            String::new(),
            "x".repeat(256),
            "a b".into(),
            "é".into(),
            "a\t".into(),
            "a\u{7f}".into(),
        ] {
            assert!(IdempotencyKey::parse(&bad).is_err(), "{bad:?}");
        }
    }
}
