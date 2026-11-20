//! Application (plugin) identifiers: globally unique reverse-DNS style, e.g. `org.example.photos`
//! (spec §7.2).
//!
//! Syntax (design): 2..=16 labels separated by `.`, each label matching
//! `[a-z][a-z0-9]*(-[a-z0-9]+)*` and at most 63 bytes; total length at most 128 bytes.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

pub const MAX_APPLICATION_ID_LEN: usize = 128;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("invalid application id")]
pub struct ApplicationIdError;

/// A validated application ID.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ApplicationId(String);

fn valid_label(l: &str) -> bool {
    let b = l.as_bytes();
    if b.is_empty() || b.len() > 63 || !b[0].is_ascii_lowercase() {
        return false;
    }
    if b[b.len() - 1] == b'-' {
        return false;
    }
    let mut prev_dash = false;
    for c in b {
        match c {
            b'a'..=b'z' | b'0'..=b'9' => prev_dash = false,
            b'-' if !prev_dash => prev_dash = true,
            _ => return false,
        }
    }
    true
}

impl ApplicationId {
    pub fn parse(s: &str) -> Result<Self, ApplicationIdError> {
        if s.len() > MAX_APPLICATION_ID_LEN {
            return Err(ApplicationIdError);
        }
        let labels: Vec<&str> = s.split('.').collect();
        if labels.len() < 2 || labels.len() > 16 || !labels.iter().all(|l| valid_label(l)) {
            return Err(ApplicationIdError);
        }
        Ok(Self(s.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ApplicationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for ApplicationId {
    type Err = ApplicationIdError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for ApplicationId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ApplicationId {
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
        for ok in ["org.example.photos", "a.b", "com.my-co.app2"] {
            assert!(ApplicationId::parse(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "photos",
            "Org.example",
            "org..x",
            "org.-x",
            "org.x-",
            "org.x--y",
            "org.1x",
            "org.ex_ample",
            " org.x",
        ] {
            assert!(ApplicationId::parse(bad).is_err(), "{bad}");
        }
        assert!(ApplicationId::parse(&format!("a.{}", "b".repeat(127))).is_err());
    }
}
