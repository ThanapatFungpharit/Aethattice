//! Type-level secret redaction (contract §8, spec §15.4).
//!
//! `Secret<T>` never prints its contents: `Debug` shows `Secret([REDACTED])`, there is no
//! `Display` and no `Serialize`. The value is zeroized on drop. Access is explicit through
//! [`Secret::expose_secret`].

use serde::{Deserialize, Deserializer};
use std::fmt;
use zeroize::Zeroize;

pub struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Secret<T> {
    pub fn new(v: T) -> Self {
        Self(v)
    }

    /// Explicit access to the secret value. Never log the result.
    pub fn expose_secret(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}

impl<T: Zeroize + Clone> Clone for Secret<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Zeroize> From<T> for Secret<T> {
    fn from(v: T) -> Self {
        Self(v)
    }
}

impl<'de, T: Zeroize + Deserialize<'de>> Deserialize<'de> for Secret<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        T::deserialize(d).map(Secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let s = Secret::new(String::from("postgres://u:hunter2@h/db"));
        let d = format!("{s:?}");
        assert_eq!(d, "Secret([REDACTED])");
        assert!(!d.contains("hunter2"));
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Holder {
            url: Secret<String>,
        }
        assert!(!format!("{:?}", Holder { url: s.clone() }).contains("hunter2"));
        assert_eq!(s.expose_secret(), "postgres://u:hunter2@h/db");
    }
}
