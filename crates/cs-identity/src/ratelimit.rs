//! Rate limiting of authentication endpoints (contract §5 `[R12]`, rev 11; spec §5.2, §18.5,
//! §21.3).
//!
//! - Dimensions: per source (IPv4 /32, IPv6 /64, see [`crate::auth::source_of`]), per account
//!   (tenant + normalized login) and per tenant. Limits are policies
//!   `rate_limit_{source,account,tenant}_per_min` over fixed 60 s windows.
//! - Counters live in Valkey (`INCR` + `EXPIRE`, 250 ms per call). If Valkey is unavailable
//!   (or not configured) a node falls back to **local buckets at limit/N**, where N is
//!   `[cluster] node_count` (≥ 1). It never falls back to unlimited (contract §5).
//! - Exceeding a limit is `rate_limited` (429) with `retry_after_ms` (the end of the window).
//! - Account keys are counted whether or not the account exists, and the tenant segment is
//!   whatever the request names, so an unknown account is limited exactly like a known one
//!   (no enumeration oracle). Keys are BLAKE3 digests: no login name is stored in Valkey.

use crate::admin::AdminResult as AuthResult;
use cs_common::config::{Policy, PolicyKey};
use cs_common::error::{Error, ErrorCode};
use std::collections::HashMap;
use std::sync::Mutex as StdMutex;
use std::time::Duration;
use tokio::sync::Mutex;

/// Window length (rev 11: fixed 60 s windows).
pub const WINDOW_SECS: i64 = 60;
const VALKEY_TIMEOUT: Duration = Duration::from_millis(250);
/// Local buckets kept at most (older windows are dropped first).
const LOCAL_MAX_KEYS: usize = 100_000;

/// What a counter limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dimension {
    Source,
    Account,
    Tenant,
}

impl Dimension {
    fn as_str(self) -> &'static str {
        match self {
            Dimension::Source => "src",
            Dimension::Account => "acct",
            Dimension::Tenant => "tenant",
        }
    }
}

/// Limits per window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimits {
    pub source: i64,
    pub account: i64,
    pub tenant: i64,
    /// `[cluster] node_count` (≥ 1): the local fallback allows limit/N per node.
    pub node_count: i64,
}

impl RateLimits {
    pub fn from_policy(p: &Policy, node_count: i64) -> Self {
        Self {
            source: p.get(PolicyKey::RateLimitSourcePerMin),
            account: p.get(PolicyKey::RateLimitAccountPerMin),
            tenant: p.get(PolicyKey::RateLimitTenantPerMin),
            node_count: node_count.max(1),
        }
    }

    fn limit(&self, d: Dimension) -> i64 {
        match d {
            Dimension::Source => self.source,
            Dimension::Account => self.account,
            Dimension::Tenant => self.tenant,
        }
    }

    /// limit/N, at least 1 (never unlimited, never zero).
    fn local_limit(&self, d: Dimension) -> i64 {
        (self.limit(d) / self.node_count).max(1)
    }
}

impl Default for RateLimits {
    fn default() -> Self {
        Self::from_policy(&Policy::default(), 1)
    }
}

/// Which store counted (tests and observability).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Valkey,
    Local,
}

/// One counter to bump: dimension, endpoint class and the identifying parts.
#[derive(Debug, Clone)]
pub struct Key {
    pub dimension: Dimension,
    /// Endpoint class (`login`, `register`, `recovery`, `webauthn_login`, `mfa`).
    pub class: &'static str,
    digest: String,
}

impl Key {
    /// `parts` are hashed (BLAKE3) with the dimension and class.
    pub fn new(dimension: Dimension, class: &'static str, parts: &[&[u8]]) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(b"cs-ratelimit/v1");
        h.update(dimension.as_str().as_bytes());
        h.update(class.as_bytes());
        for p in parts {
            h.update(&(p.len() as u64).to_be_bytes());
            h.update(p);
        }
        Self {
            dimension,
            class,
            digest: h.finalize().to_hex()[..32].to_owned(),
        }
    }

    fn redis_key(&self, window: i64) -> String {
        format!(
            "cs:rl:{}:{}:{window}:{}",
            self.dimension.as_str(),
            self.class,
            self.digest
        )
    }
}

struct Valkey {
    client: redis::Client,
    manager: Mutex<Option<redis::aio::ConnectionManager>>,
}

impl Valkey {
    async fn conn(&self) -> Option<redis::aio::ConnectionManager> {
        let mut m = self.manager.lock().await;
        if let Some(c) = m.as_ref() {
            return Some(c.clone());
        }
        let cfg = redis::aio::ConnectionManagerConfig::new()
            .set_connection_timeout(Some(VALKEY_TIMEOUT))
            .set_response_timeout(Some(VALKEY_TIMEOUT))
            .set_number_of_retries(0);
        let c = tokio::time::timeout(
            VALKEY_TIMEOUT,
            redis::aio::ConnectionManager::new_with_config(self.client.clone(), cfg),
        )
        .await
        .ok()?
        .ok()?;
        *m = Some(c.clone());
        Some(c)
    }

    /// `INCR` the window counters and set their expiry; `None` when Valkey is unavailable.
    async fn incr(&self, keys: &[String]) -> Option<Vec<i64>> {
        let mut c = self.conn().await?;
        let mut pipe = redis::pipe();
        for k in keys {
            pipe.cmd("INCR").arg(k);
            pipe.cmd("EXPIRE")
                .arg(k)
                .arg(2 * WINDOW_SECS)
                .arg("NX")
                .ignore();
        }
        let r: Result<Vec<i64>, _> = tokio::time::timeout(VALKEY_TIMEOUT, pipe.query_async(&mut c))
            .await
            .ok()?;
        r.ok()
    }
}

/// The limiter (one per node).
pub struct RateLimiter {
    limits: RateLimits,
    valkey: Option<Valkey>,
    local: StdMutex<HashMap<String, i64>>,
}

impl std::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiter")
            .field("limits", &self.limits)
            .field("valkey_configured", &self.valkey.is_some())
            .finish_non_exhaustive()
    }
}

fn rate_limited(retry_after_ms: u64) -> crate::admin::AdminError {
    Error::new(ErrorCode::RateLimited)
        .with_detail("Too many attempts. Try again later.")
        .with_retry_after_ms(retry_after_ms)
        .into()
}

impl RateLimiter {
    /// `valkey_url`: `redis://` / `rediss://`, or `None` (local buckets at limit/N only).
    pub fn new(limits: RateLimits, valkey_url: Option<&str>) -> AuthResult<Self> {
        let valkey = match valkey_url {
            Some(u) => Some(Valkey {
                client: redis::Client::open(u).map_err(Error::internal)?,
                manager: Mutex::new(None),
            }),
            None => None,
        };
        Ok(Self {
            limits,
            valkey,
            local: StdMutex::new(HashMap::new()),
        })
    }

    /// Local buckets only (no Valkey configured).
    pub fn local_only(limits: RateLimits) -> Self {
        Self {
            limits,
            valkey: None,
            local: StdMutex::new(HashMap::new()),
        }
    }

    pub fn limits(&self) -> RateLimits {
        self.limits
    }

    /// Count one attempt against every key; `rate_limited` when any limit is exceeded.
    /// Every key is counted even when an earlier one is over its limit, so the response does
    /// not depend on which dimension tripped first.
    pub async fn check(&self, keys: &[Key]) -> AuthResult<Backend> {
        self.check_at(keys, unix_ms()).await
    }

    async fn check_at(&self, keys: &[Key], now_ms: i64) -> AuthResult<Backend> {
        let window = now_ms.div_euclid(WINDOW_SECS * 1000);
        let retry = u64::try_from((window + 1) * WINDOW_SECS * 1000 - now_ms)
            .unwrap_or(1000)
            .max(1);
        let rkeys: Vec<String> = keys.iter().map(|k| k.redis_key(window)).collect();
        if let Some(v) = &self.valkey
            && let Some(counts) = v.incr(&rkeys).await
            && counts.len() == keys.len()
        {
            let over = keys
                .iter()
                .zip(&counts)
                .any(|(k, n)| *n > self.limits.limit(k.dimension));
            return if over {
                Err(rate_limited(retry))
            } else {
                Ok(Backend::Valkey)
            };
        }
        // Fallback: local buckets at limit/N (contract §5).
        let over = {
            let mut m = self
                .local
                .lock()
                .map_err(|_| Error::new(ErrorCode::Internal))?;
            if m.len() > LOCAL_MAX_KEYS {
                let suffix = format!(":{window}:");
                m.retain(|k, _| k.contains(&suffix));
            }
            let mut over = false;
            for (k, rk) in keys.iter().zip(&rkeys) {
                let n = m.entry(rk.clone()).or_insert(0);
                *n += 1;
                over |= *n > self.limits.local_limit(k.dimension);
            }
            // Drop buckets of past windows.
            let current = format!(":{window}:");
            m.retain(|k, _| k.contains(&current));
            over
        };
        if over {
            Err(rate_limited(retry))
        } else {
            Ok(Backend::Local)
        }
    }
}

fn unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cs_common::error::Code;

    fn lim(source: i64, account: i64, tenant: i64, n: i64) -> RateLimits {
        RateLimits {
            source,
            account,
            tenant,
            node_count: n,
        }
    }

    fn keys(acct: &str) -> Vec<Key> {
        vec![
            Key::new(Dimension::Source, "login", &[b"10.0.0.1"]),
            Key::new(Dimension::Account, "login", &[b"t", acct.as_bytes()]),
        ]
    }

    #[tokio::test]
    async fn local_fallback_is_limit_over_n_and_resets_per_window() {
        let r = RateLimiter::local_only(lim(1000, 9, 1000, 3));
        let t0 = 1_000_000 * 60_000;
        for _ in 0..3 {
            assert_eq!(r.check_at(&keys("a"), t0).await.unwrap(), Backend::Local);
        }
        let e = r.check_at(&keys("a"), t0 + 10_000).await.unwrap_err();
        assert_eq!(*e.code(), Code::Core(ErrorCode::RateLimited));
        assert_eq!(e.retry_after_ms(), Some(50_000));
        // Other accounts are unaffected; the next window starts fresh.
        assert!(r.check_at(&keys("b"), t0).await.is_ok());
        assert!(r.check_at(&keys("a"), t0 + 60_000).await.is_ok());
    }

    #[tokio::test]
    async fn never_unlimited_even_when_limit_below_node_count() {
        let r = RateLimiter::local_only(lim(5, 3, 60, 10));
        let t0 = 7 * 60_000;
        assert!(r.check_at(&keys("a"), t0).await.is_ok());
        assert!(r.check_at(&keys("a"), t0).await.is_err());
    }

    #[test]
    fn keys_hash_parts_unambiguously() {
        let a = Key::new(Dimension::Account, "login", &[b"ab", b"c"]);
        let b = Key::new(Dimension::Account, "login", &[b"a", b"bc"]);
        assert_ne!(a.redis_key(1), b.redis_key(1));
        assert!(!a.redis_key(1).contains("ab"));
    }
}
