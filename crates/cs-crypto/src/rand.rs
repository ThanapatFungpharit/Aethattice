//! The only source of randomness in the platform (contract §1, spec §17.2).
//!
//! Every random value (IDs, keys, salts, nonces, tokens, retry jitter) comes from the
//! operating-system CSPRNG through this module. If the CSPRNG fails the operation fails:
//! there is no fallback to timestamps, counters or user-space PRNGs.

use thiserror::Error;

/// The OS CSPRNG could not produce bytes. Callers must fail the operation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("operating-system CSPRNG unavailable: {reason}")]
pub struct RandError {
    reason: String,
}

#[cfg(any(test, feature = "fault-injection"))]
mod fault {
    use std::cell::Cell;

    thread_local! {
        static FAIL: Cell<bool> = const { Cell::new(false) };
    }

    pub(super) fn should_fail() -> bool {
        FAIL.with(Cell::get)
    }

    /// Guard returned by [`super::inject_failure`]; restores normal operation on drop.
    #[derive(Debug)]
    pub struct FailureGuard(());

    impl Drop for FailureGuard {
        fn drop(&mut self) {
            FAIL.with(|f| f.set(false));
        }
    }

    pub(super) fn set() -> FailureGuard {
        FAIL.with(|f| f.set(true));
        FailureGuard(())
    }
}

#[cfg(any(test, feature = "fault-injection"))]
pub use fault::FailureGuard;

/// Test-only: make every CSPRNG call on the current thread fail until the guard drops.
#[cfg(any(test, feature = "fault-injection"))]
pub fn inject_failure() -> FailureGuard {
    fault::set()
}

/// Fill `buf` from the OS CSPRNG.
pub fn fill(buf: &mut [u8]) -> Result<(), RandError> {
    #[cfg(any(test, feature = "fault-injection"))]
    if fault::should_fail() {
        return Err(RandError {
            reason: "injected failure".to_owned(),
        });
    }
    getrandom::fill(buf).map_err(|e| RandError {
        reason: e.to_string(),
    })
}

/// Return `N` random bytes.
pub fn bytes<const N: usize>() -> Result<[u8; N], RandError> {
    let mut b = [0u8; N];
    fill(&mut b)?;
    Ok(b)
}

/// Return a uniformly random `u64`.
pub fn u64() -> Result<u64, RandError> {
    Ok(u64::from_be_bytes(bytes::<8>()?))
}

/// Return a uniformly random integer in `0..=max` (rejection sampling, no modulo bias).
pub fn u64_inclusive(max: u64) -> Result<u64, RandError> {
    if max == u64::MAX {
        return u64();
    }
    let range = max + 1;
    // 2^64 mod range; values above `u64::MAX - rem` would bias the result.
    let rem = (u64::MAX % range + 1) % range;
    let limit = u64::MAX - rem;
    loop {
        let v = u64()?;
        if v <= limit {
            return Ok(v % range);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_and_differs() {
        let a = bytes::<32>().unwrap();
        let b = bytes::<32>().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn injected_failure_fails_closed() {
        let guard = inject_failure();
        assert!(fill(&mut [0u8; 16]).is_err());
        assert!(bytes::<16>().is_err());
        assert!(u64().is_err());
        drop(guard);
        assert!(bytes::<16>().is_ok());
    }

    #[test]
    fn inclusive_range_bounds() {
        for _ in 0..1000 {
            assert!(u64_inclusive(7).unwrap() <= 7);
        }
        assert_eq!(u64_inclusive(0).unwrap(), 0);
        u64_inclusive(u64::MAX).unwrap();
    }
}
