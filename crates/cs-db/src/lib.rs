//! Metadata-store access: per-domain pools, bounded conflict retry, migration runner,
//! transactional outbox and idempotency records.
//!
//! Spec: §18, §24, App. C (C1, C2), App. D (D.3), App. E. Contract: `docs/contracts/M0-foundations.md` §5.

pub mod error;
pub mod idempotency;
pub mod migrate;
pub mod outbox;
pub mod pool;
#[cfg(feature = "testing")]
pub mod testing;

pub use error::DbError;
pub use pool::{DomainPool, DomainTx, RetryPolicy, TxFuture};
