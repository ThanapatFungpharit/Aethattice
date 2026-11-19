//! Database error type and mapping to Appendix D codes.

use cs_common::error::{Error as CsError, ErrorCode};
use thiserror::Error;

/// SQLSTATE values retried as whole transactions (§18.2).
pub const RETRYABLE_SQLSTATES: [&str; 2] = ["40001", "40P01"];

#[derive(Debug, Error)]
pub enum DbError {
    /// A database or driver error.
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),
    /// Conflicts persisted beyond the retry bound.
    #[error(
        "transaction retry bound exhausted after {attempts} attempts (last SQLSTATE {last_sqlstate})"
    )]
    RetryExhausted {
        attempts: u32,
        last_sqlstate: String,
    },
    /// The connection failed while committing: the transaction may or may not have committed.
    #[error("commit outcome unknown: {0}")]
    OutcomeUnknown(sqlx::Error),
    /// A business error raised by the transaction closure. Never retried.
    #[error("{0}")]
    App(Box<CsError>),
    /// Outbox sequence gap: an earlier sequence is missing.
    #[error("outbox gap in partition {partition}: expected sequence {expected}, found {found:?}")]
    OutboxGap {
        partition: i32,
        expected: i64,
        found: Option<i64>,
    },
    #[error(transparent)]
    Migration(#[from] crate::migrate::MigrationError),
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error(transparent)]
    Rand(#[from] cs_crypto::rand::RandError),
}

impl DbError {
    /// SQLSTATE of the underlying database error, if any.
    pub fn sqlstate(&self) -> Option<String> {
        match self {
            DbError::Sqlx(sqlx::Error::Database(e)) => e.code().map(|c| c.into_owned()),
            _ => None,
        }
    }

    /// Whether the whole transaction should be retried (40001 / 40P01).
    pub fn is_retryable_conflict(&self) -> bool {
        self.sqlstate()
            .is_some_and(|s| RETRYABLE_SQLSTATES.contains(&s.as_str()))
    }

    pub fn app(e: impl Into<CsError>) -> Self {
        DbError::App(Box::new(e.into()))
    }
}

fn is_connection_error(e: &sqlx::Error) -> bool {
    matches!(
        e,
        sqlx::Error::Io(_)
            | sqlx::Error::Tls(_)
            | sqlx::Error::PoolTimedOut
            | sqlx::Error::PoolClosed
            | sqlx::Error::WorkerCrashed
    )
}

impl From<DbError> for CsError {
    fn from(e: DbError) -> CsError {
        match e {
            DbError::App(e) => *e,
            DbError::RetryExhausted { .. } => CsError::new(ErrorCode::Unavailable)
                .with_retry_after_ms(1000)
                .with_cause(e),
            DbError::OutcomeUnknown(_) => CsError::new(ErrorCode::OutcomeUnknown)
                .with_detail("The write may have committed. Retry with the same Idempotency-Key.")
                .with_cause(e),
            DbError::Sqlx(ref s) if is_connection_error(s) => {
                CsError::new(ErrorCode::Unavailable).with_cause(e)
            }
            other => CsError::internal(other),
        }
    }
}
