//! Shared types: identifiers, Appendix D error model, consistency vectors, configuration,
//! secrets and telemetry.
//!
//! Spec: §3.4, §4.1, §25.1, App. C, App. D, App. E, J.4. Contract: `docs/contracts/M0-foundations.md`
//! §1, §2, §4, §6, §8.

pub mod app_id;
pub mod config;
pub mod error;
pub mod id;
pub mod idempotency;
pub mod secret;
pub mod telemetry;
pub mod urn;
pub mod vector;

pub use app_id::ApplicationId;
pub use error::{Code, Error, ErrorCode, ProblemDocument};
pub use secret::Secret;
pub use vector::{ConsistencyVector, DomainId, VectorComponent};
