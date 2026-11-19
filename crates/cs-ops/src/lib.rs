//! Operations domain: durable sagas (M0 framework). Leases, epochs and jobs arrive in M3+.
//!
//! Spec: §18.4, §2.6, App. C (C1, C3, C9). Contract: `docs/contracts/M0-foundations.md` §5.4.

pub mod saga;

use cs_db::migrate::{MigrationError, MigrationSet};

/// Migrations of the operations domain owned by this crate (in addition to
/// `cs_db::migrate::common_migrations`).
pub fn migrations() -> Result<MigrationSet, MigrationError> {
    MigrationSet::from_files(&[(
        "0100_sagas.expand.sql",
        include_str!("../migrations/operations/0100_sagas.expand.sql"),
    )])
}
