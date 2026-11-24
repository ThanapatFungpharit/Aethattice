//! Identity domain: tenants, principals, OPAQUE, sessions, tokens, recovery.
//!
//! Spec: §5. Contract: `docs/contracts/M1-identity.md` (rev 3).
//!
//! M1 slice 1 (this crate so far):
//! - [`migrations`]: the identity-domain schema of contract §1.
//! - [`token`]: the `rt1.<tenant>.<random>` bearer format shared by refresh tokens, setup
//!   links and recovery grants (contract §3 `[R8]`).
//! - [`login`]: login-name normalization.
//! - [`admin`]: tenant, user and group administration and first-administrator setup links,
//!   used only by the `cs admin` CLI in M1 (contract §0). Every action is one identity-domain
//!   transaction that writes an outbox event.
//!
//! Not yet: OPAQUE, tokens/DPoP, sessions, WebAuthn, recovery flows, rate limiting.

pub mod admin;
pub mod login;
pub mod token;

use cs_db::migrate::{MigrationError, MigrationSet};

/// Migrations of the identity domain owned by this crate (in addition to
/// `cs_db::migrate::common_migrations`).
pub fn migrations() -> Result<MigrationSet, MigrationError> {
    MigrationSet::from_files(&[(
        "0100_identity_core.expand.sql",
        include_str!("../migrations/identity/0100_identity_core.expand.sql"),
    )])
}
