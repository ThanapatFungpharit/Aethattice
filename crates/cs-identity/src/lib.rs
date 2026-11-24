//! Identity domain: tenants, principals, OPAQUE, sessions, tokens, recovery.
//!
//! Spec: §5. Contract: `docs/contracts/M1-identity.md` (rev 7).
//!
//! M1 slices 1–2 (this crate so far):
//! - [`migrations`]: the identity-domain schema of contract §1.
//! - [`token`]: the `rt1.<tenant>.<random>` bearer format shared by refresh tokens, setup
//!   links and recovery grants (contract §3 `[R8]`).
//! - [`login`]: login-name normalization (re-exported from `cs-identity-wire`, rev 5).
//! - [`admin`]: tenant, user and group administration and first-administrator setup links,
//!   used only by the `cs admin` CLI in M1 (contract §0). Every action is one identity-domain
//!   transaction that writes an outbox event.
//!
//! - [`keys`]: OPAQUE server key material, envelope-encrypted under the KMS (rev 6).
//! - [`auth`]: OPAQUE registration (setup-link grant), login with unknown-account
//!   indistinguishability `[R3]`, password reauth (rev 7), `/me`, refresh `[R1]`, logout `[R10]`.
//! - [`session`]: sessions and refresh-token rotation; [`jws`]: EdDSA access tokens and JWKS.
//! - [`http`]: the `/api/v2/auth/*` and `/api/v2/me` routes.
//!
//! Not yet: DPoP, WebAuthn/MFA, recovery flows, rate limiting, step-up enforcement,
//! `/me/sessions`, transparent KSF re-registration, native (device-bound) refresh.

pub mod admin;
pub mod auth;
pub mod http;
pub mod jws;
pub mod keys;
pub use cs_identity_wire::login;
pub mod session;
pub mod token;

use cs_db::migrate::{MigrationError, MigrationSet};

/// Migrations of the identity domain owned by this crate (in addition to
/// `cs_db::migrate::common_migrations`).
pub fn migrations() -> Result<MigrationSet, MigrationError> {
    MigrationSet::from_files(&[
        (
            "0100_identity_core.expand.sql",
            include_str!("../migrations/identity/0100_identity_core.expand.sql"),
        ),
        (
            "0101_opaque_txns_keys.expand.sql",
            include_str!("../migrations/identity/0101_opaque_txns_keys.expand.sql"),
        ),
    ])
}
