//! Shared QA test support. Included by every test file with `mod support;`.
#![allow(dead_code, unused_imports, unused_macros)]

pub mod db;
pub mod server;
pub mod spec;
pub mod types;
pub mod vectors;

/// The ONLY module that names engineer-owned APIs. Bound to the real M0 crates.
#[cfg(feature = "m0-contract")]
#[path = "contract.rs"]
pub mod contract;

/// Same signatures as `contract.rs`, panicking bodies. Lets QA type-check its own test logic
/// before the implementation is merged (`--features qa-selfcheck`).
#[cfg(all(feature = "qa-selfcheck", not(feature = "m0-contract")))]
#[path = "contract_stub.rs"]
pub mod contract;

/// Obtain the admin database URL or skip the test (see `db::admin_url`).
#[macro_export]
macro_rules! require_db {
    () => {
        match $crate::support::db::admin_url().await {
            Some(url) => url,
            None => {
                eprintln!("SKIP {}: no database (set CS_TEST_DATABASE_URL; CS_REQUIRE_DB=1 makes this a failure)", module_path!());
                return;
            }
        }
    };
}
