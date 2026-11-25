//! M1 identity QA suite (docs/contracts/M1-identity.md rev 12 §9, docs/qa/M0-gate.md §6.1).
//!
//! Run (dev stack up, `cargo build -p cs` first for the binary tests):
//! ```text
//! CS_REQUIRE_DB=1 CS_TEST_DATABASE_URL=postgres://yugabyte@localhost:5433/yugabyte \
//!   CS_TEST_VALKEY_URL=redis://localhost:6379 \
//!   cargo test -p cs-qa-tests --features m1-contract --test m1 -- --test-threads=2
//! ```
#![cfg(feature = "m1-contract")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[macro_use]
#[path = "../support/mod.rs"]
mod support;

mod fx;

mod dpop;
mod enumeration;
mod isolation;
mod logscan;
mod recovery;
mod refresh;
mod scopes;
mod tokens;
