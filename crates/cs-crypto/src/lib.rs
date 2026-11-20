//! Signing envelopes with domain separation (C8), deterministic CBOR and the
//! fail-closed CSPRNG wrapper.
//!
//! The sealed object format v1 (§17.2) is NOT implemented here yet; it arrives in
//! M3 and is NON-PRODUCTION-STABLE until independent review (R4/C10).
//!
//! Spec: §17.2 (randomness), C8, C10. Contract: `docs/contracts/M0-foundations.md` §1, §3.

pub mod cbor;
pub mod rand;
pub mod sig;

pub use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
