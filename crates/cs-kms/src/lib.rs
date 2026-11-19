//! Key management: the `Kms` trait and the local software KMS for single-node deployments
//! (contract §9; spec §17.2, J.4, §23.5).
//!
//! Key IDs are versioned (`<name>/v<version>`, see [`cs_crypto::sig::KeyId`]). Rotation creates
//! the next version; earlier versions stay usable for unwrap and verification, so data and
//! signatures produced before a rotation remain readable on every node.

mod local;

pub use local::{LocalSoftwareKms, SINGLE_NODE_WARNING};

use async_trait::async_trait;
use cs_crypto::cbor;
use cs_crypto::sig::KeyId;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

/// What a key may be used for. A key is never used outside its purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyPurpose {
    /// Ed25519 signing key.
    Signing,
    /// 256-bit key-encryption key (wraps other keys).
    KeyEncryption,
}

#[derive(Debug, Error)]
pub enum KmsError {
    #[error("unknown key {0}")]
    UnknownKey(String),
    #[error("key {0} already exists")]
    KeyExists(String),
    #[error("key {key} cannot be used for {operation}")]
    WrongPurpose {
        key: String,
        operation: &'static str,
    },
    #[error("invalid key name or id")]
    InvalidKeyId,
    #[error("unwrap failed (wrong key or corrupted ciphertext)")]
    UnwrapFailed,
    #[error("invalid plaintext key length")]
    InvalidKeyLength,
    #[error("malformed wrapped key")]
    MalformedWrappedKey,
    #[error("key store error: {0}")]
    Store(String),
    #[error("insecure key file {path}: {reason}")]
    InsecureFile { path: String, reason: String },
    #[error(transparent)]
    Rand(#[from] cs_crypto::rand::RandError),
    #[error("internal KMS state error")]
    Poisoned,
}

/// A key wrapped (encrypted) under a key-encryption key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrappedKey {
    /// `<name>/v<version>` of the KEK.
    pub kek_id: String,
    #[serde(with = "cbor::bstr")]
    pub nonce: Vec<u8>,
    #[serde(with = "cbor::bstr")]
    pub ciphertext: Vec<u8>,
}

impl WrappedKey {
    /// Deterministic CBOR encoding for storage in metadata rows.
    pub fn to_bytes(&self) -> Result<Vec<u8>, KmsError> {
        cbor::to_canonical(self).map_err(|_| KmsError::MalformedWrappedKey)
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, KmsError> {
        cbor::from_canonical(b, 4096).map_err(|_| KmsError::MalformedWrappedKey)
    }

    pub fn kek_id(&self) -> Result<KeyId, KmsError> {
        self.kek_id.parse().map_err(|_| KmsError::InvalidKeyId)
    }
}

/// Key management service. All operations are by versioned key ID; there is never a single
/// global key.
#[async_trait]
pub trait Kms: Send + Sync {
    /// Create version 1 of a new key.
    async fn generate_key(&self, name: &str, purpose: KeyPurpose) -> Result<KeyId, KmsError>;
    /// Wrap a plaintext key (16..=64 bytes) under `kek_id`.
    async fn wrap(&self, kek_id: &KeyId, plaintext_key: &[u8]) -> Result<WrappedKey, KmsError>;
    /// Unwrap into a zeroizing buffer.
    async fn unwrap(&self, wrapped: &WrappedKey) -> Result<Zeroizing<Vec<u8>>, KmsError>;
    /// Ed25519-sign `bytes` with a signing key.
    async fn sign(&self, key_id: &KeyId, bytes: &[u8]) -> Result<Signature, KmsError>;
    /// Public half of a signing key.
    async fn public_key(&self, key_id: &KeyId) -> Result<VerifyingKey, KmsError>;
    /// Create the next version of the named key and make it current. Returns the new ID.
    async fn rotate(&self, name: &str) -> Result<KeyId, KmsError>;
    /// The current (highest) version of the named key.
    async fn current(&self, name: &str) -> Result<KeyId, KmsError>;
}
