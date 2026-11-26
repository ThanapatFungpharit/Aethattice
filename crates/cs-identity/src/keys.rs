//! OPAQUE server key material (contract rev 6 §2.1; spec §5.2).
//!
//! One versioned set per deployment, in `opaque_server_keys`: the opaque-ke `ServerSetup`
//! (OPRF seed and AKE key pair), the `[R3]` PRF key and the auth-txn sealing key. It is
//! envelope-encrypted: a random data key wrapped by the KMS key-encryption key
//! `identity-opaque@vN`, and the material sealed under the data key with XChaCha20-Poly1305,
//! associated data `key_version ‖ purpose`. It is unwrapped into memory only and never logged
//! (the `Debug` impls are redacted).
//!
//! Creation is race-safe across nodes: a node inserts its candidate with
//! `INSERT … ON CONFLICT DO NOTHING`, then re-reads and uses the stored row, never its own
//! candidate. Rotation adds the next version the same way; registrations record their version
//! and older versions stay loaded for login.

use crate::admin::{AdminError as AuthError, AdminResult as AuthResult};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use cs_common::error::{Error, ErrorCode};
use cs_db::{DbError, DomainPool};
use cs_identity_wire::Suite;
use cs_kms::{KeyPurpose, Kms, KmsError, WrappedKey};
use opaque_ke::ServerSetup;
use std::collections::BTreeMap;
use std::sync::Arc;
use zeroize::Zeroizing;

/// KMS key-encryption key name (versions `identity-opaque@vN`).
pub const KEK_NAME: &str = "identity-opaque";
/// Purpose bound into the associated data of the sealed material.
const PURPOSE: &[u8] = b"opaque-server-keys";
/// BLAKE3 `derive_key` context of the idempotency replay sealing key (contract rev 16 P2).
const IDEMPOTENCY_KEY_CONTEXT: &str = "identity idempotency v1";
/// `opaque_registrations.server_key_version` prefix.
pub const KEY_VERSION_PREFIX: &str = "opaque-server/v";

/// One version of the server key material.
pub struct ServerKeyVersion {
    pub version: i32,
    pub setup: ServerSetup<Suite>,
    prf_key: Zeroizing<[u8; 32]>,
    seal_key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for ServerKeyVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerKeyVersion")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl ServerKeyVersion {
    /// `opaque_registrations.server_key_version` value of this version.
    pub fn label(&self) -> String {
        format!("{KEY_VERSION_PREFIX}{}", self.version)
    }

    /// `[R3]` keyed PRF: BLAKE3 keyed with the PRF key over `input`.
    pub fn prf(&self, input: &[u8]) -> [u8; 32] {
        *blake3::keyed_hash(&self.prf_key, input).as_bytes()
    }

    /// Seal auth-txn state: `nonce(24) ‖ ciphertext`.
    pub fn seal(&self, plaintext: &[u8], ad: &[u8]) -> AuthResult<Vec<u8>> {
        let (nonce, ct) = aead_seal(&self.seal_key, plaintext, ad)?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Open sealed auth-txn state; `None` on any authentication failure.
    pub fn open(&self, sealed: &[u8], ad: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        if sealed.len() < 24 {
            return None;
        }
        let (nonce, ct) = sealed.split_at(24);
        aead_open(&self.seal_key, nonce, ct, ad)
    }

    /// (rev 16 P2) Seal an idempotency replay payload under the purpose key derived from this
    /// version's seal key (BLAKE3 `derive_key`, context `identity idempotency v1`):
    /// `nonce(24) ‖ ciphertext`.
    pub fn seal_idempotency(&self, plaintext: &[u8], ad: &[u8]) -> AuthResult<Vec<u8>> {
        let k = self.idempotency_key();
        let (nonce, ct) = aead_seal(&k, plaintext, ad)?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Open a payload sealed by [`Self::seal_idempotency`]; `None` on any failure.
    pub fn open_idempotency(&self, sealed: &[u8], ad: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        if sealed.len() < 24 {
            return None;
        }
        let (nonce, ct) = sealed.split_at(24);
        aead_open(&self.idempotency_key(), nonce, ct, ad)
    }

    fn idempotency_key(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(blake3::derive_key(
            IDEMPOTENCY_KEY_CONTEXT,
            self.seal_key.as_slice(),
        ))
    }

    fn generate(version: i32) -> AuthResult<(Self, Zeroizing<Vec<u8>>)> {
        let setup = ServerSetup::<Suite>::new(&mut rand_core_06::OsRng);
        let prf_key = Zeroizing::new(cs_crypto::rand::bytes::<32>().map_err(Error::internal)?);
        let seal_key = Zeroizing::new(cs_crypto::rand::bytes::<32>().map_err(Error::internal)?);
        let me = Self {
            version,
            setup,
            prf_key,
            seal_key,
        };
        let pt = me.encode();
        Ok((me, pt))
    }

    /// `u16 setup_len ‖ setup ‖ prf_key ‖ seal_key`.
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let setup = Zeroizing::new(self.setup.serialize().to_vec());
        let mut v = Zeroizing::new(Vec::with_capacity(2 + setup.len() + 64));
        // ServerSetup is 128 bytes for this suite; the length always fits in u16.
        let len = u16::try_from(setup.len()).unwrap_or(u16::MAX);
        v.extend_from_slice(&len.to_be_bytes());
        v.extend_from_slice(&setup);
        v.extend_from_slice(self.prf_key.as_slice());
        v.extend_from_slice(self.seal_key.as_slice());
        v
    }

    fn decode(version: i32, b: &[u8]) -> Option<Self> {
        let len = usize::from(u16::from_be_bytes(b.get(..2)?.try_into().ok()?));
        let setup_b = b.get(2..2 + len)?;
        let rest = b.get(2 + len..)?;
        if rest.len() != 64 {
            return None;
        }
        let setup = ServerSetup::<Suite>::deserialize(setup_b).ok()?;
        let mut prf_key = Zeroizing::new([0u8; 32]);
        prf_key.copy_from_slice(&rest[..32]);
        let mut seal_key = Zeroizing::new([0u8; 32]);
        seal_key.copy_from_slice(&rest[32..]);
        Some(Self {
            version,
            setup,
            prf_key,
            seal_key,
        })
    }
}

fn aead_seal(key: &[u8; 32], pt: &[u8], ad: &[u8]) -> AuthResult<([u8; 24], Vec<u8>)> {
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    let nonce = cs_crypto::rand::bytes::<24>().map_err(Error::internal)?;
    let ct = cipher
        .encrypt(&XNonce::from(nonce), Payload { msg: pt, aad: ad })
        .map_err(|_| Error::new(ErrorCode::Internal).with_detail("sealing failed"))?;
    Ok((nonce, ct))
}

fn aead_open(key: &[u8; 32], nonce: &[u8], ct: &[u8], ad: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let nonce: [u8; 24] = nonce.try_into().ok()?;
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    cipher
        .decrypt(&XNonce::from(nonce), Payload { msg: ct, aad: ad })
        .ok()
        .map(Zeroizing::new)
}

fn material_ad(version: i32) -> Vec<u8> {
    let mut ad = version.to_be_bytes().to_vec();
    ad.extend_from_slice(PURPOSE);
    ad
}

/// Every loaded version, and the current (highest) one.
#[derive(Debug)]
pub struct OpaqueKeys {
    versions: BTreeMap<i32, Arc<ServerKeyVersion>>,
    current: Arc<ServerKeyVersion>,
}

type Row = (i32, String, Vec<u8>, Vec<u8>, Vec<u8>);

fn kms_err(e: KmsError) -> AuthError {
    Error::new(ErrorCode::Unavailable)
        .with_detail("key management is unavailable")
        .with_cause(e)
        .into()
}

impl OpaqueKeys {
    /// Load every stored version, creating version 1 if none exists.
    pub async fn load_or_init(pool: &DomainPool, kms: &dyn Kms) -> AuthResult<Self> {
        let rows = read_rows(pool).await?;
        if rows.is_empty() {
            insert_candidate(pool, kms, 1).await?;
            return Self::from_rows(read_rows(pool).await?, kms).await;
        }
        Self::from_rows(rows, kms).await
    }

    /// Add the next version (rotation) and reload. Older versions stay usable.
    pub async fn rotate(pool: &DomainPool, kms: &dyn Kms) -> AuthResult<Self> {
        let rows = read_rows(pool).await?;
        let next = rows.iter().map(|r| r.0).max().unwrap_or(0) + 1;
        insert_candidate(pool, kms, next).await?;
        Self::from_rows(read_rows(pool).await?, kms).await
    }

    async fn from_rows(rows: Vec<Row>, kms: &dyn Kms) -> AuthResult<Self> {
        let mut versions = BTreeMap::new();
        for (version, _kek, wrapped, nonce, ct) in rows {
            let w = WrappedKey::from_bytes(&wrapped).map_err(kms_err)?;
            let dek = kms.unwrap(&w).await.map_err(kms_err)?;
            let dek: [u8; 32] = dek.as_slice().try_into().map_err(|_| {
                Error::new(ErrorCode::Internal).with_detail("OPAQUE data key has the wrong length")
            })?;
            let dek = Zeroizing::new(dek);
            let pt = aead_open(&dek, &nonce, &ct, &material_ad(version)).ok_or_else(|| {
                Error::new(ErrorCode::Internal)
                    .with_detail(format!("OPAQUE key version {version} cannot be opened"))
            })?;
            let k = ServerKeyVersion::decode(version, &pt).ok_or_else(|| {
                Error::new(ErrorCode::Internal)
                    .with_detail(format!("OPAQUE key version {version} is malformed"))
            })?;
            versions.insert(version, Arc::new(k));
        }
        let current = versions.values().next_back().cloned().ok_or_else(|| {
            Error::new(ErrorCode::Internal).with_detail("no OPAQUE key version stored")
        })?;
        Ok(Self { versions, current })
    }

    pub fn current(&self) -> Arc<ServerKeyVersion> {
        self.current.clone()
    }

    pub fn get(&self, version: i32) -> Option<Arc<ServerKeyVersion>> {
        self.versions.get(&version).cloned()
    }

    /// Version from an `opaque_registrations.server_key_version` label.
    pub fn by_label(&self, label: &str) -> Option<Arc<ServerKeyVersion>> {
        label
            .strip_prefix(KEY_VERSION_PREFIX)
            .and_then(|v| v.parse::<i32>().ok())
            .and_then(|v| self.get(v))
    }

    pub fn versions(&self) -> Vec<i32> {
        self.versions.keys().copied().collect()
    }
}

async fn read_rows(pool: &DomainPool) -> AuthResult<Vec<Row>> {
    pool.read_snapshot(|tx| {
        Box::pin(async move {
            Ok(sqlx::query_as::<_, Row>(
                "SELECT key_version, kek_id, wrapped_dek, nonce, ciphertext \
                 FROM opaque_server_keys ORDER BY key_version",
            )
            .fetch_all(tx.conn())
            .await?)
        })
    })
    .await
    .map_err(AuthError::from)
}

async fn current_kek(kms: &dyn Kms) -> AuthResult<cs_crypto::sig::KeyId> {
    match kms.current(KEK_NAME).await {
        Ok(k) => Ok(k),
        Err(KmsError::UnknownKey(_)) => {
            match kms.generate_key(KEK_NAME, KeyPurpose::KeyEncryption).await {
                Ok(k) => Ok(k),
                Err(KmsError::KeyExists(_)) => kms.current(KEK_NAME).await.map_err(kms_err),
                Err(e) => Err(kms_err(e)),
            }
        }
        Err(e) => Err(kms_err(e)),
    }
}

/// Build a candidate version and insert it unless one exists. KMS calls happen before the
/// (single-statement) transaction, never inside it.
async fn insert_candidate(pool: &DomainPool, kms: &dyn Kms, version: i32) -> AuthResult<()> {
    let kek = current_kek(kms).await?;
    let (_cand, pt) = ServerKeyVersion::generate(version)?;
    let dek = Zeroizing::new(cs_crypto::rand::bytes::<32>().map_err(Error::internal)?);
    let wrapped = kms
        .wrap(&kek, dek.as_slice())
        .await
        .map_err(kms_err)?
        .to_bytes()
        .map_err(kms_err)?;
    let (nonce, ct) = aead_seal(&dek, &pt, &material_ad(version))?;
    let kek_s = kek.to_string();
    pool.transaction(move |tx| {
        let (kek_s, wrapped, ct) = (kek_s.clone(), wrapped.clone(), ct.clone());
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO opaque_server_keys (key_version, kek_id, wrapped_dek, nonce, ciphertext) \
                 VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
            )
            .bind(version)
            .bind(kek_s)
            .bind(wrapped)
            .bind(nonce.as_slice())
            .bind(ct)
            .execute(tx.conn())
            .await?;
            Ok::<_, DbError>(())
        })
    })
    .await
    .map_err(AuthError::from)
}
