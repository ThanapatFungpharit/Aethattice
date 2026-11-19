//! Local software KMS (J.4): acceptable only for single-node deployments.
//!
//! - Root key: 32 random bytes in a file created with mode 0600. Opening refuses a file that
//!   is readable or writable by group/others, or that has the wrong length.
//! - Key store: every generated key version, encrypted under the root key with
//!   XChaCha20-Poly1305 (random 192-bit nonce, associated data binds name, version and
//!   purpose), written atomically (temp file 0600, fsync, rename, fsync dir).
//! - In memory, key material lives in `Zeroizing` buffers.

use crate::{KeyPurpose, Kms, KmsError, WrappedKey};
use async_trait::async_trait;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use cs_crypto::cbor;
use cs_crypto::rand;
use cs_crypto::sig::{Context, KeyId, KeyResolver, RawSigner, SigError};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use zeroize::Zeroizing;

/// Logged whenever a local software KMS is opened.
pub const SINGLE_NODE_WARNING: &str = "local software KMS in use: the root key is a local file (0600). This is acceptable ONLY for single-node deployments (spec J.4); use an external KMS or HSM for clusters";

const ROOT_KEY_LEN: usize = 32;
const STORE_FORMAT: u64 = 1;
const WRAP_AD: &[u8] = b"cs-kms/wrap/v1";
const STORE_AD: &[u8] = b"cs-kms/keystore/v1";

struct Entry {
    purpose: KeyPurpose,
    material: Zeroizing<[u8; 32]>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredKey {
    name: String,
    version: u32,
    purpose: KeyPurpose,
    #[serde(with = "cbor::bstr")]
    nonce: Vec<u8>,
    #[serde(with = "cbor::bstr")]
    ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreFile {
    format: u64,
    keys: Vec<StoredKey>,
}

/// Local software KMS. See module docs.
pub struct LocalSoftwareKms {
    root: Zeroizing<[u8; ROOT_KEY_LEN]>,
    store_path: PathBuf,
    keys: RwLock<BTreeMap<KeyId, Entry>>,
}

impl fmt::Debug for LocalSoftwareKms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalSoftwareKms")
            .field("store_path", &self.store_path)
            .field("root", &"[REDACTED]")
            .finish()
    }
}

fn store_err(e: impl fmt::Display) -> KmsError {
    KmsError::Store(e.to_string())
}

fn check_mode(path: &Path) -> Result<(), KmsError> {
    let meta = fs::metadata(path).map_err(store_err)?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(KmsError::InsecureFile {
            path: path.display().to_string(),
            reason: format!("mode {mode:o}; must not be accessible by group or others (0600)"),
        });
    }
    Ok(())
}

fn write_atomic_0600(path: &Path, bytes: &[u8]) -> Result<(), KmsError> {
    let dir = path
        .parent()
        .ok_or_else(|| store_err("key store path has no parent directory"))?;
    let suffix = rand::u64()?;
    let tmp = dir.join(format!(
        ".{}.tmp-{suffix:016x}",
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    ));
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(store_err)?;
        f.write_all(bytes).map_err(store_err)?;
        f.sync_all().map_err(store_err)?;
    }
    fs::rename(&tmp, path).map_err(store_err)?;
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(store_err)?;
    Ok(())
}

fn store_ad(name: &str, version: u32, purpose: KeyPurpose) -> Vec<u8> {
    let p = match purpose {
        KeyPurpose::Signing => "signing",
        KeyPurpose::KeyEncryption => "key_encryption",
    };
    let mut ad = STORE_AD.to_vec();
    ad.push(0);
    ad.extend_from_slice(format!("{name}/v{version}").as_bytes());
    ad.push(0);
    ad.extend_from_slice(p.as_bytes());
    ad
}

fn wrap_ad(kek_id: &KeyId) -> Vec<u8> {
    let mut ad = WRAP_AD.to_vec();
    ad.push(0);
    ad.extend_from_slice(kek_id.to_string().as_bytes());
    ad
}

fn seal(key: &[u8; 32], plaintext: &[u8], ad: &[u8]) -> Result<(Vec<u8>, Vec<u8>), KmsError> {
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    let nonce_bytes = rand::bytes::<24>()?;
    let nonce = XNonce::from(nonce_bytes);
    let ct = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: ad,
            },
        )
        .map_err(|_| store_err("encryption failed"))?;
    Ok((nonce_bytes.to_vec(), ct))
}

fn open(
    key: &[u8; 32],
    nonce: &[u8],
    ct: &[u8],
    ad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KmsError> {
    let nonce: [u8; 24] = nonce.try_into().map_err(|_| KmsError::UnwrapFailed)?;
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    cipher
        .decrypt(&XNonce::from(nonce), Payload { msg: ct, aad: ad })
        .map(Zeroizing::new)
        .map_err(|_| KmsError::UnwrapFailed)
}

impl LocalSoftwareKms {
    /// Create a new root key file (mode 0600; fails if the file exists) and open the KMS.
    pub fn init(root_key_path: &Path, store_path: Option<&Path>) -> Result<Self, KmsError> {
        let root = Zeroizing::new(rand::bytes::<ROOT_KEY_LEN>()?);
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(root_key_path)
                .map_err(store_err)?;
            f.write_all(root.as_ref()).map_err(store_err)?;
            f.sync_all().map_err(store_err)?;
        }
        if let Some(dir) = root_key_path.parent() {
            File::open(dir)
                .and_then(|d| d.sync_all())
                .map_err(store_err)?;
        }
        Self::open(root_key_path, store_path)
    }

    /// Open an existing root key and key store. Logs the single-node warning.
    pub fn open(root_key_path: &Path, store_path: Option<&Path>) -> Result<Self, KmsError> {
        check_mode(root_key_path)?;
        let mut buf = Zeroizing::new(Vec::new());
        File::open(root_key_path)
            .and_then(|mut f| f.read_to_end(&mut buf))
            .map_err(store_err)?;
        let root: [u8; ROOT_KEY_LEN] =
            buf.as_slice()
                .try_into()
                .map_err(|_| KmsError::InsecureFile {
                    path: root_key_path.display().to_string(),
                    reason: format!("root key must be exactly {ROOT_KEY_LEN} bytes"),
                })?;
        let root = Zeroizing::new(root);
        let store_path = store_path.map(Path::to_path_buf).unwrap_or_else(|| {
            let mut p = root_key_path.as_os_str().to_owned();
            p.push(".keys");
            PathBuf::from(p)
        });
        let mut keys = BTreeMap::new();
        if store_path.exists() {
            check_mode(&store_path)?;
            let bytes = fs::read(&store_path).map_err(store_err)?;
            let file: StoreFile =
                cbor::from_canonical(&bytes, 64 * 1024 * 1024).map_err(store_err)?;
            if file.format != STORE_FORMAT {
                return Err(store_err("unsupported key store format"));
            }
            for k in file.keys {
                let id = KeyId::new(&k.name, k.version).map_err(|_| KmsError::InvalidKeyId)?;
                let pt = open(
                    &root,
                    &k.nonce,
                    &k.ciphertext,
                    &store_ad(&k.name, k.version, k.purpose),
                )
                .map_err(|_| {
                    store_err("key store entry failed authentication (wrong root key or tampering)")
                })?;
                let material: [u8; 32] = pt
                    .as_slice()
                    .try_into()
                    .map_err(|_| store_err("bad key length"))?;
                keys.insert(
                    id,
                    Entry {
                        purpose: k.purpose,
                        material: Zeroizing::new(material),
                    },
                );
            }
        }
        tracing::warn!(target: "cs_kms", "{SINGLE_NODE_WARNING}");
        Ok(Self {
            root,
            store_path,
            keys: RwLock::new(keys),
        })
    }

    fn persist(&self, keys: &BTreeMap<KeyId, Entry>) -> Result<(), KmsError> {
        let mut out = Vec::with_capacity(keys.len());
        for (id, e) in keys {
            let (nonce, ciphertext) = seal(
                &self.root,
                e.material.as_ref(),
                &store_ad(id.name(), id.version(), e.purpose),
            )?;
            out.push(StoredKey {
                name: id.name().to_owned(),
                version: id.version(),
                purpose: e.purpose,
                nonce,
                ciphertext,
            });
        }
        let bytes = cbor::to_canonical(&StoreFile {
            format: STORE_FORMAT,
            keys: out,
        })
        .map_err(store_err)?;
        write_atomic_0600(&self.store_path, &bytes)
    }

    fn with_entry<T>(
        &self,
        id: &KeyId,
        purpose: KeyPurpose,
        operation: &'static str,
        f: impl FnOnce(&Entry) -> Result<T, KmsError>,
    ) -> Result<T, KmsError> {
        let keys = self.keys.read().map_err(|_| KmsError::Poisoned)?;
        let e = keys
            .get(id)
            .ok_or_else(|| KmsError::UnknownKey(id.to_string()))?;
        if e.purpose != purpose {
            return Err(KmsError::WrongPurpose {
                key: id.to_string(),
                operation,
            });
        }
        f(e)
    }

    fn insert_version(&self, id: KeyId, purpose: KeyPurpose) -> Result<KeyId, KmsError> {
        let material = Zeroizing::new(rand::bytes::<32>()?);
        let mut keys = self.keys.write().map_err(|_| KmsError::Poisoned)?;
        if keys.contains_key(&id) {
            return Err(KmsError::KeyExists(id.to_string()));
        }
        keys.insert(id.clone(), Entry { purpose, material });
        if let Err(e) = self.persist(&keys) {
            keys.remove(&id);
            return Err(e);
        }
        Ok(id)
    }

    fn current_sync(&self, name: &str) -> Result<KeyId, KmsError> {
        let keys = self.keys.read().map_err(|_| KmsError::Poisoned)?;
        keys.keys()
            .filter(|k| k.name() == name)
            .max_by_key(|k| k.version())
            .cloned()
            .ok_or_else(|| KmsError::UnknownKey(name.to_owned()))
    }

    fn sign_sync(&self, key_id: &KeyId, bytes: &[u8]) -> Result<Signature, KmsError> {
        self.with_entry(key_id, KeyPurpose::Signing, "signing", |e| {
            Ok(SigningKey::from_bytes(&e.material).sign(bytes))
        })
    }

    fn public_key_sync(&self, key_id: &KeyId) -> Result<VerifyingKey, KmsError> {
        self.with_entry(key_id, KeyPurpose::Signing, "public key", |e| {
            Ok(SigningKey::from_bytes(&e.material).verifying_key())
        })
    }
}

#[async_trait]
impl Kms for LocalSoftwareKms {
    async fn generate_key(&self, name: &str, purpose: KeyPurpose) -> Result<KeyId, KmsError> {
        let id = KeyId::new(name, 1).map_err(|_| KmsError::InvalidKeyId)?;
        if self.current_sync(name).is_ok() {
            return Err(KmsError::KeyExists(name.to_owned()));
        }
        self.insert_version(id, purpose)
    }

    async fn wrap(&self, kek_id: &KeyId, plaintext_key: &[u8]) -> Result<WrappedKey, KmsError> {
        if !(16..=64).contains(&plaintext_key.len()) {
            return Err(KmsError::InvalidKeyLength);
        }
        self.with_entry(kek_id, KeyPurpose::KeyEncryption, "wrapping", |e| {
            let (nonce, ciphertext) = seal(&e.material, plaintext_key, &wrap_ad(kek_id))?;
            Ok(WrappedKey {
                kek_id: kek_id.to_string(),
                nonce,
                ciphertext,
            })
        })
    }

    async fn unwrap(&self, wrapped: &WrappedKey) -> Result<Zeroizing<Vec<u8>>, KmsError> {
        let kek_id = wrapped.kek_id()?;
        self.with_entry(&kek_id, KeyPurpose::KeyEncryption, "unwrapping", |e| {
            open(
                &e.material,
                &wrapped.nonce,
                &wrapped.ciphertext,
                &wrap_ad(&kek_id),
            )
        })
    }

    async fn sign(&self, key_id: &KeyId, bytes: &[u8]) -> Result<Signature, KmsError> {
        self.sign_sync(key_id, bytes)
    }

    async fn public_key(&self, key_id: &KeyId) -> Result<VerifyingKey, KmsError> {
        self.public_key_sync(key_id)
    }

    async fn rotate(&self, name: &str) -> Result<KeyId, KmsError> {
        let cur = self.current_sync(name)?;
        let purpose = {
            let keys = self.keys.read().map_err(|_| KmsError::Poisoned)?;
            keys.get(&cur)
                .map(|e| e.purpose)
                .ok_or_else(|| KmsError::UnknownKey(cur.to_string()))?
        };
        let next = cur.next_version().map_err(|_| KmsError::InvalidKeyId)?;
        self.insert_version(next, purpose)
    }

    async fn current(&self, name: &str) -> Result<KeyId, KmsError> {
        self.current_sync(name)
    }
}

impl RawSigner for LocalSoftwareKms {
    fn sign_raw(&self, key_id: &KeyId, message: &[u8]) -> Result<Signature, SigError> {
        self.sign_sync(key_id, message).map_err(|e| match e {
            KmsError::UnknownKey(_) | KmsError::WrongPurpose { .. } => SigError::UnknownKey,
            other => SigError::Signing(other.to_string()),
        })
    }
}

impl KeyResolver for LocalSoftwareKms {
    /// Resolves any signing key version held by this KMS. Context binding of keys is the
    /// job of a policy-aware resolver layered on top (M1+); this resolver does not restrict
    /// contexts.
    fn resolve(&self, key_id: &KeyId, _context: Context) -> Result<VerifyingKey, SigError> {
        self.public_key_sync(key_id)
            .map_err(|_| SigError::UnknownKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cs_crypto::sig;

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[tokio::test]
    async fn root_key_file_is_0600_and_keys_persist() {
        let d = tmp();
        let root = d.path().join("root.key");
        let kms = LocalSoftwareKms::init(&root, None).unwrap();
        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let kek = kms
            .generate_key("tenant-kek", KeyPurpose::KeyEncryption)
            .await
            .unwrap();
        let sk = kms
            .generate_key("token-signing", KeyPurpose::Signing)
            .await
            .unwrap();
        let store = d.path().join("root.key.keys");
        assert_eq!(
            fs::metadata(&store).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let w = kms.wrap(&kek, &[9u8; 32]).await.unwrap();
        let sig = kms.sign(&sk, b"msg").await.unwrap();
        drop(kms);

        let kms2 = LocalSoftwareKms::open(&root, None).unwrap();
        assert_eq!(kms2.unwrap(&w).await.unwrap().as_slice(), &[9u8; 32]);
        kms2.public_key(&sk)
            .await
            .unwrap()
            .verify_strict(b"msg", &sig)
            .unwrap();
        // init refuses to overwrite an existing root key
        assert!(LocalSoftwareKms::init(&root, None).is_err());
    }

    #[tokio::test]
    async fn insecure_permissions_refused() {
        let d = tmp();
        let root = d.path().join("root.key");
        drop(LocalSoftwareKms::init(&root, None).unwrap());
        fs::set_permissions(&root, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            LocalSoftwareKms::open(&root, None),
            Err(KmsError::InsecureFile { .. })
        ));
        fs::set_permissions(&root, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&root, [1u8; 31]).unwrap();
        assert!(matches!(
            LocalSoftwareKms::open(&root, None),
            Err(KmsError::InsecureFile { .. })
        ));
    }

    #[tokio::test]
    async fn wrong_root_key_cannot_open_store() {
        let d = tmp();
        let root = d.path().join("root.key");
        let kms = LocalSoftwareKms::init(&root, None).unwrap();
        kms.generate_key("k", KeyPurpose::Signing).await.unwrap();
        drop(kms);
        fs::write(&root, [5u8; 32]).unwrap();
        assert!(matches!(
            LocalSoftwareKms::open(&root, None),
            Err(KmsError::Store(_))
        ));
    }

    #[tokio::test]
    async fn rotation_keeps_old_versions_usable() {
        let d = tmp();
        let kms = LocalSoftwareKms::init(&d.path().join("r"), None).unwrap();
        let v1 = kms
            .generate_key("kek", KeyPurpose::KeyEncryption)
            .await
            .unwrap();
        let w1 = kms.wrap(&v1, &[1u8; 32]).await.unwrap();
        let v2 = kms.rotate("kek").await.unwrap();
        assert_eq!(v2.to_string(), "kek@v2");
        assert_eq!(kms.current("kek").await.unwrap(), v2);
        let w2 = kms.wrap(&v2, &[2u8; 32]).await.unwrap();
        assert_eq!(kms.unwrap(&w1).await.unwrap().as_slice(), &[1u8; 32]);
        assert_eq!(kms.unwrap(&w2).await.unwrap().as_slice(), &[2u8; 32]);
        assert!(matches!(
            kms.generate_key("kek", KeyPurpose::Signing).await,
            Err(KmsError::KeyExists(_))
        ));
        assert!(kms.rotate("missing").await.is_err());
    }

    #[tokio::test]
    async fn purposes_and_tampering_enforced() {
        let d = tmp();
        let kms = LocalSoftwareKms::init(&d.path().join("r"), None).unwrap();
        let kek = kms
            .generate_key("kek", KeyPurpose::KeyEncryption)
            .await
            .unwrap();
        let sk = kms.generate_key("sig", KeyPurpose::Signing).await.unwrap();
        assert!(matches!(
            kms.sign(&kek, b"x").await,
            Err(KmsError::WrongPurpose { .. })
        ));
        assert!(matches!(
            kms.wrap(&sk, &[0u8; 32]).await,
            Err(KmsError::WrongPurpose { .. })
        ));
        assert!(matches!(
            kms.wrap(&kek, &[0u8; 8]).await,
            Err(KmsError::InvalidKeyLength)
        ));
        let mut w = kms.wrap(&kek, &[3u8; 32]).await.unwrap();
        let w_bytes = w.to_bytes().unwrap();
        assert_eq!(WrappedKey::from_bytes(&w_bytes).unwrap(), w);
        // relabelling a wrapped key under another KEK version fails (AD binds the KEK id)
        let kek2 = kms.rotate("kek").await.unwrap();
        w.kek_id = kek2.to_string();
        assert!(matches!(kms.unwrap(&w).await, Err(KmsError::UnwrapFailed)));
        w.kek_id = kek.to_string();
        w.ciphertext[0] ^= 1;
        assert!(matches!(kms.unwrap(&w).await, Err(KmsError::UnwrapFailed)));
    }

    #[tokio::test]
    async fn envelope_signing_via_kms() {
        let d = tmp();
        let kms = LocalSoftwareKms::init(&d.path().join("r"), None).unwrap();
        let k = kms
            .generate_key("receipts", KeyPurpose::Signing)
            .await
            .unwrap();
        let env = sig::sign(Context::Test, &k, &"hello", &kms).unwrap();
        let v: sig::Verified<String> =
            sig::verify(&env, Context::Test, &kms, sig::DEFAULT_MAX_ENVELOPE_BYTES).unwrap();
        assert_eq!(v.payload, "hello");
        // after rotation, the old version still verifies; the new version is distinct
        let k2 = kms.rotate("receipts").await.unwrap();
        assert!(
            sig::verify::<String>(&env, Context::Test, &kms, sig::DEFAULT_MAX_ENVELOPE_BYTES)
                .is_ok()
        );
        assert_ne!(
            kms.public_key(&k).await.unwrap(),
            kms.public_key(&k2).await.unwrap()
        );
    }

    #[tokio::test]
    async fn csprng_failure_fails_key_generation() {
        let d = tmp();
        let kms = LocalSoftwareKms::init(&d.path().join("r"), None).unwrap();
        let kek = kms
            .generate_key("kek", KeyPurpose::KeyEncryption)
            .await
            .unwrap();
        let _g = cs_crypto::rand::inject_failure();
        assert!(matches!(
            kms.generate_key("other", KeyPurpose::Signing).await,
            Err(KmsError::Rand(_))
        ));
        assert!(matches!(
            kms.wrap(&kek, &[0u8; 32]).await,
            Err(KmsError::Rand(_))
        ));
    }
}
