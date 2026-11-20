//! Ed25519 signing envelope with domain separation (C8, contract §3).
//!
//! ```text
//! signed_bytes = "cs-sig/v1" 0x00 context 0x00 payload
//! signature    = Ed25519(key, signed_bytes)
//! envelope     = CBOR [1, context, key_id, payload_bstr, signature_bstr]
//! ```
//!
//! `payload` is deterministic CBOR. Verification order: size limit, envelope structure,
//! envelope version, context (closed registry, must equal the expected context), key
//! resolution through [`KeyResolver`], strict Ed25519 verification, and only then payload
//! decoding with the decode/re-encode equality check.

use crate::cbor::{self, CborError, Value};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

/// Domain-separation prefix of every signed byte string.
pub const SIG_PREFIX: &[u8] = b"cs-sig/v1";
/// Envelope format version on the wire.
pub const ENVELOPE_VERSION: u64 = 1;
/// Default maximum envelope size in bytes (contract §3).
pub const DEFAULT_MAX_ENVELOPE_BYTES: usize = 16 * 1024;
/// Maximum length of a key ID's text form.
pub const MAX_KEY_ID_LEN: usize = 128;

/// The closed registry of signing contexts. Adding a context is a contract change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Context {
    ConsistencyContext,
    SnapshotHandle,
    DecisionTicket,
    RevocationRecord,
    WatermarkHeartbeat,
    StorageReceipt,
    DataPlaneToken,
    StateAttestation,
    /// For tests and published test vectors only.
    Test,
}

impl Context {
    /// Every registered context.
    pub const ALL: [Context; 9] = [
        Context::ConsistencyContext,
        Context::SnapshotHandle,
        Context::DecisionTicket,
        Context::RevocationRecord,
        Context::WatermarkHeartbeat,
        Context::StorageReceipt,
        Context::DataPlaneToken,
        Context::StateAttestation,
        Context::Test,
    ];

    /// Wire string of the context.
    pub const fn as_str(self) -> &'static str {
        match self {
            Context::ConsistencyContext => "consistency-context/v1",
            Context::SnapshotHandle => "snapshot-handle/v1",
            Context::DecisionTicket => "decision-ticket/v1",
            Context::RevocationRecord => "revocation-record/v1",
            Context::WatermarkHeartbeat => "watermark-heartbeat/v1",
            Context::StorageReceipt => "storage-receipt/v1",
            Context::DataPlaneToken => "data-plane-token/v1",
            Context::StateAttestation => "state-attestation/v1",
            Context::Test => "test/v1",
        }
    }
}

impl fmt::Display for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Context {
    type Err = SigError;
    fn from_str(s: &str) -> Result<Self, SigError> {
        Context::ALL
            .into_iter()
            .find(|c| c.as_str() == s)
            .ok_or(SigError::UnknownContext)
    }
}

/// A versioned key identifier: `<key-name>@v<version>`, e.g. `token-signing@v3`; at most
/// 128 bytes of text (contract §3 rev 2).
///
/// `name` matches `^[a-z][a-z0-9_.-]*$` (design); `version` is ≥ 1 without leading zeros.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyId {
    name: String,
    version: u32,
}

impl KeyId {
    /// Build a key ID, validating the name and version.
    pub fn new(name: &str, version: u32) -> Result<Self, SigError> {
        let valid_name = !name.is_empty()
            && name.len() + 2 + version.to_string().len() <= MAX_KEY_ID_LEN
            && name.as_bytes()[0].is_ascii_lowercase()
            && name.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-')
            });
        if !valid_name || version == 0 {
            return Err(SigError::InvalidKeyId);
        }
        Ok(KeyId {
            name: name.to_owned(),
            version,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    /// The same key name at the next version.
    pub fn next_version(&self) -> Result<Self, SigError> {
        let v = self.version.checked_add(1).ok_or(SigError::InvalidKeyId)?;
        KeyId::new(&self.name, v)
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@v{}", self.name, self.version)
    }
}

impl FromStr for KeyId {
    type Err = SigError;
    fn from_str(s: &str) -> Result<Self, SigError> {
        if s.len() > MAX_KEY_ID_LEN {
            return Err(SigError::InvalidKeyId);
        }
        let (name, v) = s.rsplit_once("@v").ok_or(SigError::InvalidKeyId)?;
        // Strict: no leading zeros, no sign, digits only.
        if v.is_empty() || v.starts_with('0') || !v.bytes().all(|b| b.is_ascii_digit()) {
            return Err(SigError::InvalidKeyId);
        }
        let version = v.parse::<u32>().map_err(|_| SigError::InvalidKeyId)?;
        KeyId::new(name, version)
    }
}

/// Envelope signing and verification failures. Every variant is a rejection.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SigError {
    #[error("envelope exceeds {limit} bytes")]
    TooLarge { limit: usize },
    #[error("malformed envelope")]
    Malformed,
    #[error("unsupported envelope version")]
    UnsupportedVersion,
    #[error("unknown signing context")]
    UnknownContext,
    #[error("signing context does not match the expected context")]
    WrongContext,
    #[error("invalid key id")]
    InvalidKeyId,
    #[error("unknown or unusable key")]
    UnknownKey,
    #[error("signature verification failed")]
    BadSignature,
    #[error("payload is not deterministic CBOR")]
    NonCanonicalPayload,
    #[error("payload does not match the artifact schema: {0}")]
    PayloadSchema(String),
    #[error("signing failed: {0}")]
    Signing(String),
    #[error("encoding failed: {0}")]
    Encoding(CborError),
}

/// Resolves the verifying key for a key ID. Implementations may bind keys to contexts
/// (a key ID valid for receipts need not be valid for tokens); returning `UnknownKey`
/// for a context the key is not authorized for is the expected behaviour.
pub trait KeyResolver: Send + Sync {
    fn resolve(&self, key_id: &KeyId, context: Context) -> Result<VerifyingKey, SigError>;
}

/// Produces raw Ed25519 signatures for a key ID (implemented by the KMS).
pub trait RawSigner: Send + Sync {
    fn sign_raw(&self, key_id: &KeyId, message: &[u8]) -> Result<Signature, SigError>;
}

/// In-memory resolver: explicit (key ID, allowed contexts) → key table.
#[derive(Debug, Default, Clone)]
pub struct StaticKeyResolver {
    keys: BTreeMap<KeyId, (VerifyingKey, Vec<Context>)>,
}

impl StaticKeyResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `key` under `key_id` for the given contexts.
    pub fn insert(&mut self, key_id: KeyId, key: VerifyingKey, contexts: &[Context]) {
        self.keys.insert(key_id, (key, contexts.to_vec()));
    }
}

impl KeyResolver for StaticKeyResolver {
    fn resolve(&self, key_id: &KeyId, context: Context) -> Result<VerifyingKey, SigError> {
        match self.keys.get(key_id) {
            Some((k, ctxs)) if ctxs.contains(&context) => Ok(*k),
            _ => Err(SigError::UnknownKey),
        }
    }
}

/// A signer holding one Ed25519 key in memory (tests, vectors, and the local KMS).
pub struct LocalSigner {
    key_id: KeyId,
    key: SigningKey,
}

impl fmt::Debug for LocalSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalSigner")
            .field("key_id", &self.key_id)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl LocalSigner {
    pub fn new(key_id: KeyId, key: SigningKey) -> Self {
        Self { key_id, key }
    }

    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }
}

impl RawSigner for LocalSigner {
    fn sign_raw(&self, key_id: &KeyId, message: &[u8]) -> Result<Signature, SigError> {
        if key_id != &self.key_id {
            return Err(SigError::UnknownKey);
        }
        Ok(self.key.sign(message))
    }
}

/// Build `"cs-sig/v1" 0x00 context 0x00 payload`.
pub fn signed_bytes(context: Context, payload: &[u8]) -> Vec<u8> {
    let c = context.as_str().as_bytes();
    let mut v = Vec::with_capacity(SIG_PREFIX.len() + 2 + c.len() + payload.len());
    v.extend_from_slice(SIG_PREFIX);
    v.push(0);
    v.extend_from_slice(c);
    v.push(0);
    v.extend_from_slice(payload);
    v
}

/// Sign an already-encoded payload. The payload must be deterministic CBOR.
pub fn sign_payload_bytes(
    context: Context,
    key_id: &KeyId,
    payload: &[u8],
    signer: &dyn RawSigner,
    max_envelope_bytes: usize,
) -> Result<Vec<u8>, SigError> {
    cbor::decode_canonical(payload, max_envelope_bytes)
        .map_err(|_| SigError::NonCanonicalPayload)?;
    let sig = signer.sign_raw(key_id, &signed_bytes(context, payload))?;
    let env = Value::Array(vec![
        Value::Unsigned(ENVELOPE_VERSION),
        Value::Text(context.as_str().to_owned()),
        Value::Text(key_id.to_string()),
        Value::Bytes(payload.to_vec()),
        Value::Bytes(sig.to_bytes().to_vec()),
    ]);
    let bytes = cbor::encode(&env).map_err(SigError::Encoding)?;
    if bytes.len() > max_envelope_bytes {
        return Err(SigError::TooLarge {
            limit: max_envelope_bytes,
        });
    }
    Ok(bytes)
}

/// Serialize `payload` as deterministic CBOR and sign it into an envelope.
pub fn sign<T: Serialize + ?Sized>(
    context: Context,
    key_id: &KeyId,
    payload: &T,
    signer: &dyn RawSigner,
) -> Result<Vec<u8>, SigError> {
    let p = cbor::to_canonical(payload).map_err(SigError::Encoding)?;
    sign_payload_bytes(context, key_id, &p, signer, DEFAULT_MAX_ENVELOPE_BYTES)
}

/// A verified envelope. Fields are only constructed after signature verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified<T> {
    pub context: Context,
    pub key_id: KeyId,
    pub payload: T,
}

/// Verify an envelope and return its raw (canonical) payload bytes.
pub fn verify_bytes(
    envelope: &[u8],
    expected: Context,
    resolver: &dyn KeyResolver,
    max_envelope_bytes: usize,
) -> Result<Verified<Vec<u8>>, SigError> {
    if envelope.len() > max_envelope_bytes {
        return Err(SigError::TooLarge {
            limit: max_envelope_bytes,
        });
    }
    let v = cbor::decode_canonical(envelope, max_envelope_bytes).map_err(|e| match e {
        CborError::TooLarge { limit } => SigError::TooLarge { limit },
        _ => SigError::Malformed,
    })?;
    let Value::Array(items) = v else {
        return Err(SigError::Malformed);
    };
    let [version, ctx, kid, payload, sig] =
        <[Value; 5]>::try_from(items).map_err(|_| SigError::Malformed)?;
    match version {
        Value::Unsigned(ENVELOPE_VERSION) => {}
        Value::Unsigned(_) => return Err(SigError::UnsupportedVersion),
        _ => return Err(SigError::Malformed),
    }
    let (Value::Text(ctx), Value::Text(kid), Value::Bytes(payload), Value::Bytes(sig)) =
        (ctx, kid, payload, sig)
    else {
        return Err(SigError::Malformed);
    };
    let context: Context = ctx.parse()?;
    if context != expected {
        return Err(SigError::WrongContext);
    }
    let key_id: KeyId = kid.parse()?;
    let sig: [u8; 64] = sig.try_into().map_err(|_| SigError::Malformed)?;
    let sig = Signature::from_bytes(&sig);
    let key = resolver.resolve(&key_id, context)?;
    key.verify_strict(&signed_bytes(context, &payload), &sig)
        .map_err(|_| SigError::BadSignature)?;
    // Signature is valid; the payload must still be deterministic CBOR.
    cbor::decode_canonical(&payload, max_envelope_bytes)
        .map_err(|_| SigError::NonCanonicalPayload)?;
    Ok(Verified {
        context,
        key_id,
        payload,
    })
}

/// Verify an envelope and decode its payload into `T`.
pub fn verify<T: DeserializeOwned>(
    envelope: &[u8],
    expected: Context,
    resolver: &dyn KeyResolver,
    max_envelope_bytes: usize,
) -> Result<Verified<T>, SigError> {
    let v = verify_bytes(envelope, expected, resolver, max_envelope_bytes)?;
    let payload = cbor::from_canonical(&v.payload, max_envelope_bytes)
        .map_err(|e| SigError::PayloadSchema(e.to_string()))?;
    Ok(Verified {
        context: v.context,
        key_id: v.key_id,
        payload,
    })
}

/// Text transport form: base64url without padding.
pub fn to_text(envelope: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(envelope)
}

/// Parse the text transport form, checking the size limit before decoding.
pub fn from_text(text: &str, max_envelope_bytes: usize) -> Result<Vec<u8>, SigError> {
    // Contract §3 rev 2: encoded length <= ceil(limit * 4 / 3), checked before decoding.
    let max_text = (max_envelope_bytes * 4).div_ceil(3);
    if text.len() > max_text {
        return Err(SigError::TooLarge {
            limit: max_envelope_bytes,
        });
    }
    let b = URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| SigError::Malformed)?;
    if b.len() > max_envelope_bytes {
        return Err(SigError::TooLarge {
            limit: max_envelope_bytes,
        });
    }
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Claim {
        subject: String,
        n: u64,
    }

    fn setup() -> (LocalSigner, StaticKeyResolver, KeyId) {
        let kid = KeyId::new("test-key", 1).unwrap();
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let signer = LocalSigner::new(kid.clone(), sk);
        let mut r = StaticKeyResolver::new();
        r.insert(kid.clone(), signer.verifying_key(), &[Context::Test]);
        (signer, r, kid)
    }

    #[test]
    fn roundtrip() {
        let (s, r, kid) = setup();
        let c = Claim {
            subject: "a".into(),
            n: 5,
        };
        let env = sign(Context::Test, &kid, &c, &s).unwrap();
        let v: Verified<Claim> =
            verify(&env, Context::Test, &r, DEFAULT_MAX_ENVELOPE_BYTES).unwrap();
        assert_eq!(v.payload, c);
        assert_eq!(v.key_id, kid);
        let t = to_text(&env);
        assert!(!t.contains('='));
        assert_eq!(from_text(&t, DEFAULT_MAX_ENVELOPE_BYTES).unwrap(), env);
    }

    #[test]
    fn wrong_context_rejected() {
        let (s, mut r, kid) = setup();
        r.insert(
            kid.clone(),
            s.verifying_key(),
            &[Context::Test, Context::DecisionTicket],
        );
        let env = sign(Context::Test, &kid, &1u8, &s).unwrap();
        assert_eq!(
            verify::<u8>(
                &env,
                Context::DecisionTicket,
                &r,
                DEFAULT_MAX_ENVELOPE_BYTES
            ),
            Err(SigError::WrongContext)
        );
    }

    #[test]
    fn key_not_authorized_for_context_rejected() {
        let (s, r, kid) = setup();
        let env = sign(Context::StorageReceipt, &kid, &1u8, &s).unwrap();
        assert_eq!(
            verify::<u8>(
                &env,
                Context::StorageReceipt,
                &r,
                DEFAULT_MAX_ENVELOPE_BYTES
            ),
            Err(SigError::UnknownKey)
        );
    }

    #[test]
    fn tampered_payload_rejected() {
        let (s, r, kid) = setup();
        let mut env = sign(
            Context::Test,
            &kid,
            &Claim {
                subject: "a".into(),
                n: 5,
            },
            &s,
        )
        .unwrap();
        // flip the last payload byte ('n' value 5 -> 6); payload precedes the 64-byte sig + 2-byte header
        let idx = env.len() - 64 - 2 - 1;
        env[idx] ^= 0x03;
        assert_eq!(
            verify::<Claim>(&env, Context::Test, &r, DEFAULT_MAX_ENVELOPE_BYTES),
            Err(SigError::BadSignature)
        );
    }

    #[test]
    fn oversized_rejected_before_decode() {
        let (_, r, _) = setup();
        let junk = vec![0xffu8; DEFAULT_MAX_ENVELOPE_BYTES + 1];
        assert_eq!(
            verify_bytes(&junk, Context::Test, &r, DEFAULT_MAX_ENVELOPE_BYTES),
            Err(SigError::TooLarge {
                limit: DEFAULT_MAX_ENVELOPE_BYTES
            })
        );
        // exact bound: ceil(16384 * 4 / 3) = 21846 characters
        assert!(!matches!(
            from_text(&"A".repeat(21846), DEFAULT_MAX_ENVELOPE_BYTES),
            Err(SigError::TooLarge { .. })
        ));
        let text = "A".repeat(21847);
        assert!(matches!(
            from_text(&text, DEFAULT_MAX_ENVELOPE_BYTES),
            Err(SigError::TooLarge { .. })
        ));
    }

    #[test]
    fn oversized_payload_refused_at_signing() {
        let (s, _, kid) = setup();
        let big = Value::Bytes(vec![0u8; DEFAULT_MAX_ENVELOPE_BYTES]);
        let p = cbor::encode(&big).unwrap();
        assert!(matches!(
            sign_payload_bytes(Context::Test, &kid, &p, &s, DEFAULT_MAX_ENVELOPE_BYTES),
            Err(SigError::NonCanonicalPayload | SigError::TooLarge { .. })
        ));
    }

    #[test]
    fn non_canonical_payload_refused_at_signing() {
        let (s, _, kid) = setup();
        assert_eq!(
            sign_payload_bytes(
                Context::Test,
                &kid,
                &[0x18, 0x01],
                &s,
                DEFAULT_MAX_ENVELOPE_BYTES
            ),
            Err(SigError::NonCanonicalPayload)
        );
    }

    #[test]
    fn key_id_parsing_is_strict() {
        assert_eq!(
            "a@v1".parse::<KeyId>().unwrap(),
            KeyId::new("a", 1).unwrap()
        );
        let long = format!("{}@v1", "k".repeat(125));
        assert_eq!(long.len(), 128);
        assert!(long.parse::<KeyId>().is_ok());
        assert!(format!("{}@v1", "k".repeat(126)).parse::<KeyId>().is_err());
        assert!(format!("{}@v10", "k".repeat(125)).parse::<KeyId>().is_err());
        assert!("a/v1".parse::<KeyId>().is_err());
        assert_eq!(KeyId::new("tok", 12).unwrap().to_string(), "tok@v12");
        for bad in [
            "",
            "a",
            "a@v0",
            "a@v01",
            "A@v1",
            "a@v-1",
            "@v1",
            "a@v1 ",
            "1a@v1",
            "a@v99999999999",
        ] {
            assert!(bad.parse::<KeyId>().is_err(), "{bad}");
        }
    }

    #[test]
    fn context_registry_closed() {
        for c in Context::ALL {
            assert_eq!(c.as_str().parse::<Context>().unwrap(), c);
        }
        assert_eq!("other/v1".parse::<Context>(), Err(SigError::UnknownContext));
    }
}
