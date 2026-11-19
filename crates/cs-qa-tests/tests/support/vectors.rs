//! Loader for `vectors/signing_envelope.json` (generated independently by
//! `vectors/gen/gen_sig_vectors.py`).

use serde_json::Value;

pub const SIGNING_JSON: &str = include_str!("../../vectors/signing_envelope.json");

#[derive(Debug, Clone)]
pub struct Key {
    pub key_id: String,
    pub seed: [u8; 32],
    pub public: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct Valid {
    pub name: String,
    pub context: String,
    pub key_id: String,
    pub payload: Vec<u8>,
    pub signed_bytes: Vec<u8>,
    pub signature: Vec<u8>,
    pub envelope: Vec<u8>,
    pub envelope_b64url: String,
}

#[derive(Debug, Clone)]
pub struct Invalid {
    pub name: String,
    pub expected_context: String,
    pub envelope: Vec<u8>,
    pub reason: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SigningVectors {
    pub max_envelope_bytes: usize,
    pub contexts: Vec<String>,
    pub keys: Vec<Key>,
    pub valid: Vec<Valid>,
    pub invalid: Vec<Invalid>,
}

fn s(v: &Value, k: &str) -> String {
    v[k].as_str()
        .unwrap_or_else(|| panic!("vector field {k}"))
        .to_string()
}
fn h(v: &Value, k: &str) -> Vec<u8> {
    hex::decode(s(v, k)).unwrap_or_else(|_| panic!("hex field {k}"))
}
fn arr32(b: Vec<u8>) -> [u8; 32] {
    b.try_into().expect("32 bytes")
}

pub fn signing() -> SigningVectors {
    let doc: Value = serde_json::from_str(SIGNING_JSON).expect("vectors json");
    let list = |k: &str| doc[k].as_array().cloned().unwrap_or_default();
    SigningVectors {
        max_envelope_bytes: doc["max_envelope_bytes"].as_u64().expect("max") as usize,
        contexts: list("contexts")
            .iter()
            .map(|c| c.as_str().expect("ctx").to_string())
            .collect(),
        keys: list("keys")
            .iter()
            .map(|k| Key {
                key_id: s(k, "key_id"),
                seed: arr32(h(k, "seed_hex")),
                public: arr32(h(k, "public_hex")),
            })
            .collect(),
        valid: list("valid")
            .iter()
            .map(|v| Valid {
                name: s(v, "name"),
                context: s(v, "context"),
                key_id: s(v, "key_id"),
                payload: h(v, "payload_hex"),
                signed_bytes: h(v, "signed_bytes_hex"),
                signature: h(v, "signature_hex"),
                envelope: h(v, "envelope_hex"),
                envelope_b64url: s(v, "envelope_b64url"),
            })
            .collect(),
        invalid: list("invalid")
            .iter()
            .map(|v| Invalid {
                name: s(v, "name"),
                expected_context: s(v, "expected_context"),
                envelope: h(v, "envelope_hex"),
                reason: s(v, "reason"),
                tags: v["tags"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|t| t.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default(),
            })
            .collect(),
    }
}
