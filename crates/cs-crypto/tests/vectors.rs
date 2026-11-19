//! Signing-envelope test vectors (contract §3). The JSON files in `tests/vectors/` are the
//! published vectors; this test checks that the implementation reproduces the positive
//! vectors byte for byte and rejects every negative vector with the stated error.
//!
//! Regenerate (only when the contract changes): `CS_REGENERATE_VECTORS=1 cargo test -p cs-crypto --test vectors`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use cs_crypto::cbor::{self, Value};
use cs_crypto::sig::{
    self, Context, DEFAULT_MAX_ENVELOPE_BYTES, KeyId, KeyResolver, LocalSigner, SigError,
    StaticKeyResolver,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value as Json, json};
use std::path::PathBuf;

/// RFC 8032 §7.1 TEST 1 secret key. Test use only.
const SECRET: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn signer() -> (LocalSigner, KeyId) {
    let kid = KeyId::new("test-vector-key", 1).unwrap();
    let sk: [u8; 32] = hex::decode(SECRET).unwrap().try_into().unwrap();
    (
        LocalSigner::new(kid.clone(), SigningKey::from_bytes(&sk)),
        kid,
    )
}

fn resolver(s: &LocalSigner, kid: &KeyId) -> StaticKeyResolver {
    let mut r = StaticKeyResolver::new();
    r.insert(
        kid.clone(),
        s.verifying_key(),
        &[Context::Test, Context::DecisionTicket],
    );
    r
}

fn payload() -> Value {
    Value::Map(vec![
        (Value::Text("subject".into()), Value::Text("vector".into())),
        (Value::Text("n".into()), Value::Unsigned(42)),
        (Value::Text("neg".into()), Value::Negative(9)),
        (Value::Text("id".into()), Value::Bytes((0u8..16).collect())),
        (Value::Text("flag".into()), Value::Bool(true)),
        (Value::Text("none".into()), Value::Null),
        (
            Value::Text("list".into()),
            Value::Array(vec![Value::Unsigned(1), Value::Unsigned(500)]),
        ),
    ])
}

fn envelope(version: u64, ctx: &str, kid: &str, payload: &[u8], sig: &[u8]) -> Vec<u8> {
    cbor::encode(&Value::Array(vec![
        Value::Unsigned(version),
        Value::Text(ctx.into()),
        Value::Text(kid.into()),
        Value::Bytes(payload.to_vec()),
        Value::Bytes(sig.to_vec()),
    ]))
    .unwrap()
}

fn err_name(e: &SigError) -> &'static str {
    match e {
        SigError::TooLarge { .. } => "too_large",
        SigError::Malformed => "malformed",
        SigError::UnsupportedVersion => "unsupported_version",
        SigError::UnknownContext => "unknown_context",
        SigError::WrongContext => "wrong_context",
        SigError::InvalidKeyId => "invalid_key_id",
        SigError::UnknownKey => "unknown_key",
        SigError::BadSignature => "bad_signature",
        SigError::NonCanonicalPayload => "non_canonical_payload",
        SigError::PayloadSchema(_) => "payload_schema",
        SigError::Signing(_) => "signing",
        SigError::Encoding(_) => "encoding",
    }
}

fn generate() -> (Json, Json) {
    let (s, kid) = signer();
    let p = cbor::encode(&payload()).unwrap();
    let sb = sig::signed_bytes(Context::Test, &p);
    let env =
        sig::sign_payload_bytes(Context::Test, &kid, &p, &s, DEFAULT_MAX_ENVELOPE_BYTES).unwrap();
    let raw_sig = env[env.len() - 64..].to_vec();
    let positive = json!({
        "description": "Ed25519 signing envelope, context test/v1, deterministic CBOR payload. Key: RFC 8032 TEST 1.",
        "secret_key_hex": SECRET,
        "public_key_hex": hex::encode(s.verifying_key().to_bytes()),
        "context": "test/v1",
        "key_id": kid.to_string(),
        "payload_hex": hex::encode(&p),
        "signed_bytes_hex": hex::encode(&sb),
        "signature_hex": hex::encode(&raw_sig),
        "envelope_hex": hex::encode(&env),
        "envelope_text": sig::to_text(&env),
    });

    let sk = SigningKey::from_bytes(&hex::decode(SECRET).unwrap().try_into().unwrap());
    let mut neg = Vec::new();
    let mut push = |name: &str, desc: &str, env: Vec<u8>, expected_ctx: &str, err: &str| {
        neg.push(
            json!({"name": name, "description": desc, "envelope_hex": hex::encode(env),
                        "expected_context": expected_ctx, "expected_error": err}),
        );
    };
    push(
        "wrong-context",
        "valid test/v1 envelope presented where decision-ticket/v1 is expected",
        env.clone(),
        "decision-ticket/v1",
        "wrong_context",
    );
    let mut flipped = env.clone();
    let n = flipped.len();
    flipped[n - 1] ^= 0x01;
    push(
        "bad-signature",
        "last signature bit flipped",
        flipped,
        "test/v1",
        "bad_signature",
    );
    let mut tampered = p.clone();
    let i = tampered.len() - 1;
    tampered[i] ^= 0x01;
    push(
        "tampered-payload",
        "payload modified after signing",
        envelope(1, "test/v1", &kid.to_string(), &tampered, &raw_sig),
        "test/v1",
        "bad_signature",
    );
    // Non-canonical payload (non-preferred integer encoding of 42) with a VALID signature over it.
    let nc_payload = vec![0xa1, 0x61, b'n', 0x19, 0x00, 0x2a];
    let nc_sig = sk
        .sign(&sig::signed_bytes(Context::Test, &nc_payload))
        .to_bytes();
    push(
        "non-canonical-payload",
        "validly signed payload that is not deterministic CBOR (0x19002a for 42)",
        envelope(1, "test/v1", &kid.to_string(), &nc_payload, &nc_sig),
        "test/v1",
        "non_canonical_payload",
    );
    // Unsorted map keys, validly signed.
    let unsorted = vec![0xa2, 0x61, b'b', 0x01, 0x61, b'a', 0x02];
    let us_sig = sk
        .sign(&sig::signed_bytes(Context::Test, &unsorted))
        .to_bytes();
    push(
        "unsorted-map-payload",
        "validly signed payload with unsorted map keys",
        envelope(1, "test/v1", &kid.to_string(), &unsorted, &us_sig),
        "test/v1",
        "non_canonical_payload",
    );
    // Signature made over a different context but labelled test/v1 (domain separation).
    let cross = sk
        .sign(&sig::signed_bytes(Context::DecisionTicket, &p))
        .to_bytes();
    push(
        "cross-context-signature",
        "signature computed for decision-ticket/v1 but envelope labelled test/v1",
        envelope(1, "test/v1", &kid.to_string(), &p, &cross),
        "test/v1",
        "bad_signature",
    );
    push(
        "unknown-context",
        "context not in the registry",
        envelope(1, "other/v1", &kid.to_string(), &p, &raw_sig),
        "test/v1",
        "unknown_context",
    );
    push(
        "unsupported-version",
        "envelope version 2",
        envelope(2, "test/v1", &kid.to_string(), &p, &raw_sig),
        "test/v1",
        "unsupported_version",
    );
    push(
        "unknown-key",
        "key id not known to the resolver",
        envelope(1, "test/v1", "other-key@v1", &p, &raw_sig),
        "test/v1",
        "unknown_key",
    );
    push(
        "invalid-key-id",
        "key id without version",
        envelope(1, "test/v1", "test-vector-key", &p, &raw_sig),
        "test/v1",
        "invalid_key_id",
    );
    // Indefinite-length outer array.
    let mut indef = vec![0x9f];
    indef.extend_from_slice(&env[1..]);
    indef.push(0xff);
    push(
        "non-canonical-envelope",
        "envelope array uses indefinite length",
        indef,
        "test/v1",
        "malformed",
    );
    push(
        "short-signature",
        "63-byte signature",
        envelope(1, "test/v1", &kid.to_string(), &p, &raw_sig[..63]),
        "test/v1",
        "malformed",
    );
    // Malleated signature: S + L (non-canonical scalar); rejected by strict verification.
    let mut mall = raw_sig.clone();
    let l: [u8; 32] =
        hex::decode("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
            .unwrap()
            .try_into()
            .unwrap();
    let mut carry = 0u16;
    for k in 0..32 {
        let v = u16::from(mall[32 + k]) + u16::from(l[k]) + carry;
        mall[32 + k] = v as u8;
        carry = v >> 8;
    }
    push(
        "malleated-signature",
        "S replaced by S + L (non-canonical scalar)",
        envelope(1, "test/v1", &kid.to_string(), &p, &mall),
        "test/v1",
        "bad_signature",
    );
    let mut big = env.clone();
    big.resize(DEFAULT_MAX_ENVELOPE_BYTES + 1, 0);
    push(
        "oversized",
        "16 KiB + 1 bytes; rejected before decoding",
        big,
        "test/v1",
        "too_large",
    );
    (positive, Json::Array(neg))
}

#[test]
fn vectors_match_and_negatives_fail() {
    let (positive, negative) = generate();
    let pos_path = dir().join("envelope-positive.json");
    let neg_path = dir().join("envelope-negative.json");
    if std::env::var("CS_REGENERATE_VECTORS").as_deref() == Ok("1") {
        std::fs::create_dir_all(dir()).unwrap();
        std::fs::write(
            &pos_path,
            serde_json::to_string_pretty(&positive).unwrap() + "\n",
        )
        .unwrap();
        std::fs::write(
            &neg_path,
            serde_json::to_string_pretty(&negative).unwrap() + "\n",
        )
        .unwrap();
    }
    let file_pos: Json =
        serde_json::from_str(&std::fs::read_to_string(&pos_path).unwrap()).unwrap();
    let file_neg: Json =
        serde_json::from_str(&std::fs::read_to_string(&neg_path).unwrap()).unwrap();
    assert_eq!(
        file_pos, positive,
        "positive vector drifted from implementation"
    );
    assert_eq!(
        file_neg, negative,
        "negative vectors drifted from implementation"
    );

    // Verify the positive vector from the file alone (public key + envelope).
    let (s, kid) = signer();
    let r = resolver(&s, &kid);
    let env = hex::decode(file_pos["envelope_hex"].as_str().unwrap()).unwrap();
    let v = sig::verify_bytes(&env, Context::Test, &r, DEFAULT_MAX_ENVELOPE_BYTES).unwrap();
    assert_eq!(
        hex::encode(v.payload),
        file_pos["payload_hex"].as_str().unwrap()
    );
    let from_text = sig::from_text(
        file_pos["envelope_text"].as_str().unwrap(),
        DEFAULT_MAX_ENVELOPE_BYTES,
    )
    .unwrap();
    assert_eq!(from_text, env);

    for case in file_neg.as_array().unwrap() {
        let env = hex::decode(case["envelope_hex"].as_str().unwrap()).unwrap();
        let ctx: Context = case["expected_context"].as_str().unwrap().parse().unwrap();
        let err = sig::verify_bytes(
            &env,
            ctx,
            &r as &dyn KeyResolver,
            DEFAULT_MAX_ENVELOPE_BYTES,
        )
        .expect_err(case["name"].as_str().unwrap());
        assert_eq!(
            err_name(&err),
            case["expected_error"].as_str().unwrap(),
            "{}",
            case["name"]
        );
    }
}
