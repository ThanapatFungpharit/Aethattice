//! Signing envelope (§6.4, erratum C8, contract §3) against independently generated vectors
//! (vectors/gen/gen_sig_vectors.py: stdlib RFC 8032 Ed25519 + RFC 8949 CBOR, cross-checked
//! with OpenSSL). Traceability: 6.4-12..6.4-14, L.2-3, L.6-14, CT.M0-6..CT.M0-10.
#![cfg(any(feature = "m0-contract", feature = "qa-selfcheck"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use base64::Engine;
use support::contract as c;
use support::spec;
use support::vectors::{self, SigningVectors};

fn keys(v: &SigningVectors) -> Vec<(String, [u8; 32])> {
    v.keys
        .iter()
        .map(|k| (k.key_id.clone(), k.public))
        .collect()
}

#[test]
fn vectors_are_self_consistent() {
    // Guards against a corrupted vector file (does not touch the implementation).
    let v = vectors::signing();
    assert_eq!(v.max_envelope_bytes, spec::MAX_ENVELOPE_BYTES);
    assert_eq!(v.contexts, spec::SIG_CONTEXTS);
    assert!(v.valid.len() >= 10 && v.invalid.len() >= 40);
    for x in &v.valid {
        let mut expect = b"cs-sig/v1\0".to_vec();
        expect.extend_from_slice(x.context.as_bytes());
        expect.push(0);
        expect.extend_from_slice(&x.payload);
        assert_eq!(x.signed_bytes, expect, "{}: signed_bytes layout", x.name);
        assert_eq!(x.signature.len(), 64);
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&x.envelope);
        assert_eq!(b64, x.envelope_b64url, "{}: base64url form", x.name);
    }
}

#[test]
fn valid_vectors_verify() {
    let v = vectors::signing();
    let k = keys(&v);
    let mut bad = Vec::new();
    for x in &v.valid {
        match c::sig_verify(&x.envelope, &x.context, &k) {
            Ok(payload) if payload == x.payload => {}
            Ok(payload) => bad.push(format!(
                "{}: verified but returned different payload ({} bytes)",
                x.name,
                payload.len()
            )),
            Err(e) => bad.push(format!("{}: rejected: {e}", x.name)),
        }
    }
    assert!(bad.is_empty(), "valid vectors failed:\n{}", bad.join("\n"));
}

#[test]
fn valid_vectors_verify_in_text_form() {
    let v = vectors::signing();
    let k = keys(&v);
    for x in &v.valid {
        let p = c::sig_verify_text(&x.envelope_b64url, &x.context, &k)
            .unwrap_or_else(|e| panic!("{}: {e}", x.name));
        assert_eq!(p, x.payload, "{}", x.name);
    }
}

#[test]
fn base64url_text_form_unpadded() {
    let v = vectors::signing();
    for x in &v.valid {
        let t = c::sig_encode_text(&x.envelope);
        assert_eq!(t, x.envelope_b64url, "{}", x.name);
        assert!(
            !t.contains('=') && !t.contains('+') && !t.contains('/'),
            "{}: not base64url without padding",
            x.name
        );
    }
    // Padded or standard-alphabet text is not the contract form.
    let x = v
        .valid
        .iter()
        .find(|x| x.envelope_b64url.len() % 4 != 0)
        .expect("a vector needing padding");
    let k = keys(&v);
    let padded = format!(
        "{}{}",
        x.envelope_b64url,
        "=".repeat(4 - x.envelope_b64url.len() % 4)
    );
    assert!(
        c::sig_verify_text(&padded, &x.context, &k).is_err(),
        "padded base64 accepted"
    );
    let std_alpha = base64::engine::general_purpose::STANDARD_NO_PAD.encode(&x.envelope);
    if std_alpha != x.envelope_b64url {
        assert!(
            c::sig_verify_text(&std_alpha, &x.context, &k).is_err(),
            "standard base64 alphabet accepted"
        );
    }
}

#[test]
fn signer_produces_identical_bytes() {
    // Ed25519 is deterministic: the implementation's signer must reproduce the independent
    // implementation's envelope byte-for-byte (payload already canonical).
    let v = vectors::signing();
    let mut bad = Vec::new();
    for x in &v.valid {
        let seed = v.keys.iter().find(|k| k.key_id == x.key_id).unwrap().seed;
        match c::sig_sign_with_seed(&seed, &x.key_id, &x.context, &x.payload) {
            Ok(env) if env == x.envelope => {}
            Ok(env) => bad.push(format!(
                "{}: envelope differs\n  expected {}\n  actual   {}",
                x.name,
                hex::encode(&x.envelope),
                hex::encode(env)
            )),
            Err(e) => bad.push(format!("{}: sign failed: {e}", x.name)),
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn negative_vectors_rejected() {
    let v = vectors::signing();
    let k = keys(&v);
    let mut accepted = Vec::new();
    for x in v
        .invalid
        .iter()
        .filter(|x| !x.tags.iter().any(|t| t == "oq8"))
    {
        if c::sig_verify(&x.envelope, &x.expected_context, &k).is_ok() {
            accepted.push(format!("{} ({})", x.name, x.reason));
        }
    }
    assert!(
        accepted.is_empty(),
        "invalid envelopes ACCEPTED:\n{}",
        accepted.join("\n")
    );
}

#[test]
fn negative_vectors_rejected_oq8_interpretation() {
    // QA's interpretation of points the contract leaves open (OQ-8). Kept separate so a failure
    // is attributable to the interpretation, not to the core rules.
    let v = vectors::signing();
    let k = keys(&v);
    let mut accepted = Vec::new();
    for x in v
        .invalid
        .iter()
        .filter(|x| x.tags.iter().any(|t| t == "oq8"))
    {
        if c::sig_verify(&x.envelope, &x.expected_context, &k).is_ok() {
            accepted.push(format!("{} ({})", x.name, x.reason));
        }
    }
    assert!(
        accepted.is_empty(),
        "OQ-8 interpretation: envelopes accepted:\n{}",
        accepted.join("\n")
    );
}

#[test]
fn non_canonical_payload_rejected_even_with_valid_signature() {
    let v = vectors::signing();
    let k = keys(&v);
    let cases: Vec<_> = v
        .invalid
        .iter()
        .filter(|x| x.name.starts_with("payload_") && x.name != "payload_modified_after_signing")
        .collect();
    assert!(
        cases.len() >= 15,
        "expected the non-canonical payload family in the vectors"
    );
    for x in cases {
        assert!(
            c::sig_verify(&x.envelope, &x.expected_context, &k).is_err(),
            "{}: {}",
            x.name,
            x.reason
        );
    }
}

#[test]
fn cross_context_signature_never_verifies() {
    // Every valid vector re-checked against every OTHER registry context must fail.
    let v = vectors::signing();
    let k = keys(&v);
    for x in &v.valid {
        for ctx in spec::SIG_CONTEXTS.iter().filter(|c| **c != x.context) {
            assert!(
                c::sig_verify(&x.envelope, ctx, &k).is_err(),
                "{} (signed as {}) verified as {ctx}",
                x.name,
                x.context
            );
        }
    }
}

#[test]
fn context_registry_is_closed() {
    let mut got = c::sig_contexts();
    got.sort();
    let mut want: Vec<String> = spec::SIG_CONTEXTS.iter().map(|s| s.to_string()).collect();
    want.sort();
    assert_eq!(
        got, want,
        "context registry differs from contract §3 (adding one is a contract change)"
    );
    for unknown in [
        "",
        "test",
        "test/v2",
        "TEST/v1",
        "test/v1 ",
        "test/v1\0",
        "unknown-artifact/v1",
        "consistency-context/v1/x",
    ] {
        assert!(
            !c::sig_context_known(unknown),
            "context {unknown:?} accepted"
        );
    }
}

#[test]
fn oversized_envelope_rejected_before_decode() {
    let v = vectors::signing();
    let k = keys(&v);
    let max = v
        .valid
        .iter()
        .find(|x| x.name == "max_size_envelope")
        .unwrap();
    assert_eq!(max.envelope.len(), spec::MAX_ENVELOPE_BYTES);
    assert!(
        c::sig_verify(&max.envelope, &max.context, &k).is_ok(),
        "envelope of exactly 16 KiB must be accepted"
    );
    for x in v.invalid.iter().filter(|x| x.name.starts_with("oversized")) {
        assert!(x.envelope.len() > spec::MAX_ENVELOPE_BYTES);
        assert!(
            c::sig_verify(&x.envelope, &x.expected_context, &k).is_err(),
            "{} accepted",
            x.name
        );
    }
    // Garbage larger than the limit: must be refused by size, without attempting to decode
    // (a decoder would choke on 0xff anyway; the point is it must not allocate per its header).
    let mut hostile = vec![0x9b_u8]; // array with 8-byte length
    hostile.extend_from_slice(&u64::MAX.to_be_bytes());
    hostile.resize(spec::MAX_ENVELOPE_BYTES + 1, 0xff);
    let t = std::time::Instant::now();
    assert!(c::sig_verify(&hostile, "test/v1", &k).is_err());
    // Hostile length prefix within the size limit must not cause a huge allocation or hang.
    let mut short = vec![0x9b_u8];
    short.extend_from_slice(&u64::MAX.to_be_bytes());
    assert!(c::sig_verify(&short, "test/v1", &k).is_err());
    let mut bstr = vec![0x85, 0x01, 0x67];
    bstr.extend_from_slice(b"test/v1");
    bstr.push(0x5b);
    bstr.extend_from_slice(&(u64::MAX / 2).to_be_bytes());
    assert!(c::sig_verify(&bstr, "test/v1", &k).is_err());
    assert!(
        t.elapsed() < std::time::Duration::from_secs(2),
        "hostile inputs took {:?}",
        t.elapsed()
    );
}

#[test]
fn rotated_keys_both_resolve() {
    let v = vectors::signing();
    let k = keys(&v);
    let a1 = v.valid.iter().find(|x| x.key_id == "qa-a/1").unwrap();
    let a2 = v.valid.iter().find(|x| x.key_id == "qa-a/2").unwrap();
    assert!(c::sig_verify(&a1.envelope, &a1.context, &k).is_ok());
    assert!(c::sig_verify(&a2.envelope, &a2.context, &k).is_ok());
    // With only the new version available, an artifact naming the old one fails (no fallback
    // to "some key of the same issuer").
    let only_new: Vec<_> = k.iter().filter(|(id, _)| id != "qa-a/1").cloned().collect();
    assert!(
        c::sig_verify(&a1.envelope, &a1.context, &only_new).is_err(),
        "resolver fell back to another key version"
    );
    // Empty resolver: nothing verifies.
    assert!(c::sig_verify(&a2.envelope, &a2.context, &[]).is_err());
}
