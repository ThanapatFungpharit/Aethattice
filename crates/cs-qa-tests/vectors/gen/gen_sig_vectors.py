#!/usr/bin/env python3
"""Independent test-vector generator for the M0 signing envelope (contract §3, erratum C8).

Written by QA from the frozen contract and RFC texts only, without reading the
engineers' implementation. It uses only the Python standard library:

* Ed25519 is implemented here from RFC 8032 §5.1 / §6 (reference algorithm),
  and self-checked against RFC 8032 §7.1 test vectors 1-3 before any vector is
  produced. If `openssl` (>= 3.0) is on PATH, every valid signature is also
  cross-checked with OpenSSL's independent Ed25519 implementation.
* CBOR is encoded here from RFC 8949 §3 and §4.2.1 (core deterministic
  encoding). Deliberately non-canonical encodings for negative vectors are
  built by hand with explicit byte layouts.

Envelope under test (contract §3):
    signed_bytes = b"cs-sig/v1" 0x00 context 0x00 payload
    signature    = Ed25519(key, signed_bytes)
    wire         = CBOR array [1, context(tstr), key_id(tstr), payload(bstr), signature(bstr)]
    text form    = base64url without padding
    max envelope = 16 KiB (16384 bytes) unless the artifact contract says otherwise

Interpretations of points the contract leaves open are tagged "oq8" (see
docs/traceability.md, Open question OQ-8).

Usage:  python3 -I gen_sig_vectors.py <output.json>
The output is deterministic: re-running produces byte-identical JSON.
"""

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

# ---------------------------------------------------------------------------
# Ed25519 (RFC 8032 §5.1, transcribed from the RFC's reference algorithm)
# ---------------------------------------------------------------------------

P = 2**255 - 19
Q = 2**252 + 27742317777372353535851937790883648493  # group order L


def _inv(x):
    return pow(x, P - 2, P)


D = -121665 * _inv(121666) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _sha512(b):
    return hashlib.sha512(b).digest()


def _sha512_modq(b):
    return int.from_bytes(_sha512(b), "little") % Q


def _pt_add(a, b):
    A = (a[1] - a[0]) * (b[1] - b[0]) % P
    B = (a[1] + a[0]) * (b[1] + b[0]) % P
    C = 2 * a[3] * b[3] * D % P
    Dd = 2 * a[2] * b[2] % P
    E, F, G, H = B - A, Dd - C, Dd + C, B + A
    return (E * F % P, G * H % P, F * G % P, E * H % P)


def _pt_mul(s, pt):
    acc = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            acc = _pt_add(acc, pt)
        pt = _pt_add(pt, pt)
        s >>= 1
    return acc


def _pt_eq(a, b):
    return (a[0] * b[2] - b[0] * a[2]) % P == 0 and (a[1] * b[2] - b[1] * a[2]) % P == 0


def _recover_x(y, sign):
    if y >= P:
        return None
    x2 = (y * y - 1) * _inv(D * y * y + 1) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


_GY = 4 * _inv(5) % P
_GX = _recover_x(_GY, 0)
G = (_GX, _GY, 1, _GX * _GY % P)


def _compress(pt):
    zi = _inv(pt[2])
    x, y = pt[0] * zi % P, pt[1] * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decompress(b):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def _expand(seed):
    h = _sha512(seed)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def ed25519_public(seed):
    a, _ = _expand(seed)
    return _compress(_pt_mul(a, G))


def ed25519_sign(seed, msg):
    a, prefix = _expand(seed)
    pub = _compress(_pt_mul(a, G))
    r = _sha512_modq(prefix + msg)
    R = _compress(_pt_mul(r, G))
    k = _sha512_modq(R + pub + msg)
    s = (r + k * a) % Q
    return R + s.to_bytes(32, "little")


def ed25519_verify(pub, msg, sig):
    """Strict RFC 8032 §5.1.7 verification (rejects s >= L)."""
    if len(pub) != 32 or len(sig) != 64:
        return False
    A = _decompress(pub)
    R = _decompress(sig[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= Q:
        return False
    k = _sha512_modq(sig[:32] + pub + msg)
    return _pt_eq(_pt_mul(s, G), _pt_add(R, _pt_mul(k, A)))


RFC8032_VECTORS = [
    # (secret, public, message, signature) -- RFC 8032 §7.1 TEST 1, 2, 3
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
]


def self_test():
    for sk, pk, msg, sig in RFC8032_VECTORS:
        sk, pk, msg, sig = map(bytes.fromhex, (sk, pk, msg, sig))
        assert ed25519_public(sk) == pk, "RFC 8032 public key mismatch"
        assert ed25519_sign(sk, msg) == sig, "RFC 8032 signature mismatch"
        assert ed25519_verify(pk, msg, sig), "RFC 8032 verify failed"
        bad = bytearray(sig)
        bad[0] ^= 1
        assert not ed25519_verify(pk, msg, bytes(bad))


# ---------------------------------------------------------------------------
# Optional second implementation: OpenSSL
# ---------------------------------------------------------------------------

_ED25519_PKCS8_PREFIX = bytes.fromhex("302e020100300506032b657004220420")


def openssl_sign(seed, msg):
    """Return OpenSSL's Ed25519 signature, or None when openssl is unavailable."""
    exe = shutil.which("openssl")
    if exe is None:
        return None
    with tempfile.TemporaryDirectory() as td:
        key = os.path.join(td, "k.der")
        data = os.path.join(td, "m.bin")
        out = os.path.join(td, "s.bin")
        with open(key, "wb") as f:
            f.write(_ED25519_PKCS8_PREFIX + seed)
        with open(data, "wb") as f:
            f.write(msg)
        r = subprocess.run(
            [exe, "pkeyutl", "-sign", "-inkey", key, "-keyform", "DER", "-rawin", "-in", data, "-out", out],
            capture_output=True,
        )
        if r.returncode != 0:
            return None
        with open(out, "rb") as f:
            return f.read()


# ---------------------------------------------------------------------------
# CBOR (RFC 8949): deterministic encoder + explicit non-canonical helpers
# ---------------------------------------------------------------------------


def _head(major, n):
    """Preferred (shortest) head encoding, RFC 8949 §4.2.1."""
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 0x100:
        return bytes([(major << 5) | 24, n])
    if n < 0x10000:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    if n < 0x100000000:
        return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")
    if n < 0x10000000000000000:
        return bytes([(major << 5) | 27]) + n.to_bytes(8, "big")
    raise ValueError("integer out of CBOR range")


def head_wide(major, n, ai):
    """Deliberately non-shortest head: force additional-info 24..27."""
    width = {24: 1, 25: 2, 26: 4, 27: 8}[ai]
    return bytes([(major << 5) | ai]) + n.to_bytes(width, "big")


class Tag:
    def __init__(self, tag, value):
        self.tag, self.value = tag, value


def enc(v):
    if v is None:
        return b"\xf6"
    if v is True:
        return b"\xf5"
    if v is False:
        return b"\xf4"
    if isinstance(v, int):
        return _head(0, v) if v >= 0 else _head(1, -1 - v)
    if isinstance(v, bytes):
        return _head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(v, list):
        return _head(4, len(v)) + b"".join(enc(x) for x in v)
    if isinstance(v, dict):
        items = sorted(((enc(k), enc(x)) for k, x in v.items()), key=lambda kv: kv[0])
        keys = [k for k, _ in items]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate map key")
        return _head(5, len(items)) + b"".join(k + x for k, x in items)
    if isinstance(v, Tag):
        return _head(6, v.tag) + enc(v.value)
    raise TypeError(type(v))


def raw_map(pairs):
    """Map with entries in the given order (may be unsorted / duplicated)."""
    return _head(5, len(pairs)) + b"".join(k + x for k, x in pairs)


def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------------
# Envelope
# ---------------------------------------------------------------------------

PREFIX = b"cs-sig/v1"
MAX_ENVELOPE = 16384
CONTEXTS = [
    "consistency-context/v1",
    "snapshot-handle/v1",
    "decision-ticket/v1",
    "revocation-record/v1",
    "watermark-heartbeat/v1",
    "storage-receipt/v1",
    "data-plane-token/v1",
    "state-attestation/v1",
    "test/v1",
]


def signed_bytes(context, payload):
    return PREFIX + b"\x00" + context.encode("ascii") + b"\x00" + payload


def envelope(context, key_id, payload, sig, version=1):
    return enc([version, context, key_id, payload, sig])


# Fixed, published test seeds (never use outside tests).
KEYS = {
    "qa-a/1": bytes.fromhex("a1" * 32),
    "qa-a/2": bytes.fromhex("a2" * 32),
    "qa-b/1": bytes.fromhex("b1" * 32),
}


def sign_with(key_id, context, payload, msg=None):
    m = signed_bytes(context, payload) if msg is None else msg
    sig = ed25519_sign(KEYS[key_id], m)
    assert ed25519_verify(ed25519_public(KEYS[key_id]), m, sig)
    return sig


OPENSSL_CHECKED = [0]


def valid_vector(name, context, key_id, payload_value=None, payload=None, note=""):
    if payload is None:
        payload = enc(payload_value)
    msg = signed_bytes(context, payload)
    sig = sign_with(key_id, context, payload)
    other = openssl_sign(KEYS[key_id], msg)
    if other is not None:
        assert other == sig, "OpenSSL disagrees with RFC 8032 implementation: " + name
        OPENSSL_CHECKED[0] += 1
    env = envelope(context, key_id, payload, sig)
    assert len(env) <= MAX_ENVELOPE
    return {
        "name": name,
        "context": context,
        "key_id": key_id,
        "payload_hex": payload.hex(),
        "signed_bytes_hex": msg.hex(),
        "signature_hex": sig.hex(),
        "envelope_hex": env.hex(),
        "envelope_b64url": b64url(env),
        "note": note,
    }


def invalid_vector(name, expected_context, env, reason, tags=()):
    return {
        "name": name,
        "expected_context": expected_context,
        "envelope_hex": env.hex(),
        "reason": reason,
        "tags": list(tags),
    }


def main(out_path):
    self_test()

    T = "test/v1"
    A = "qa-a/1"
    base_payload = {"n": 1, "s": "x"}

    valid = []
    valid.append(valid_vector("empty_map_test_context", T, A, {}))
    for ctx in CONTEXTS:
        valid.append(valid_vector("context_" + ctx.replace("/", "_").replace("-", "_"), ctx, A,
                                  {"ctx": ctx, "seq": 7}))
    valid.append(valid_vector("integer_boundaries", T, A, {
        "u": [0, 23, 24, 255, 256, 65535, 65536, 4294967295, 4294967296, 18446744073709551615],
        "i": [-1, -24, -25, -256, -257, -65536, -65537, -4294967296, -4294967297, -18446744073709551616],
    }, note="every preferred-encoding width boundary for major types 0 and 1"))
    valid.append(valid_vector("nested_mixed_types", T, A, {
        "bytes": bytes(range(40)),
        "text": "héllo 世界",
        "arr": [[], [1, [2, [3]]], {"k": None}],
        "flags": [True, False, None],
        "empty_b": b"",
        "empty_t": "",
    }))
    valid.append(valid_vector("map_key_ordering", T, A, {
        "b": 1, "aa": 2, 10: 3, 1: 4, -1: 5, "": 6, b"\x00": 7,
    }, note="RFC 8949 4.2.1: keys sorted bytewise by their encoding: ints before tstr, shorter tstr before longer"))
    valid.append(valid_vector("rotated_key_version_2", T, "qa-a/2", base_payload,
                              note="second version of key qa-a; both versions must resolve"))
    valid.append(valid_vector("second_issuer_key", T, "qa-b/1", base_payload))

    # Largest envelope that fits exactly in MAX_ENVELOPE bytes.
    def env_len_for(n):
        payload = enc({"pad": b"\x00" * n})
        return len(envelope(T, A, payload, b"\x00" * 64)), payload

    n = 16000
    while env_len_for(n + 1)[0] <= MAX_ENVELOPE:
        n += 1
    while env_len_for(n)[0] > MAX_ENVELOPE:
        n -= 1
    size, max_payload = env_len_for(n)
    v = valid_vector("max_size_envelope", T, A, payload=max_payload,
                     note="envelope length %d bytes (limit %d)" % (size, MAX_ENVELOPE))
    valid.append(v)
    # The smallest envelope that is over the limit (by construction, padding length n+1 or more).
    m = n + 1
    while env_len_for(m)[0] <= MAX_ENVELOPE:
        m += 1
    over_size, over_payload = env_len_for(m)

    invalid = []
    good_payload = enc(base_payload)
    good_sig = sign_with(A, T, good_payload)
    good_env = envelope(T, A, good_payload, good_sig)

    def signed_env(payload, ctx=T, key_id=A, signer=None):
        sig = sign_with(signer or key_id, ctx, payload)
        return envelope(ctx, key_id, payload, sig)

    # --- context / domain separation
    dt = "decision-ticket/v1"
    invalid.append(invalid_vector("wrong_expected_context", "consistency-context/v1",
                                  signed_env(good_payload, ctx=dt),
                                  "correctly signed decision ticket presented where a consistency context is expected"))
    sig_dt = sign_with(A, dt, good_payload)
    invalid.append(invalid_vector("declared_context_differs_from_signed_context", T,
                                  envelope(T, A, good_payload, sig_dt),
                                  "envelope declares test/v1 but signature covers decision-ticket/v1"))
    invalid.append(invalid_vector("unknown_context", "test/v1",
                                  signed_env(good_payload, ctx="unknown-artifact/v1"),
                                  "context outside the closed registry, correctly signed"))
    invalid.append(invalid_vector("context_version_suffix", "test/v1",
                                  signed_env(good_payload, ctx="test/v2"),
                                  "registry contains test/v1 only"))
    invalid.append(invalid_vector("context_case_variant", "test/v1",
                                  signed_env(good_payload, ctx="TEST/v1"),
                                  "contexts are exact ASCII strings"))
    msg_nosep = PREFIX + T.encode() + good_payload
    invalid.append(invalid_vector("signature_without_separators", T,
                                  envelope(T, A, good_payload, ed25519_sign(KEYS[A], msg_nosep)),
                                  "signature over prefix||context||payload without the 0x00 separators"))
    invalid.append(invalid_vector("signature_over_raw_payload", T,
                                  envelope(T, A, good_payload, ed25519_sign(KEYS[A], good_payload)),
                                  "signature over the payload alone, without domain separation"))
    invalid.append(invalid_vector("signature_with_wrong_prefix", T,
                                  envelope(T, A, good_payload,
                                           ed25519_sign(KEYS[A], b"cs-sig/v2\x00" + T.encode() + b"\x00" + good_payload)),
                                  "prefix cs-sig/v2"))

    # --- non-canonical payloads (signature is VALID over the non-canonical bytes)
    k_n, k_s = enc("n"), enc("s")
    noncanon = {
        "payload_unsorted_map_keys": raw_map([(k_s, enc("x")), (k_n, enc(1))]),
        "payload_duplicate_map_key": raw_map([(k_n, enc(1)), (k_n, enc(1))]),
        "payload_non_shortest_int_1byte": raw_map([(k_n, head_wide(0, 1, 24)), (k_s, enc("x"))]),
        "payload_non_shortest_int_8byte": raw_map([(k_n, head_wide(0, 1, 27)), (k_s, enc("x"))]),
        "payload_non_shortest_negative_int": raw_map([(k_n, head_wide(1, 0, 25)), (k_s, enc("x"))]),
        "payload_non_shortest_text_length": raw_map([(k_n, enc(1)), (k_s, head_wide(3, 1, 24) + b"x")]),
        "payload_non_shortest_map_length": head_wide(5, 2, 24) + k_n + enc(1) + k_s + enc("x"),
        "payload_indefinite_map": b"\xbf" + k_n + enc(1) + k_s + enc("x") + b"\xff",
        "payload_indefinite_array": raw_map([(k_n, b"\x9f\x01\x02\xff"), (k_s, enc("x"))]),
        "payload_indefinite_bytes": raw_map([(k_n, b"\x5f\x41\x00\x41\x01\xff"), (k_s, enc("x"))]),
        "payload_indefinite_text": raw_map([(k_n, enc(1)), (k_s, b"\x7f\x61x\xff")]),
        "payload_float": raw_map([(k_n, b"\xf9\x3c\x00"), (k_s, enc("x"))]),
        "payload_float64": raw_map([(k_n, b"\xfb" + bytes.fromhex("3ff0000000000000")), (k_s, enc("x"))]),
        "payload_tag": raw_map([(k_n, enc(Tag(1, 1))), (k_s, enc("x"))]),
        "payload_undefined_simple": raw_map([(k_n, b"\xf7"), (k_s, enc("x"))]),
        "payload_trailing_bytes": good_payload + b"\x00",
        "payload_truncated_item": good_payload[:-1],
        "payload_empty": b"",
        "payload_invalid_utf8_text": raw_map([(k_n, enc(1)), (k_s, b"\x62\xc3\x28")]),
    }
    for name, p in noncanon.items():
        invalid.append(invalid_vector(name, T, signed_env(p),
                                      "payload is not RFC 8949 4.2.1 deterministic CBOR (signature valid over these bytes)"))

    # --- envelope structure
    invalid.append(invalid_vector("empty_input", T, b"", "zero bytes"))
    for cut in (1, len(good_env) // 2, len(good_env) - 1):
        invalid.append(invalid_vector("envelope_truncated_%d_of_%d" % (cut, len(good_env)), T,
                                      good_env[:cut], "truncated envelope"))
    invalid.append(invalid_vector("signature_63_bytes", T, envelope(T, A, good_payload, good_sig[:63]),
                                  "Ed25519 signature must be exactly 64 bytes"))
    invalid.append(invalid_vector("signature_65_bytes", T, envelope(T, A, good_payload, good_sig + b"\x00"),
                                  "Ed25519 signature must be exactly 64 bytes"))
    invalid.append(invalid_vector("signature_empty", T, envelope(T, A, good_payload, b""), "missing signature"))
    invalid.append(invalid_vector("version_2", T, envelope(T, A, good_payload, good_sig, version=2),
                                  "envelope version must be 1"))
    invalid.append(invalid_vector("version_0", T, envelope(T, A, good_payload, good_sig, version=0),
                                  "envelope version must be 1"))
    invalid.append(invalid_vector("array_4_elements", T, enc([1, T, A, good_payload]), "missing signature element"))
    invalid.append(invalid_vector("array_6_elements", T, enc([1, T, A, good_payload, good_sig, 0]),
                                  "extra element"))
    invalid.append(invalid_vector("envelope_is_map", T,
                                  enc({"v": 1, "context": T, "key_id": A, "payload": good_payload, "sig": good_sig}),
                                  "envelope must be an array"))
    invalid.append(invalid_vector("payload_as_text", T,
                                  enc([1, T, A, good_payload.decode("latin-1"), good_sig]),
                                  "payload must be a byte string"))
    invalid.append(invalid_vector("context_as_bytes", T, enc([1, T.encode(), A, good_payload, good_sig]),
                                  "context must be a text string"))
    invalid.append(invalid_vector("key_id_as_bytes", T, enc([1, T, A.encode(), good_payload, good_sig]),
                                  "key_id must be a text string", tags=["oq8"]))
    invalid.append(invalid_vector("envelope_trailing_bytes", T, good_env + b"\x00",
                                  "bytes after the envelope array", tags=["oq8"]))
    invalid.append(invalid_vector("envelope_non_shortest_version", T,
                                  bytes([0x85]) + head_wide(0, 1, 24) + good_env[2:],
                                  "envelope version encoded as 0x18 0x01", tags=["oq8"]))
    invalid.append(invalid_vector("envelope_indefinite_array", T,
                                  b"\x9f" + good_env[1:] + b"\xff",
                                  "envelope array with indefinite length", tags=["oq8"]))
    invalid.append(invalid_vector("envelope_non_shortest_payload_length", T,
                                  bytes([0x85]) + enc(1) + enc(T) + enc(A)
                                  + head_wide(2, len(good_payload), 25) + good_payload + enc(good_sig),
                                  "payload byte-string length not in preferred form", tags=["oq8"]))

    # --- keys
    invalid.append(invalid_vector("unknown_key_id", T, signed_env(good_payload, key_id="qa-unknown/1", signer=A),
                                  "key_id not known to the resolver"))
    invalid.append(invalid_vector("wrong_key_for_key_id", T, signed_env(good_payload, key_id=A, signer="qa-b/1"),
                                  "signed by qa-b/1 but names qa-a/1"))
    invalid.append(invalid_vector("old_key_version_names_new", T, signed_env(good_payload, key_id="qa-a/2", signer=A),
                                  "signed by qa-a/1 but names qa-a/2"))

    # --- signature tampering
    for byte_i, bit in ((0, 0), (31, 7), (32, 0), (63, 3)):
        s = bytearray(good_sig)
        s[byte_i] ^= 1 << bit
        invalid.append(invalid_vector("bitflip_signature_byte%d_bit%d" % (byte_i, bit), T,
                                      envelope(T, A, good_payload, bytes(s)), "single bit flipped in signature"))
    invalid.append(invalid_vector("signature_all_zero", T, envelope(T, A, good_payload, b"\x00" * 64),
                                  "all-zero signature"))
    s_int = int.from_bytes(good_sig[32:], "little")
    malleable = good_sig[:32] + (s_int + Q).to_bytes(32, "little")
    invalid.append(invalid_vector("signature_s_not_reduced", T, envelope(T, A, good_payload, malleable),
                                  "S >= L (RFC 8032 5.1.7 requires rejection; malleability)"))
    flipped_payload = bytearray(good_payload)
    flipped_payload[-1] ^= 0x01  # "x" -> "y": still canonical
    invalid.append(invalid_vector("payload_modified_after_signing", T,
                                  envelope(T, A, bytes(flipped_payload), good_sig),
                                  "canonical payload changed after signing"))

    # --- size
    over_sig = sign_with(A, T, over_payload)
    over_env = envelope(T, A, over_payload, over_sig)
    assert len(over_env) == over_size and over_size > MAX_ENVELOPE
    invalid.append(invalid_vector("oversized_by_%d_bytes" % (over_size - MAX_ENVELOPE), T, over_env,
                                  "validly signed envelope of %d bytes exceeds the 16 KiB limit" % over_size))
    huge = signed_env(enc({"pad": b"\x00" * (1 << 16)}))
    invalid.append(invalid_vector("oversized_64kib", T, huge, "validly signed 64 KiB envelope"))

    for v in invalid:
        assert v["name"] not in {x["name"] for x in valid}
    names = [v["name"] for v in valid + invalid]
    assert len(names) == len(set(names)), "duplicate vector names"

    doc = {
        "description": "Independent QA vectors for the cs-sig/v1 signing envelope (M0 contract §3, erratum C8).",
        "generator": "crates/cs-qa-tests/vectors/gen/gen_sig_vectors.py (Python stdlib only; RFC 8032 Ed25519 "
                     "self-tested against RFC 8032 7.1 TEST 1-3)",
        "openssl_cross_checked_signatures": OPENSSL_CHECKED[0],
        "max_envelope_bytes": MAX_ENVELOPE,
        "contexts": CONTEXTS,
        "keys": [{"key_id": k, "seed_hex": s.hex(), "public_hex": ed25519_public(s).hex()} for k, s in KEYS.items()],
        "valid": valid,
        "invalid": invalid,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1, sort_keys=True)
        f.write("\n")
    print("wrote %s: %d valid, %d invalid, %d signatures cross-checked with OpenSSL"
          % (out_path, len(valid), len(invalid), OPENSSL_CHECKED[0]))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: gen_sig_vectors.py <output.json>")
    main(sys.argv[1])
