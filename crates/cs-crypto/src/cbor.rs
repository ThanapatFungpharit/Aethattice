//! Deterministic CBOR (RFC 8949 §4.2.1 core deterministic encoding), contract §3.
//!
//! Rules enforced by the encoder:
//! - preferred (shortest) integer and length encoding;
//! - definite lengths only;
//! - map keys sorted bytewise by their encoded form, no duplicates;
//! - no floating-point values, no tags, no simple values other than `false`, `true`, `null`.
//!
//! The decoder in this module is written for untrusted input: it accepts any well-formed
//! CBOR in the supported subset (including non-preferred or indefinite forms), never
//! allocates based on a declared length larger than the remaining input, and bounds
//! nesting depth. [`decode_canonical`] then re-encodes the value and rejects the input
//! unless the bytes are identical, which is exactly the verifier rule of contract §3.
//!
//! Serde integration ([`to_canonical`], [`from_canonical`]) uses `ciborium::Value` purely as an
//! in-memory bridge; untrusted bytes are never handed to ciborium's parser.

use serde::Serialize;
use serde::de::DeserializeOwned;
use std::cmp::Ordering;
use thiserror::Error;

/// Maximum nesting depth accepted by the decoder.
pub const MAX_DEPTH: usize = 64;

/// A CBOR data item in the platform's deterministic subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Major type 0.
    Unsigned(u64),
    /// Major type 1: the represented integer is `-1 - n`.
    Negative(u64),
    /// Major type 2.
    Bytes(Vec<u8>),
    /// Major type 3.
    Text(String),
    /// Major type 4.
    Array(Vec<Value>),
    /// Major type 5, in insertion order; the encoder sorts.
    Map(Vec<(Value, Value)>),
    /// Simple values 20/21.
    Bool(bool),
    /// Simple value 22.
    Null,
}

/// CBOR encoding / decoding failures.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CborError {
    #[error("input exceeds the size limit of {limit} bytes")]
    TooLarge { limit: usize },
    #[error("truncated CBOR input")]
    Truncated,
    #[error("trailing bytes after the CBOR item")]
    TrailingBytes,
    #[error("unsupported CBOR item: {0}")]
    Unsupported(&'static str),
    #[error("malformed CBOR: {0}")]
    Malformed(&'static str),
    #[error("nesting deeper than {MAX_DEPTH}")]
    TooDeep,
    #[error("duplicate map key")]
    DuplicateKey,
    #[error("input is not in deterministic (canonical) encoding")]
    NotCanonical,
    #[error("serde mapping failed: {0}")]
    Serde(String),
}

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

fn write_head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if n <= u64::from(u8::MAX) {
        out.push(m | 24);
        out.push(n as u8);
    } else if n <= u64::from(u16::MAX) {
        out.push(m | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= u64::from(u32::MAX) {
        out.push(m | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

fn encode_into(v: &Value, out: &mut Vec<u8>) -> Result<(), CborError> {
    match v {
        Value::Unsigned(n) => write_head(out, 0, *n),
        Value::Negative(n) => write_head(out, 1, *n),
        Value::Bytes(b) => {
            write_head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(s) => {
            write_head(out, 3, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(items) => {
            write_head(out, 4, items.len() as u64);
            for i in items {
                encode_into(i, out)?;
            }
        }
        Value::Map(entries) => {
            let mut encoded: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(entries.len());
            for (k, val) in entries {
                let mut kb = Vec::new();
                encode_into(k, &mut kb)?;
                let mut vb = Vec::new();
                encode_into(val, &mut vb)?;
                encoded.push((kb, vb));
            }
            encoded.sort_by(|a, b| bytewise(&a.0, &b.0));
            for w in encoded.windows(2) {
                if w[0].0 == w[1].0 {
                    return Err(CborError::DuplicateKey);
                }
            }
            write_head(out, 5, encoded.len() as u64);
            for (k, val) in encoded {
                out.extend_from_slice(&k);
                out.extend_from_slice(&val);
            }
        }
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Null => out.push(0xf6),
    }
    Ok(())
}

fn bytewise(a: &[u8], b: &[u8]) -> Ordering {
    // RFC 8949 §4.2.1: bytewise lexicographic order of the deterministic encodings.
    a.cmp(b)
}

/// Encode `v` in deterministic CBOR.
pub fn encode(v: &Value) -> Result<Vec<u8>, CborError> {
    let mut out = Vec::new();
    encode_into(v, &mut out)?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Decoder (accepts non-canonical forms so that the re-encode check can reject them)
// ---------------------------------------------------------------------------

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

enum Len {
    Definite(u64),
    Indefinite,
}

impl<'a> Reader<'a> {
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn byte(&mut self) -> Result<u8, CborError> {
        let b = *self.buf.get(self.pos).ok_or(CborError::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: u64) -> Result<&'a [u8], CborError> {
        let n = usize::try_from(n).map_err(|_| CborError::Truncated)?;
        if n > self.remaining() {
            return Err(CborError::Truncated);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn arg(&mut self, info: u8) -> Result<Len, CborError> {
        Ok(match info {
            0..=23 => Len::Definite(u64::from(info)),
            24 => Len::Definite(u64::from(self.byte()?)),
            25 => {
                let b = self.take(2)?;
                Len::Definite(u64::from(u16::from_be_bytes([b[0], b[1]])))
            }
            26 => {
                let b = self.take(4)?;
                Len::Definite(u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]])))
            }
            27 => {
                let b = self.take(8)?;
                let mut a = [0u8; 8];
                a.copy_from_slice(b);
                Len::Definite(u64::from_be_bytes(a))
            }
            31 => Len::Indefinite,
            _ => return Err(CborError::Malformed("reserved additional information")),
        })
    }

    fn definite(&mut self, info: u8) -> Result<u64, CborError> {
        match self.arg(info)? {
            Len::Definite(n) => Ok(n),
            Len::Indefinite => Err(CborError::Malformed("indefinite length on integer")),
        }
    }

    fn is_break(&mut self) -> Result<bool, CborError> {
        if *self.buf.get(self.pos).ok_or(CborError::Truncated)? == 0xff {
            self.pos += 1;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn string_chunks(&mut self, major: u8, info: u8) -> Result<Vec<u8>, CborError> {
        match self.arg(info)? {
            Len::Definite(n) => Ok(self.take(n)?.to_vec()),
            Len::Indefinite => {
                let mut acc = Vec::new();
                loop {
                    if self.is_break()? {
                        return Ok(acc);
                    }
                    let ib = self.byte()?;
                    if ib >> 5 != major {
                        return Err(CborError::Malformed("bad chunk in indefinite string"));
                    }
                    let n = match self.arg(ib & 0x1f)? {
                        Len::Definite(n) => n,
                        Len::Indefinite => {
                            return Err(CborError::Malformed("nested indefinite string"));
                        }
                    };
                    acc.extend_from_slice(self.take(n)?);
                }
            }
        }
    }

    fn item(&mut self, depth: usize) -> Result<Value, CborError> {
        if depth > MAX_DEPTH {
            return Err(CborError::TooDeep);
        }
        let ib = self.byte()?;
        let major = ib >> 5;
        let info = ib & 0x1f;
        match major {
            0 => Ok(Value::Unsigned(self.definite(info)?)),
            1 => Ok(Value::Negative(self.definite(info)?)),
            2 => Ok(Value::Bytes(self.string_chunks(2, info)?)),
            3 => {
                let raw = self.string_chunks(3, info)?;
                String::from_utf8(raw)
                    .map(Value::Text)
                    .map_err(|_| CborError::Malformed("invalid UTF-8 in text string"))
            }
            4 => match self.arg(info)? {
                Len::Definite(n) => {
                    // Every item needs at least one byte: never pre-allocate beyond the input.
                    if n > self.remaining() as u64 {
                        return Err(CborError::Truncated);
                    }
                    let mut v = Vec::with_capacity(n as usize);
                    for _ in 0..n {
                        v.push(self.item(depth + 1)?);
                    }
                    Ok(Value::Array(v))
                }
                Len::Indefinite => {
                    let mut v = Vec::new();
                    while !self.is_break()? {
                        v.push(self.item(depth + 1)?);
                    }
                    Ok(Value::Array(v))
                }
            },
            5 => match self.arg(info)? {
                Len::Definite(n) => {
                    if n.saturating_mul(2) > self.remaining() as u64 {
                        return Err(CborError::Truncated);
                    }
                    let mut v = Vec::with_capacity(n as usize);
                    for _ in 0..n {
                        let k = self.item(depth + 1)?;
                        let val = self.item(depth + 1)?;
                        v.push((k, val));
                    }
                    Ok(Value::Map(v))
                }
                Len::Indefinite => {
                    let mut v = Vec::new();
                    while !self.is_break()? {
                        let k = self.item(depth + 1)?;
                        let val = self.item(depth + 1)?;
                        v.push((k, val));
                    }
                    Ok(Value::Map(v))
                }
            },
            6 => Err(CborError::Unsupported("tags are not permitted")),
            7 => match info {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                23 => Err(CborError::Unsupported("undefined")),
                25..=27 => Err(CborError::Unsupported(
                    "floating-point values are not permitted",
                )),
                31 => Err(CborError::Malformed("unexpected break")),
                _ => Err(CborError::Unsupported("simple value")),
            },
            _ => Err(CborError::Malformed("invalid major type")),
        }
    }
}

/// Decode one CBOR item from `bytes` (which must contain exactly one item), accepting
/// non-canonical forms. Use [`decode_canonical`] for verification paths.
pub fn decode_lenient(bytes: &[u8], limit: usize) -> Result<Value, CborError> {
    if bytes.len() > limit {
        return Err(CborError::TooLarge { limit });
    }
    let mut r = Reader { buf: bytes, pos: 0 };
    let v = r.item(0)?;
    if r.remaining() != 0 {
        return Err(CborError::TrailingBytes);
    }
    Ok(v)
}

/// Decode `bytes` and require that they are the deterministic encoding of the decoded
/// value (decode, re-encode, compare). The size limit is checked before decoding.
pub fn decode_canonical(bytes: &[u8], limit: usize) -> Result<Value, CborError> {
    let v = decode_lenient(bytes, limit)?;
    let re = encode(&v)?;
    if re != bytes {
        return Err(CborError::NotCanonical);
    }
    Ok(v)
}

// ---------------------------------------------------------------------------
// Serde bridge
// ---------------------------------------------------------------------------

fn from_ciborium(v: ciborium::Value) -> Result<Value, CborError> {
    use ciborium::Value as C;
    Ok(match v {
        C::Integer(i) => {
            let i = i128::from(i);
            if i >= 0 {
                Value::Unsigned(
                    u64::try_from(i).map_err(|_| CborError::Unsupported("integer range"))?,
                )
            } else {
                Value::Negative(
                    u64::try_from(-1 - i).map_err(|_| CborError::Unsupported("integer range"))?,
                )
            }
        }
        C::Bytes(b) => Value::Bytes(b),
        C::Text(s) => Value::Text(s),
        C::Bool(b) => Value::Bool(b),
        C::Null => Value::Null,
        C::Array(a) => Value::Array(a.into_iter().map(from_ciborium).collect::<Result<_, _>>()?),
        C::Map(m) => Value::Map(
            m.into_iter()
                .map(|(k, v)| Ok((from_ciborium(k)?, from_ciborium(v)?)))
                .collect::<Result<_, CborError>>()?,
        ),
        C::Float(_) => {
            return Err(CborError::Unsupported(
                "floating-point values are not permitted",
            ));
        }
        C::Tag(_, _) => return Err(CborError::Unsupported("tags are not permitted")),
        _ => return Err(CborError::Unsupported("unknown value kind")),
    })
}

fn to_ciborium(v: Value) -> ciborium::Value {
    use ciborium::Value as C;
    match v {
        Value::Unsigned(n) => C::Integer(n.into()),
        Value::Negative(n) => {
            // -1 - n always fits in i128 and in ciborium::Integer's range.
            let i: i128 = -1 - i128::from(n);
            match ciborium::value::Integer::try_from(i) {
                Ok(i) => C::Integer(i),
                Err(_) => C::Null,
            }
        }
        Value::Bytes(b) => C::Bytes(b),
        Value::Text(s) => C::Text(s),
        Value::Bool(b) => C::Bool(b),
        Value::Null => C::Null,
        Value::Array(a) => C::Array(a.into_iter().map(to_ciborium).collect()),
        Value::Map(m) => C::Map(
            m.into_iter()
                .map(|(k, v)| (to_ciborium(k), to_ciborium(v)))
                .collect(),
        ),
    }
}

/// Convert a serializable value into the CBOR value model.
pub fn to_value<T: Serialize + ?Sized>(t: &T) -> Result<Value, CborError> {
    let c = ciborium::Value::serialized(t).map_err(|e| CborError::Serde(e.to_string()))?;
    from_ciborium(c)
}

/// Convert a CBOR value into a deserializable type.
pub fn from_value<T: DeserializeOwned>(v: Value) -> Result<T, CborError> {
    to_ciborium(v)
        .deserialized()
        .map_err(|e| CborError::Serde(e.to_string()))
}

/// Serialize `t` into deterministic CBOR bytes.
pub fn to_canonical<T: Serialize + ?Sized>(t: &T) -> Result<Vec<u8>, CborError> {
    encode(&to_value(t)?)
}

/// Decode deterministic CBOR bytes (rejecting non-canonical input) into `T`.
pub fn from_canonical<T: DeserializeOwned>(bytes: &[u8], limit: usize) -> Result<T, CborError> {
    from_value(decode_canonical(bytes, limit)?)
}

/// Serde helper: serialize `Vec<u8>` as a CBOR byte string instead of an array of integers.
/// Use with `#[serde(with = "cs_crypto::cbor::bstr")]`.
pub mod bstr {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a byte string")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
                Ok(v.to_vec())
            }
            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
                Ok(v)
            }
        }
        d.deserialize_bytes(V)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn preferred_integer_encoding() {
        let cases: &[(u64, &str)] = &[
            (0, "00"),
            (23, "17"),
            (24, "1818"),
            (255, "18ff"),
            (256, "190100"),
            (65535, "19ffff"),
            (65536, "1a00010000"),
            (u64::from(u32::MAX), "1affffffff"),
            (u64::from(u32::MAX) + 1, "1b0000000100000000"),
        ];
        for (n, h) in cases {
            assert_eq!(hex(&encode(&Value::Unsigned(*n)).unwrap()), *h);
        }
        assert_eq!(hex(&encode(&Value::Negative(0)).unwrap()), "20");
        assert_eq!(hex(&encode(&Value::Negative(99)).unwrap()), "3863");
    }

    #[test]
    fn map_keys_sorted_bytewise() {
        // RFC 8949 §4.2.1 example ordering: 10, 100, -1, "z", "aa", [100], [-1], false
        let v = Value::Map(vec![
            (Value::Bool(false), Value::Null),
            (Value::Text("aa".into()), Value::Null),
            (Value::Array(vec![Value::Negative(0)]), Value::Null),
            (Value::Unsigned(100), Value::Null),
            (Value::Text("z".into()), Value::Null),
            (Value::Negative(0), Value::Null),
            (Value::Array(vec![Value::Unsigned(100)]), Value::Null),
            (Value::Unsigned(10), Value::Null),
        ]);
        let enc = encode(&v).unwrap();
        assert_eq!(
            hex(&enc),
            "a80af61864f620f6617af6626161f6811864f68120f6f4f6"
        );
        decode_canonical(&enc, 1024).unwrap();
    }

    #[test]
    fn duplicate_keys_rejected() {
        let v = Value::Map(vec![
            (Value::Text("a".into()), Value::Null),
            (Value::Text("a".into()), Value::Bool(true)),
        ]);
        assert_eq!(encode(&v), Err(CborError::DuplicateKey));
        // a1-like map with duplicate keys on the wire
        let wire = [0xa2, 0x61, b'a', 0xf6, 0x61, b'a', 0xf5];
        assert_eq!(decode_canonical(&wire, 64), Err(CborError::DuplicateKey));
    }

    #[test]
    fn non_canonical_inputs_rejected() {
        let cases: &[&[u8]] = &[
            &[0x18, 0x05],                               // non-preferred integer
            &[0x19, 0x00, 0x10],                         // non-preferred integer
            &[0x5f, 0x41, 0x01, 0xff],                   // indefinite byte string
            &[0x9f, 0x01, 0xff],                         // indefinite array
            &[0xbf, 0x61, b'a', 0x01, 0xff],             // indefinite map
            &[0xa2, 0x61, b'b', 0x01, 0x61, b'a', 0x02], // unsorted keys
            &[0x59, 0x00, 0x01, 0x00],                   // non-preferred length
        ];
        for c in cases {
            assert_eq!(
                decode_canonical(c, 64),
                Err(CborError::NotCanonical),
                "{c:02x?}"
            );
        }
    }

    #[test]
    fn unsupported_items_rejected() {
        assert!(matches!(
            decode_canonical(&[0xf9, 0x3c, 0x00], 64),
            Err(CborError::Unsupported(_))
        )); // f16
        assert!(matches!(
            decode_canonical(&[0xfb, 0, 0, 0, 0, 0, 0, 0, 0], 64),
            Err(CborError::Unsupported(_))
        ));
        assert!(matches!(
            decode_canonical(&[0xc1, 0x00], 64),
            Err(CborError::Unsupported(_))
        )); // tag
        assert!(matches!(
            decode_canonical(&[0xf7], 64),
            Err(CborError::Unsupported(_))
        )); // undefined
        assert!(matches!(
            decode_canonical(&[0xe0], 64),
            Err(CborError::Unsupported(_))
        )); // simple(0)
        assert!(matches!(
            decode_canonical(&[0x62, 0xff, 0xfe], 64),
            Err(CborError::Malformed(_))
        )); // bad utf8
        assert_eq!(
            decode_canonical(&[0x01, 0x02], 64),
            Err(CborError::TrailingBytes)
        );
        assert_eq!(
            decode_canonical(&[0x82, 0x01], 64),
            Err(CborError::Truncated)
        );
    }

    #[test]
    fn huge_declared_lengths_do_not_allocate() {
        // array claiming 2^63 elements, byte string claiming 2^63 bytes
        let arr = [0x9b, 0x80, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(decode_canonical(&arr, 64), Err(CborError::Truncated));
        let bs = [0x5b, 0x80, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(decode_canonical(&bs, 64), Err(CborError::Truncated));
        let map = [0xbb, 0x80, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(decode_canonical(&map, 64), Err(CborError::Truncated));
    }

    #[test]
    fn depth_limit() {
        let mut deep = vec![0x81u8; MAX_DEPTH + 2];
        deep.push(0x00);
        assert_eq!(decode_canonical(&deep, 1024), Err(CborError::TooDeep));
    }

    #[test]
    fn size_limit_checked_first() {
        let big = vec![0u8; 100];
        assert_eq!(
            decode_canonical(&big, 10),
            Err(CborError::TooLarge { limit: 10 })
        );
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Sample {
        zeta: u32,
        alpha: String,
        #[serde(with = "bstr")]
        blob: Vec<u8>,
        neg: i64,
        opt: Option<bool>,
    }

    #[test]
    fn serde_roundtrip_is_canonical() {
        let s = Sample {
            zeta: 300,
            alpha: "x".into(),
            blob: vec![1, 2, 3],
            neg: -500,
            opt: None,
        };
        let b = to_canonical(&s).unwrap();
        // keys sorted: "neg"(63) < "opt"(63) < "blob"(64) < "zeta"(64) < "alpha"(65)
        let Value::Map(m) = decode_canonical(&b, 1024).unwrap() else {
            panic!()
        };
        let keys: Vec<_> = m
            .iter()
            .map(|(k, _)| match k {
                Value::Text(t) => t.clone(),
                _ => panic!(),
            })
            .collect();
        assert_eq!(keys, ["neg", "opt", "blob", "zeta", "alpha"]);
        let back: Sample = from_canonical(&b, 1024).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn floats_rejected_on_encode() {
        #[derive(Serialize)]
        struct F {
            f: f64,
        }
        assert!(matches!(
            to_canonical(&F { f: 1.5 }),
            Err(CborError::Unsupported(_))
        ));
    }
}
