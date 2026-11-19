//! Typed identifiers (contract §1, spec §4.1, App. E).
//!
//! Every ID is a UUIDv7 (RFC 9562) except [`ChunkId`] and [`ExtentId`], which are 128-bit
//! random values: 16 CSPRNG bytes with no version or variant bits (spec §17.1, contract rev 2).
//! They use the same hyphenated hex text form and YSQL `uuid` storage but are not RFC 9562 UUIDs. All randomness comes from
//! `cs_crypto::rand`; generation fails if the CSPRNG fails.
//!
//! Text form is lowercase hyphenated and parsing is strict (no braces, no URN prefix, no
//! uppercase, no surrounding whitespace, correct version and RFC 9562 variant). In
//! non-human-readable serde formats (CBOR) IDs are 16 big-endian bytes.

use cs_crypto::rand::{self, RandError};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::{Uuid, Variant};

/// Identifier parsing failures.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IdError {
    #[error("identifier is not a lowercase hyphenated UUID")]
    Syntax,
    #[error("identifier has UUID version {found}, expected {expected}")]
    WrongVersion { expected: usize, found: usize },
    #[error("identifier does not use the RFC 9562 variant")]
    WrongVariant,
    #[error("identifier must be 16 bytes")]
    Length,
    #[error(transparent)]
    Rand(#[from] RandError),
}

/// Generate a UUIDv7 from the system clock and the OS CSPRNG.
pub fn new_v7() -> Result<Uuid, RandError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    // 48-bit field; clamp rather than wrap (year 10889).
    let millis = u64::try_from(millis)
        .unwrap_or(u64::MAX)
        .min((1u64 << 48) - 1);
    let rnd = rand::bytes::<10>()?;
    Ok(uuid::Builder::from_unix_timestamp_millis(millis, &rnd).into_uuid())
}

/// Generate a full 128-bit random identifier (no version/variant bits) from the OS CSPRNG.
pub fn new_random128() -> Result<Uuid, RandError> {
    Ok(Uuid::from_bytes(rand::bytes::<16>()?))
}

/// Strictly parse lowercase hyphenated hex. `version`: `Some(v)` requires an RFC 9562 UUID of
/// version `v`; `None` accepts any 128-bit value.
pub fn parse_strict(s: &str, version: Option<usize>) -> Result<Uuid, IdError> {
    let b = s.as_bytes();
    if b.len() != 36 {
        return Err(IdError::Syntax);
    }
    for (i, c) in b.iter().enumerate() {
        let ok = match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(c),
        };
        if !ok {
            return Err(IdError::Syntax);
        }
    }
    let u = Uuid::parse_str(s).map_err(|_| IdError::Syntax)?;
    check(u, version)
}

fn check(u: Uuid, version: Option<usize>) -> Result<Uuid, IdError> {
    let Some(version) = version else {
        return Ok(u);
    };
    if u.get_variant() != Variant::RFC4122 {
        return Err(IdError::WrongVariant);
    }
    if u.get_version_num() != version {
        return Err(IdError::WrongVersion {
            expected: version,
            found: u.get_version_num(),
        });
    }
    Ok(u)
}

macro_rules! typed_id {
    ($(#[$m:meta])* $name:ident, $version:expr, $gen:path) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(Uuid);

        impl $name {
            /// UUID version required for this identifier type (`None`: 128 random bits).
            pub const VERSION: Option<usize> = $version;

            /// Generate a new identifier. Fails if the CSPRNG fails.
            pub fn generate() -> Result<Self, RandError> {
                Ok(Self($gen()?))
            }

            /// Wrap a UUID after checking its version and variant.
            pub fn from_uuid(u: Uuid) -> Result<Self, IdError> {
                Ok(Self(check(u, $version)?))
            }

            /// Build from 16 big-endian bytes (binary formats).
            pub fn from_bytes(b: [u8; 16]) -> Result<Self, IdError> {
                Self::from_uuid(Uuid::from_bytes(b))
            }

            /// Build from a byte slice that must be exactly 16 bytes long.
            pub fn from_slice(b: &[u8]) -> Result<Self, IdError> {
                let a: [u8; 16] = b.try_into().map_err(|_| IdError::Length)?;
                Self::from_bytes(a)
            }

            pub fn as_uuid(&self) -> &Uuid {
                &self.0
            }

            pub fn into_uuid(self) -> Uuid {
                self.0
            }

            pub fn as_bytes(&self) -> &[u8; 16] {
                self.0.as_bytes()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0.hyphenated(), f)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.0.hyphenated())
            }
        }

        impl FromStr for $name {
            type Err = IdError;
            fn from_str(s: &str) -> Result<Self, IdError> {
                Ok(Self(parse_strict(s, $version)?))
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                if s.is_human_readable() {
                    s.collect_str(&self.0.hyphenated())
                } else {
                    s.serialize_bytes(self.0.as_bytes())
                }
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                struct V;
                impl serde::de::Visitor<'_> for V {
                    type Value = $name;
                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str(concat!("a ", stringify!($name)))
                    }
                    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<$name, E> {
                        v.parse().map_err(E::custom)
                    }
                    fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<$name, E> {
                        $name::from_slice(v).map_err(E::custom)
                    }
                }
                if d.is_human_readable() {
                    d.deserialize_str(V)
                } else {
                    d.deserialize_bytes(V)
                }
            }
        }
    };
}

typed_id!(/// Tenant identifier (UUIDv7).
    TenantId, Some(7), new_v7);
typed_id!(/// Principal identifier (UUIDv7): users, groups, guests, service and application identities.
    PrincipalId, Some(7), new_v7);
typed_id!(/// User identifier (UUIDv7).
    UserId, Some(7), new_v7);
typed_id!(/// Group identifier (UUIDv7).
    GroupId, Some(7), new_v7);
typed_id!(/// Resource identifier (UUIDv7, spec §4.1).
    ResourceId, Some(7), new_v7);
typed_id!(/// Space identifier (UUIDv7).
    SpaceId, Some(7), new_v7);
typed_id!(/// Object version identifier (UUIDv7).
    VersionId, Some(7), new_v7);
typed_id!(/// Session identifier (UUIDv7): login sessions and upload sessions.
    SessionId, Some(7), new_v7);
typed_id!(/// Chunk identifier: 128 random bits, server-assigned (spec §17.1). NOT a UUIDv7.
    ChunkId, None, new_random128);
typed_id!(/// Seal identifier (UUIDv7).
    SealId, Some(7), new_v7);
typed_id!(/// Extent identifier: 128 random bits per write attempt, never reused (spec §17.1). NOT a UUIDv7.
    ExtentId, None, new_random128);
typed_id!(/// Cluster node identifier (UUIDv7).
    NodeId, Some(7), new_v7);
typed_id!(/// Saga / operation identifier (UUIDv7).
    OperationId, Some(7), new_v7);
typed_id!(/// Event identifier (UUIDv7).
    EventId, Some(7), new_v7);
typed_id!(/// Request identifier (UUIDv7), carried in `X-Request-Id` and problem bodies.
    RequestId, Some(7), new_v7);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v7_generation_and_roundtrip() {
        let a = TenantId::generate().unwrap();
        let b = TenantId::generate().unwrap();
        assert_ne!(a, b);
        assert_eq!(a.as_uuid().get_version_num(), 7);
        let s = a.to_string();
        assert_eq!(s, s.to_lowercase());
        assert_eq!(s.parse::<TenantId>().unwrap(), a);
        // time-ordered at millisecond granularity
        let ts = |u: &Uuid| u.as_bytes()[..6].to_vec();
        assert!(ts(a.as_uuid()) <= ts(b.as_uuid()));
    }

    #[test]
    fn chunk_and_extent_ids_use_all_128_bits() {
        // Over many samples every bit position (including the UUID version/variant bits)
        // takes both values: there are no fixed layout bits (contract §1 rev 2).
        let mut ones = [0u32; 128];
        for _ in 0..512 {
            let c = ChunkId::generate().unwrap();
            for (i, b) in c.as_bytes().iter().enumerate() {
                for bit in 0..8 {
                    ones[i * 8 + bit] += u32::from((b >> bit) & 1);
                }
            }
        }
        assert!(ones.iter().all(|n| *n > 0 && *n < 512), "{ones:?}");
        let e = ExtentId::generate().unwrap();
        assert_eq!(e.to_string().parse::<ExtentId>().unwrap(), e);
        // Any 16 bytes are a valid ChunkId; an arbitrary value is not a UUIDv7 ID.
        assert!(
            ResourceId::generate()
                .unwrap()
                .to_string()
                .parse::<ChunkId>()
                .is_ok()
        );
        let zero = ChunkId::from_bytes([0u8; 16]).unwrap().to_string();
        assert!(zero.parse::<ResourceId>().is_err());
        // text form is still strict
        let up = ChunkId::generate().unwrap().to_string().to_uppercase();
        assert!(up.parse::<ChunkId>().is_err());
    }

    #[test]
    fn strict_parsing() {
        let good = ResourceId::generate().unwrap().to_string();
        assert!(good.parse::<ResourceId>().is_ok());
        let bad = [
            good.to_uppercase(),
            format!(" {good}"),
            format!("{good} "),
            format!("{{{good}}}"),
            format!("urn:uuid:{good}"),
            good.replace('-', ""),
            "00000000-0000-0000-0000-000000000000".to_owned(),
            String::new(),
        ];
        for b in bad {
            assert!(b.parse::<ResourceId>().is_err(), "{b:?}");
        }
        // wrong variant (Microsoft, 0xc0)
        let mut bytes = *ResourceId::generate().unwrap().as_bytes();
        bytes[8] = 0xc0 | (bytes[8] & 0x1f);
        assert_eq!(ResourceId::from_bytes(bytes), Err(IdError::WrongVariant));
    }

    #[test]
    fn csprng_failure_fails_generation() {
        let _g = cs_crypto::rand::inject_failure();
        assert!(TenantId::generate().is_err());
        assert!(ChunkId::generate().is_err());
    }

    #[test]
    fn serde_forms() {
        let id = EventId::generate().unwrap();
        let j = serde_json::to_string(&id).unwrap();
        assert_eq!(j, format!("\"{id}\""));
        assert_eq!(serde_json::from_str::<EventId>(&j).unwrap(), id);
        let c = cs_crypto::cbor::to_canonical(&id).unwrap();
        assert_eq!(c.len(), 17); // 0x50 + 16 bytes
        assert_eq!(c[0], 0x50);
        assert_eq!(&c[1..], id.as_bytes());
        assert_eq!(
            cs_crypto::cbor::from_canonical::<EventId>(&c, 64).unwrap(),
            id
        );
    }
}
