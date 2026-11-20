//! Resource URNs `cs:{tenant}:{type}:{id}` (contract §1, spec §4.1).

use crate::id::{IdError, ResourceId, SpaceId, TenantId, parse_strict};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;
use uuid::Uuid;

/// Maximum length of a resource type name (design).
pub const MAX_TYPE_LEN: usize = 128;

/// The core type of spaces.
pub const SPACE_TYPE: &str = "core.space";

/// URN / resource-type parsing failures.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum UrnError {
    #[error("URN must have the form cs:{{tenant}}:{{type}}:{{id}}")]
    Syntax,
    #[error("invalid resource type")]
    Type,
    #[error("invalid identifier in URN: {0}")]
    Id(#[from] IdError),
}

/// A registered resource type name, e.g. `drive.folder`, matching
/// `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ResourceType(String);

impl ResourceType {
    pub fn parse(s: &str) -> Result<Self, UrnError> {
        if s.is_empty() || s.len() > MAX_TYPE_LEN {
            return Err(UrnError::Type);
        }
        let mut segments = 0;
        for seg in s.split('.') {
            let b = seg.as_bytes();
            let ok = !b.is_empty()
                && b[0].is_ascii_lowercase()
                && b.iter()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_');
            if !ok {
                return Err(UrnError::Type);
            }
            segments += 1;
        }
        if segments < 2 {
            return Err(UrnError::Type);
        }
        Ok(Self(s.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_space(&self) -> bool {
        self.0 == SPACE_TYPE
    }
}

impl fmt::Display for ResourceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A resource URN. The `id` segment is a UUIDv7: a [`ResourceId`] for resource types or a
/// [`SpaceId`] for `core.space`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Urn {
    tenant: TenantId,
    resource_type: ResourceType,
    id: Uuid,
}

impl Urn {
    /// URN of a resource. Refuses `core.space`; use [`Urn::space`].
    pub fn resource(
        tenant: TenantId,
        resource_type: ResourceType,
        id: ResourceId,
    ) -> Result<Self, UrnError> {
        if resource_type.is_space() {
            return Err(UrnError::Type);
        }
        Ok(Self {
            tenant,
            resource_type,
            id: id.into_uuid(),
        })
    }

    /// URN of a space (`cs:{tenant}:core.space:{space}`).
    pub fn space(tenant: TenantId, space: SpaceId) -> Self {
        Self {
            tenant,
            resource_type: ResourceType(SPACE_TYPE.to_owned()),
            id: space.into_uuid(),
        }
    }

    /// Strict parse: no whitespace, lowercase only, exactly four segments.
    pub fn parse(s: &str) -> Result<Self, UrnError> {
        let mut parts = s.split(':');
        let (Some("cs"), Some(t), Some(ty), Some(id), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return Err(UrnError::Syntax);
        };
        let tenant: TenantId = t.parse()?;
        let resource_type = ResourceType::parse(ty)?;
        let id = parse_strict(id, Some(7))?;
        Ok(Self {
            tenant,
            resource_type,
            id,
        })
    }

    pub fn tenant(&self) -> TenantId {
        self.tenant
    }

    pub fn resource_type(&self) -> &ResourceType {
        &self.resource_type
    }

    /// The resource ID, unless this is a space URN.
    pub fn resource_id(&self) -> Option<ResourceId> {
        if self.resource_type.is_space() {
            None
        } else {
            ResourceId::from_uuid(self.id).ok()
        }
    }

    /// The space ID, if this is a space URN.
    pub fn space_id(&self) -> Option<SpaceId> {
        if self.resource_type.is_space() {
            SpaceId::from_uuid(self.id).ok()
        } else {
            None
        }
    }
}

impl fmt::Display for Urn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cs:{}:{}:{}",
            self.tenant,
            self.resource_type,
            self.id.hyphenated()
        )
    }
}

impl FromStr for Urn {
    type Err = UrnError;
    fn from_str(s: &str) -> Result<Self, UrnError> {
        Urn::parse(s)
    }
}

impl Serialize for Urn {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Urn {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Urn::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let t = TenantId::generate().unwrap();
        let r = ResourceId::generate().unwrap();
        let u = Urn::resource(t, ResourceType::parse("drive.folder").unwrap(), r).unwrap();
        let s = u.to_string();
        assert_eq!(s, format!("cs:{t}:drive.folder:{r}"));
        let p = Urn::parse(&s).unwrap();
        assert_eq!(p, u);
        assert_eq!(p.resource_id(), Some(r));
        assert_eq!(p.space_id(), None);
    }

    #[test]
    fn space_urn() {
        let t = TenantId::generate().unwrap();
        let sp = SpaceId::generate().unwrap();
        let u = Urn::space(t, sp);
        assert_eq!(u.to_string(), format!("cs:{t}:core.space:{sp}"));
        assert_eq!(Urn::parse(&u.to_string()).unwrap().space_id(), Some(sp));
        assert!(
            Urn::resource(
                t,
                ResourceType::parse("core.space").unwrap(),
                ResourceId::generate().unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn strict_rejections() {
        let t = TenantId::generate().unwrap();
        let r = ResourceId::generate().unwrap();
        let good = format!("cs:{t}:drive.folder:{r}");
        assert!(Urn::parse(&good).is_ok());
        let bad = [
            format!(" {good}"),
            format!("{good} "),
            format!("{good}\n"),
            good.to_uppercase(),
            format!("CS:{t}:drive.folder:{r}"),
            format!("cs:{t}:Drive.folder:{r}"),
            format!("cs:{t}:drive:{r}"),
            format!("cs:{t}:drive.:{r}"),
            format!("cs:{t}:.drive:{r}"),
            format!("cs:{t}:drive..folder:{r}"),
            format!("cs:{t}:drive.1folder:{r}"),
            format!("cs:{t}:drive-x.folder:{r}"),
            format!("cs:{t}:drive.folder:{r}:extra"),
            format!("cs:{t}:drive.folder"),
            format!("xs:{t}:drive.folder:{r}"),
            // fixed v7 tenant with hex letters, upper-cased
            format!("cs:01890A5D-AC96-774B-BCCE-B302099A8057:drive.folder:{r}"),
            // a fixed UUIDv4 (not v7); a random 128-bit ChunkId would be a valid v7 1 time in 64
            format!("cs:{t}:drive.folder:1b4e28ba-2fa1-41d2-883f-0016d3cca427"),
            format!("cs:{t}:{}:{r}", "a.".repeat(70) + "b"),
        ];
        for b in bad {
            assert!(Urn::parse(&b).is_err(), "{b:?}");
        }
    }

    #[test]
    fn resource_type_rules() {
        for ok in ["drive.folder", "core.space", "a.b", "a_1.b_2.c3"] {
            assert!(ResourceType::parse(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "drive",
            "Drive.folder",
            "_a.b",
            "a.b.",
            "a b.c",
            "a.b-c",
        ] {
            assert!(ResourceType::parse(bad).is_err(), "{bad}");
        }
    }
}
