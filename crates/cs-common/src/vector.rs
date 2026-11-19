//! Consistency vectors (contract §4; App. C C10; spec §6.4, §18.4).
//!
//! A vector is a sorted, deduplicated list of `(cluster_id, domain_id, partition, position)`
//! with at most [`MAX_COMPONENTS`] entries. Exceeding the bound is an error, never a
//! truncation. Comparison is per component; there is no global or wall-clock order.

use crate::app_id::ApplicationId;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;
use thiserror::Error;
use uuid::Uuid;

/// Hard maximum number of components in a vector.
pub const MAX_COMPONENTS: usize = 64;

/// Logical metadata domains (§18.1) plus per-application databases.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DomainId {
    Identity,
    Resources,
    Authz,
    Objects,
    Cluster,
    Operations,
    Collab,
    Events,
    Accounting,
    Plugins,
    Audit,
    /// `app_<application_id>`.
    App(ApplicationId),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("unknown domain id")]
pub struct DomainIdError;

impl DomainId {
    /// The eleven core domains.
    pub const CORE: [DomainId; 11] = [
        DomainId::Identity,
        DomainId::Resources,
        DomainId::Authz,
        DomainId::Objects,
        DomainId::Cluster,
        DomainId::Operations,
        DomainId::Collab,
        DomainId::Events,
        DomainId::Accounting,
        DomainId::Plugins,
        DomainId::Audit,
    ];

    /// Wire name: the §18.1 domain name, or `app_<application_id>`.
    pub fn as_str(&self) -> std::borrow::Cow<'_, str> {
        use std::borrow::Cow::Borrowed;
        match self {
            DomainId::Identity => Borrowed("identity"),
            DomainId::Resources => Borrowed("resources"),
            DomainId::Authz => Borrowed("authz"),
            DomainId::Objects => Borrowed("objects"),
            DomainId::Cluster => Borrowed("cluster"),
            DomainId::Operations => Borrowed("operations"),
            DomainId::Collab => Borrowed("collab"),
            DomainId::Events => Borrowed("events"),
            DomainId::Accounting => Borrowed("accounting"),
            DomainId::Plugins => Borrowed("plugins"),
            DomainId::Audit => Borrowed("audit"),
            DomainId::App(a) => std::borrow::Cow::Owned(format!("app_{a}")),
        }
    }

    /// Default logical database name (`cs_<domain>`), contract §5. Application databases are
    /// not provisioned in M0.
    pub fn default_database_name(&self) -> String {
        format!("cs_{}", self.as_str().replace(['.', '-'], "_"))
    }
}

impl fmt::Display for DomainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_str())
    }
}

impl FromStr for DomainId {
    type Err = DomainIdError;
    fn from_str(s: &str) -> Result<Self, DomainIdError> {
        if let Some(app) = s.strip_prefix("app_") {
            return ApplicationId::parse(app)
                .map(DomainId::App)
                .map_err(|_| DomainIdError);
        }
        DomainId::CORE
            .into_iter()
            .find(|d| d.as_str() == s)
            .ok_or(DomainIdError)
    }
}

impl PartialOrd for DomainId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DomainId {
    /// Bytewise order of the wire name (stable across nodes and versions).
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_str().as_bytes().cmp(other.as_str().as_bytes())
    }
}

impl Serialize for DomainId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.as_str())
    }
}

impl<'de> Deserialize<'de> for DomainId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// One authoritative position.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VectorComponent {
    pub cluster_id: Uuid,
    pub domain_id: DomainId,
    pub partition: u32,
    pub position: u64,
}

impl VectorComponent {
    fn key(&self) -> (&[u8; 16], &DomainId, u32) {
        (self.cluster_id.as_bytes(), &self.domain_id, self.partition)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum VectorError {
    #[error("consistency vector exceeds {MAX_COMPONENTS} components")]
    TooManyComponents,
    #[error("consistency vector is not sorted and deduplicated")]
    NotNormalized,
}

/// A bounded, sorted, deduplicated set of positions, at most one per
/// `(cluster_id, domain_id, partition)` key.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
#[serde(transparent)]
pub struct ConsistencyVector {
    components: Vec<VectorComponent>,
}

impl ConsistencyVector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from arbitrary components: sorts by key and merges duplicate keys by taking the
    /// maximum position (positions on one key are totally ordered). Errors if more than
    /// [`MAX_COMPONENTS`] distinct keys remain.
    pub fn from_components(
        components: impl IntoIterator<Item = VectorComponent>,
    ) -> Result<Self, VectorError> {
        let mut v: Vec<VectorComponent> = components.into_iter().collect();
        v.sort_by(|a, b| a.key().cmp(&b.key()).then(b.position.cmp(&a.position)));
        v.dedup_by(|later, earlier| earlier.key() == later.key());
        if v.len() > MAX_COMPONENTS {
            return Err(VectorError::TooManyComponents);
        }
        Ok(Self { components: v })
    }

    pub fn components(&self) -> &[VectorComponent] {
        &self.components
    }

    pub fn len(&self) -> usize {
        self.components.len()
    }

    pub fn is_empty(&self) -> bool {
        self.components.is_empty()
    }

    /// Position recorded for a key, if any.
    pub fn position(&self, cluster_id: &Uuid, domain: &DomainId, partition: u32) -> Option<u64> {
        let key = (cluster_id.as_bytes(), domain, partition);
        self.components
            .binary_search_by(|c| c.key().cmp(&key))
            .ok()
            .map(|i| self.components[i].position)
    }

    /// Advance (or insert) one component. Errors on overflow, leaving `self` unchanged.
    pub fn advance(&mut self, c: VectorComponent) -> Result<(), VectorError> {
        match self.components.binary_search_by(|x| x.key().cmp(&c.key())) {
            Ok(i) => {
                if c.position > self.components[i].position {
                    self.components[i].position = c.position;
                }
                Ok(())
            }
            Err(i) => {
                if self.components.len() >= MAX_COMPONENTS {
                    return Err(VectorError::TooManyComponents);
                }
                self.components.insert(i, c);
                Ok(())
            }
        }
    }

    /// Per-component maximum (join). Errors on overflow.
    pub fn merge(&self, other: &ConsistencyVector) -> Result<ConsistencyVector, VectorError> {
        Self::from_components(
            self.components
                .iter()
                .chain(other.components.iter())
                .cloned(),
        )
    }

    /// `true` iff for every component of `other`, `self` has the same key with a position
    /// at least as large. (An empty `other` is dominated by everything.)
    pub fn dominates(&self, other: &ConsistencyVector) -> bool {
        other.components.iter().all(|c| {
            self.position(&c.cluster_id, &c.domain_id, c.partition)
                .is_some_and(|p| p >= c.position)
        })
    }
}

impl<'de> Deserialize<'de> for ConsistencyVector {
    /// Deserialization is strict: the list must already be sorted, deduplicated and bounded.
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = Vec::<VectorComponent>::deserialize(d)?;
        if v.len() > MAX_COMPONENTS {
            return Err(serde::de::Error::custom(VectorError::TooManyComponents));
        }
        if !v.windows(2).all(|w| w[0].key() < w[1].key()) {
            return Err(serde::de::Error::custom(VectorError::NotNormalized));
        }
        Ok(Self { components: v })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(cluster: u8, d: DomainId, p: u32, pos: u64) -> VectorComponent {
        VectorComponent {
            cluster_id: Uuid::from_bytes([cluster; 16]),
            domain_id: d,
            partition: p,
            position: pos,
        }
    }

    #[test]
    fn sorted_and_deduplicated() {
        let v = ConsistencyVector::from_components([
            c(2, DomainId::Resources, 0, 5),
            c(1, DomainId::Resources, 1, 3),
            c(1, DomainId::Authz, 0, 9),
            c(1, DomainId::Resources, 1, 7),
            c(1, DomainId::Resources, 1, 2),
        ])
        .unwrap();
        assert_eq!(v.len(), 3);
        assert_eq!(v.components()[0].domain_id, DomainId::Authz);
        assert_eq!(
            v.position(&Uuid::from_bytes([1; 16]), &DomainId::Resources, 1),
            Some(7)
        );
    }

    #[test]
    fn overflow_is_error_not_truncation() {
        let ok = ConsistencyVector::from_components((0..64).map(|p| c(1, DomainId::Events, p, 1)));
        assert_eq!(ok.unwrap().len(), 64);
        let too_many =
            ConsistencyVector::from_components((0..65).map(|p| c(1, DomainId::Events, p, 1)));
        assert_eq!(too_many, Err(VectorError::TooManyComponents));
        let mut v =
            ConsistencyVector::from_components((0..64).map(|p| c(1, DomainId::Events, p, 1)))
                .unwrap();
        assert_eq!(
            v.advance(c(1, DomainId::Events, 99, 1)),
            Err(VectorError::TooManyComponents)
        );
        assert_eq!(v.len(), 64);
        v.advance(c(1, DomainId::Events, 3, 10)).unwrap(); // existing key still advances
        let other = ConsistencyVector::from_components([c(9, DomainId::Audit, 0, 1)]).unwrap();
        assert_eq!(v.merge(&other), Err(VectorError::TooManyComponents));
    }

    #[test]
    fn dominance() {
        let a = ConsistencyVector::from_components([
            c(1, DomainId::Authz, 0, 5),
            c(1, DomainId::Identity, 0, 3),
        ])
        .unwrap();
        let b = ConsistencyVector::from_components([c(1, DomainId::Authz, 0, 4)]).unwrap();
        let d = ConsistencyVector::from_components([c(1, DomainId::Authz, 0, 6)]).unwrap();
        let other_cluster =
            ConsistencyVector::from_components([c(2, DomainId::Authz, 0, 1)]).unwrap();
        assert!(a.dominates(&b));
        assert!(!b.dominates(&a));
        assert!(!a.dominates(&d));
        assert!(a.dominates(&a));
        assert!(a.dominates(&ConsistencyVector::new()));
        // Different cluster for the same domain is incomparable, never ordered by value.
        assert!(!a.dominates(&other_cluster));
        let m = a.merge(&d).unwrap();
        assert!(m.dominates(&a) && m.dominates(&d));
    }

    #[test]
    fn serialization_roundtrip_and_strictness() {
        let app = DomainId::App(ApplicationId::parse("org.example.photos").unwrap());
        let v = ConsistencyVector::from_components([
            c(1, app.clone(), 2, 3),
            c(1, DomainId::Audit, 0, 1),
        ])
        .unwrap();
        let j = serde_json::to_string(&v).unwrap();
        assert!(j.contains("app_org.example.photos"));
        assert_eq!(serde_json::from_str::<ConsistencyVector>(&j).unwrap(), v);
        let cb = cs_crypto::cbor::to_canonical(&v).unwrap();
        assert_eq!(
            cs_crypto::cbor::from_canonical::<ConsistencyVector>(&cb, 1 << 16).unwrap(),
            v
        );
        // unsorted input is rejected on decode
        let mut rev = v.components().to_vec();
        rev.reverse();
        let bad = serde_json::to_string(&rev).unwrap();
        assert!(serde_json::from_str::<ConsistencyVector>(&bad).is_err());
        // duplicates rejected
        let dup =
            serde_json::to_string(&[v.components()[0].clone(), v.components()[0].clone()]).unwrap();
        assert!(serde_json::from_str::<ConsistencyVector>(&dup).is_err());
        // > 64 rejected
        let many: Vec<_> = (0..65).map(|p| c(1, DomainId::Events, p, 1)).collect();
        assert!(
            serde_json::from_str::<ConsistencyVector>(&serde_json::to_string(&many).unwrap())
                .is_err()
        );
    }

    #[test]
    fn domain_ids() {
        for d in DomainId::CORE {
            assert_eq!(d.as_str().parse::<DomainId>().unwrap(), d);
        }
        assert_eq!(DomainId::Identity.default_database_name(), "cs_identity");
        assert!("app_".parse::<DomainId>().is_err());
        assert!("Identity".parse::<DomainId>().is_err());
        assert!("app_org.x".parse::<DomainId>().is_ok());
    }
}
