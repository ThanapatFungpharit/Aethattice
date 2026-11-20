//! Consistency vectors (App. C rule C10, §18.4, §6.4, contract §4): bounded, sorted,
//! deduplicated, per-component dominance, no time fields. Property tests compare the
//! implementation with an independent reference model.
//! Traceability: 2.6-8, 6.4-9, 18.4-12, C.2-10, CT.M0-11, CT.M0-12.
#![cfg(any(feature = "m0-contract", feature = "qa-selfcheck"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use support::contract as c;
use support::spec;
use support::types::Comp;
use uuid::Uuid;

type Key = (Uuid, String, u32);

/// Reference model: a vector is a map key -> position. `a` dominates `b` iff every component of
/// `b` is present in `a` with a position at least as large.
fn model(cs: &[Comp]) -> BTreeMap<Key, u64> {
    cs.iter()
        .map(|c| ((c.cluster, c.domain.clone(), c.partition), c.position))
        .collect()
}
fn model_dominates(a: &BTreeMap<Key, u64>, b: &BTreeMap<Key, u64>) -> bool {
    b.iter().all(|(k, pb)| a.get(k).is_some_and(|pa| pa >= pb))
}

const CLUSTERS: [u128; 2] = [
    0x0190_0000_0000_7000_8000_0000_0000_0001,
    0x0190_0000_0000_7000_8000_0000_0000_0002,
];
const DOMS: [&str; 3] = ["resources", "identity", "authz"];

fn comp_strategy() -> impl Strategy<Value = Comp> {
    (0..CLUSTERS.len(), 0..DOMS.len(), 0u32..3, 0u64..6).prop_map(|(c, d, p, pos)| Comp {
        cluster: Uuid::from_u128(CLUSTERS[c]),
        domain: DOMS[d].to_string(),
        partition: p,
        position: pos,
    })
}

/// Unique keys (conflicting duplicates are OQ-9 and not generated), in arbitrary order.
fn vec_strategy() -> impl Strategy<Value = Vec<Comp>> {
    prop::collection::vec(comp_strategy(), 0..12)
        .prop_map(|v| {
            let m: BTreeMap<Key, Comp> = v
                .into_iter()
                .map(|c| ((c.cluster, c.domain.clone(), c.partition), c))
                .collect();
            m.into_values().collect()
        })
        .prop_shuffle()
}

fn comps(n: usize) -> Vec<Comp> {
    (0..n)
        .map(|i| Comp {
            cluster: Uuid::from_u128(CLUSTERS[0]),
            domain: "resources".into(),
            partition: i as u32,
            position: i as u64,
        })
        .collect()
}

#[test]
fn sixty_four_components_accepted() {
    let v = c::cv_new(comps(spec::MAX_VECTOR_COMPONENTS)).expect("64 components must be accepted");
    assert_eq!(c::cv_components(&v).len(), spec::MAX_VECTOR_COMPONENTS);
    let back = c::cv_decode(&c::cv_encode(&v)).expect("64-component vector must round-trip");
    assert_eq!(c::cv_components(&back).len(), spec::MAX_VECTOR_COMPONENTS);
}

#[test]
fn sixty_five_components_rejected_not_truncated() {
    for n in [spec::MAX_VECTOR_COMPONENTS + 1, 100, 1000] {
        match c::cv_new(comps(n)) {
            Err(_) => {}
            Ok(v) => panic!(
                "{n} components accepted (kept {}): vectors must be rejected, never truncated",
                c::cv_components(&v).len()
            ),
        }
    }
    // Exact duplicates collapse, so 65 entries with one duplicate is 64 distinct components.
    let mut v = comps(spec::MAX_VECTOR_COMPONENTS);
    v.push(v[0].clone());
    if let Ok(cv) = c::cv_new(v) {
        assert_eq!(
            c::cv_components(&cv).len(),
            spec::MAX_VECTOR_COMPONENTS,
            "exact duplicate not deduplicated"
        );
    }
}

#[test]
fn exact_duplicates_are_deduplicated() {
    let a = comps(3);
    let mut with_dups = a.clone();
    with_dups.extend(a.clone());
    with_dups.reverse();
    let v = c::cv_new(with_dups).unwrap();
    assert_eq!(c::cv_components(&v).len(), 3);
    assert_eq!(c::cv_encode(&v), c::cv_encode(&c::cv_new(a).unwrap()));
}

#[test]
fn conflicting_duplicates_merge_to_maximum() {
    // Contract rev 2 (OQ-9): same (cluster, domain, partition) merges to the maximum position,
    // and the 64 limit applies after merging.
    let key = |pos| Comp {
        cluster: Uuid::from_u128(CLUSTERS[0]),
        domain: "authz".into(),
        partition: 7,
        position: pos,
    };
    for order in [vec![3, 9, 5], vec![9, 3, 5], vec![5, 5, 9, 3]] {
        let v = c::cv_new(order.iter().map(|p| key(*p)).collect()).unwrap();
        let out = c::cv_components(&v);
        assert_eq!(out.len(), 1, "{order:?}");
        assert_eq!(
            out[0].position, 9,
            "{order:?}: must keep the maximum position"
        );
    }
    let mut v = comps(spec::MAX_VECTOR_COMPONENTS);
    v.extend(comps(spec::MAX_VECTOR_COMPONENTS).into_iter().map(|mut c| {
        c.position += 100;
        c
    }));
    let merged =
        c::cv_new(v).expect("128 entries over 64 distinct keys is 64 components after merging");
    assert_eq!(c::cv_components(&merged).len(), spec::MAX_VECTOR_COMPONENTS);
    assert!(c::cv_components(&merged).iter().all(|c| c.position >= 100));
}

#[test]
fn domain_ids_match_spec_18_1() {
    let mut got = c::domain_wire_names();
    got.sort();
    let mut want: Vec<String> = spec::DOMAINS.iter().map(|s| s.to_string()).collect();
    want.sort();
    assert_eq!(
        got, want,
        "DomainId core variants must be exactly the §18.1 domains"
    );
    let app = c::app_domain_name("org.example.photos");
    assert!(
        !spec::DOMAINS.contains(&app.as_str()),
        "App(application_id) collides with a core domain"
    );
    assert_ne!(
        c::app_domain_name("org.example.a"),
        c::app_domain_name("org.example.b")
    );
}

#[test]
fn vector_has_no_time_fields() {
    // App. C rule C10: HLC or wall-clock values are never part of a vector. Building the same
    // components at different times must give byte-identical encodings.
    let a = c::cv_encode(&c::cv_new(comps(5)).unwrap());
    std::thread::sleep(std::time::Duration::from_millis(20));
    let b = c::cv_encode(&c::cv_new(comps(5)).unwrap());
    assert_eq!(a, b, "encoding depends on construction time");
    let empty = c::cv_encode(&c::cv_new(vec![]).unwrap());
    assert!(
        empty.len() <= 8,
        "empty vector encodes to {} bytes: hidden fields?",
        empty.len()
    );
}

#[test]
fn position_extremes_roundtrip() {
    let cs = vec![
        Comp {
            cluster: Uuid::from_u128(CLUSTERS[0]),
            domain: "objects".into(),
            partition: u32::MAX,
            position: u64::MAX,
        },
        Comp {
            cluster: Uuid::from_u128(CLUSTERS[1]),
            domain: "audit".into(),
            partition: 0,
            position: 0,
        },
    ];
    let v = c::cv_new(cs.clone()).unwrap();
    let back = c::cv_decode(&c::cv_encode(&v)).unwrap();
    assert_eq!(model(&c::cv_components(&back)), model(&cs));
}

#[test]
fn decode_rejects_garbage() {
    for bad in [&b""[..], b"\xff", b"\x9f", &[0x9b; 9][..]] {
        assert!(c::cv_decode(bad).is_err(), "garbage {bad:?} decoded");
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn prop_canonical_sorted_dedup(v in vec_strategy()) {
        let cv = c::cv_new(v.clone()).unwrap();
        let out = c::cv_components(&cv);
        prop_assert_eq!(model(&out), model(&v));
        let keys: Vec<Key> = out.iter().map(|c| (c.cluster, c.domain.clone(), c.partition)).collect();
        let set: BTreeSet<Key> = keys.iter().cloned().collect();
        prop_assert_eq!(set.len(), keys.len(), "duplicate keys in output");
        // Canonical: input order does not matter.
        let mut rev = v.clone();
        rev.reverse();
        prop_assert_eq!(c::cv_encode(&cv), c::cv_encode(&c::cv_new(rev).unwrap()));
        // Sorted: the output order is the same as re-sorting it.
        let again = c::cv_components(&c::cv_new(out.clone()).unwrap());
        prop_assert_eq!(again, out);
    }

    #[test]
    fn prop_dominance_matches_reference_model(a in vec_strategy(), b in vec_strategy()) {
        let (ca, cb) = (c::cv_new(a.clone()).unwrap(), c::cv_new(b.clone()).unwrap());
        prop_assert_eq!(c::cv_dominates(&ca, &cb), model_dominates(&model(&a), &model(&b)));
        prop_assert_eq!(c::cv_dominates(&cb, &ca), model_dominates(&model(&b), &model(&a)));
    }

    #[test]
    fn prop_dominance_reflexive(a in vec_strategy()) {
        let ca = c::cv_new(a).unwrap();
        prop_assert!(c::cv_dominates(&ca, &ca));
    }

    #[test]
    fn prop_dominance_antisymmetric(a in vec_strategy(), b in vec_strategy()) {
        let (ca, cb) = (c::cv_new(a).unwrap(), c::cv_new(b).unwrap());
        if c::cv_dominates(&ca, &cb) && c::cv_dominates(&cb, &ca) {
            prop_assert_eq!(c::cv_encode(&ca), c::cv_encode(&cb));
        }
    }

    #[test]
    fn prop_dominance_transitive(a in vec_strategy(), b in vec_strategy(), x in vec_strategy()) {
        let (ca, cb, cx) = (c::cv_new(a).unwrap(), c::cv_new(b).unwrap(), c::cv_new(x).unwrap());
        if c::cv_dominates(&ca, &cb) && c::cv_dominates(&cb, &cx) {
            prop_assert!(c::cv_dominates(&ca, &cx));
        }
    }

    #[test]
    fn prop_empty_vector_bounds(a in vec_strategy()) {
        let ca = c::cv_new(a.clone()).unwrap();
        let e = c::cv_new(vec![]).unwrap();
        prop_assert!(c::cv_dominates(&ca, &e), "everything dominates the empty vector");
        prop_assert_eq!(c::cv_dominates(&e, &ca), a.is_empty());
    }

    #[test]
    fn prop_raising_a_position_never_loses_dominance(a in vec_strategy(), idx in 0usize..12, bump in 1u64..5) {
        prop_assume!(!a.is_empty());
        let i = idx % a.len();
        let mut higher = a.clone();
        higher[i].position = higher[i].position.saturating_add(bump);
        let (ca, ch) = (c::cv_new(a).unwrap(), c::cv_new(higher).unwrap());
        prop_assert!(c::cv_dominates(&ch, &ca));
        prop_assert!(!c::cv_dominates(&ca, &ch));
    }

    #[test]
    fn prop_serialization_roundtrip(a in vec_strategy(), b in vec_strategy()) {
        let (ca, cb) = (c::cv_new(a.clone()).unwrap(), c::cv_new(b).unwrap());
        let ra = c::cv_decode(&c::cv_encode(&ca)).unwrap();
        prop_assert_eq!(model(&c::cv_components(&ra)), model(&a));
        prop_assert_eq!(c::cv_encode(&ra), c::cv_encode(&ca));
        prop_assert_eq!(c::cv_dominates(&ra, &cb), c::cv_dominates(&ca, &cb));
    }
}
