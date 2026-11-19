//! Identifiers and URNs (§4.1, §17.1, App. E, contract §1).
//! Traceability: 4.1-2, 17.1-2, E-1, CT.M0-1, CT.M0-2.
#![cfg(any(feature = "m0-contract", feature = "qa-selfcheck"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::collections::HashSet;
use support::contract as c;
use uuid::Uuid;

#[test]
fn typed_ids_are_uuidv7() {
    for kind in c::ID_KINDS_V7 {
        let mut seen = HashSet::new();
        for _ in 0..200 {
            let t = c::new_id_text(kind);
            let u = Uuid::parse_str(&t).unwrap_or_else(|_| panic!("{kind}: {t} is not a UUID"));
            assert_eq!(u.get_version_num(), 7, "{kind}: {t} is not UUIDv7");
            assert_eq!(
                u.get_variant(),
                uuid::Variant::RFC4122,
                "{kind}: wrong variant"
            );
            assert!(seen.insert(u), "{kind}: duplicate id");
        }
    }
}

#[test]
fn id_text_form_lowercase_hyphenated() {
    for kind in c::ID_KINDS_V7.iter().chain(c::ID_KINDS_RANDOM) {
        let t = c::new_id_text(kind);
        assert_eq!(t.len(), 36, "{kind}: {t}");
        assert_eq!(t, t.to_lowercase(), "{kind}: text form must be lowercase");
        assert_eq!(
            t.matches('-').count(),
            4,
            "{kind}: hyphenated form expected"
        );
    }
}

#[test]
fn chunk_and_extent_ids_are_random_v4() {
    for kind in c::ID_KINDS_RANDOM {
        let mut seen = HashSet::new();
        let mut first_bytes = HashSet::new();
        for _ in 0..500 {
            let u = Uuid::parse_str(&c::new_id_text(kind)).unwrap();
            assert_eq!(
                u.get_version_num(),
                4,
                "{kind} must be random (UUIDv4 layout), not time-ordered"
            );
            assert!(seen.insert(u), "{kind}: duplicate");
            first_bytes.insert(u.as_bytes()[0]);
        }
        // A time-ordered or counter id would share its leading bytes; random ones spread out.
        assert!(
            first_bytes.len() > 100,
            "{kind}: leading byte only took {} values in 500 ids",
            first_bytes.len()
        );
    }
}

#[test]
fn urn_parse_strict() {
    let t = "0190a0a0-0000-7000-8000-000000000001";
    let r = "0190a0a0-0000-7000-8000-0000000000ff";
    for good in [
        format!("cs:{t}:drive.folder:{r}"),
        format!("cs:{t}:core.space:{r}"),
        format!("cs:{t}:a.b_c.d9:{r}"),
    ] {
        assert_eq!(c::urn_parse_display(&good).unwrap(), good, "{good}");
    }
    let bad = [
        format!(" cs:{t}:drive.folder:{r}"),
        format!("cs:{t}:drive.folder:{r} "),
        format!("CS:{t}:drive.folder:{r}"),
        format!("cs:{}:drive.folder:{r}", t.to_uppercase()),
        format!("cs:{t}:Drive.folder:{r}"),
        format!("cs:{t}:drive:{r}"),
        format!("cs:{t}:drive.:{r}"),
        format!("cs:{t}:.folder:{r}"),
        format!("cs:{t}:9drive.folder:{r}"),
        format!("cs:{t}:drive.folder:{r}:extra"),
        format!("cs:{t}:drive.folder"),
        format!("cs::drive.folder:{r}"),
        format!("cs:{t}:drive.folder:not-a-uuid"),
        format!("cs:{}:drive.folder:{r}", t.replace('-', "")),
        format!("cs:{t}:drive-x.folder:{r}"),
        format!("cs:{t}:drive.fol der:{r}"),
        String::new(),
    ];
    for b in bad {
        assert!(c::urn_parse_display(&b).is_err(), "URN {b:?} accepted");
    }
}

#[test]
fn urn_roundtrip() {
    for _ in 0..50 {
        let s = format!(
            "cs:{}:docs.document:{}",
            c::new_id_text("tenant"),
            c::new_id_text("resource")
        );
        assert_eq!(c::urn_parse_display(&s).unwrap(), s);
    }
}
