//! Appendix D error contract (D.1–D.3) and contract §2. Traceability: D.1-*, D.2-*, D.3-5, D.3-6,
//! CT.M0-4, 21.3-2.
#![cfg(any(feature = "m0-contract", feature = "qa-selfcheck"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use support::contract as c;
use support::spec;
use support::types::FieldError;

#[test]
fn d2_code_set_is_exact() {
    let mut actual = c::error_codes();
    actual.sort();
    let mut expected: Vec<String> = spec::D2.iter().map(|(c, _, _)| c.to_string()).collect();
    expected.sort();
    assert_eq!(expected.len(), spec::D2_LEN);
    let missing: Vec<_> = expected.iter().filter(|e| !actual.contains(e)).collect();
    let extra: Vec<_> = actual.iter().filter(|a| !expected.contains(a)).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "D.2 code set differs: missing {missing:?}, extra {extra:?}"
    );
}

#[test]
fn d2_status_and_retryable_table() {
    let mut bad = Vec::new();
    for (code, status, retryable) in spec::D2 {
        match c::error_code_meta(code) {
            Some((s, r)) if s == *status && r == *retryable => {}
            other => bad.push(format!(
                "{code}: expected ({status}, retryable={retryable}), got {other:?}"
            )),
        }
    }
    assert!(
        bad.is_empty(),
        "D.2 mapping violations:\n{}",
        bad.join("\n")
    );
}

#[test]
fn d2_wire_strings_roundtrip() {
    for code in c::error_codes() {
        assert!(
            code.chars().all(|ch| ch.is_ascii_lowercase() || ch == '_')
                && !code.starts_with('_')
                && !code.ends_with('_'),
            "wire value {code:?} is not snake_case"
        );
        assert!(
            c::error_code_meta(&code).is_some(),
            "wire value {code:?} does not parse back"
        );
    }
}

#[test]
fn d2_unknown_code_string_rejected() {
    for bogus in [
        "",
        "NOT_FOUND",
        "Not_Found",
        "not-found",
        "notfound",
        " not_found",
        "not_found ",
        "teapot",
        "app.",
        "app.x",
    ] {
        assert!(
            c::error_code_meta(bogus).is_none(),
            "unknown code {bogus:?} was accepted"
        );
    }
}

#[test]
fn app_codes_namespace_and_status_mapping() {
    // D.3: app.<application ID>.<code> mapped to one of the D.2 HTTP statuses.
    for status in spec::d2_statuses() {
        let v =
            c::app_error_code("org.example.photos", "album_full", status).expect("valid app code");
        assert_eq!(v.code, "app.org.example.photos.album_full");
        assert_eq!(v.status, status);
    }
    for bad_status in [200u16, 302, 418, 451, 502, 599] {
        assert!(
            c::app_error_code("org.example.photos", "album_full", bad_status).is_err(),
            "app code mapped to non-D.2 status {bad_status} was accepted"
        );
    }
}

#[test]
fn app_codes_cannot_shadow_core_codes() {
    // D.3: applications may not reuse core codes with different meanings. An application code
    // can therefore never surface as a bare core code, whatever name the app picks.
    for (core, status, _) in spec::D2 {
        if let Ok(v) = c::app_error_code("org.example.photos", core, *status) {
            assert_eq!(
                v.code,
                format!("app.org.example.photos.{core}"),
                "app code surfaced outside its namespace"
            );
            assert_ne!(v.code, *core);
        }
        assert!(
            c::app_error_code("", core, *status).is_err(),
            "empty application id accepted for {core}"
        );
    }
    for bad_code in ["", "Album", "album full", "album.full", "../x"] {
        assert!(
            c::app_error_code("org.example.photos", bad_code, 400).is_err(),
            "malformed app code {bad_code:?} accepted"
        );
    }
}

fn render(code: &str) -> support::types::Rendered {
    c::render_problem(code, "/api/v2/qa/thing", None, None, &[])
}

#[test]
fn problem_required_fields_present() {
    for (code, status, retryable) in spec::D2 {
        let r = render(code);
        assert_eq!(r.status, *status, "{code}: HTTP status");
        let ct = r.header("content-type").unwrap_or("");
        assert!(
            ct.starts_with("application/problem+json"),
            "{code}: content-type {ct:?}"
        );
        let j = r.json();
        for f in spec::PROBLEM_REQUIRED_FIELDS {
            assert!(!j[f].is_null(), "{code}: field {f} missing in {j}");
        }
        assert_eq!(j["code"], *code);
        assert_eq!(j["status"], *status);
        assert_eq!(j["retryable"], *retryable);
        assert_eq!(j["instance"], "/api/v2/qa/thing");
        assert!(j["title"].as_str().is_some_and(|t| !t.is_empty()));
    }
}

#[test]
fn problem_type_uri_format() {
    for (code, _, _) in spec::D2 {
        let j = render(code).json();
        assert_eq!(
            j["type"],
            format!("https://errors.{}/v1/{code}", c::DEPLOYMENT_DOMAIN),
            "{code}"
        );
    }
}

#[test]
fn problem_title_stable_per_code() {
    for (code, _, _) in spec::D2 {
        let a = render(code).json();
        let b = c::render_problem(
            code,
            "/other",
            Some("different internal cause"),
            Some(10),
            &[],
        )
        .json();
        assert_eq!(a["title"], b["title"], "{code}: title must be stable");
    }
}

#[test]
fn problem_status_retryable_derived_from_code() {
    // Contract §2: status and retryable can never be set independently. Whatever optional
    // inputs are supplied, they come from the table.
    for (code, status, retryable) in spec::D2 {
        let fe = [FieldError {
            pointer: "/x".into(),
            code: "invalid_request".into(),
            detail: "bad".into(),
        }];
        let r = c::render_problem(code, "/p", Some("cause"), Some(1500), &fe);
        assert_eq!(r.status, *status, "{code}");
        assert_eq!(r.json()["retryable"], *retryable, "{code}");
    }
}

#[test]
fn problem_retry_after_header_iff_retry_after_ms() {
    for (code, _, _) in spec::D2 {
        let without = c::render_problem(code, "/p", None, None, &[]);
        assert!(
            without.header("retry-after").is_none(),
            "{code}: Retry-After without retry_after_ms"
        );
        assert!(
            without
                .json()
                .get("retry_after_ms")
                .is_none_or(|v| v.is_null()),
            "{code}: spurious retry_after_ms"
        );

        let with = c::render_problem(code, "/p", None, Some(2500), &[]);
        assert_eq!(with.json()["retry_after_ms"], 2500, "{code}");
        assert_eq!(
            with.header("retry-after"),
            Some("3"),
            "{code}: Retry-After must be seconds rounded up"
        );
    }
}

#[test]
fn retry_after_rounds_up_to_seconds() {
    for (ms, secs) in [
        (1u64, "1"),
        (999, "1"),
        (1000, "1"),
        (1001, "2"),
        (59_999, "60"),
        (60_000, "60"),
    ] {
        let r = c::render_problem("rate_limited", "/p", None, Some(ms), &[]);
        assert_eq!(r.header("retry-after"), Some(secs), "retry_after_ms={ms}");
    }
    // 0 ms: header must still be consistent with the body (present iff field present).
    let r = c::render_problem("unavailable", "/p", None, Some(0), &[]);
    let has_field = r.json().get("retry_after_ms").is_some_and(|v| !v.is_null());
    assert_eq!(
        has_field,
        r.header("retry-after").is_some(),
        "retry_after_ms=0: header iff field"
    );
}

#[test]
fn internal_error_detail_is_generic() {
    let secret = "SELECT * FROM identity.users WHERE password_hash = 'deadbeef' at src/db.rs:42 postgres://admin:hunter2@db";
    let r = c::render_problem("internal", "/p", Some(secret), None, &[]);
    let body = String::from_utf8_lossy(&r.body).to_string();
    for needle in [
        "SELECT",
        "password_hash",
        "deadbeef",
        "src/db.rs",
        "hunter2",
        "postgres://",
        "identity.users",
    ] {
        assert!(
            !body.contains(needle),
            "internal cause leaked into problem body ({needle}): {body}"
        );
    }
    let j = r.json();
    assert!(
        j["request_id"].as_str().is_some_and(|s| !s.is_empty()),
        "request_id needed to correlate the logged cause"
    );
    // Any code: an internal cause never reaches the client.
    for (code, _, _) in spec::D2 {
        let b =
            String::from_utf8_lossy(&c::render_problem(code, "/p", Some(secret), None, &[]).body)
                .to_string();
        assert!(
            !b.contains("hunter2") && !b.contains("password_hash"),
            "{code}: internal cause leaked"
        );
    }
}

#[test]
fn field_errors_shape() {
    let fe = [
        FieldError {
            pointer: "/name".into(),
            code: "invalid_request".into(),
            detail: "must not be empty".into(),
        },
        FieldError {
            pointer: "/size".into(),
            code: "invalid_request".into(),
            detail: "too large".into(),
        },
    ];
    let j = c::render_problem("invalid_request", "/p", None, None, &fe).json();
    let errs = j["errors"].as_array().expect("errors[]");
    assert_eq!(errs.len(), 2);
    for (e, f) in errs.iter().zip(fe.iter()) {
        assert_eq!(e["pointer"], f.pointer.as_str());
        assert_eq!(e["code"], f.code.as_str());
        assert_eq!(e["detail"], f.detail.as_str());
    }
}
