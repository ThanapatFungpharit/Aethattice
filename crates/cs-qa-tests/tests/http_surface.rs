//! Black-box HTTP surface of the `cs` binary in M0 (contract §7, App. D.1). Runs the real
//! binary; domain databases are deliberately unreachable (no DB needed).
//! Traceability: D.1-1, D.1-5..D.1-7, D.1-9, D.2-1, D.2-4, D.2-5, CT.M0-27, 25.4-1.
#![cfg(any(feature = "m0-contract", feature = "qa-selfcheck"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use support::contract as c;
use support::server::{Server, free_port, http};
use support::{db, spec};

async fn start_without_db() -> (Server, tempfile::TempDir) {
    let state = tempfile::tempdir().unwrap();
    let port = free_port();
    let cfg = c::config_toml(
        port,
        &["api"],
        &|d| db::unreachable_url(&format!("cs_{d}")),
        state.path(),
    );
    (Server::start(&cfg, port).await, state)
}

/// Asserts the D.1 problem shape and returns the parsed body.
async fn assert_problem(
    resp: reqwest::Response,
    status: u16,
    code: &str,
    path: &str,
) -> serde_json::Value {
    assert_eq!(resp.status().as_u16(), status, "{path}: status");
    let headers = resp.headers().clone();
    let ct = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ct.starts_with("application/problem+json"),
        "{path}: content-type {ct:?}"
    );
    let rid = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(!rid.is_empty(), "{path}: X-Request-Id missing");
    let text = resp.text().await.unwrap();
    let j: serde_json::Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("{path}: body not JSON ({e}): {text}"));
    for f in spec::PROBLEM_REQUIRED_FIELDS {
        assert!(!j[f].is_null(), "{path}: problem field {f} missing: {j}");
    }
    assert_eq!(j["code"], code, "{path}");
    assert_eq!(j["status"], status, "{path}");
    assert_eq!(j["retryable"], spec::d2(code).unwrap().1, "{path}");
    assert_eq!(
        j["request_id"],
        rid.as_str(),
        "{path}: body request_id must equal X-Request-Id"
    );
    // OQ-13: instance is the request path, without the query string.
    assert_eq!(
        j["instance"],
        path.split('?').next().unwrap(),
        "{path}: instance"
    );
    if let Some(m) = spec::leak_in(&text) {
        panic!("{path}: internal detail leaked ({m}): {text}");
    }
    let retry_after = headers
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let ms = j.get("retry_after_ms").and_then(|v| v.as_u64());
    assert_eq!(
        retry_after.is_some(),
        ms.is_some(),
        "{path}: Retry-After present iff retry_after_ms"
    );
    if let (Some(h), Some(ms)) = (retry_after, ms) {
        assert_eq!(
            h,
            ms.div_ceil(1000).to_string(),
            "{path}: Retry-After = ceil(ms/1000)"
        );
    }
    j
}

#[tokio::test]
async fn unknown_route_returns_404_problem() {
    let (s, _st) = start_without_db().await;
    let cl = http();
    for path in [
        "/no/such/route",
        "/api/v2/does-not-exist",
        "/api/v3/x",
        "/api/v2/qa/x?secret=1",
        "/%2e%2e/etc/passwd",
    ] {
        let r = cl.get(s.url(path)).send().await.unwrap();
        // Percent-encoded traversal may be normalized by the client; the response must still be a 404 problem.
        let shown = if path.starts_with("/%2e") {
            r.url().path().to_string()
        } else {
            path.to_string()
        };
        let j = assert_problem(r, 404, "not_found", &shown).await;
        assert!(
            !j.to_string().contains("secret=1"),
            "query string echoed: {j}"
        );
    }
    s.stop().await;
}

#[tokio::test]
async fn wrong_method_returns_405_problem() {
    let (s, _st) = start_without_db().await;
    let cl = http();
    for path in ["/healthz", "/readyz"] {
        for m in [
            reqwest::Method::POST,
            reqwest::Method::PUT,
            reqwest::Method::DELETE,
            reqwest::Method::PATCH,
        ] {
            let r = cl.request(m.clone(), s.url(path)).send().await.unwrap();
            let allow = r
                .headers()
                .get("allow")
                .map(|v| v.to_str().unwrap_or("").to_string());
            assert_problem(r, 405, "method_not_allowed", path).await;
            if let Some(a) = allow {
                assert!(
                    a.contains("GET"),
                    "{m} {path}: Allow header should list GET, got {a}"
                );
            }
        }
    }
    s.stop().await;
}

#[tokio::test]
async fn malformed_json_body_returns_400_problem() {
    let Some(route) = c::JSON_POST_ROUTE else {
        panic!(
            "OQ-7: no M0 route accepting a JSON body is named in the contract; cannot test body-parse failures black-box"
        );
    };
    let (s, _st) = start_without_db().await;
    let cl = http();
    let bodies: [&[u8]; 6] = [
        b"{",
        b"{\"a\":}",
        b"[1,2",
        b"\xff\xfe",
        b"{\"a\":1}{\"b\":2}",
        b"nul",
    ];
    for body in bodies {
        let r = cl
            .post(s.url(route))
            .header("content-type", "application/json")
            .body(body.to_vec())
            .send()
            .await
            .unwrap();
        let j = assert_problem(r, 400, "invalid_request", route).await;
        let detail = j["detail"].as_str().unwrap_or("");
        assert!(
            !detail.contains("serde") && !detail.contains("line ") && !detail.contains("column "),
            "parser internals in detail: {detail}"
        );
    }
    // Wrong media type is 415, not a parse error.
    let r = cl
        .post(s.url(route))
        .header("content-type", "text/plain")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_problem(r, 415, "unsupported_media_type", route).await;
    s.stop().await;
}

#[tokio::test]
async fn every_response_has_request_id() {
    let (s, _st) = start_without_db().await;
    let cl = http();
    let mut seen = std::collections::HashSet::new();
    for path in ["/healthz", "/readyz", "/nope", "/healthz", "/api/v2/x"] {
        let r = cl.get(s.url(path)).send().await.unwrap();
        let rid = r
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            !rid.is_empty(),
            "{path}: X-Request-Id missing (status {})",
            r.status()
        );
        assert!(seen.insert(rid.clone()), "request id {rid} reused");
    }
    // A client-supplied X-Request-Id must not allow header injection or unbounded values.
    let r = cl
        .get(s.url("/healthz"))
        .header("x-request-id", "a".repeat(10_000))
        .send()
        .await
        .unwrap();
    let rid = r
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        rid.len() <= 256,
        "unbounded client request id echoed ({} bytes)",
        rid.len()
    );
    s.stop().await;
}

#[tokio::test]
async fn error_responses_never_leak_internals() {
    // Readiness with unreachable DBs is the richest internal-failure path available in M0:
    // the body must not contain connection strings, credentials, driver or OS error text.
    let (s, _st) = start_without_db().await;
    let cl = http();
    for path in ["/readyz", "/nope", "/api/v2/../../etc"] {
        let r = cl.get(s.url(path)).send().await.unwrap();
        let text = r.text().await.unwrap();
        assert!(
            !text.contains("qa_secret_must_not_leak"),
            "{path}: DB password leaked: {text}"
        );
        assert!(!text.contains("qa_user"), "{path}: DB user leaked: {text}");
        if let Some(m) = spec::leak_in(&text) {
            panic!("{path}: internal detail leaked ({m}): {text}");
        }
    }
    let log = s.stop().await;
    assert!(
        !log.contains("qa_secret_must_not_leak"),
        "DB password written to logs (§15.4)"
    );
}

#[tokio::test]
async fn retry_after_header_consistent_on_all_errors() {
    let (s, _st) = start_without_db().await;
    let cl = http();
    for path in ["/readyz", "/nope"] {
        let r = cl.get(s.url(path)).send().await.unwrap();
        if r.status().is_success() {
            continue;
        }
        let h = r
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let j: serde_json::Value = r.json().await.unwrap();
        let ms = j.get("retry_after_ms").and_then(|v| v.as_u64());
        assert_eq!(
            h.is_some(),
            ms.is_some(),
            "{path}: Retry-After iff retry_after_ms"
        );
        if let (Some(h), Some(ms)) = (h, ms) {
            assert_eq!(h, ms.div_ceil(1000).to_string(), "{path}");
        }
    }
    s.stop().await;
}

#[tokio::test]
async fn healthz_is_liveness_only() {
    let (s, _st) = start_without_db().await;
    let cl = http();
    for _ in 0..3 {
        let r = cl.get(s.url("/healthz")).send().await.unwrap();
        assert_eq!(
            r.status().as_u16(),
            200,
            "healthz must not depend on domain databases"
        );
        assert!(r.headers().get("x-request-id").is_some());
    }
    s.stop().await;
}
