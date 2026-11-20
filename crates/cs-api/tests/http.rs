//! HTTP surface tests (contract §7, §2): problem+json everywhere, X-Request-Id, readiness
//! barriers, Idempotency-Key plumbing, admin metrics.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::routing::{get, post};
use cs_api::{
    ApiError, ApiState, DomainReachable, IdempotencyKeyHeader, JsonBody, MigrationsCurrent,
    ReadinessBarrier,
};
use cs_common::error::{Error as CsError, ErrorCode, ProblemDocument};
use cs_common::id::RequestId;
use cs_common::vector::DomainId;
use cs_db::migrate::{Migrator, common_migrations};
use cs_db::testing::TestDomains;
use http_body_util::BodyExt;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

struct Fixed(&'static str, bool);

#[async_trait]
impl ReadinessBarrier for Fixed {
    fn name(&self) -> String {
        self.0.to_owned()
    }
    async fn check(&self) -> Result<(), String> {
        if self.1 {
            Ok(())
        } else {
            Err("secret internal reason".into())
        }
    }
}

struct Slow;

#[async_trait]
impl ReadinessBarrier for Slow {
    fn name(&self) -> String {
        "slow".into()
    }
    async fn check(&self) -> Result<(), String> {
        tokio::time::sleep(Duration::from_secs(10)).await;
        Ok(())
    }
}

fn state(barriers: Vec<Arc<dyn ReadinessBarrier>>) -> ApiState {
    ApiState::new("qa.example", barriers, Duration::from_millis(2000))
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct Thing {
    name: String,
}

async fn echo_key(IdempotencyKeyHeader(k): IdempotencyKeyHeader) -> String {
    k.map(|k| k.as_str().to_owned())
        .unwrap_or_else(|| "none".into())
}

async fn make_thing(JsonBody(t): JsonBody<Thing>) -> String {
    t.name
}

async fn limited() -> Result<(), ApiError> {
    Err(ApiError::new(
        CsError::new(ErrorCode::RateLimited).with_retry_after_ms(1500),
    ))
}

async fn boom() -> Result<(), ApiError> {
    Err(ApiError::new(CsError::internal(std::io::Error::other(
        "db password=hunter2",
    ))))
}

async fn panics() -> &'static str {
    panic!("handler panic with secret=hunter2")
}

fn app(barriers: Vec<Arc<dyn ReadinessBarrier>>) -> Router {
    app_with_state(state(barriers))
}

/// Readiness timeout for barriers against a real database. A new connection to a
/// just-created YugabyteDB database loads its catalog cache and can exceed 2 s under a
/// parallel test load; this test checks barrier semantics, not the timeout (covered by
/// `readiness_reports_failing_barriers_without_internal_detail`).
const REAL_DB_READINESS_TIMEOUT: Duration = Duration::from_secs(30);

fn app_with_state(st: ApiState) -> Router {
    let routes = cs_api::public_routes()
        .route("/test/key", post(echo_key))
        .route("/test/things", post(make_thing))
        .route("/test/limited", get(limited))
        .route("/test/boom", get(boom))
        .route("/test/panic", get(panics));
    cs_api::with_middleware(routes, st, 64)
}

async fn call(app: &Router, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let r = app.clone().oneshot(req).await.unwrap();
    let status = r.status();
    let headers = r.headers().clone();
    let body = r.into_body().collect().await.unwrap().to_bytes().to_vec();
    (status, headers, body)
}

fn get_req(uri: &str) -> Request<Body> {
    Request::get(uri).body(Body::empty()).unwrap()
}

fn assert_problem(
    status: StatusCode,
    h: &axum::http::HeaderMap,
    body: &[u8],
    code: &str,
) -> ProblemDocument {
    assert_eq!(
        h.get(header::CONTENT_TYPE).unwrap(),
        "application/problem+json"
    );
    let p: ProblemDocument = serde_json::from_slice(body)
        .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(body)));
    assert_eq!(p.code, code);
    assert_eq!(p.status, status.as_u16());
    assert_eq!(p.r#type, format!("https://errors.qa.example/v1/{code}"));
    let rid = h.get("x-request-id").unwrap().to_str().unwrap();
    assert_eq!(p.request_id, rid);
    p
}

#[tokio::test]
async fn healthz_and_request_id() {
    let app = app(vec![]);
    let (s, h, b) = call(&app, get_req("/healthz")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b, br#"{"status":"ok"}"#);
    let rid: RequestId = h
        .get("x-request-id")
        .unwrap()
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let (_, h2, _) = call(&app, get_req("/healthz")).await;
    assert_ne!(
        h2.get("x-request-id").unwrap().to_str().unwrap(),
        rid.to_string()
    );
}

#[tokio::test]
async fn unknown_route_is_404_problem_and_instance_has_no_query() {
    let app = app(vec![]);
    let (s, h, b) = call(&app, get_req("/no/such/route?token=secret123")).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let p = assert_problem(s, &h, &b, "not_found");
    assert_eq!(p.instance, "/no/such/route");
    assert!(!String::from_utf8_lossy(&b).contains("secret123"));
    assert!(!p.retryable);
}

#[tokio::test]
async fn wrong_method_is_405_problem() {
    let app = app(vec![]);
    let req = Request::delete("/healthz").body(Body::empty()).unwrap();
    let (s, h, b) = call(&app, req).await;
    assert_eq!(s, StatusCode::METHOD_NOT_ALLOWED);
    assert_problem(s, &h, &b, "method_not_allowed");
}

#[tokio::test]
async fn body_failures_are_problems() {
    let app = app(vec![]);
    let json = |b: &'static str| {
        Request::post("/test/things")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(b))
            .unwrap()
    };
    let (s, h, b) = call(&app, json(r#"{"name":"x"}"#)).await;
    assert_eq!((s, b.as_slice()), (StatusCode::OK, &b"x"[..]), "{h:?}");
    let (s, h, b) = call(&app, json("{not json")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_problem(s, &h, &b, "invalid_request");
    let (s, h, b) = call(&app, json(r#"{"other":1}"#)).await;
    assert_problem(s, &h, &b, "invalid_request");
    let wrong_type = Request::post("/test/things")
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from("x"))
        .unwrap();
    let (s, h, b) = call(&app, wrong_type).await;
    assert_eq!(s, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_problem(s, &h, &b, "unsupported_media_type");
    let big = json(Box::leak(
        format!(r#"{{"name":"{}"}}"#, "x".repeat(200)).into_boxed_str(),
    ));
    let (s, h, b) = call(&app, big).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
    assert_problem(s, &h, &b, "payload_too_large");
}

#[tokio::test]
async fn idempotency_key_header_plumbing() {
    let app = app(vec![]);
    let with = |v: Option<&str>| {
        let mut r = Request::post("/test/key");
        if let Some(v) = v {
            r = r.header("Idempotency-Key", v);
        }
        r.body(Body::empty()).unwrap()
    };
    let (s, _, b) = call(&app, with(Some("abc-123"))).await;
    assert_eq!((s, b.as_slice()), (StatusCode::OK, &b"abc-123"[..]));
    let (_, _, b) = call(&app, with(None)).await;
    assert_eq!(b, b"none");
    for bad in ["has space", "", &"x".repeat(256)] {
        let (s, h, b) = call(&app, with(Some(bad))).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad:?}");
        assert_problem(s, &h, &b, "invalid_request");
    }
    let two = Request::post("/test/key")
        .header("Idempotency-Key", "a")
        .header("Idempotency-Key", "b")
        .body(Body::empty())
        .unwrap();
    assert_eq!(call(&app, two).await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn retry_after_header_and_internal_errors_are_generic() {
    let app = app(vec![]);
    let (s, h, b) = call(&app, get_req("/test/limited")).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    let p = assert_problem(s, &h, &b, "rate_limited");
    assert_eq!(p.retry_after_ms, Some(1500));
    assert_eq!(h.get(header::RETRY_AFTER).unwrap(), "2");
    assert!(p.retryable);
    for uri in ["/test/boom", "/test/panic"] {
        let (s, h, b) = call(&app, get_req(uri)).await;
        assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR, "{uri}");
        let p = assert_problem(s, &h, &b, "internal");
        assert_eq!(p.detail, cs_common::error::INTERNAL_DETAIL);
        assert!(!String::from_utf8_lossy(&b).contains("hunter2"), "{uri}");
    }
}

#[tokio::test]
async fn readiness_reports_failing_barriers_without_internal_detail() {
    let ok = app(vec![Arc::new(Fixed("a", true)), Arc::new(Fixed("b", true))]);
    let (s, _, b) = call(&ok, get_req("/readyz")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(String::from_utf8_lossy(&b).contains("\"ready\""));

    let bad = app(vec![
        Arc::new(Fixed("a", true)),
        Arc::new(Fixed("b", false)),
        Arc::new(Slow),
    ]);
    let (s, h, b) = call(&bad, get_req("/readyz")).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    let p = assert_problem(s, &h, &b, "unavailable");
    let ptrs: Vec<_> = p.errors.iter().map(|e| e.pointer.as_str()).collect();
    assert_eq!(
        ptrs,
        ["/barriers/b", "/barriers/slow"],
        "timeouts count as failing"
    );
    assert!(!String::from_utf8_lossy(&b).contains("secret internal reason"));
    // liveness is independent of readiness
    assert_eq!(call(&bad, get_req("/healthz")).await.0, StatusCode::OK);
}

#[tokio::test]
async fn readiness_with_real_domains_requires_reachable_and_migrated() {
    let Some(t) = TestDomains::create(&[DomainId::Identity]).await else {
        return;
    };
    let pool = t.pool(&DomainId::Identity).clone();
    let set = common_migrations().unwrap();
    let barriers = |p: &cs_db::DomainPool| -> Vec<Arc<dyn ReadinessBarrier>> {
        vec![
            Arc::new(DomainReachable(p.clone())),
            Arc::new(MigrationsCurrent {
                pool: p.clone(),
                set: set.clone(),
            }),
        ]
    };
    let real_db_app = |p: &cs_db::DomainPool| {
        app_with_state(ApiState::new(
            "qa.example",
            barriers(p),
            REAL_DB_READINESS_TIMEOUT,
        ))
    };
    let a = real_db_app(&pool);
    let (s, h, b) = call(&a, get_req("/readyz")).await;
    let p = assert_problem(s, &h, &b, "unavailable");
    assert_eq!(p.errors.len(), 1);
    assert_eq!(p.errors[0].pointer, "/barriers/domain.identity.migrations");
    Migrator::run(&pool, &set).await.unwrap();
    assert_eq!(call(&a, get_req("/readyz")).await.0, StatusCode::OK);
    // unreachable domain
    let cfg = cs_common::config::DomainConfig {
        url: cs_common::Secret::new("postgres://nobody@127.0.0.1:1/none".into()),
        pool: cs_common::config::PoolConfig {
            acquire_timeout_ms: 200,
            ..Default::default()
        },
    };
    let dead =
        cs_db::DomainPool::connect_lazy(DomainId::Identity, &cfg, cs_db::RetryPolicy::default())
            .unwrap();
    let (s, h, b) = call(&real_db_app(&dead), get_req("/readyz")).await;
    let p = assert_problem(s, &h, &b, "unavailable");
    assert!(
        p.errors
            .iter()
            .any(|e| e.pointer == "/barriers/domain.identity.reachable")
    );
    t.cleanup().await;
}

#[tokio::test]
async fn admin_metrics_endpoint() {
    let handle = metrics_handle();
    let st = state(vec![]);
    let public = cs_api::router(st.clone(), 1024);
    let _ = call(&public, get_req("/healthz")).await;
    let admin = cs_api::admin_router(st, handle);
    let (s, h, b) = call(&admin, get_req("/metrics")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        h.get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("text/plain")
    );
    assert!(String::from_utf8_lossy(&b).contains("cs_http_requests_total"));
    // metrics are not exposed on the public router
    assert_eq!(
        call(&public, get_req("/metrics")).await.0,
        StatusCode::NOT_FOUND
    );
}

fn metrics_handle() -> metrics_exporter_prometheus::PrometheusHandle {
    static H: std::sync::OnceLock<metrics_exporter_prometheus::PrometheusHandle> =
        std::sync::OnceLock::new();
    H.get_or_init(|| {
        metrics_exporter_prometheus::PrometheusBuilder::new()
            .install_recorder()
            .unwrap()
    })
    .clone()
}
