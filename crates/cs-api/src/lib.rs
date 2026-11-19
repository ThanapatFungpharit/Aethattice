//! HTTP surface of M0 (contract §7, §2, §8; spec §2.6, §3.4, App. D).
//!
//! - `GET /healthz`: liveness (process only).
//! - `GET /readyz`: readiness; 200 only when every [`ReadinessBarrier`] passes, otherwise 503
//!   `unavailable` problem listing the failing barriers (names only, causes go to the log).
//! - Every response carries `X-Request-Id` (generated server-side, UUIDv7).
//! - Every error is `application/problem+json`: handler errors ([`ApiError`]), unknown routes
//!   (404), wrong methods (405), body-limit and body-parse failures, panics (500) — the
//!   finalizing middleware converts any non-problem error response.
//! - `instance` is the request path without the query string (rev 2).
//! - W3C trace context (`traceparent`) is extracted into the request span.
//! - The admin listener serves Prometheus `/metrics` separately from the public listener.

mod readiness;

pub use readiness::{DomainReachable, MigrationsCurrent, ReadinessBarrier};

use axum::body::Bytes;
use axum::extract::{FromRequest, FromRequestParts, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use cs_common::error::{Error as CsError, ErrorCode, PROBLEM_CONTENT_TYPE};
use cs_common::id::RequestId;
use cs_common::idempotency::{IDEMPOTENCY_KEY_HEADER, IdempotencyKey};
use metrics_exporter_prometheus::PrometheusHandle;
use serde::de::DeserializeOwned;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::Instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// Response header carrying the request ID.
pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// Per-request context inserted by the middleware.
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub request_id: RequestId,
    /// Path without the query string; used as problem `instance`.
    pub path: String,
}

/// Shared server state.
#[derive(Clone)]
pub struct ApiState {
    deployment_domain: Arc<str>,
    barriers: Arc<Vec<Arc<dyn ReadinessBarrier>>>,
    readiness_timeout: Duration,
}

impl std::fmt::Debug for ApiState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiState")
            .field("deployment_domain", &self.deployment_domain)
            .field(
                "barriers",
                &self.barriers.iter().map(|b| b.name()).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl ApiState {
    pub fn new(
        deployment_domain: &str,
        barriers: Vec<Arc<dyn ReadinessBarrier>>,
        readiness_timeout: Duration,
    ) -> Self {
        Self {
            deployment_domain: Arc::from(deployment_domain),
            barriers: Arc::new(barriers),
            readiness_timeout,
        }
    }

    pub fn deployment_domain(&self) -> &str {
        &self.deployment_domain
    }
}

// ---------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------

/// A handler error. Rendered as problem+json by the finalizing middleware, which knows the
/// request ID, path and deployment domain.
#[derive(Debug)]
pub struct ApiError(pub Box<CsError>);

impl ApiError {
    pub fn new(e: CsError) -> Self {
        ApiError(Box::new(e))
    }
}

impl<E: Into<CsError>> From<E> for ApiError {
    fn from(e: E) -> Self {
        ApiError::new(e.into())
    }
}

#[derive(Clone)]
struct PendingProblem(Arc<CsError>);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.0.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut r = status.into_response();
        r.extensions_mut().insert(PendingProblem(Arc::new(*self.0)));
        r
    }
}

/// Render a problem response (also usable outside the middleware, e.g. by tests or adapters).
pub fn problem_response(
    err: &CsError,
    deployment_domain: &str,
    instance: &str,
    request_id: &RequestId,
) -> Response {
    if matches!(err.code(), cs_common::Code::Core(ErrorCode::Internal)) || err.cause().is_some() {
        tracing::error!(request_id = %request_id, code = %err.code(), error = %err, "request failed");
    }
    let doc = err.to_problem(deployment_domain, instance, request_id);
    let body = serde_json::to_vec(&doc).unwrap_or_else(|_| b"{}".to_vec());
    let status = StatusCode::from_u16(doc.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut r = (status, body).into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(PROBLEM_CONTENT_TYPE),
    );
    if let Some(secs) = err.retry_after_header_secs()
        && let Ok(v) = HeaderValue::from_str(&secs.to_string())
    {
        r.headers_mut().insert(header::RETRY_AFTER, v);
    }
    r
}

/// Error code for a non-problem error response produced by the framework.
fn code_for_status(status: StatusCode) -> ErrorCode {
    match status.as_u16() {
        400 | 422 => ErrorCode::InvalidRequest,
        401 => ErrorCode::Unauthenticated,
        403 => ErrorCode::PermissionDenied,
        404 => ErrorCode::NotFound,
        405 => ErrorCode::MethodNotAllowed,
        409 => ErrorCode::Conflict,
        412 => ErrorCode::PreconditionFailed,
        413 => ErrorCode::PayloadTooLarge,
        415 => ErrorCode::UnsupportedMediaType,
        429 => ErrorCode::RateLimited,
        503 => ErrorCode::Unavailable,
        408 | 504 => ErrorCode::Timeout,
        _ => ErrorCode::Internal,
    }
}

fn is_problem(r: &Response) -> bool {
    r.headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|v| v.as_bytes() == PROBLEM_CONTENT_TYPE.as_bytes())
}

struct HeaderExtractor<'a>(&'a HeaderMap);

impl opentelemetry::propagation::Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }
    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}

/// Outermost middleware: request ID, trace context, metrics, problem finalization.
async fn request_middleware(
    State(state): State<ApiState>,
    mut req: Request,
    next: Next,
) -> Response {
    let started = Instant::now();
    let path = req.uri().path().to_owned();
    let method = req.method().clone();
    let Ok(request_id) = RequestId::generate() else {
        // CSPRNG failure: fail closed without an ID.
        let mut r = (
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"type":"about:blank","title":"Service unavailable","status":503,"code":"unavailable","retryable":true}"#,
        )
            .into_response();
        r.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(PROBLEM_CONTENT_TYPE),
        );
        return r;
    };
    let span = tracing::info_span!("http_request", %request_id, %method, path = %path);
    let parent = opentelemetry::global::get_text_map_propagator(|p| {
        p.extract(&HeaderExtractor(req.headers()))
    });
    let _ = span.set_parent(parent);
    req.extensions_mut().insert(RequestContext {
        request_id,
        path: path.clone(),
    });
    let mut resp = next.run(req).instrument(span).await;

    let status = resp.status();
    if let Some(PendingProblem(err)) = resp.extensions_mut().remove::<PendingProblem>() {
        resp = problem_response(&err, &state.deployment_domain, &path, &request_id);
    } else if (status.is_client_error() || status.is_server_error()) && !is_problem(&resp) {
        // Framework-produced error (unknown route, body limit, extractor rejection, panic).
        let err = CsError::new(code_for_status(status));
        resp = problem_response(&err, &state.deployment_domain, &path, &request_id);
    }
    if let Ok(v) = HeaderValue::from_str(&request_id.to_string()) {
        resp.headers_mut().insert(REQUEST_ID_HEADER, v);
    }
    metrics::counter!("cs_http_requests_total", "status" => resp.status().as_u16().to_string())
        .increment(1);
    metrics::histogram!("cs_http_request_duration_seconds").record(started.elapsed().as_secs_f64());
    resp
}

// ---------------------------------------------------------------------------------------------
// Extractors
// ---------------------------------------------------------------------------------------------

/// The `Idempotency-Key` request header (D.3). Absent → `None`; malformed → 400 problem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdempotencyKeyHeader(pub Option<IdempotencyKey>);

impl<S: Send + Sync> FromRequestParts<S> for IdempotencyKeyHeader {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, ApiError> {
        let mut values = parts.headers.get_all(IDEMPOTENCY_KEY_HEADER).iter();
        let Some(v) = values.next() else {
            return Ok(Self(None));
        };
        let invalid = || {
            ApiError::new(CsError::new(ErrorCode::InvalidRequest).with_detail(
                "Idempotency-Key must be a single header of 1 to 255 visible ASCII characters.",
            ))
        };
        if values.next().is_some() {
            return Err(invalid());
        }
        let s = v.to_str().map_err(|_| invalid())?;
        IdempotencyKey::parse(s)
            .map(|k| Self(Some(k)))
            .map_err(|_| invalid())
    }
}

/// A JSON body whose every rejection is a problem: wrong media type → 415, too large → 413,
/// malformed or wrong shape → 400 `invalid_request`.
#[derive(Debug, Clone)]
pub struct JsonBody<T>(pub T);

impl<T: DeserializeOwned, S: Send + Sync> FromRequest<S> for JsonBody<T> {
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, ApiError> {
        let is_json = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/json"));
        if !is_json {
            return Err(ApiError::new(CsError::new(ErrorCode::UnsupportedMediaType)));
        }
        let bytes = body_bytes(req, state).await?;
        serde_json::from_slice(&bytes).map(JsonBody).map_err(|_| {
            ApiError::new(
                CsError::new(ErrorCode::InvalidRequest)
                    .with_detail("The request body is not valid JSON for this operation."),
            )
        })
    }
}

/// Read the whole body (respecting the configured limit) or fail with a problem.
pub async fn body_bytes<S: Send + Sync>(req: Request, state: &S) -> Result<Bytes, ApiError> {
    Bytes::from_request(req, state).await.map_err(|e| {
        if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::new(CsError::new(ErrorCode::PayloadTooLarge))
        } else {
            ApiError::new(
                CsError::new(ErrorCode::InvalidRequest).with_detail("Unreadable request body."),
            )
        }
    })
}

// ---------------------------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------------------------

async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn readyz(State(state): State<ApiState>) -> Result<Json<serde_json::Value>, ApiError> {
    let checks = state.barriers.iter().map(|b| {
        let b = b.clone();
        let timeout = state.readiness_timeout;
        async move {
            let res = match tokio::time::timeout(timeout, b.check()).await {
                Ok(r) => r,
                Err(_) => Err("timed out".to_owned()),
            };
            (b.name(), res)
        }
    });
    let results = futures::future::join_all(checks).await;
    let failing: Vec<_> = results.iter().filter(|(_, r)| r.is_err()).collect();
    if failing.is_empty() {
        let names: Vec<_> = results
            .iter()
            .map(|(n, _)| serde_json::json!({ "name": n, "ok": true }))
            .collect();
        return Ok(Json(
            serde_json::json!({ "status": "ready", "barriers": names }),
        ));
    }
    let mut err = CsError::new(ErrorCode::Unavailable)
        .with_detail("Not ready: one or more readiness barriers are not satisfied.");
    for (name, r) in failing {
        if let Err(reason) = r {
            tracing::warn!(barrier = %name, %reason, "readiness barrier failing");
        }
        err = err.with_field_error(cs_common::error::FieldError {
            pointer: format!("/barriers/{name}"),
            code: ErrorCode::Unavailable.as_str().to_owned(),
            detail: format!("readiness barrier {name} is not satisfied"),
        });
    }
    Err(ApiError::new(err))
}

async fn method_not_allowed() -> ApiError {
    ApiError::new(CsError::new(ErrorCode::MethodNotAllowed))
}

async fn not_found() -> ApiError {
    ApiError::new(CsError::new(ErrorCode::NotFound))
}

/// Wrap any router with the M0 middleware stack (request ID, trace context, problem
/// finalization, body limit, panic catching) and problem fallbacks for 404 / 405.
pub fn with_middleware(routes: Router<ApiState>, state: ApiState, max_body_bytes: usize) -> Router {
    routes
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(tower_http::catch_panic::CatchPanicLayer::new())
        .layer(axum::extract::DefaultBodyLimit::max(max_body_bytes))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            max_body_bytes,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            request_middleware,
        ))
        .with_state(state)
}

/// The public route table: `/healthz`, `/readyz`. Later milestones add `/api/v2/...` routes
/// to this table before [`with_middleware`] is applied.
pub fn public_routes() -> Router<ApiState> {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
}

/// The public router with the full middleware stack.
pub fn router(state: ApiState, max_body_bytes: usize) -> Router {
    with_middleware(public_routes(), state, max_body_bytes)
}

/// The admin router (separate listener): Prometheus `/metrics`.
pub fn admin_router(state: ApiState, metrics: PrometheusHandle) -> Router {
    let routes = Router::new()
        .route(
            "/metrics",
            get(move || {
                let m = metrics.clone();
                async move {
                    let mut r = m.render().into_response();
                    r.headers_mut().insert(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
                    );
                    r
                }
            }),
        )
        .route("/healthz", get(healthz));
    with_middleware(routes, state, 4096)
}

/// Serve `app` on `listener` until `shutdown` resolves.
pub async fn serve(
    listener: tokio::net::TcpListener,
    app: Router,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown)
        .await
}
