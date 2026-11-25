//! HTTP routes of the identity domain (contract §2.1, §2.4, §3).
//!
//! - `POST /api/v2/auth/opaque/login/start`, `…/login/finish`
//! - `POST /api/v2/auth/opaque/register/start`, `…/register/finish` (204): with a setup-link
//!   `grant`, or (rev 9) with the session's access token and `purpose` (step-up required)
//! - `POST /api/v2/auth/token/refresh` (cookie `__Secure-cs_rt`, `Idempotency-Key` required)
//! - `POST /api/v2/auth/logout` (bearer access token; clears the cookie)
//! - `GET /api/v2/auth/jwks`
//! - (rev 7) `POST /api/v2/auth/opaque/reauth/start`, `…/reauth/finish` (204; bearer access
//!   token; password step-up on the existing session)
//! - (rev 7) `GET /api/v2/me` (bearer access token)
//!
//! DPoP (rev 8): `login/finish` and `token/refresh` take an optional `DPoP` proof; requests with
//! an access token use `Authorization: DPoP <token>` plus a proof when the token is `cnf`-bound,
//! `Bearer` otherwise ([`AuthService::authorize`]).
//!
//! OPAQUE messages are base64url without padding (rev 5). Token responses carry
//! `Cache-Control: no-store`. Nothing here logs a token, txn id, grant or OPAQUE message.

use crate::auth::{AuthService, Authenticated, RequestCtx, source_of};
use crate::jws::AccessClaims;
use axum::extract::{ConnectInfo, Extension, FromRequestParts, OriginalUri};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header, request::Parts};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cs_api::{ApiError, ApiState, IdempotencyKeyHeader, JsonBody};
use cs_common::error::{Error, ErrorCode};
use cs_identity_wire::{KSF_ALGORITHM, KsfParams};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

/// Refresh cookie name (contract §2.4).
pub const REFRESH_COOKIE: &str = "__Secure-cs_rt";
/// Refresh cookie path (contract §2.4).
pub const REFRESH_COOKIE_PATH: &str = "/api/v2/auth/token";

/// The identity routes, to merge into the public route table before the M0 middleware.
pub fn routes(auth: Arc<AuthService>) -> axum::Router<ApiState> {
    Router::new()
        .route("/api/v2/auth/opaque/login/start", post(login_start))
        .route("/api/v2/auth/opaque/login/finish", post(login_finish))
        .route("/api/v2/auth/opaque/register/start", post(register_start))
        .route("/api/v2/auth/opaque/register/finish", post(register_finish))
        .route("/api/v2/auth/token/refresh", post(refresh))
        .route("/api/v2/auth/logout", post(logout))
        .route("/api/v2/auth/jwks", get(jwks))
        .route("/api/v2/auth/opaque/reauth/start", post(reauth_start))
        .route("/api/v2/auth/opaque/reauth/finish", post(reauth_finish))
        .route("/api/v2/me", get(me))
        .layer(Extension(auth))
}

/// The client source (`[R12]`: IPv4 /32, IPv6 /64) from the connection.
#[derive(Debug, Clone)]
pub struct Source(pub String);

impl<S: Send + Sync> FromRequestParts<S> for Source {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, ApiError> {
        let ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip());
        Ok(Source(source_of(ip)))
    }
}

#[derive(Debug, Serialize)]
struct KsfWire {
    algorithm: &'static str,
    m_kib: u32,
    t: u32,
    p: u32,
}

impl From<KsfParams> for KsfWire {
    fn from(k: KsfParams) -> Self {
        Self {
            algorithm: KSF_ALGORITHM,
            m_kib: k.m_kib,
            t: k.t,
            p: k.p,
        }
    }
}

fn b64(field: &str, s: &str) -> Result<Vec<u8>, ApiError> {
    URL_SAFE_NO_PAD.decode(s).map_err(|_| {
        ApiError::new(
            Error::new(ErrorCode::InvalidRequest)
                .with_detail(format!("{field} must be base64url without padding")),
        )
    })
}

fn no_store(mut r: Response) -> Response {
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginStartReq {
    tenant: String,
    login: String,
    credential_request: String,
}

#[derive(Debug, Serialize)]
struct LoginStartResp {
    login_txn: String,
    credential_response: String,
    ksf_params: KsfWire,
}

async fn login_start(
    Extension(auth): Extension<Arc<AuthService>>,
    Source(source): Source,
    JsonBody(req): JsonBody<LoginStartReq>,
) -> Result<Response, ApiError> {
    let cr = b64("credential_request", &req.credential_request)?;
    let r = auth
        .login_start(&req.tenant, &req.login, &cr, &source)
        .await?;
    Ok(no_store(
        Json(LoginStartResp {
            login_txn: r.login_txn.expose_secret().clone(),
            credential_response: URL_SAFE_NO_PAD.encode(&r.credential_response),
            ksf_params: r.ksf_params.into(),
        })
        .into_response(),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginFinishReq {
    login_txn: String,
    credential_finalization: String,
}

#[derive(Debug, Serialize)]
struct AuthResult {
    state: &'static str,
    access_token: String,
    expires_in: i64,
    session_id: String,
    /// rev 9: present (and `true`) only when the client should re-register (`ksf_upgrade`).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    reregister: bool,
}

fn unauthenticated(detail: &str) -> ApiError {
    ApiError::new(Error::new(ErrorCode::Unauthenticated).with_detail(detail.to_owned()))
}

/// The single `DPoP` header, if any (two headers are refused, RFC 9449 §4.3).
fn dpop_header(headers: &HeaderMap) -> Result<Option<&str>, ApiError> {
    let mut it = headers.get_all("dpop").iter();
    let first = it.next();
    if it.next().is_some() {
        return Err(unauthenticated("Invalid DPoP proof."));
    }
    first
        .map(|v| {
            v.to_str()
                .map_err(|_| unauthenticated("Invalid DPoP proof."))
        })
        .transpose()
}

fn ctx<'a>(
    method: &'a Method,
    uri: &'a axum::http::Uri,
    headers: &'a HeaderMap,
) -> Result<RequestCtx<'a>, ApiError> {
    Ok(RequestCtx {
        method: method.as_str(),
        path: uri.path(),
        dpop: dpop_header(headers)?,
    })
}

/// `Set-Cookie` for a refresh token (contract §2.4).
pub fn refresh_cookie(token: &str, max_age: i64) -> String {
    format!(
        "{REFRESH_COOKIE}={token}; Path={REFRESH_COOKIE_PATH}; Max-Age={}; Secure; HttpOnly; SameSite=Strict",
        max_age.max(0)
    )
}

/// `Set-Cookie` clearing the refresh cookie (contract §3 `[R10]`; `Secure` is required by
/// browsers for a `__Secure-` cookie to be accepted, so the attributes are repeated).
pub fn clear_refresh_cookie() -> String {
    format!(
        "{REFRESH_COOKIE}=; Path={REFRESH_COOKIE_PATH}; Max-Age=0; Secure; HttpOnly; SameSite=Strict"
    )
}

fn authenticated(a: Authenticated) -> Result<Response, ApiError> {
    let cookie = refresh_cookie(a.refresh_token.expose_secret(), a.refresh_max_age);
    let mut r = Json(AuthResult {
        state: "authenticated",
        access_token: a.access_token.expose_secret().clone(),
        expires_in: a.expires_in,
        session_id: a.session_id.as_uuid().to_string(),
        reregister: a.reregister,
    })
    .into_response();
    r.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).map_err(Error::internal)?,
    );
    Ok(no_store(r))
}

async fn login_finish(
    Extension(auth): Extension<Arc<AuthService>>,
    Source(source): Source,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    JsonBody(req): JsonBody<LoginFinishReq>,
) -> Result<Response, ApiError> {
    let fin = b64("credential_finalization", &req.credential_finalization)?;
    let c = ctx(&method, &uri, &headers)?;
    let a = auth.login_finish(&req.login_txn, &fin, &source, &c).await?;
    authenticated(a)
}

/// Either `{grant, login, registration_request}` (setup link) or, with the session's access
/// token, `{purpose, registration_request}` (rev 9; a `login` is refused).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterStartReq {
    #[serde(default)]
    grant: Option<String>,
    #[serde(default)]
    login: Option<String>,
    #[serde(default)]
    purpose: Option<String>,
    registration_request: String,
}

fn field_invalid(pointer: &str, detail: &str) -> ApiError {
    ApiError::new(
        Error::new(ErrorCode::InvalidRequest)
            .with_detail(detail.to_owned())
            .with_field_error(cs_common::error::FieldError {
                pointer: pointer.to_owned(),
                code: ErrorCode::InvalidRequest.as_str().to_owned(),
                detail: detail.to_owned(),
            }),
    )
}

#[derive(Debug, Serialize)]
struct RegisterStartResp {
    registration_txn: String,
    registration_response: String,
    ksf_params: KsfWire,
}

async fn register_start(
    Extension(auth): Extension<Arc<AuthService>>,
    Source(source): Source,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    JsonBody(req): JsonBody<RegisterStartReq>,
) -> Result<Response, ApiError> {
    let rr = b64("registration_request", &req.registration_request)?;
    let r = match (req.purpose, req.grant, req.login) {
        (Some(purpose), None, None) => {
            let claims = claims_of(&auth, &method, &uri, &headers).await?;
            auth.register_start_session(&claims, &purpose, &rr, &source)
                .await?
        }
        (Some(_), _, Some(_)) => {
            return Err(field_invalid(
                "/login",
                "login is taken from the session; it must not be sent with purpose",
            ));
        }
        (Some(_), Some(_), None) => {
            return Err(field_invalid(
                "/grant",
                "grant and purpose are mutually exclusive",
            ));
        }
        (None, Some(grant), Some(login)) => {
            auth.register_start(&grant, &login, &rr, &source).await?
        }
        (None, None, _) => {
            return Err(field_invalid("/grant", "grant or purpose is required"));
        }
        (None, Some(_), None) => return Err(field_invalid("/login", "login is required")),
    };
    Ok(no_store(
        Json(RegisterStartResp {
            registration_txn: r.registration_txn.expose_secret().clone(),
            registration_response: URL_SAFE_NO_PAD.encode(&r.registration_response),
            ksf_params: r.ksf_params.into(),
        })
        .into_response(),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterFinishReq {
    registration_txn: String,
    registration_upload: String,
}

/// With an `Authorization` header the txn must be a session re-registration (rev 9);
/// without one, a setup-link registration.
async fn register_finish(
    Extension(auth): Extension<Arc<AuthService>>,
    Source(source): Source,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    JsonBody(req): JsonBody<RegisterFinishReq>,
) -> Result<StatusCode, ApiError> {
    let up = b64("registration_upload", &req.registration_upload)?;
    if headers.contains_key(header::AUTHORIZATION) {
        let claims = claims_of(&auth, &method, &uri, &headers).await?;
        auth.register_finish_session(&claims, &req.registration_txn, &up, &source)
            .await?;
    } else {
        auth.register_finish(&req.registration_txn, &up, &source)
            .await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut found = None;
    for v in headers.get_all(header::COOKIE) {
        let Ok(s) = v.to_str() else { continue };
        for part in s.split(';') {
            if let Some((k, val)) = part.trim().split_once('=')
                && k == name
            {
                if found.is_some() {
                    // Two refresh cookies: ambiguous, refuse.
                    return None;
                }
                found = Some(val.to_owned());
            }
        }
    }
    found
}

async fn refresh(
    Extension(auth): Extension<Arc<AuthService>>,
    IdempotencyKeyHeader(key): IdempotencyKeyHeader,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let key = key.ok_or_else(|| {
        ApiError::new(
            Error::new(ErrorCode::InvalidRequest)
                .with_detail("Idempotency-Key is required for token refresh."),
        )
    })?;
    let token = cookie_value(&headers, REFRESH_COOKIE).ok_or_else(|| {
        ApiError::new(Error::new(ErrorCode::Unauthenticated).with_detail("Authentication failed."))
    })?;
    let c = ctx(&method, &uri, &headers)?;
    let a = auth.refresh(&token, key.as_str(), &c).await?;
    authenticated(a)
}

async fn logout(
    Extension(auth): Extension<Arc<AuthService>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let claims = claims_of(&auth, &method, &uri, &headers).await?;
    auth.logout(&claims).await?;
    let mut r = StatusCode::NO_CONTENT.into_response();
    r.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&clear_refresh_cookie()).map_err(Error::internal)?,
    );
    Ok(no_store(r))
}

async fn jwks(Extension(auth): Extension<Arc<AuthService>>) -> Result<Response, ApiError> {
    let doc = auth.access_tokens().jwks().await?;
    Ok(Json(doc).into_response())
}

/// Claims of the request's access token (`DPoP` or `Bearer`, rev 8).
async fn claims_of(
    auth: &AuthService,
    method: &Method,
    uri: &axum::http::Uri,
    headers: &HeaderMap,
) -> Result<AccessClaims, ApiError> {
    let authorization = match headers.get(header::AUTHORIZATION) {
        Some(v) => Some(
            v.to_str()
                .map_err(|_| unauthenticated("Access token required."))?,
        ),
        None => None,
    };
    let c = ctx(method, uri, headers)?;
    Ok(auth.authorize(authorization, &c).await?)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReauthStartReq {
    credential_request: String,
}

#[derive(Debug, Serialize)]
struct ReauthStartResp {
    reauth_txn: String,
    credential_response: String,
    ksf_params: KsfWire,
}

async fn reauth_start(
    Extension(auth): Extension<Arc<AuthService>>,
    Source(source): Source,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    JsonBody(req): JsonBody<ReauthStartReq>,
) -> Result<Response, ApiError> {
    let claims = claims_of(&auth, &method, &uri, &headers).await?;
    let cr = b64("credential_request", &req.credential_request)?;
    let r = auth.reauth_start(&claims, &cr, &source).await?;
    Ok(no_store(
        Json(ReauthStartResp {
            reauth_txn: r.login_txn.expose_secret().clone(),
            credential_response: URL_SAFE_NO_PAD.encode(&r.credential_response),
            ksf_params: r.ksf_params.into(),
        })
        .into_response(),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReauthFinishReq {
    reauth_txn: String,
    credential_finalization: String,
}

async fn reauth_finish(
    Extension(auth): Extension<Arc<AuthService>>,
    Source(source): Source,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    JsonBody(req): JsonBody<ReauthFinishReq>,
) -> Result<StatusCode, ApiError> {
    let claims = claims_of(&auth, &method, &uri, &headers).await?;
    let fin = b64("credential_finalization", &req.credential_finalization)?;
    auth.reauth_finish(&claims, &req.reauth_txn, &fin, &source)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn me(
    Extension(auth): Extension<Arc<AuthService>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let claims = claims_of(&auth, &method, &uri, &headers).await?;
    let m = auth.me(&claims).await?;
    Ok(no_store(Json(m).into_response()))
}
