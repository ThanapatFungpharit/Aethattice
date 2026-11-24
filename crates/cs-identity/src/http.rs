//! HTTP routes of the identity domain (contract §2.1, §2.4, §3).
//!
//! - `POST /api/v2/auth/opaque/login/start`, `…/login/finish`
//! - `POST /api/v2/auth/opaque/register/start`, `…/register/finish` (204)
//! - `POST /api/v2/auth/token/refresh` (cookie `__Secure-cs_rt`, `Idempotency-Key` required)
//! - `POST /api/v2/auth/logout` (bearer access token; clears the cookie)
//! - `GET /api/v2/auth/jwks`
//! - (rev 7) `POST /api/v2/auth/opaque/reauth/start`, `…/reauth/finish` (204; bearer access
//!   token; password step-up on the existing session)
//! - (rev 7) `GET /api/v2/me` (bearer access token)
//!
//! OPAQUE messages are base64url without padding (rev 5). Token responses carry
//! `Cache-Control: no-store`. Nothing here logs a token, txn id, grant or OPAQUE message.

use crate::auth::{AuthService, Authenticated, source_of};
use axum::extract::{ConnectInfo, Extension, FromRequestParts};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts};
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
    JsonBody(req): JsonBody<LoginFinishReq>,
) -> Result<Response, ApiError> {
    let fin = b64("credential_finalization", &req.credential_finalization)?;
    let a = auth.login_finish(&req.login_txn, &fin, &source).await?;
    authenticated(a)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterStartReq {
    grant: String,
    login: String,
    registration_request: String,
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
    JsonBody(req): JsonBody<RegisterStartReq>,
) -> Result<Response, ApiError> {
    let rr = b64("registration_request", &req.registration_request)?;
    let r = auth
        .register_start(&req.grant, &req.login, &rr, &source)
        .await?;
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

async fn register_finish(
    Extension(auth): Extension<Arc<AuthService>>,
    Source(source): Source,
    JsonBody(req): JsonBody<RegisterFinishReq>,
) -> Result<StatusCode, ApiError> {
    let up = b64("registration_upload", &req.registration_upload)?;
    auth.register_finish(&req.registration_txn, &up, &source)
        .await?;
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
    let a = auth.refresh(&token, key.as_str()).await?;
    authenticated(a)
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, tok) = v.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then_some(tok.trim())
}

async fn logout(
    Extension(auth): Extension<Arc<AuthService>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let tok = bearer(&headers).ok_or_else(|| {
        ApiError::new(Error::new(ErrorCode::Unauthenticated).with_detail("Access token required."))
    })?;
    let claims = auth.verify_bearer(tok).await?;
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

async fn claims_of(
    auth: &AuthService,
    headers: &HeaderMap,
) -> Result<crate::jws::AccessClaims, ApiError> {
    let tok = bearer(headers).ok_or_else(|| {
        ApiError::new(Error::new(ErrorCode::Unauthenticated).with_detail("Access token required."))
    })?;
    Ok(auth.verify_bearer(tok).await?)
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
    headers: HeaderMap,
    JsonBody(req): JsonBody<ReauthStartReq>,
) -> Result<Response, ApiError> {
    let claims = claims_of(&auth, &headers).await?;
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
    headers: HeaderMap,
    JsonBody(req): JsonBody<ReauthFinishReq>,
) -> Result<StatusCode, ApiError> {
    let claims = claims_of(&auth, &headers).await?;
    let fin = b64("credential_finalization", &req.credential_finalization)?;
    auth.reauth_finish(&claims, &req.reauth_txn, &fin, &source)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn me(
    Extension(auth): Extension<Arc<AuthService>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let claims = claims_of(&auth, &headers).await?;
    let m = auth.me(&claims).await?;
    Ok(no_store(Json(m).into_response()))
}
