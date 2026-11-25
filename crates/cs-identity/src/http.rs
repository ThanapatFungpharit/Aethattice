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

use crate::auth::{AuthService, Authenticated, LoginResult, RequestCtx, source_of};
use crate::jws::AccessClaims;
use crate::me::Revoked;
use crate::recovery::{RecoveryStart, StatusBy};
use crate::webauthn::AssertOutcome;
use axum::extract::Path;
use axum::extract::{ConnectInfo, Extension, FromRequestParts, OriginalUri};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header, request::Parts};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
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
        // rev 10/11: WebAuthn, MFA, sessions, passkeys, recovery.
        .route(
            "/api/v2/auth/webauthn/register/start",
            post(wa_register_start),
        )
        .route(
            "/api/v2/auth/webauthn/register/finish",
            post(wa_register_finish),
        )
        .route("/api/v2/auth/webauthn/login/start", post(wa_login_start))
        .route("/api/v2/auth/webauthn/login/finish", post(wa_login_finish))
        .route("/api/v2/auth/webauthn/assert/start", post(wa_assert_start))
        .route(
            "/api/v2/auth/webauthn/assert/finish",
            post(wa_assert_finish),
        )
        .route("/api/v2/auth/mfa/recovery-code", post(mfa_recovery_code))
        .route("/api/v2/auth/recovery/start", post(recovery_start))
        .route("/api/v2/auth/recovery/status", post(recovery_status))
        .route("/api/v2/me/sessions", get(me_sessions))
        .route("/api/v2/me/sessions/{sid}", delete(me_session_delete))
        .route("/api/v2/me/passkeys", get(me_passkeys))
        .route("/api/v2/me/passkeys/{id}", delete(me_passkey_delete))
        .route(
            "/api/v2/me/recovery-codes",
            get(me_recovery_codes).post(me_recovery_codes_new),
        )
        .route("/api/v2/me/recovery-requests", get(me_recovery_requests))
        .route(
            "/api/v2/me/recovery-requests/{id}",
            delete(me_recovery_request_cancel),
        )
        .route(
            "/api/v2/me/recovery-requests/{id}/approve",
            post(me_recovery_request_approve),
        )
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
    let ua = user_agent(&headers);
    match auth
        .login_finish(&req.login_txn, &fin, &source, ua.as_deref(), &c)
        .await?
    {
        LoginResult::Authenticated(a) => authenticated(a),
        LoginResult::MfaRequired(m) => Ok(no_store(
            Json(MfaRequiredResp {
                state: "mfa_required",
                auth_txn: m.auth_txn.expose_secret().clone(),
                methods: m.methods,
            })
            .into_response(),
        )),
    }
}

/// `200 {state: "mfa_required", auth_txn, methods}` (rev 11).
#[derive(Debug, Serialize)]
struct MfaRequiredResp {
    state: &'static str,
    auth_txn: String,
    methods: Vec<&'static str>,
}

/// The request's `User-Agent`, if it is valid text.
fn user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
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
    IdempotencyKeyHeader(key): IdempotencyKeyHeader,
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
        auth.register_finish(&req.registration_txn, &up, &source, key.as_ref())
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

// ----- rev 10/11: WebAuthn, MFA, sessions, passkeys, recovery -----

/// Optional access token: claims when an `Authorization` header is present.
async fn optional_claims(
    auth: &AuthService,
    method: &Method,
    uri: &axum::http::Uri,
    headers: &HeaderMap,
) -> Result<Option<AccessClaims>, ApiError> {
    if headers.contains_key(header::AUTHORIZATION) {
        Ok(Some(claims_of(auth, method, uri, headers).await?))
    } else {
        Ok(None)
    }
}

#[derive(Debug, Serialize)]
struct RegistrationStartResp {
    registration_txn: String,
    public_key: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

async fn wa_register_start(
    Extension(auth): Extension<Arc<AuthService>>,
    Source(source): Source,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    JsonBody(_): JsonBody<Empty>,
) -> Result<Response, ApiError> {
    let claims = claims_of(&auth, &method, &uri, &headers).await?;
    let s = auth.webauthn_register_start(&claims, &source).await?;
    Ok(no_store(
        Json(RegistrationStartResp {
            registration_txn: s.txn.expose_secret().clone(),
            public_key: s.public_key,
        })
        .into_response(),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WaRegisterFinishReq {
    registration_txn: String,
    credential: serde_json::Value,
    /// Missing, empty or > 100 characters (trimmed): `invalid_request` at `/label`, and the
    /// registration txn is not consumed.
    #[serde(default)]
    label: Option<String>,
}

async fn wa_register_finish(
    Extension(auth): Extension<Arc<AuthService>>,
    Source(source): Source,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    JsonBody(req): JsonBody<WaRegisterFinishReq>,
) -> Result<Response, ApiError> {
    let claims = claims_of(&auth, &method, &uri, &headers).await?;
    let p = auth
        .webauthn_register_finish(
            &claims,
            &req.registration_txn,
            &req.credential,
            req.label.as_deref().unwrap_or_default(),
            &source,
        )
        .await?;
    Ok(no_store(Json(p).into_response()))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WaLoginStartReq {
    tenant: String,
}

#[derive(Debug, Serialize)]
struct WaLoginStartResp {
    login_txn: String,
    public_key: serde_json::Value,
}

async fn wa_login_start(
    Extension(auth): Extension<Arc<AuthService>>,
    Source(source): Source,
    JsonBody(req): JsonBody<WaLoginStartReq>,
) -> Result<Response, ApiError> {
    let s = auth.webauthn_login_start(&req.tenant, &source).await?;
    Ok(no_store(
        Json(WaLoginStartResp {
            login_txn: s.txn.expose_secret().clone(),
            public_key: s.public_key,
        })
        .into_response(),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WaLoginFinishReq {
    login_txn: String,
    credential: serde_json::Value,
}

async fn wa_login_finish(
    Extension(auth): Extension<Arc<AuthService>>,
    Source(source): Source,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    JsonBody(req): JsonBody<WaLoginFinishReq>,
) -> Result<Response, ApiError> {
    let c = ctx(&method, &uri, &headers)?;
    let ua = user_agent(&headers);
    let a = auth
        .webauthn_login_finish(&req.login_txn, &req.credential, &source, ua.as_deref(), &c)
        .await?;
    authenticated(a)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WaAssertStartReq {
    #[serde(default)]
    auth_txn: Option<String>,
}

#[derive(Debug, Serialize)]
struct WaAssertStartResp {
    assert_txn: String,
    public_key: serde_json::Value,
}

async fn wa_assert_start(
    Extension(auth): Extension<Arc<AuthService>>,
    Source(source): Source,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    JsonBody(req): JsonBody<WaAssertStartReq>,
) -> Result<Response, ApiError> {
    let claims = optional_claims(&auth, &method, &uri, &headers).await?;
    let s = auth
        .webauthn_assert_start(req.auth_txn.as_deref(), claims.as_ref(), &source)
        .await?;
    Ok(no_store(
        Json(WaAssertStartResp {
            assert_txn: s.txn.expose_secret().clone(),
            public_key: s.public_key,
        })
        .into_response(),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WaAssertFinishReq {
    assert_txn: String,
    credential: serde_json::Value,
}

async fn wa_assert_finish(
    Extension(auth): Extension<Arc<AuthService>>,
    Source(source): Source,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    JsonBody(req): JsonBody<WaAssertFinishReq>,
) -> Result<Response, ApiError> {
    let claims = optional_claims(&auth, &method, &uri, &headers).await?;
    let c = ctx(&method, &uri, &headers)?;
    let ua = user_agent(&headers);
    match auth
        .webauthn_assert_finish(
            &req.assert_txn,
            &req.credential,
            claims.as_ref(),
            &source,
            ua.as_deref(),
            &c,
        )
        .await?
    {
        AssertOutcome::Authenticated(a) => authenticated(a),
        AssertOutcome::SteppedUp => Ok(no_store(StatusCode::NO_CONTENT.into_response())),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MfaRecoveryCodeReq {
    auth_txn: String,
    code: String,
}

async fn mfa_recovery_code(
    Extension(auth): Extension<Arc<AuthService>>,
    Source(source): Source,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    JsonBody(req): JsonBody<MfaRecoveryCodeReq>,
) -> Result<Response, ApiError> {
    let c = ctx(&method, &uri, &headers)?;
    let ua = user_agent(&headers);
    let a = auth
        .mfa_recovery_code(&req.auth_txn, &req.code, &source, ua.as_deref(), &c)
        .await?;
    authenticated(a)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryStartReq {
    tenant: String,
    login: String,
    method: String,
    #[serde(default)]
    code: Option<String>,
}

#[derive(Debug, Serialize)]
struct RecoveryResp {
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery_txn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    available_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant_expires_in: Option<i64>,
}

async fn recovery_start(
    Extension(auth): Extension<Arc<AuthService>>,
    Source(source): Source,
    headers: HeaderMap,
    JsonBody(req): JsonBody<RecoveryStartReq>,
) -> Result<Response, ApiError> {
    let ua = user_agent(&headers);
    let r = auth
        .recovery_start(
            &req.tenant,
            &req.login,
            &req.method,
            req.code.as_deref(),
            &source,
            ua.as_deref(),
        )
        .await?;
    let (status, body) = match r {
        RecoveryStart::Granted {
            grant,
            grant_expires_in,
        } => (
            StatusCode::OK,
            RecoveryResp {
                state: "granted",
                recovery_txn: None,
                available_at: None,
                grant: Some(grant.expose_secret().clone()),
                grant_expires_in: Some(grant_expires_in),
            },
        ),
        RecoveryStart::Pending { recovery_txn } => (
            StatusCode::ACCEPTED,
            RecoveryResp {
                state: "pending",
                recovery_txn: recovery_txn.map(|t| t.expose_secret().clone()),
                available_at: None,
                grant: None,
                grant_expires_in: None,
            },
        ),
    };
    Ok(no_store((status, Json(body)).into_response()))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryStatusReq {
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    recovery_txn: Option<String>,
}

async fn recovery_status(
    Extension(auth): Extension<Arc<AuthService>>,
    Source(source): Source,
    JsonBody(req): JsonBody<RecoveryStatusReq>,
) -> Result<Response, ApiError> {
    let by = match (&req.token, &req.recovery_txn, &req.code) {
        (Some(t), None, c) => StatusBy::Link {
            token: t,
            code: c.as_deref(),
        },
        (None, Some(t), None) => StatusBy::Txn(t),
        (None, Some(_), Some(_)) => {
            return Err(field_invalid(
                "/code",
                "code is only sent with an email link token",
            ));
        }
        _ => {
            return Err(field_invalid(
                "/token",
                "exactly one of token and recovery_txn is required",
            ));
        }
    };
    let s = auth.recovery_status(by, &source).await?;
    Ok(no_store(
        Json(RecoveryResp {
            state: s.state,
            recovery_txn: None,
            available_at: s.available_at,
            grant: s.grant.map(|g| g.expose_secret().clone()),
            grant_expires_in: s.grant_expires_in,
        })
        .into_response(),
    ))
}

#[derive(Debug, Serialize)]
struct Items<T> {
    items: Vec<T>,
}

async fn me_sessions(
    Extension(auth): Extension<Arc<AuthService>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let claims = claims_of(&auth, &method, &uri, &headers).await?;
    let items = auth.sessions(&claims).await?;
    Ok(no_store(Json(Items { items }).into_response()))
}

async fn me_session_delete(
    Extension(auth): Extension<Arc<AuthService>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(sid): Path<String>,
) -> Result<Response, ApiError> {
    let claims = claims_of(&auth, &method, &uri, &headers).await?;
    let mut r = StatusCode::NO_CONTENT.into_response();
    if auth.session_revoke(&claims, &sid).await? == Revoked::Current {
        r.headers_mut().insert(
            header::SET_COOKIE,
            HeaderValue::from_str(&clear_refresh_cookie()).map_err(Error::internal)?,
        );
    }
    Ok(no_store(r))
}

async fn me_passkeys(
    Extension(auth): Extension<Arc<AuthService>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let claims = claims_of(&auth, &method, &uri, &headers).await?;
    let items = auth.passkeys(&claims).await?;
    Ok(no_store(Json(Items { items }).into_response()))
}

async fn me_passkey_delete(
    Extension(auth): Extension<Arc<AuthService>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let claims = claims_of(&auth, &method, &uri, &headers).await?;
    auth.passkey_delete(&claims, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize)]
struct Remaining {
    remaining: i64,
}

#[derive(Debug, Serialize)]
struct Codes {
    codes: Vec<String>,
}

async fn me_recovery_codes(
    Extension(auth): Extension<Arc<AuthService>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let claims = claims_of(&auth, &method, &uri, &headers).await?;
    let remaining = auth.recovery_codes_remaining(&claims).await?;
    Ok(no_store(Json(Remaining { remaining }).into_response()))
}

async fn me_recovery_codes_new(
    Extension(auth): Extension<Arc<AuthService>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let claims = claims_of(&auth, &method, &uri, &headers).await?;
    let codes = auth.recovery_codes_generate(&claims).await?;
    Ok(no_store(
        Json(Codes {
            codes: codes.iter().map(|c| c.expose_secret().clone()).collect(),
        })
        .into_response(),
    ))
}

async fn me_recovery_requests(
    Extension(auth): Extension<Arc<AuthService>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let claims = claims_of(&auth, &method, &uri, &headers).await?;
    let items = auth.recovery_requests(&claims).await?;
    Ok(no_store(Json(Items { items }).into_response()))
}

fn request_id(id: &str) -> Result<uuid::Uuid, ApiError> {
    uuid::Uuid::parse_str(id).map_err(|_| {
        ApiError::new(Error::new(ErrorCode::NotFound).with_detail("No such recovery request."))
    })
}

async fn me_recovery_request_cancel(
    Extension(auth): Extension<Arc<AuthService>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let claims = claims_of(&auth, &method, &uri, &headers).await?;
    auth.recovery_cancel(&claims, request_id(&id)?).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn me_recovery_request_approve(
    Extension(auth): Extension<Arc<AuthService>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let claims = claims_of(&auth, &method, &uri, &headers).await?;
    auth.recovery_approve(&claims, request_id(&id)?).await?;
    Ok(StatusCode::NO_CONTENT)
}
