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
//!
//! Rev 15/16: every write except `token/refresh` takes an optional `Idempotency-Key`; the
//! digest covers the method, the route template, the path parameters and the JCS body, and
//! the services record the result in the same transaction as the effect ([`crate::idem`]).
//! Fresh and replayed responses are rendered by [`crate::wire`], so they are byte-identical.

use crate::auth::{AuthService, LoginResult, RequestCtx, source_of};
use crate::idem::{IdemRequest, Out, Reply};
use crate::jws::AccessClaims;
use crate::me::Revoked;
use crate::recovery::StatusBy;
use crate::webauthn::AssertOutcome;
use crate::wire::{self, CeremonyField};
use axum::extract::{
    ConnectInfo, Extension, FromRequest, FromRequestParts, MatchedPath, OriginalUri, Path,
    RawPathParams, Request,
};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header, request::Parts};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cs_api::{ApiError, ApiState, IdempotencyKeyHeader, body_bytes};
use cs_common::error::{Code, Error, ErrorCode};
use cs_db::DbError;
use cs_db::idempotency::{RequestBody, request_digest};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

pub use crate::wire::{REFRESH_COOKIE, REFRESH_COOKIE_PATH, clear_refresh_cookie, refresh_cookie};

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

// ----- rev 15: Idempotency-Key on identity writes -----

/// A write's JSON body plus, with an `Idempotency-Key`, its digest over
/// `[method, route template, path params, JCS(body)]` (M0 §5.3). Rejections as [`JsonBody`].
#[derive(Debug)]
pub struct IdemJson<T>(pub T, pub Option<IdemRequest>);

impl<T: DeserializeOwned, S: Send + Sync> FromRequest<S> for IdemJson<T> {
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, ApiError> {
        let (mut parts, body) = req.into_parts();
        let IdemParts(idem) = IdemParts::from_request_parts(&mut parts, state).await?;
        let req = Request::from_parts(parts, body);
        let is_json = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/json"));
        if !is_json {
            return Err(ApiError::new(Error::new(ErrorCode::UnsupportedMediaType)));
        }
        let bytes = body_bytes(req, state).await?;
        let v: T = serde_json::from_slice(&bytes).map_err(|_| {
            ApiError::new(
                Error::new(ErrorCode::InvalidRequest)
                    .with_detail("The request body is not valid JSON for this operation."),
            )
        })?;
        let idem = match idem {
            Some(p) => Some(p.digest(RequestBody::Json(&bytes))?),
            None => None,
        };
        Ok(IdemJson(v, idem))
    }
}

/// The idempotency parts of a request (key, method, route template, path params); a
/// body-less write digests the empty body.
#[derive(Debug)]
pub struct IdemParts(Option<Pending>);

#[derive(Debug)]
pub struct Pending {
    key: cs_common::idempotency::IdempotencyKey,
    method: String,
    route: String,
    params: BTreeMap<String, String>,
}

impl Pending {
    fn digest(self, body: RequestBody<'_>) -> Result<IdemRequest, ApiError> {
        let digest = request_digest(&self.method, &self.route, &self.params, body)
            .map_err(|e| ApiError::new(Error::internal(e)))?;
        Ok(IdemRequest {
            key: self.key,
            digest,
            route: self.route,
        })
    }
}

impl<S: Send + Sync> FromRequestParts<S> for IdemParts {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        let IdempotencyKeyHeader(key) =
            IdempotencyKeyHeader::from_request_parts(parts, state).await?;
        let Some(key) = key else {
            return Ok(IdemParts(None));
        };
        let route = parts
            .extensions
            .get::<MatchedPath>()
            .map(|m| m.as_str().to_owned())
            .ok_or_else(|| ApiError::new(Error::new(ErrorCode::Internal)))?;
        let params = match RawPathParams::from_request_parts(parts, state).await {
            Ok(p) => p
                .iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect(),
            Err(_) => BTreeMap::new(),
        };
        Ok(IdemParts(Some(Pending {
            key,
            method: parts.method.as_str().to_owned(),
            route,
            params,
        })))
    }
}

impl IdemParts {
    fn absent_body(self) -> Result<Option<IdemRequest>, ApiError> {
        self.0.map(|p| p.digest(RequestBody::Absent)).transpose()
    }
}

/// The response of a [`Reply`]: status, JSON body, `Set-Cookie`, `Cache-Control: no-store`.
fn respond(r: Reply) -> Result<Response, ApiError> {
    let status = StatusCode::from_u16(r.status).map_err(Error::internal)?;
    let mut resp = if r.body.is_empty() {
        status.into_response()
    } else {
        let mut x = (status, r.body).into_response();
        x.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        x
    };
    if let Some(c) = &r.cookie {
        resp.headers_mut().insert(
            header::SET_COOKIE,
            HeaderValue::from_str(c).map_err(Error::internal)?,
        );
    }
    Ok(no_store(resp))
}

/// Render a fresh value with the same function the idempotency store used, or the stored
/// reply: the bytes are identical either way.
fn out<T>(
    o: Out<T>,
    render: impl FnOnce(T) -> Result<Reply, DbError>,
) -> Result<Response, ApiError> {
    let r = match o {
        Out::Value(v) => render(v).map_err(Error::internal)?,
        Out::Reply(r) => r,
    };
    respond(r)
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

async fn login_start(
    Extension(auth): Extension<Arc<AuthService>>,
    Source(source): Source,
    IdemJson(req, idem): IdemJson<LoginStartReq>,
) -> Result<Response, ApiError> {
    let cr = b64("credential_request", &req.credential_request)?;
    let o = auth
        .login_start(&req.tenant, &req.login, &cr, &source, idem)
        .await?;
    out(o, |v| wire::login_start(&v))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginFinishReq {
    login_txn: String,
    credential_finalization: String,
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

fn login_result(r: LoginResult) -> Result<Reply, DbError> {
    match r {
        LoginResult::Authenticated(a) => wire::authenticated(&a),
        LoginResult::MfaRequired(m) => wire::mfa_required(&m.auth_txn, &m.methods),
    }
}

async fn login_finish(
    Extension(auth): Extension<Arc<AuthService>>,
    Source(source): Source,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    IdemJson(req, idem): IdemJson<LoginFinishReq>,
) -> Result<Response, ApiError> {
    let fin = b64("credential_finalization", &req.credential_finalization)?;
    let c = ctx(&method, &uri, &headers)?;
    let ua = user_agent(&headers);
    let o = auth
        .login_finish(&req.login_txn, &fin, &source, ua.as_deref(), &c, idem)
        .await?;
    out(o, login_result)
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

async fn register_start(
    Extension(auth): Extension<Arc<AuthService>>,
    Source(source): Source,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    IdemJson(req, idem): IdemJson<RegisterStartReq>,
) -> Result<Response, ApiError> {
    let rr = b64("registration_request", &req.registration_request)?;
    let o = match (req.purpose, req.grant, req.login) {
        (Some(purpose), None, None) => {
            let claims = claims_of(&auth, &method, &uri, &headers).await?;
            auth.register_start_session(&claims, &purpose, &rr, &source, idem)
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
            auth.register_start(&grant, &login, &rr, &source, idem)
                .await?
        }
        (None, None, _) => {
            return Err(field_invalid("/grant", "grant or purpose is required"));
        }
        (None, Some(_), None) => return Err(field_invalid("/login", "login is required")),
    };
    out(o, |v| wire::register_start(&v))
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
    IdemJson(req, idem): IdemJson<RegisterFinishReq>,
) -> Result<Response, ApiError> {
    let up = b64("registration_upload", &req.registration_upload)?;
    let o = if headers.contains_key(header::AUTHORIZATION) {
        let claims = claims_of(&auth, &method, &uri, &headers).await?;
        auth.register_finish_session(&claims, &req.registration_txn, &up, &source, idem)
            .await?
    } else {
        auth.register_finish(&req.registration_txn, &up, &source, idem)
            .await?
    };
    out(o, |()| Ok(wire::no_content(false)))
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

/// `token/refresh` keeps its own `[R1]` mechanism (rev 15).
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
    respond(wire::authenticated(&a).map_err(Error::internal)?)
}

/// Rev 16 P4: when the session check fails with `unauthenticated` and the request carries an
/// `Idempotency-Key`, a stored logout reply may still be replayed.
async fn logout_or_replay(
    auth: &AuthService,
    e: ApiError,
    idem: Option<IdemRequest>,
    method: &Method,
    uri: &axum::http::Uri,
    headers: &HeaderMap,
    own_sid: Option<&str>,
) -> Result<Response, ApiError> {
    let Some(idem) = idem else { return Err(e) };
    if !matches!(e.0.code(), Code::Core(ErrorCode::Unauthenticated)) {
        return Err(e);
    }
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let c = ctx(method, uri, headers)?;
    let r = auth.logout_replay(authorization, &c, idem, own_sid).await?;
    respond(r)
}

async fn logout(
    Extension(auth): Extension<Arc<AuthService>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    idem: IdemParts,
) -> Result<Response, ApiError> {
    let idem = idem.absent_body()?;
    let claims = match claims_of(&auth, &method, &uri, &headers).await {
        Ok(c) => c,
        Err(e) => return logout_or_replay(&auth, e, idem, &method, &uri, &headers, None).await,
    };
    let o = auth.logout(&claims, idem).await?;
    out(o, |()| Ok(wire::no_content(true)))
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

async fn reauth_start(
    Extension(auth): Extension<Arc<AuthService>>,
    Source(source): Source,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    IdemJson(req, idem): IdemJson<ReauthStartReq>,
) -> Result<Response, ApiError> {
    let claims = claims_of(&auth, &method, &uri, &headers).await?;
    let cr = b64("credential_request", &req.credential_request)?;
    let o = auth.reauth_start(&claims, &cr, &source, idem).await?;
    out(o, |v| wire::reauth_start(&v))
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
    IdemJson(req, idem): IdemJson<ReauthFinishReq>,
) -> Result<Response, ApiError> {
    let claims = claims_of(&auth, &method, &uri, &headers).await?;
    let fin = b64("credential_finalization", &req.credential_finalization)?;
    let o = auth
        .reauth_finish(&claims, &req.reauth_txn, &fin, &source, idem)
        .await?;
    out(o, |()| Ok(wire::no_content(false)))
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

async fn wa_register_start(
    Extension(auth): Extension<Arc<AuthService>>,
    Source(source): Source,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    IdemJson(_, idem): IdemJson<Empty>,
) -> Result<Response, ApiError> {
    let claims = claims_of(&auth, &method, &uri, &headers).await?;
    let o = auth.webauthn_register_start(&claims, &source, idem).await?;
    out(o, |s| wire::ceremony_start(CeremonyField::Registration, &s))
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
    IdemJson(req, idem): IdemJson<WaRegisterFinishReq>,
) -> Result<Response, ApiError> {
    let claims = claims_of(&auth, &method, &uri, &headers).await?;
    let o = auth
        .webauthn_register_finish(
            &claims,
            &req.registration_txn,
            &req.credential,
            req.label.as_deref().unwrap_or_default(),
            &source,
            idem,
        )
        .await?;
    out(o, |p| Reply::json(200, &p))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WaLoginStartReq {
    tenant: String,
}

async fn wa_login_start(
    Extension(auth): Extension<Arc<AuthService>>,
    Source(source): Source,
    IdemJson(req, idem): IdemJson<WaLoginStartReq>,
) -> Result<Response, ApiError> {
    let o = auth
        .webauthn_login_start(&req.tenant, &source, idem)
        .await?;
    out(o, |s| wire::ceremony_start(CeremonyField::Login, &s))
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
    IdemJson(req, idem): IdemJson<WaLoginFinishReq>,
) -> Result<Response, ApiError> {
    let c = ctx(&method, &uri, &headers)?;
    let ua = user_agent(&headers);
    let o = auth
        .webauthn_login_finish(
            &req.login_txn,
            &req.credential,
            &source,
            ua.as_deref(),
            &c,
            idem,
        )
        .await?;
    out(o, |a| wire::authenticated(&a))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WaAssertStartReq {
    #[serde(default)]
    auth_txn: Option<String>,
}

async fn wa_assert_start(
    Extension(auth): Extension<Arc<AuthService>>,
    Source(source): Source,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    IdemJson(req, idem): IdemJson<WaAssertStartReq>,
) -> Result<Response, ApiError> {
    let claims = optional_claims(&auth, &method, &uri, &headers).await?;
    let o = auth
        .webauthn_assert_start(req.auth_txn.as_deref(), claims.as_ref(), &source, idem)
        .await?;
    out(o, |s| wire::ceremony_start(CeremonyField::Assert, &s))
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
    IdemJson(req, idem): IdemJson<WaAssertFinishReq>,
) -> Result<Response, ApiError> {
    let claims = optional_claims(&auth, &method, &uri, &headers).await?;
    let c = ctx(&method, &uri, &headers)?;
    let ua = user_agent(&headers);
    let o = auth
        .webauthn_assert_finish(
            &req.assert_txn,
            &req.credential,
            claims.as_ref(),
            &source,
            ua.as_deref(),
            &c,
            idem,
        )
        .await?;
    out(o, |a| match a {
        AssertOutcome::Authenticated(a) => wire::authenticated(&a),
        AssertOutcome::SteppedUp => Ok(wire::no_content(false)),
    })
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
    IdemJson(req, idem): IdemJson<MfaRecoveryCodeReq>,
) -> Result<Response, ApiError> {
    let c = ctx(&method, &uri, &headers)?;
    let ua = user_agent(&headers);
    let o = auth
        .mfa_recovery_code(&req.auth_txn, &req.code, &source, ua.as_deref(), &c, idem)
        .await?;
    out(o, |a| wire::authenticated(&a))
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

async fn recovery_start(
    Extension(auth): Extension<Arc<AuthService>>,
    Source(source): Source,
    headers: HeaderMap,
    IdemJson(req, idem): IdemJson<RecoveryStartReq>,
) -> Result<Response, ApiError> {
    let ua = user_agent(&headers);
    let o = auth
        .recovery_start(
            &req.tenant,
            &req.login,
            &req.method,
            req.code.as_deref(),
            &source,
            ua.as_deref(),
            idem,
        )
        .await?;
    out(o, |r| wire::recovery_start(&r))
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
    IdemJson(req, idem): IdemJson<RecoveryStatusReq>,
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
    let o = auth.recovery_status(by, &source, idem).await?;
    out(o, |s| wire::recovery_status(&s))
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
    idem: IdemParts,
) -> Result<Response, ApiError> {
    let idem = idem.absent_body()?;
    let claims = match claims_of(&auth, &method, &uri, &headers).await {
        Ok(c) => c,
        // rev 16 P4: only the caller's own session is replayable after revocation.
        Err(e) => {
            return logout_or_replay(&auth, e, idem, &method, &uri, &headers, Some(&sid)).await;
        }
    };
    let o = auth.session_revoke(&claims, &sid, idem).await?;
    out(o, |r| Ok(wire::no_content(r == Revoked::Current)))
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
    idem: IdemParts,
) -> Result<Response, ApiError> {
    let idem = idem.absent_body()?;
    let claims = claims_of(&auth, &method, &uri, &headers).await?;
    let o = auth.passkey_delete(&claims, &id, idem).await?;
    out(o, |()| Ok(wire::no_content(false)))
}

#[derive(Debug, Serialize)]
struct Remaining {
    remaining: i64,
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
    idem: IdemParts,
) -> Result<Response, ApiError> {
    let idem = idem.absent_body()?;
    let claims = claims_of(&auth, &method, &uri, &headers).await?;
    let o = auth.recovery_codes_generate(&claims, idem).await?;
    out(o, |c| wire::codes(&c))
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
    idem: IdemParts,
) -> Result<Response, ApiError> {
    let idem = idem.absent_body()?;
    let claims = claims_of(&auth, &method, &uri, &headers).await?;
    let o = auth
        .recovery_cancel(&claims, request_id(&id)?, idem)
        .await?;
    out(o, |()| Ok(wire::no_content(false)))
}

async fn me_recovery_request_approve(
    Extension(auth): Extension<Arc<AuthService>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(id): Path<String>,
    idem: IdemParts,
) -> Result<Response, ApiError> {
    let idem = idem.absent_body()?;
    let claims = claims_of(&auth, &method, &uri, &headers).await?;
    let o = auth
        .recovery_approve(&claims, request_id(&id)?, idem)
        .await?;
    out(o, |()| Ok(wire::no_content(false)))
}
