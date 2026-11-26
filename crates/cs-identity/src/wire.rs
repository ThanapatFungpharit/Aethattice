//! Wire bodies of the identity write routes. The HTTP layer and the idempotency store
//! (contract rev 15) render through the same functions, so a replay is byte-identical to the
//! original response.

use crate::auth::{Authenticated, LoginStart, RegisterStart};
use crate::idem::Reply;
use crate::recovery::{RecoveryStart, RecoveryStatus};
use crate::webauthn::CeremonyStart;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cs_common::secret::Secret;
use cs_db::DbError;
use cs_identity_wire::{KSF_ALGORITHM, KsfParams};
use serde::Serialize;

/// Refresh cookie name (contract §2.4).
pub const REFRESH_COOKIE: &str = "__Secure-cs_rt";
/// Refresh cookie path (contract §2.4).
pub const REFRESH_COOKIE_PATH: &str = "/api/v2/auth/token";

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

#[derive(Debug, Serialize)]
struct AuthBody<'a> {
    state: &'static str,
    access_token: &'a str,
    expires_in: i64,
    session_id: String,
    /// rev 9: present (and `true`) only when the client should re-register (`ksf_upgrade`).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    reregister: bool,
}

/// The §2.4 result: `200 {state: "authenticated", …}` plus the refresh cookie.
pub fn authenticated(a: &Authenticated) -> Result<Reply, DbError> {
    Ok(Reply::json(
        200,
        &AuthBody {
            state: "authenticated",
            access_token: a.access_token.expose_secret(),
            expires_in: a.expires_in,
            session_id: a.session_id.as_uuid().to_string(),
            reregister: a.reregister,
        },
    )?
    .with_cookie(Some(refresh_cookie(
        a.refresh_token.expose_secret(),
        a.refresh_max_age,
    ))))
}

#[derive(Debug, Serialize)]
struct MfaRequiredBody<'a> {
    state: &'static str,
    auth_txn: &'a str,
    methods: &'a [&'static str],
}

/// `200 {state: "mfa_required", auth_txn, methods}` (rev 11).
pub fn mfa_required(auth_txn: &Secret<String>, methods: &[&'static str]) -> Result<Reply, DbError> {
    Reply::json(
        200,
        &MfaRequiredBody {
            state: "mfa_required",
            auth_txn: auth_txn.expose_secret(),
            methods,
        },
    )
}

#[derive(Debug, Serialize)]
struct LoginStartBody<'a> {
    login_txn: &'a str,
    credential_response: String,
    ksf_params: KsfWire,
}

pub fn login_start(r: &LoginStart) -> Result<Reply, DbError> {
    Reply::json(
        200,
        &LoginStartBody {
            login_txn: r.login_txn.expose_secret(),
            credential_response: URL_SAFE_NO_PAD.encode(&r.credential_response),
            ksf_params: r.ksf_params.into(),
        },
    )
}

#[derive(Debug, Serialize)]
struct ReauthStartBody<'a> {
    reauth_txn: &'a str,
    credential_response: String,
    ksf_params: KsfWire,
}

pub fn reauth_start(r: &LoginStart) -> Result<Reply, DbError> {
    Reply::json(
        200,
        &ReauthStartBody {
            reauth_txn: r.login_txn.expose_secret(),
            credential_response: URL_SAFE_NO_PAD.encode(&r.credential_response),
            ksf_params: r.ksf_params.into(),
        },
    )
}

#[derive(Debug, Serialize)]
struct RegisterStartBody<'a> {
    registration_txn: &'a str,
    registration_response: String,
    ksf_params: KsfWire,
}

pub fn register_start(r: &RegisterStart) -> Result<Reply, DbError> {
    Reply::json(
        200,
        &RegisterStartBody {
            registration_txn: r.registration_txn.expose_secret(),
            registration_response: URL_SAFE_NO_PAD.encode(&r.registration_response),
            ksf_params: r.ksf_params.into(),
        },
    )
}

/// The txn member name of a WebAuthn ceremony start.
#[derive(Debug, Clone, Copy)]
pub enum CeremonyField {
    Registration,
    Login,
    Assert,
}

#[derive(Debug, Serialize)]
struct RegistrationStartBody<'a> {
    registration_txn: &'a str,
    public_key: &'a serde_json::Value,
}

#[derive(Debug, Serialize)]
struct LoginCeremonyBody<'a> {
    login_txn: &'a str,
    public_key: &'a serde_json::Value,
}

#[derive(Debug, Serialize)]
struct AssertStartBody<'a> {
    assert_txn: &'a str,
    public_key: &'a serde_json::Value,
}

pub fn ceremony_start(field: CeremonyField, s: &CeremonyStart) -> Result<Reply, DbError> {
    let (txn, public_key) = (s.txn.expose_secret().as_str(), &s.public_key);
    match field {
        CeremonyField::Registration => Reply::json(
            200,
            &RegistrationStartBody {
                registration_txn: txn,
                public_key,
            },
        ),
        CeremonyField::Login => Reply::json(
            200,
            &LoginCeremonyBody {
                login_txn: txn,
                public_key,
            },
        ),
        CeremonyField::Assert => Reply::json(
            200,
            &AssertStartBody {
                assert_txn: txn,
                public_key,
            },
        ),
    }
}

#[derive(Debug, Serialize)]
struct RecoveryBody<'a> {
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery_txn: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    available_at: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant_expires_in: Option<i64>,
}

/// `recovery/start`: `200 {state: "granted", grant, grant_expires_in}` or
/// `202 {state: "pending", recovery_txn?}`.
pub fn recovery_start(r: &RecoveryStart) -> Result<Reply, DbError> {
    match r {
        RecoveryStart::Granted {
            grant,
            grant_expires_in,
        } => Reply::json(
            200,
            &RecoveryBody {
                state: "granted",
                recovery_txn: None,
                available_at: None,
                grant: Some(grant.expose_secret()),
                grant_expires_in: Some(*grant_expires_in),
            },
        ),
        RecoveryStart::Pending { recovery_txn } => Reply::json(
            202,
            &RecoveryBody {
                state: "pending",
                recovery_txn: recovery_txn.as_ref().map(|t| t.expose_secret().as_str()),
                available_at: None,
                grant: None,
                grant_expires_in: None,
            },
        ),
    }
}

/// `recovery/status`: `200 {state, available_at?, grant?, grant_expires_in?}`.
pub fn recovery_status(s: &RecoveryStatus) -> Result<Reply, DbError> {
    Reply::json(
        200,
        &RecoveryBody {
            state: s.state,
            recovery_txn: None,
            available_at: s.available_at.as_deref(),
            grant: s.grant.as_ref().map(|g| g.expose_secret().as_str()),
            grant_expires_in: s.grant_expires_in,
        },
    )
}

#[derive(Debug, Serialize)]
struct CodesBody<'a> {
    codes: Vec<&'a str>,
}

/// `POST /me/recovery-codes`: `200 {codes}`.
pub fn codes(codes: &[Secret<String>]) -> Result<Reply, DbError> {
    Reply::json(
        200,
        &CodesBody {
            codes: codes.iter().map(|c| c.expose_secret().as_str()).collect(),
        },
    )
}

/// `204`, optionally clearing the refresh cookie.
pub fn no_content(clear_cookie: bool) -> Reply {
    Reply::empty(204).with_cookie(clear_cookie.then(clear_refresh_cookie))
}
